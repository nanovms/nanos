#include <kernel.h>
#include <page.h>
#include <pci.h>
#include "pvscsi.h"
#include "storage.h"
#include "virtio/scsi.h"

#ifdef PVSCSI_DEBUG
# define pvscsi_debug rprintf
#else
# define pvscsi_debug(...) do { } while(0)
#endif // defined(PVSCSI_DEBUG)

#define PVSCSI_DEFAULT_NUM_PAGES_REQ_RING 8
#define PVSCSI_CDB_SIZE 16
#define PVSCSI_SENSE_SIZE 256
#define PVSCSI_RETRY_LIMIT  3

struct pvscsi_hcb {
    struct pvscsi_ring_req_desc    *e;
    struct list links;

    u16 target;
    u16 lun;
    u32 data_len;
    u64 data_addr;

    u8 cdb[PVSCSI_CDB_SIZE];
    u16 host_status;
    u16 scsi_status;

    thunk completion;
    u32 alloc_len;                     // allocated data length
    void *data;                       // allocated data

    u8 sense[PVSCSI_SENSE_SIZE];
};

typedef struct pvscsi {
    struct pci_dev _dev;
    pci_dev dev;

    struct pci_bar bar;

    heap contiguous;
    heap general;

    heap hcb_objcache;
    struct spinlock mem_lock;

    struct pvscsi_rings_state    *rings_state;
    struct pvscsi_ring_req_desc    *req_ring;
    struct pvscsi_ring_cmp_desc    *cmp_ring;

    u32 max_targets;
    u32 adapter_queue_size;

    struct list hcb_queue;
    struct spinlock queue_lock;

    thunk intr_handler;
    thunk rx_service;
    queue rx_servicequeue;
} *pvscsi;

typedef struct pvscsi_disk {
    pvscsi scsi;
    u16 target;
    u16 lun;
    u64 capacity;
    u64 block_size;
} *pvscsi_disk;

static void pvscsi_write_cmd(pvscsi dev, u32 cmd, void *data, u32 len)
{
    assert(len % sizeof(u32) == 0);

    u32 *data_ptr = data;
    len /= sizeof(u32);

    pci_bar_write_4(&dev->bar, PVSCSI_REG_OFFSET_COMMAND, cmd);
    for (int i = 0; i < len; ++i) {
        pci_bar_write_4(&dev->bar, PVSCSI_REG_OFFSET_COMMAND_DATA, data_ptr[i]);
    }
}

static void pvscsi_hcb_dealloc(pvscsi dev, struct pvscsi_hcb *hcb)
{
    spin_lock(&dev->mem_lock);
    if (hcb->alloc_len) {
        deallocate(dev->contiguous, hcb->data, pad(hcb->alloc_len, dev->contiguous->pagesize));
    }
    deallocate(dev->hcb_objcache, hcb, sizeof(struct pvscsi_hcb));
    spin_unlock(&dev->mem_lock);
}

static struct pvscsi_hcb *pvscsi_hcb_alloc(pvscsi dev, u16 target, u16 lun, u8 cmd)
{
    int alloc_len = scsi_data_len(cmd);
    spin_lock(&dev->mem_lock);
    struct pvscsi_hcb *hcb = allocate(dev->hcb_objcache, sizeof(struct pvscsi_hcb));
    assert(hcb != INVALID_ADDRESS);
    if (alloc_len) {
        hcb->data = allocate(dev->contiguous, alloc_len);
        assert(hcb->data != INVALID_ADDRESS);
        hcb->alloc_len = alloc_len;
    } else {
        hcb->data = 0;
        hcb->alloc_len = 0;
    }
    spin_unlock(&dev->mem_lock);
    zero(hcb->cdb, sizeof(hcb->cdb));
    hcb->cdb[0] = cmd;
    pvscsi_debug("%s: hcb %p, cmd 0x%02x\n", __func__, hcb, hcb->cdb[0]);
    return hcb;
}

static boolean pvscsi_action_io(pvscsi dev, struct pvscsi_hcb *hcb);

static void pvscsi_action_io_queued(pvscsi dev, struct pvscsi_hcb *hcb, u16 target, u16 lun,
                                    void *buf, u64 length)
{
    hcb->data_len = length;
    if (!hcb->data_len) {
        hcb->data_addr = 0;
    } else {
        hcb->data_addr = physical_from_virtual(buf);
        assert(hcb->data_addr != INVALID_PHYSICAL);
    }
    hcb->target = target;
    hcb->lun = lun;

    // order: put into hcb queue if not empty
    spin_lock(&dev->queue_lock);
    if (!list_empty(&dev->hcb_queue)) {
        list_push_back(&dev->hcb_queue, &hcb->links);
        spin_unlock(&dev->queue_lock);
        return;
    }
    spin_unlock(&dev->queue_lock);

    if (!pvscsi_action_io(dev, hcb)) {
        list_push_back(&dev->hcb_queue, &hcb->links);
    }
}

static inline void pvscsi_action(pvscsi dev, struct pvscsi_hcb *hcb, u16 target, u16 lun)
{
    pvscsi_action_io_queued(dev, hcb, target, lun, hcb->data, hcb->alloc_len);
}

closure_function(6, 0, void, pvscsi_io_done,
                 status_handler, sh, void *, buf, u64, len,
                 pvscsi_disk, d, struct pvscsi_hcb *, hcb, int, retries)
{
    struct pvscsi_hcb *hcb = bound(hcb);

    status st = 0;
    if (hcb->host_status != BTSTAT_SUCCESS) {
        st = timm("result", "response %d", hcb->host_status);
    } else if (hcb->scsi_status != SCSI_STATUS_OK) {
        if ((hcb->scsi_status == SCSI_STATUS_BUSY) &&
                (bound(retries++) < PVSCSI_RETRY_LIMIT)) {
            pvscsi_debug("%s: scsi_status busy, retrying\n", __func__);

            /* Clone the failed request and retry. */
            pvscsi_disk d = bound(d);
            struct scsi_cdb_readwrite_16 *old_cdb =
                    (struct scsi_cdb_readwrite_16 *)hcb->cdb;
            u8 cmd = old_cdb->opcode;
            struct pvscsi_hcb *r = pvscsi_hcb_alloc(d->scsi, d->target, d->lun, cmd);
            struct scsi_cdb_readwrite_16 *new_cdb =
                    (struct scsi_cdb_readwrite_16 *)r->cdb;
            new_cdb->opcode = cmd;
            new_cdb->addr = old_cdb->addr;
            new_cdb->length = old_cdb->length;
            bound(hcb) = r;
            r->completion = (thunk)closure_self();
            pvscsi_action_io_queued(d->scsi, r, d->target, d->lun, bound(buf),
                                    bound(len));
            return;
        }
        rprintf("scsi_status not ok: %d\n", hcb->scsi_status);
        scsi_dump_sense(hcb->sense, sizeof(hcb->sense));
        st = timm("result", "status %d", hcb->scsi_status);
    }
    apply(bound(sh), st);
    closure_finish();
}

static void pvscsi_io(pvscsi_disk disk, u8 cmd, void *buf, range blocks, status_handler sh)
{
    pvscsi dev = disk->scsi;
    struct pvscsi_hcb *r = pvscsi_hcb_alloc(dev, disk->target, disk->lun, cmd);
    struct scsi_cdb_readwrite_16 *cdb = (struct scsi_cdb_readwrite_16 *)r->cdb;
    cdb->opcode = cmd;
    u32 nblocks = range_span(blocks);
    cdb->addr = htobe64(blocks.start);
    cdb->length = htobe32(nblocks);
    pvscsi_debug("%s: cmd %d, blocks %R, addr 0x%016lx, length 0x%08x\n",
        __func__, cmd, blocks, cdb->addr, cdb->length);
    r->completion = closure(dev->general, pvscsi_io_done, sh, buf,
        nblocks * disk->block_size, disk, r, 0);
    pvscsi_action_io_queued(dev, r, disk->target, disk->lun, buf, nblocks * disk->block_size);
}

closure_function(1, 3, void, pvscsi_write,
                 pvscsi_disk, s,
                 void *, buf, range, blocks, status_handler, sh)
{
    pvscsi_io(bound(s), SCSI_CMD_WRITE_16, buf, blocks, sh);
}

closure_function(1, 3, void, pvscsi_read,
                 pvscsi_disk, s,
                 void *, buf, range, blocks, status_handler, sh)
{
    pvscsi_io(bound(s), SCSI_CMD_READ_16, buf, blocks, sh);
}

closure_function(5, 0, void, pvscsi_read_capacity_done,
                 storage_attach, a, u16, target, u16, lun,
                 pvscsi, s, struct pvscsi_hcb *, hcb)
{
    pvscsi s = bound(s);
    u16 target = bound(target);
    u16 lun = bound(lun);
    struct pvscsi_hcb *hcb = bound(hcb);
    pvscsi_debug("%s: target %d, lun %d, host_status %d, scsi_status %d\n",
        __func__, target, lun, hcb->host_status, hcb->scsi_status);
    if (hcb->host_status != BTSTAT_SUCCESS) {
        scsi_dump_sense(hcb->sense, sizeof(hcb->sense));
        goto out;
    }
    if (hcb->scsi_status != SCSI_STATUS_OK) {
        scsi_dump_sense(hcb->sense, sizeof(hcb->sense));
        goto out;
    }

    pvscsi_disk d = allocate(s->general, sizeof(*d));
    if (d == INVALID_ADDRESS) {
        msg_err("cannot allocate PVSCSI disk\n");
        goto out;
    }

    struct scsi_res_read_capacity_16 *res = (struct scsi_res_read_capacity_16 *) hcb->data;
    u64 sectors = be64toh(res->addr) + 1; // returns address of last sector
    d->block_size = be32toh(res->length);
    d->capacity = sectors * d->block_size;
    d->target = target;
    d->lun = lun;
    d->scsi = s;
    pvscsi_debug("%s: target %d, lun %d, block size 0x%lx, capacity 0x%lx\n",
        __func__, target, lun, d->block_size, d->capacity);

    block_io in = closure(s->general, pvscsi_read, d);
    block_io out = closure(s->general, pvscsi_write, d);
    apply(bound(a), in, out, d->capacity);
  out:
    closure_finish();
}

static void pvscsi_test_unit_ready(pvscsi dev, storage_attach a, u16 target, u16 lun, u16 retry_count);

closure_function(6, 0, void, pvscsi_test_unit_ready_done,
                 storage_attach, a, u16, target, u16, lun, int, retry_count,
                 pvscsi, s, struct pvscsi_hcb *, hcb)
{
    struct pvscsi_hcb *hcb = bound(hcb);
    pvscsi dev = bound(s);
    storage_attach a = bound(a);
    u16 target = bound(target);
    u16 lun = bound(lun);
    int retry_count = bound(retry_count);

    pvscsi_debug("%s: target %d, lun %d, host_status %d, scsi_status %d\n",
        __func__, target, lun, hcb->host_status, hcb->scsi_status);
    if (hcb->host_status != BTSTAT_SUCCESS) {
        goto out;
    }

    if (hcb->scsi_status != SCSI_STATUS_OK) {
        if (retry_count < 3) {
            pvscsi_test_unit_ready(dev, a, target, lun, retry_count);
        } else {
            scsi_dump_sense(hcb->sense, sizeof(hcb->sense));
        }
        goto out;
    }

    // read capacity
    struct pvscsi_hcb *r = pvscsi_hcb_alloc(dev, target, lun, SCSI_CMD_SERVICE_ACTION);
    struct scsi_cdb_read_capacity_16 *cdb = (struct scsi_cdb_read_capacity_16 *)r->cdb;
    cdb->service_action = SRC16_SERVICE_ACTION;
    cdb->alloc_len = htobe32(r->alloc_len);
    r->completion = closure(dev->general, pvscsi_read_capacity_done, a, target, lun, dev, r);
    pvscsi_action(dev, r, target, lun);
  out:
    closure_finish();
}

static void pvscsi_test_unit_ready(pvscsi dev, storage_attach a, u16 target, u16 lun, u16 retry_count)
{
    struct pvscsi_hcb *r = pvscsi_hcb_alloc(dev, target, lun, SCSI_CMD_TEST_UNIT_READY);
    r->completion = closure(dev->general, pvscsi_test_unit_ready_done, a, target, lun,
                              retry_count + 1, dev, r);
    pvscsi_action(dev, r, target, lun);
}

closure_function(5, 0, void, pvscsi_inquiry_done,
                 storage_attach, a, u16, target, u16, lun,
                 pvscsi, s, struct pvscsi_hcb *, hcb)
{
    struct pvscsi_hcb *hcb = bound(hcb);
    u16 target = bound(target);
    u16 lun = bound(lun);
    pvscsi_debug("%s: target %d, lun %d, host_status %d, scsi_status %d\n",
        __func__, target, lun, hcb->host_status, hcb->scsi_status);
    if (hcb->host_status != BTSTAT_SUCCESS || hcb->scsi_status != SCSI_STATUS_OK) {
        if (hcb->scsi_status != SCSI_STATUS_OK)
            scsi_dump_sense(hcb->sense, sizeof(hcb->sense));
        closure_finish();
        return;
    }

#ifdef PVSCSI_DEBUG
    struct scsi_res_inquiry *res = (struct scsi_res_inquiry *) hcb->data;
    pvscsi_debug("%s: vendor %b, product %b, revision %b\n",
        __func__,
        alloca_wrap_buffer(res->vendor, sizeof(res->vendor)),
        alloca_wrap_buffer(res->product, sizeof(res->product)),
        alloca_wrap_buffer(res->revision, sizeof(res->revision)));
#endif

    // test unit ready
    pvscsi_test_unit_ready(bound(s), bound(a), target, lun, 0);

    closure_finish();
}

closure_function(4, 0, void, pvscsi_report_luns_done,
                 storage_attach, a, u16, target,
                 pvscsi, s, struct pvscsi_hcb *, hcb)
{
    pvscsi dev = bound(s);
    struct pvscsi_hcb *hcb = bound(hcb);
    u16 target = bound(target);
    pvscsi_debug("%s: target %d, host_status %d, scsi_status %d\n",
        __func__, target, hcb->host_status, hcb->scsi_status);
    if (hcb->host_status != BTSTAT_SUCCESS || hcb->scsi_status != SCSI_STATUS_OK) {
        if (hcb->scsi_status != SCSI_STATUS_OK)
            scsi_dump_sense(hcb->sense, sizeof(hcb->sense));
        pvscsi_debug("%s: NOT SUCCESS: host_status %d, scsi_status %d\n", __func__, hcb->host_status,
                     hcb->scsi_status);
        closure_finish();
        return;
    }

    struct scsi_res_report_luns *res = (struct scsi_res_report_luns *) hcb->data;
    u32 length = be32toh(res->length);
    pvscsi_debug("%s: got %d luns\n", __func__, length / sizeof(res->lundata[0]));
    for (u32 i = 0; i < MIN(MAX_LUN, length / sizeof(res->lundata[0])); i++) {
        u16 lun = (res->lundata[i] & 0xffff) >> 8;
        pvscsi_debug("%s: got lun %d (lundata 0x%08lx)\n", __func__, lun, res->lundata[i]);

        // inquiry
        struct pvscsi_hcb *r = pvscsi_hcb_alloc(dev, target, lun, SCSI_CMD_INQUIRY);
        struct scsi_cdb_inquiry *cdb = (struct scsi_cdb_inquiry *)r->cdb;
        cdb->length = htobe16(r->alloc_len);
        r->completion = closure(dev->general, pvscsi_inquiry_done, bound(a), target, lun, dev, r);
        pvscsi_action(dev, r, target, lun);
    }
    closure_finish();
}

static void pvscsi_report_luns(pvscsi dev, storage_attach a, u16 target)
{
    struct pvscsi_hcb *r = pvscsi_hcb_alloc(dev, target, 0, SCSI_CMD_REPORT_LUNS);
    struct scsi_cdb_report_luns *cdb = (struct scsi_cdb_report_luns *)r->cdb;
    cdb->select_report = RPL_REPORT_DEFAULT;
    cdb->length = htobe32(r->alloc_len);
    r->completion = closure(dev->general, pvscsi_report_luns_done, a, target, dev, r);
    pvscsi_action(dev, r, target, 0);
}

static inline u32 pvscsi_reg_read(pvscsi dev, u32 offset)
{
    return pci_bar_read_4(&dev->bar, offset);
}

static inline void pvscsi_reg_write(pvscsi dev, u32 offset, u32 val)
{
    pci_bar_write_4(&dev->bar, offset, val);
}

static void pvscsi_process_cmp_ring(pvscsi dev);

closure_function(1, 0, void, intr_handler,
                 pvscsi, dev)
{
    pvscsi dev = bound(dev);
    pvscsi_process_cmp_ring(dev);
}

static void *pvscsi_ring_alloc(heap h, int num_pages, u64 *ppn_list)
{
    // allocate ring memory
    void *ring = allocate_zero(h, num_pages * PAGESIZE);
    assert(ring != INVALID_ADDRESS);
    assert(pad((u64)ring, PAGESIZE) == (u64)ring);

    // get physical address
    u64 phys = physical_from_virtual(ring);
    assert(phys != INVALID_PHYSICAL);

    // fill physical page numbers list
    u64 ppn = phys >> PAGELOG;
    for (int i = 0; i < num_pages; i++)
        ppn_list[i] = ppn + i;

    return ring;
}

closure_function(1, 0, void, pvscsi_rx_service_bh, pvscsi, dev)
{
    pvscsi dev = bound(dev);
    list l;
    while ((l = (list)dequeue(dev->rx_servicequeue)) != INVALID_ADDRESS) {
        struct list q;
        assert(l);
        assert(l->prev);
        list_insert_before(l, &q); /* restore list head */
        list_foreach(&q, i) {
            assert(i);
            struct pvscsi_hcb *hcb = struct_from_list(i, struct pvscsi_hcb *, links);
            assert(hcb);
            list_delete(i);
            apply(hcb->completion);
            pvscsi_hcb_dealloc(dev, hcb);
        }
    }

    spin_lock(&dev->queue_lock);
    list_foreach(&dev->hcb_queue, i) {
        assert(i);
        struct pvscsi_hcb *hcb = struct_from_list(i, struct pvscsi_hcb *, links);
        if (!pvscsi_action_io(dev, hcb))
            break;
        list_delete(i);
    }
    spin_unlock(&dev->queue_lock);
}

static void pvscsi_attach(heap general, storage_attach a, heap page_allocator, pci_dev d)
{
    struct pvscsi *dev = allocate(general, sizeof(struct pvscsi));
    dev->_dev = *d;
    dev->dev = &dev->_dev;

    dev->general = general;
    dev->contiguous = page_allocator;

    boolean bar_found = false;
    for (int barid = 0; barid <= PCIR_MAX_BAR_0; ++barid) {
        u32 base = pci_cfgread(dev->dev, PCIR_BAR(barid), 4);

        if ((PCI_BAR_B_TYPE_MASK & base) == PCI_BAR_MEMORY) {
            pci_bar_init(dev->dev, &dev->bar, barid, 0, -1);
            bar_found = true;
            break;
        }
    }
    assert(bar_found);

    pci_set_bus_master(dev->dev);
    pci_enable_msix(dev->dev);

    // identify max targets
    pvscsi_write_cmd(dev, PVSCSI_CMD_GET_MAX_TARGETS, 0, 0);
    dev->max_targets = pvscsi_reg_read(dev, PVSCSI_REG_OFFSET_COMMAND_STATUS);
    if (dev->max_targets == ~0)
        dev->max_targets = 16;
    pvscsi_debug("%s: max targets %d\n", __func__, dev->max_targets);

    // reset
    pvscsi_write_cmd(dev, PVSCSI_CMD_ADAPTER_RESET, 0, 0);

    // setup rings
    assert(pad(dev->contiguous->pagesize, PAGESIZE) == dev->contiguous->pagesize);
    struct pvscsi_cmd_desc_setup_rings cmd;
    zero((void *)&cmd, sizeof(cmd));
    cmd.req_ring_num_pages = PVSCSI_DEFAULT_NUM_PAGES_REQ_RING;
    cmd.cmp_ring_num_pages = cmd.req_ring_num_pages;
    dev->rings_state = pvscsi_ring_alloc(dev->contiguous, 1, cmd.rings_state_ppns);
    dev->req_ring = pvscsi_ring_alloc(dev->contiguous, cmd.req_ring_num_pages, cmd.req_ring_ppns);
    dev->cmp_ring = pvscsi_ring_alloc(dev->contiguous, cmd.cmp_ring_num_pages, cmd.cmp_ring_ppns);
    pvscsi_write_cmd(dev, PVSCSI_CMD_SETUP_RINGS, &cmd, sizeof(cmd));

#ifdef PVSCSI_DEBUG
    volatile struct pvscsi_rings_state *s = dev->rings_state;
    pvscsi_debug("%s: req queue %d/%d, cmp queue %d/%d, msg queue %d\n",
        __func__,
	U64_FROM_BIT(s->req_num_entries_log2), sizeof(struct pvscsi_ring_req_desc),
	U64_FROM_BIT(s->cmp_num_entries_log2), sizeof(struct pvscsi_ring_cmp_desc),
	U64_FROM_BIT(s->msg_num_entries_log2));
#endif //PVSCSI_DEBUG

    // setup hcb cache
    dev->hcb_objcache = allocate_objcache(dev->general, page_allocator,
                      sizeof(struct pvscsi_hcb), PAGESIZE_2M);
    spin_lock_init(&dev->mem_lock);

    dev->adapter_queue_size = cmd.req_ring_num_pages * PAGESIZE / sizeof(struct pvscsi_ring_req_desc);
    dev->adapter_queue_size = MIN(dev->adapter_queue_size, PVSCSI_MAX_REQ_QUEUE_DEPTH);

    list_init(&dev->hcb_queue);
    spin_lock_init(&dev->queue_lock);

    dev->rx_servicequeue = allocate_queue(dev->general, dev->adapter_queue_size);
    assert(dev->rx_servicequeue != INVALID_ADDRESS);
    dev->rx_service = closure(dev->general, pvscsi_rx_service_bh, dev);

    // setup interrupts
    dev->intr_handler = closure(dev->general, intr_handler, dev);
    pci_setup_msix(dev->dev, 0, dev->intr_handler, "pvscsi intr");
    pvscsi_reg_write(dev, PVSCSI_REG_OFFSET_INTR_MASK, PVSCSI_INTR_CMPL_MASK);

    // scan bus
    for (u16 target = 0; target <= dev->max_targets; target++)
        pvscsi_report_luns(dev, a, target);
}

boolean pvscsi_dev_probe(pci_dev d)
{
    if (pci_get_vendor(d) != PCI_VENDOR_ID_VMWARE)
        return false;

    u16 device = pci_get_device(d);
    if (device != PCI_DEVICE_ID_VMWARE_PVSCSI)
        return false;

    return true;
}

closure_function(3, 1, boolean, pvscsi_probe,
                 heap, general, storage_attach, a, heap, page_allocator, pci_dev, d)
{
    if (!pvscsi_dev_probe(d))
        return false;

    pvscsi_attach(bound(general), bound(a), bound(page_allocator), d);
    return true;
}

static void pvscsi_kick_io(pvscsi dev, u8 cdb0)
{
    if (cdb0 == SCSI_CMD_READ_16 || cdb0 == SCSI_CMD_WRITE_16) {
        pvscsi_reg_write(dev, PVSCSI_REG_OFFSET_KICK_RW_IO, 0);
    } else {
        pvscsi_reg_write(dev, PVSCSI_REG_OFFSET_KICK_NON_RW_IO, 0);
    }
}

static void pvscsi_execute_ccb(pvscsi dev, struct pvscsi_hcb *hcb)
{
    struct pvscsi_ring_req_desc *e  = hcb->e;
    struct pvscsi_rings_state *s = dev->rings_state;

    u8 cdb0 = e->cdb[0];
    e->flags = cdb0 == SCSI_CMD_WRITE_16 ? PVSCSI_FLAG_CMD_DIR_TODEVICE : PVSCSI_FLAG_CMD_DIR_TOHOST;
    pvscsi_debug("%s: e %p, flags 0x%x\n", __func__, e, e->flags);

    memory_barrier();
    s->req_prod_idx++;
    pvscsi_kick_io(dev, cdb0);
    pvscsi_debug("%s: kicked\n", __func__);
}

static inline u64 pvscsi_hcb_to_context(pvscsi dev, struct pvscsi_hcb *hcb)
{
    return (u64)hcb;
}

static inline struct pvscsi_hcb *pvscsi_context_to_hcb(pvscsi dev, u64 context)
{
    return (struct pvscsi_hcb *)context;
}

static boolean pvscsi_action_io(pvscsi dev, struct pvscsi_hcb *hcb)
{

    struct pvscsi_ring_req_desc *ring = dev->req_ring;
    struct pvscsi_rings_state *s = dev->rings_state;

    u32 req_num_entries_log2 = s->req_num_entries_log2;

    if (s->req_prod_idx - s->cmp_cons_idx >= U64_FROM_BIT(req_num_entries_log2)) {
        pvscsi_debug("Not enough room on completion ring.\n");
        return false;
    }

    pvscsi_debug("%s: req_prod_idx 0x%x, req_num_entries_log2 0x%x, hcb %p, cmd 0x%02x\n",
        __func__, s->req_prod_idx, req_num_entries_log2, hcb, hcb->cdb[0]);
    struct pvscsi_ring_req_desc *e = ring + (s->req_prod_idx & MASK(req_num_entries_log2));

    e->bus = 0;
    e->target = hcb->target;

    zero(&e->lun, sizeof(e->lun));
    e->lun[1] = hcb->lun;

    e->data_len = hcb->data_len;
    if (!e->data_len) {
        e->data_addr = 0;
    } else {
        e->data_addr = hcb->data_addr;
        assert(e->data_addr != INVALID_PHYSICAL);
    }

    e->vcpu_hint = 0;

    e->cdb_len = sizeof(e->cdb);
    runtime_memcpy(&e->cdb, &hcb->cdb, sizeof(e->cdb));

    e->sense_addr = physical_from_virtual(&hcb->sense);
    assert(e->sense_addr != INVALID_PHYSICAL);
    e->sense_len = sizeof(hcb->sense);

    e->tag = MSG_SIMPLE_Q_TAG;

    e->context = pvscsi_hcb_to_context(dev, hcb);
    hcb->e = e;

    pvscsi_execute_ccb(dev, hcb);
    return true;
}

static void pvscsi_process_cmp_ring(pvscsi dev)
{
    struct pvscsi_rings_state *s = dev->rings_state;
    struct pvscsi_ring_cmp_desc *ring = dev->cmp_ring;
    struct list q;
    list_init(&q);

    while (s->cmp_cons_idx != s->cmp_prod_idx) {
        struct pvscsi_ring_cmp_desc *e = ring + (s->cmp_cons_idx & MASK(s->cmp_num_entries_log2));

        pvscsi_debug("%s: cmp_cons_idx %d, cmp_prod_idx %d\n",
                     __func__, s->cmp_cons_idx, s->cmp_prod_idx);

        struct pvscsi_hcb *hcb = pvscsi_context_to_hcb(dev, e->context);
        hcb->scsi_status = e->scsi_status;
        hcb->host_status = e->host_status;
        list_insert_before(&q, &hcb->links);

        memory_barrier();
        s->cmp_cons_idx++;
    }

    list l = list_get_next(&q);
    if (l) {
        /* trick: remove (local) head and queue first element */
        list_delete(&q);
        assert(enqueue(dev->rx_servicequeue, l));
        enqueue(bhqueue, dev->rx_service);
    }
}

void pvscsi_register(kernel_heaps kh, storage_attach a)
{
    heap h = heap_general(kh);
    register_pci_driver(closure(h, pvscsi_probe, h, a, heap_backed(kh)));
}
