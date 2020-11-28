#include <kernel.h>
#include <drivers/storage.h>
#include <virtio/scsi.h>
#include <io.h>

#include "virtio_internal.h"
#include "virtio_pci.h"

#ifdef VIRTIO_SCSI_DEBUG
# define virtio_scsi_debug rprintf
#else
# define virtio_scsi_debug(...) do { } while(0)
#endif // defined(VIRTIO_SCSI_DEBUG)

struct virtio_scsi_config {
    u32 num_queues;
    u32 seg_max;
    u32 max_sectors;
    u32 cmd_per_lun;
    u32 event_info_size;
    u32 sense_size;
    u32 cdb_size;
    u16 max_channel;
    u16 max_target;
    u32 max_lun;
} __attribute__((packed));

#define VIRTIO_SCSI_R_NUM_QUEUES        (offsetof(struct virtio_scsi_config *, num_queues))
#define VIRTIO_SCSI_R_SEG_MAX           (offsetof(struct virtio_scsi_config *, seg_max))
#define VIRTIO_SCSI_R_MAX_SECTORS       (offsetof(struct virtio_scsi_config *, max_sectors))
#define VIRTIO_SCSI_R_CMD_PER_LUN       (offsetof(struct virtio_scsi_config *, cmd_per_lun))
#define VIRTIO_SCSI_R_EVENT_INFO_SIZE   (offsetof(struct virtio_scsi_config *, event_info_size))
#define VIRTIO_SCSI_R_SENSE_SIZE        (offsetof(struct virtio_scsi_config *, sense_size))
#define VIRTIO_SCSI_R_CDB_SIZE          (offsetof(struct virtio_scsi_config *, cdb_size))
#define VIRTIO_SCSI_R_MAX_CHANNEL       (offsetof(struct virtio_scsi_config *, max_channel))
#define VIRTIO_SCSI_R_MAX_TARGET        (offsetof(struct virtio_scsi_config *, max_target))
#define VIRTIO_SCSI_R_MAX_LUN           (offsetof(struct virtio_scsi_config *, max_lun))

/* Feature bits */
#define VIRTIO_SCSI_F_INOUT             0x0001  /* Single request can contain both
                                                 * read and write buffers */
#define VIRTIO_SCSI_F_HOTPLUG           0x0002  /* Host should enable hot plug/unplug
                                                 * of new LUNs and targets */
#define VIRTIO_SCSI_F_CHANGE            0x0004  /* The host will report changes to LUN
                                                 * parameters via a VIRTIO_SCSI_T_PARAM_CHANGE event */

#define VIRTIO_SCSI_S_OK                0
#define VIRTIO_SCSI_S_OVERRUN           1
#define VIRTIO_SCSI_S_ABORTED           2
#define VIRTIO_SCSI_S_BAD_TARGET        3
#define VIRTIO_SCSI_S_RESET             4
#define VIRTIO_SCSI_S_BUSY              5
#define VIRTIO_SCSI_S_TRANSPORT_FAILURE 6
#define VIRTIO_SCSI_S_TARGET_FAILURE    7
#define VIRTIO_SCSI_S_NEXUS_FAILURE     8
#define VIRTIO_SCSI_S_FAILURE           9

#define VIRTIO_SCSI_SENSE_SIZE          96
#define VIRTIO_SCSI_CDB_SIZE            32

#define VIRTIO_SCSI_NUM_EVENTS          4

struct virtio_scsi_event {
    u32 event;
    u8 lun[8];
    u32 reason;
} __attribute__((packed));

typedef struct virtio_scsi_event *virtio_scsi_event;

struct virtio_scsi_req_cmd {
    u8 lun[8];
    u64 id;
    u8 task_attr;
    u8 prio;
    u8 crn;
    u8 cdb[VIRTIO_SCSI_CDB_SIZE];
} __attribute__((packed));

struct virtio_scsi_resp_cmd {
    u32 sense_len;
    u32 residual;
    u16 status_qualifier;
    u8 status;
    u8 response;
    u8 sense[VIRTIO_SCSI_SENSE_SIZE];
} __attribute__((packed));

struct virtio_scsi_request {
    struct virtio_scsi_req_cmd req;
    struct virtio_scsi_resp_cmd resp;
    u32 alloc_len;                     // allocated data length
    char data[];                       // embedded datain/dataout
};

typedef struct virtio_scsi_request *virtio_scsi_request;

struct virtio_scsi {
    vtpci v;

    struct virtqueue *command;

    struct virtqueue *eventq;
    struct virtio_scsi_event events[VIRTIO_SCSI_NUM_EVENTS];

    struct virtqueue *requestq;

    u16 max_target;
    u16 max_lun;
};

typedef struct virtio_scsi *virtio_scsi;

typedef struct virtio_scsi_disk {
    virtio_scsi scsi;
    u16 target;
    u16 lun;
    u64 capacity;
    u64 block_size;
} *virtio_scsi_disk;

/*
 * Event queue
 */

static void virtio_scsi_enqueue_event(virtio_scsi s, virtio_scsi_event e);

closure_function(2, 1, void, virtio_scsi_event_complete,
                 virtio_scsi, s, virtio_scsi_event, e,
                 u64, len)
{
    virtio_scsi_debug("%s: event 0x%x\n", __func__, bound(e)->event);
    virtio_scsi_enqueue_event(bound(s), bound(e));
    closure_finish();
}

static void virtio_scsi_enqueue_event(virtio_scsi s, virtio_scsi_event e)
{
    vqfinish c = closure(s->v->virtio_dev.general, virtio_scsi_event_complete,
        s, e);
    virtqueue vq = s->eventq;
    vqmsg m = allocate_vqmsg(vq);
    assert(m != INVALID_ADDRESS);
    vqmsg_push(vq, m, e, sizeof(*e), true);
    vqmsg_commit(vq, m, c);
}

/*
 * Request queue
 */

typedef closure_type(vsr_complete, void, virtio_scsi, virtio_scsi_request);

closure_function(3, 1, void, virtio_scsi_request_complete,
                 vsr_complete, c, virtio_scsi, s, virtio_scsi_request, r,
                 u64, len)
{
    virtio_scsi s = bound(s);
    virtio_scsi_request r = bound(r);
    apply(bound(c), s, r);
    heap contiguous = s->v->virtio_dev.contiguous;
    deallocate(contiguous, r, pad(sizeof(*r) + r->alloc_len, contiguous->pagesize));
    closure_finish();
}

static virtio_scsi_request virtio_scsi_alloc_request(virtio_scsi s, u16 target, u16 lun, u8 cmd)
{
    int alloc_len = scsi_data_len(cmd);
    virtio_scsi_debug("%s: cmd 0x%x, data len %d\n", __func__, cmd, alloc_len);

    virtio_scsi_request r = allocate(s->v->virtio_dev.contiguous,
        sizeof(*r) + alloc_len);
    zero((void *) &r->req, sizeof(r->req));
    r->req.cdb[0] = cmd;
    r->req.lun[0] = 1;
    r->req.lun[1] = target;
    r->req.lun[2] = ((lun >> 8) & 0x3f) | 0x40;
    r->req.lun[3] = (lun & 0xff);
    r->alloc_len = alloc_len;

    return r;
}

static void virtio_scsi_enqueue_request(virtio_scsi s, virtio_scsi_request r, void *buf, u64 length, vsr_complete c)
{
    vqfinish f = closure(s->v->virtio_dev.general, virtio_scsi_request_complete,
        c, s, r);
    virtqueue vq = s->requestq;
    vqmsg m = allocate_vqmsg(vq);
    assert(m != INVALID_ADDRESS);

    vqmsg_push(vq, m, &r->req, sizeof(r->req), false);
    if (r->req.cdb[0] == SCSI_CMD_WRITE_16) {
        if (length > 0)
            vqmsg_push(vq, m, buf, length, false);          // dataout
        vqmsg_push(vq, m, &r->resp, sizeof(r->resp), true); // response
    } else {
        vqmsg_push(vq, m, &r->resp, sizeof(r->resp), true); // response
        if (length > 0)
            vqmsg_push(vq, m, buf, length, true);           // datain
    }

    vqmsg_commit(vq, m, f);
}

/*
 * Device driver hooks
 *
 * If we ever really care, the following may be simplified by re-using
 * closures and maintaining a little state machine.
 */
closure_function(3, 2, void, virtio_scsi_io_done,
                 status_handler, sh, void *, buf, u64, len,
                 virtio_scsi, s, virtio_scsi_request, r)
{
    struct virtio_scsi_resp_cmd *resp = &r->resp;
    virtio_scsi_debug("%s: response %d, status %d\n", __func__, resp->response,
                      resp->status);

    status st = 0;
    if (resp->response != VIRTIO_SCSI_S_OK) {
        st = timm("result", "response %d", resp->response);
    } else if (resp->status != SCSI_STATUS_OK) {
        scsi_dump_sense(resp->sense, sizeof(resp->sense));
        st = timm("result", "status %d", resp->status);
    }
    apply(bound(sh), st);
    closure_finish();
}

static void virtio_scsi_io(virtio_scsi_disk d, u8 cmd, void *buf, range blocks,
                           status_handler sh)
{
    virtio_scsi s = d->scsi;
    virtio_scsi_request r = virtio_scsi_alloc_request(s, d->target, d->lun, cmd);
    struct scsi_cdb_readwrite_16 *cdb = (struct scsi_cdb_readwrite_16 *) r->req.cdb;
    u32 nblocks = range_span(blocks);
    cdb->addr = htobe64(blocks.start);
    cdb->length = htobe32(nblocks);
    virtio_scsi_debug("%s: cmd %d, blocks %R, addr 0x%016lx, length 0x%08x\n",
        __func__, cmd, blocks, cdb->addr, cdb->length);
    virtio_scsi_enqueue_request(s, r, buf, nblocks * d->block_size,
        closure(s->v->virtio_dev.general, virtio_scsi_io_done, sh, buf,
            nblocks * d->block_size));
}

closure_function(1, 3, void, virtio_scsi_write,
                 virtio_scsi_disk, s,
                 void *, buf, range, blocks, status_handler, sh)
{
    virtio_scsi_io(bound(s), SCSI_CMD_WRITE_16, buf, blocks, sh);
}

closure_function(1, 3, void, virtio_scsi_read,
                 virtio_scsi_disk, s,
                 void *, buf, range, blocks, status_handler, sh)
{
    virtio_scsi_io(bound(s), SCSI_CMD_READ_16, buf, blocks, sh);
}

closure_function(2, 0, void, virtio_scsi_init_done,
                 virtio_scsi_disk, d, storage_attach, a)
{
    virtio_scsi_disk d = bound(d);
    virtio_scsi s = d->scsi;
    heap h = s->v->virtio_dev.general;
    block_io in = closure(h, virtio_scsi_read, d);
    block_io out = closure(h, virtio_scsi_write, d);
    apply(bound(a), in, out, d->capacity);
    closure_finish();
}

closure_function(3, 2, void, virtio_scsi_read_capacity_done,
                 storage_attach, a, u16, target, u16, lun,
                 virtio_scsi, s, virtio_scsi_request, r)
{
    u16 target = bound(target);
    u16 lun = bound(lun);
    struct virtio_scsi_resp_cmd *resp = &r->resp;
    virtio_scsi_debug("%s: target %d, lun %d, response %d, status %d\n",
        __func__, target, lun, resp->response, resp->status);
    if (resp->response != VIRTIO_SCSI_S_OK)
        goto out;
    if (resp->status != SCSI_STATUS_OK) {
        scsi_dump_sense(resp->sense, sizeof(resp->sense));
        goto out;
    }
    virtio_scsi_disk d = allocate(s->v->virtio_dev.general, sizeof(*d));
    if (d == INVALID_ADDRESS) {
        msg_err("cannot allocate SCSI disk\n");
        goto out;
    }

    struct scsi_res_read_capacity_16 *res = (struct scsi_res_read_capacity_16 *) r->data;
    u64 sectors = be64toh(res->addr) + 1; // returns address of last sector
    d->block_size = be32toh(res->length);
    d->capacity = sectors * d->block_size;
    d->target = target;
    d->lun = lun;
    d->scsi = s;
    virtio_scsi_debug("%s: target %d, lun %d, block size 0x%lx, capacity 0x%lx\n",
        __func__, target, lun, d->block_size, d->capacity);

    enqueue_irqsafe(runqueue, closure(s->v->virtio_dev.general, virtio_scsi_init_done,
        d, bound(a)));
  out:
    closure_finish();
}

closure_function(4, 2, void, virtio_scsi_test_unit_ready_done,
                 storage_attach, a, u16, target, u16, lun, int, retry_count,
                 virtio_scsi, s, virtio_scsi_request, r)
{
    storage_attach a = bound(a);
    u16 target = bound(target);
    u16 lun = bound(lun);
    int retry_count = bound(retry_count);

    struct virtio_scsi_resp_cmd *resp = &r->resp;
    virtio_scsi_debug("%s: target %d, lun %d, response %d, status %d\n",
        __func__, target, lun, resp->response, resp->status);
    if (resp->response != VIRTIO_SCSI_S_OK) {
        goto out;
    }

    heap h = s->v->virtio_dev.general;
    if (resp->status != SCSI_STATUS_OK) {
        if (retry_count < 3) {
            r = virtio_scsi_alloc_request(s, target, lun, SCSI_CMD_TEST_UNIT_READY);
            virtio_scsi_enqueue_request(s, r, r->data, r->alloc_len,
                closure(h, virtio_scsi_test_unit_ready_done, a, target, lun, retry_count + 1));
        } else {
            scsi_dump_sense(resp->sense, sizeof(resp->sense));
        }
        goto out;
    }

    // read capacity
    r = virtio_scsi_alloc_request(s, target, lun, SCSI_CMD_SERVICE_ACTION);
    struct scsi_cdb_read_capacity_16 *cdb = (struct scsi_cdb_read_capacity_16 *) r->req.cdb;
    cdb->service_action = SRC16_SERVICE_ACTION;
    cdb->alloc_len = htobe32(r->alloc_len);
    virtio_scsi_enqueue_request(s, r, r->data, r->alloc_len,
        closure(h, virtio_scsi_read_capacity_done, a, target, lun));
  out:
    closure_finish();
}

closure_function(3, 2, void, virtio_scsi_inquiry_done,
                 storage_attach, a, u16, target, u16, lun,
                 virtio_scsi, s, virtio_scsi_request, r)
{
    u16 target = bound(target);
    u16 lun = bound(lun);
    struct virtio_scsi_resp_cmd *resp = &r->resp;
    virtio_scsi_debug("%s: target %d, lun %d, response %d, status %d\n",
        __func__, target, lun, resp->response, resp->status);
    if (resp->response != VIRTIO_SCSI_S_OK || resp->status != SCSI_STATUS_OK) {
        if (resp->status != SCSI_STATUS_OK)
            scsi_dump_sense(resp->sense, sizeof(resp->sense));
        closure_finish();
        return;
    }

    struct scsi_res_inquiry *res = (struct scsi_res_inquiry *) r->data;
#ifdef VIRTIO_SCSI_DEBUG
    virtio_scsi_debug("%s: vendor %b, product %b, revision %b\n",
        __func__,
        alloca_wrap_buffer(res->vendor, sizeof(res->vendor)),
        alloca_wrap_buffer(res->product, sizeof(res->product)),
        alloca_wrap_buffer(res->revision, sizeof(res->revision)));
#endif
    static const char vendor_google[] = "Google";
    if (runtime_memcmp(res->vendor, vendor_google, sizeof(vendor_google) - 1) == 0) {
        virtio_scsi_debug("%s: limiting max queued\n", __func__);
        virtqueue_set_max_queued(s->requestq, 1);
    }

    // test unit ready
    r = virtio_scsi_alloc_request(s, target, lun, SCSI_CMD_TEST_UNIT_READY);
    virtio_scsi_enqueue_request(s, r, r->data, r->alloc_len,
                                closure(s->v->virtio_dev.general,
                                virtio_scsi_test_unit_ready_done, bound(a), target, lun, 0));
    closure_finish();
}

closure_function(2, 2, void, virtio_scsi_report_luns_done,
                 storage_attach, a, u16, target,
                 virtio_scsi, s, virtio_scsi_request, r)
{
    u16 target = bound(target);
    struct virtio_scsi_resp_cmd *resp = &r->resp;
    virtio_scsi_debug("%s: target %d, response %d, status %d\n",
        __func__, target, resp->response, resp->status);
    if (resp->response != VIRTIO_SCSI_S_OK || resp->status != SCSI_STATUS_OK) {
        if (resp->status != SCSI_STATUS_OK)
            scsi_dump_sense(resp->sense, sizeof(resp->sense));
        closure_finish();
        return;
    }

    struct scsi_res_report_luns *res = (struct scsi_res_report_luns *) r->data;
    u32 length = be32toh(res->length);
    virtio_scsi_debug("%s: got %d luns\n", __func__, length / sizeof(res->lundata[0]));
    for (u32 i = 0; i < MIN(s->max_lun, length / sizeof(res->lundata[0])); i++) {
        u16 lun = (res->lundata[i] & 0xffff) >> 8;
        virtio_scsi_debug("%s: got lun %d (lundata 0x%08lx)\n", __func__, lun, res->lundata[i]);

        // inquiry
        virtio_scsi_request r = virtio_scsi_alloc_request(s, target, lun, SCSI_CMD_INQUIRY);
        struct scsi_cdb_inquiry *cdb = (struct scsi_cdb_inquiry *) r->req.cdb;
        cdb->length = htobe16(r->alloc_len);
        virtio_scsi_enqueue_request(s, r, r->data, r->alloc_len,
                                    closure(s->v->virtio_dev.general,
                                    virtio_scsi_inquiry_done, bound(a), target, lun));
    }
    closure_finish();
}

static void virtio_scsi_report_luns(virtio_scsi s, storage_attach a, u16 target)
{
    virtio_scsi_request r = virtio_scsi_alloc_request(s, target, 0, SCSI_CMD_REPORT_LUNS);
    struct scsi_cdb_report_luns *cdb = (struct scsi_cdb_report_luns *) r->req.cdb;
    cdb->select_report = RPL_REPORT_DEFAULT;
    cdb->length = htobe32(r->alloc_len);
    virtio_scsi_enqueue_request(s, r, r->data, r->alloc_len,
        closure(s->v->virtio_dev.general, virtio_scsi_report_luns_done, a, target));
}

static void virtio_scsi_attach(heap general, storage_attach a, heap page_allocator, pci_dev _dev)
{
    virtio_scsi s = allocate(general, sizeof(struct virtio_scsi));
    s->v = attach_vtpci(general, page_allocator, _dev, 0);

    virtio_scsi_debug("features 0x%lx\n", s->v->features);

#ifdef VIRTIO_SCSI_DEBUG
    u32 num_queues = pci_bar_read_4(&s->v->device_config, VIRTIO_SCSI_R_NUM_QUEUES);
    virtio_scsi_debug("num queues %d\n", num_queues);

    u32 seg_max = pci_bar_read_4(&s->v->device_config, VIRTIO_SCSI_R_SEG_MAX);
    virtio_scsi_debug("seg max %d\n", seg_max);

    u32 max_sectors = pci_bar_read_4(&s->v->device_config, VIRTIO_SCSI_R_MAX_SECTORS);
    virtio_scsi_debug("max sectors %d\n", max_sectors);

    u32 cmd_per_lun = pci_bar_read_4(&s->v->device_config, VIRTIO_SCSI_R_CMD_PER_LUN);
    virtio_scsi_debug("cmd per lun %d\n", cmd_per_lun);

    u32 event_info_size = pci_bar_read_4(&s->v->device_config, VIRTIO_SCSI_R_EVENT_INFO_SIZE);
    virtio_scsi_debug("event info size %d\n", event_info_size);

    u32 max_channel = pci_bar_read_2(&s->v->device_config, VIRTIO_SCSI_R_MAX_CHANNEL);
    virtio_scsi_debug("max channel %d\n", max_channel);
#endif

    s->max_target = pci_bar_read_2(&s->v->device_config, VIRTIO_SCSI_R_MAX_TARGET);
    virtio_scsi_debug("max target %d\n", s->max_target);

    s->max_lun = pci_bar_read_4(&s->v->device_config, VIRTIO_SCSI_R_MAX_LUN);
    virtio_scsi_debug("max lun %d\n", s->max_lun);

    status st = vtpci_alloc_virtqueue(s->v, "virtio scsi command", 0, bhqueue, &s->command);
    assert(st == STATUS_OK);
    st = vtpci_alloc_virtqueue(s->v, "virtio scsi event", 1, bhqueue, &s->eventq);
    assert(st == STATUS_OK);
    st = vtpci_alloc_virtqueue(s->v, "virtio scsi request", 2, bhqueue, &s->requestq);
    assert(st == STATUS_OK);

    // On reset, the device MUST set sense_size to 96 and cdb_size to 32
    pci_bar_write_4(&s->v->device_config, VIRTIO_SCSI_R_SENSE_SIZE, VIRTIO_SCSI_SENSE_SIZE);
    pci_bar_write_4(&s->v->device_config, VIRTIO_SCSI_R_CDB_SIZE, VIRTIO_SCSI_CDB_SIZE);

    // initialization complete
    vtpci_set_status(s->v, VIRTIO_CONFIG_STATUS_DRIVER_OK);

    // enqueue events
    for (int i = 0; i < VIRTIO_SCSI_NUM_EVENTS; i++)
        virtio_scsi_enqueue_event(s, s->events + i);

    // scan bus
    for (u16 target = 0; target <= s->max_target; target++)
        virtio_scsi_report_luns(s, a, target);
}

closure_function(3, 1, boolean, virtio_scsi_probe,
                 heap, general, storage_attach, a, heap, page_allocator,
                 pci_dev, d)
{
    if (!vtpci_probe(d, VIRTIO_ID_SCSI))
        return false;

    virtio_scsi_attach(bound(general), bound(a), bound(page_allocator), d);
    return true;
}

void virtio_register_scsi(kernel_heaps kh, storage_attach a)
{
    heap h = heap_locked(kh);
    register_pci_driver(closure(h, virtio_scsi_probe, h, a, heap_backed(kh)));
}
