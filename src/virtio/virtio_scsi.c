#include <kernel.h>
#include <virtio/scsi.h>
#include <storage.h>

#include "virtio_internal.h"
#include "virtio_pci.h"

#ifdef VIRTIO_SCSI_DEBUG
# define virtio_scsi_debug(x, ...) do {tprintf(sym(virtio_scsi), 0, ss(x), ##__VA_ARGS__);} while(0)
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
#define VIRTIO_SCSI_EVENT_LOST          (1<<31)

#define VIRTIO_SCSI_T_NO_EVENT          0
#define VIRTIO_SCSI_T_TRANSPORT_RESET   1
#define VIRTIO_SCSI_T_ASYNC_NOTIFY      2
#define VIRTIO_SCSI_T_PARAM_CHANGE      3

#define VIRTIO_SCSI_EVT_RESET_HARD         0
#define VIRTIO_SCSI_EVT_RESET_RESCAN       1
#define VIRTIO_SCSI_EVT_RESET_REMOVED      2

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
    struct virtio_scsi_event *events;

    struct virtqueue *requestq;

    u32 seg_max;
    u16 max_target;
    u16 max_lun;

    vector disks;
    storage_attach sa;
    struct spinlock lock;
};

typedef struct virtio_scsi *virtio_scsi;
typedef struct virtio_scsi_disk *virtio_scsi_disk;

struct virtio_scsi_disk {
    closure_struct(storage_req_handler, req_handler);
    virtio_scsi scsi;
    u16 target;
    u16 lun;
    u32 max_xfer_len;
    u64 capacity;
    u64 block_size;
};

static void virtio_scsi_report_luns(virtio_scsi s, storage_attach a, u16 target);
static void send_lun_inquiry(virtio_scsi s, u16 target, u16 lun);

/*
 * Event queue
 */

static void virtio_scsi_enqueue_event(virtio_scsi s, virtio_scsi_event e, vqfinish c);

closure_function(2, 0, void, deallocate_scsi_disk, virtio_scsi, s, virtio_scsi_disk, d)
{
    deallocate(bound(s)->v->virtio_dev.general, bound(d), sizeof(struct virtio_scsi_disk));
}

static void virtio_scsi_detach_disk(virtio_scsi s, u16 target, u16 lun)
{
    spin_lock(&s->lock);
    for (int i = 0; i < vector_length(s->disks); i++) {
        virtio_scsi_disk d = vector_get(s->disks, i);
        if (d->target != target || d->lun != lun)
            continue;
        vector_delete(s->disks, i);
        spin_unlock(&s->lock);
        storage_detach((storage_req_handler)&d->req_handler, closure(s->v->virtio_dev.general, deallocate_scsi_disk, s, d));
        return;
    }
    spin_unlock(&s->lock);
    msg_err("%s: target %d lun %d not found", func_ss, target, lun);
}

closure_function(2, 1, void, virtio_scsi_event_complete,
                 virtio_scsi, s, virtio_scsi_event, e,
                 u64 len)
{
    virtio_scsi_event e = bound(e);
    virtio_scsi s = bound(s);
    virtio_scsi_debug("event 0x%x\n", e->event);
    if (e->event & VIRTIO_SCSI_EVENT_LOST)
        msg_err("vitio_scsi event lost due to missing buffers");
    switch (e->event & ~VIRTIO_SCSI_EVENT_LOST) {
    case VIRTIO_SCSI_T_TRANSPORT_RESET: {
        u16 target = e->lun[1];
        u16 lun = ((u16)(e->lun[2] & 0x3f) << 8) | e->lun[3];
        switch (e->reason) {
        case VIRTIO_SCSI_EVT_RESET_REMOVED:
            virtio_scsi_detach_disk(s, target, lun);
            break;
        case VIRTIO_SCSI_EVT_RESET_RESCAN:
            if (lun == 0)
                virtio_scsi_report_luns(s, s->sa, target);
            else
                send_lun_inquiry(s, target, lun);
            break;
        }
        break;
    }
    default:
        break;
    }
    virtio_scsi_enqueue_event(bound(s), bound(e), (vqfinish)closure_self());
}

static void virtio_scsi_enqueue_event(virtio_scsi s, virtio_scsi_event e, vqfinish c)
{
    if (!c)
        c = closure(s->v->virtio_dev.general, virtio_scsi_event_complete,
            s, e);
    virtqueue vq = s->eventq;
    vqmsg m = allocate_vqmsg(vq);
    assert(m != INVALID_ADDRESS);
    vqmsg_push(vq, m, physical_from_virtual(e), sizeof(*e), true);
    vqmsg_commit(vq, m, c);
}

/*
 * Request queue
 */

closure_type(vsr_complete, void, virtio_scsi s, virtio_scsi_request req);

closure_function(4, 1, void, virtio_scsi_request_complete,
                 vsr_complete, c, virtio_scsi, s, virtio_scsi_request, r, u64, r_phys,
                 u64 len)
{
    virtio_scsi s = bound(s);
    virtio_scsi_request r = bound(r);
    apply(bound(c), s, r);
    backed_heap contiguous = s->v->virtio_dev.contiguous;
    dealloc_unmap(contiguous, r, bound(r_phys),
                  sizeof(*r) + r->alloc_len);
    closure_finish();
}

static virtio_scsi_request virtio_scsi_alloc_request(virtio_scsi s, u16 target, u16 lun, u8 cmd,
                                                     u64 *r_phys)
{
    int alloc_len = scsi_data_len(cmd);
    virtio_scsi_debug("%s: cmd 0x%x, data len %d\n", func_ss, cmd, alloc_len);

    virtio_scsi_request r = alloc_map(s->v->virtio_dev.contiguous,
        sizeof(*r) + alloc_len, r_phys);
    assert(r != INVALID_ADDRESS);
    zero((void *) &r->req, sizeof(r->req));
    r->req.cdb[0] = cmd;
    r->req.lun[0] = 1;
    r->req.lun[1] = target;
    r->req.lun[2] = ((lun >> 8) & 0x3f) | 0x40;
    r->req.lun[3] = (lun & 0xff);
    r->req.id = u64_from_pointer(r);
    r->alloc_len = alloc_len;

    return r;
}

static void virtio_scsi_enqueue_request(virtio_scsi s, virtio_scsi_request r,
                                        u64 r_phys, void *buf, u64 length, vsr_complete c)
{
    vqfinish f = closure(s->v->virtio_dev.general, virtio_scsi_request_complete,
        c, s, r, r_phys);
    virtqueue vq = s->requestq;
    vqmsg m = allocate_vqmsg(vq);
    assert(m != INVALID_ADDRESS);

    vqmsg_push(vq, m, r_phys + offsetof(virtio_scsi_request, req), sizeof(r->req), false);
    if (r->req.cdb[0] == SCSI_CMD_WRITE_16) {
        if (length > 0)
            vqmsg_push(vq, m, physical_from_virtual(buf), length, false);   // dataout
        vqmsg_push(vq, m, r_phys + offsetof(virtio_scsi_request, resp), sizeof(r->resp),
                   true);   // response
    } else {
        vqmsg_push(vq, m, r_phys + offsetof(virtio_scsi_request, resp), sizeof(r->resp),
                   true);   // response
        if (length > 0)
            vqmsg_push(vq, m, physical_from_virtual(buf), length, true);    // datain
    }

    vqmsg_commit(vq, m, f);
}

/*
 * Device driver hooks
 *
 * If we ever really care, the following may be simplified by re-using
 * closures and maintaining a little state machine.
 */
closure_function(1, 2, void, virtio_scsi_io_done,
                 status_handler, sh,
                 virtio_scsi s, virtio_scsi_request r)
{
    struct virtio_scsi_resp_cmd *resp = &r->resp;
    virtio_scsi_debug("%s: response %d, status %d\n", func_ss, resp->response,
                      resp->status);

    status st = 0;
    if (resp->response != VIRTIO_SCSI_S_OK) {
        st = timm("result", "response %d", resp->response);
    } else if (resp->status != SCSI_STATUS_OK) {
        scsi_dump_sense(resp->sense, sizeof(resp->sense));
        st = timm("result", "status %d", resp->status);
    }
    async_apply_status_handler(bound(sh), st);
    closure_finish();
}

static void virtio_scsi_io(virtio_scsi_disk d, u8 cmd, void *buf, range blocks,
                           status_handler sh)
{
    virtio_scsi s = d->scsi;
    u64 r_phys;
    virtio_scsi_request r = virtio_scsi_alloc_request(s, d->target, d->lun, cmd, &r_phys);
    struct scsi_cdb_readwrite_16 *cdb = (struct scsi_cdb_readwrite_16 *) r->req.cdb;
    u32 nblocks = range_span(blocks);
    cdb->addr = htobe64(blocks.start);
    cdb->length = htobe32(nblocks);
    virtio_scsi_debug("%s: cmd %d, blocks %R, addr 0x%016lx, length 0x%08x\n",
                      func_ss, cmd, blocks, cdb->addr, cdb->length);
    virtio_scsi_enqueue_request(s, r, r_phys, buf, nblocks * d->block_size,
                                closure(s->v->virtio_dev.general, virtio_scsi_io_done, sh));
}

static void virtio_scsi_io_commit(virtio_scsi s, virtqueue vq, vqmsg msg, boolean write,
                                  virtio_scsi_request r, u64 r_phys, status_handler completion)
{
    heap h = s->v->virtio_dev.general;
    if (write)
        vqmsg_push(vq, msg, r_phys + offsetof(virtio_scsi_request, resp), sizeof(r->resp), true);
    vsr_complete c = closure(h, virtio_scsi_io_done, completion);
    assert(c != INVALID_ADDRESS);
    vqfinish f = closure(h, virtio_scsi_request_complete, c, s, r, r_phys);
    assert(f != INVALID_ADDRESS);
    vqmsg_commit(vq, msg, f);
}

static void virtio_scsi_io_sg(virtio_scsi_disk d, boolean write, sg_list sg, range blocks,
                              status_handler sh)
{
    virtio_scsi_debug("%s: %c blocks %R, sh %F\n", func_ss, write ? 'w' : 'r', blocks, sh);
    virtio_scsi s = d->scsi;
    virtio_scsi_request r = 0;
    u64 r_phys;
    struct scsi_cdb_readwrite_16 *cdb;
    u32 desc_blocks, req_blocks;
    heap h = s->v->virtio_dev.general;
    virtqueue vq = s->requestq;
    vqmsg msg;
    u32 desc_count;
    merge m = 0;
    while (range_span(blocks)) {
        if (!r) {
            r = virtio_scsi_alloc_request(s, d->target, d->lun,
                                          write ? SCSI_CMD_WRITE_16 : SCSI_CMD_READ_16, &r_phys);
            cdb = (struct scsi_cdb_readwrite_16 *)r->req.cdb;
            cdb->addr = htobe64(blocks.start);
            msg = allocate_vqmsg(vq);
            assert(msg != INVALID_ADDRESS);
            vqmsg_push(vq, msg, r_phys + offsetof(virtio_scsi_request, req), sizeof(r->req), false);
            if (!write)
                vqmsg_push(vq, msg, r_phys + offsetof(virtio_scsi_request, resp), sizeof(r->resp),
                           true);
            req_blocks = 0;
            desc_count = 0;
        }
        sg_buf sgb = sg_list_head_peek(sg);
        u64 length = sg_buf_len(sgb);
        assert((length & (d->block_size - 1)) == 0);
        length = MIN(range_span(blocks) * d->block_size, length);
        if (d->max_xfer_len)
            length = MIN((d->max_xfer_len - req_blocks) * d->block_size, length);
        vqmsg_push(vq, msg, physical_from_virtual(sgb->buf + sgb->offset), length, !write);
        sg_consume(sg, length);
        desc_blocks = length / d->block_size;
        req_blocks += desc_blocks;
        blocks.start += desc_blocks;
        if ((++desc_count == s->seg_max) || (req_blocks == d->max_xfer_len)) {
            virtio_scsi_debug("  requesting %d blocks\n", req_blocks);
            cdb->length = htobe32(req_blocks);
            if (!m && range_span(blocks)) {
                m = allocate_merge(h, sh);
                sh = apply_merge(m);
            }
            virtio_scsi_io_commit(s, vq, msg, write, r, r_phys, m ? apply_merge(m) : sh);
            r = 0;
        }
    }
    if (r) {
        virtio_scsi_debug("  requesting %d blocks\n", req_blocks);
        cdb->length = htobe32(req_blocks);
        virtio_scsi_io_commit(s, vq, msg, write, r, r_phys, m ? apply_merge(m) : sh);
    }
    if (m)
        apply(sh, STATUS_OK);
}

static void virtio_scsi_flush(virtio_scsi_disk d, status_handler sh)
{
    virtio_scsi s = d->scsi;
    u64 r_phys;
    virtio_scsi_request r = virtio_scsi_alloc_request(s, d->target, d->lun,
                                                      SCSI_CMD_SYNCHRONIZE_CACHE_10,
                                                      &r_phys);
    struct scsi_cdb_synchronize_cache_10 *cdb =
        (struct scsi_cdb_synchronize_cache_10 *) r->req.cdb;
    cdb->byte2 = 0;             /* no IMMED */
    cdb->addr = 0;              /* from start */
    cdb->group = 0;             /* no group */
    cdb->length = 0;            /* all logical blocks */
    cdb->control = 0;           /* no ACA */
    virtio_scsi_debug("%s: enqueue request %p\n", func_ss, r);
    virtio_scsi_enqueue_request(s, r, r_phys, 0, 0,
                                closure(s->v->virtio_dev.general, virtio_scsi_io_done, sh));
}

closure_func_basic(storage_req_handler, void, virtio_scsi_req_handler,
                   storage_req req)
{
    virtio_scsi_disk d = struct_from_field(closure_self(), virtio_scsi_disk, req_handler);
    switch (req->op) {
    case STORAGE_OP_READSG:
        virtio_scsi_io_sg(d, false, req->data, req->blocks, req->completion);
        break;
    case STORAGE_OP_WRITESG:
        virtio_scsi_io_sg(d, true, req->data, req->blocks, req->completion);
        break;
    case STORAGE_OP_FLUSH:
        virtio_scsi_flush(d, req->completion);
        break;
    case STORAGE_OP_READ:
        virtio_scsi_io(d, SCSI_CMD_READ_16, req->data, req->blocks, req->completion);
        break;
    case STORAGE_OP_WRITE:
        virtio_scsi_io(d, SCSI_CMD_WRITE_16, req->data, req->blocks, req->completion);
        break;
    }
}

closure_function(3, 0, void, virtio_scsi_init_done,
                 virtio_scsi_disk, d, int, attach_id, storage_attach, a)
{
    virtio_scsi_disk d = bound(d);
    virtio_scsi s = d->scsi;
    spin_lock(&s->lock);
    vector_push(s->disks, d);
    spin_unlock(&s->lock);
    apply(bound(a),
          init_closure_func(&d->req_handler, storage_req_handler, virtio_scsi_req_handler),
          d->capacity,
          bound(attach_id));
    closure_finish();
}

closure_function(5, 2, void, virtio_scsi_read_capacity_done,
                 storage_attach, a, u16, target, u16, lun, int, attach_id, u32, max_xfer_len,
                 virtio_scsi s, virtio_scsi_request r)
{
    u16 target = bound(target);
    u16 lun = bound(lun);
    struct virtio_scsi_resp_cmd *resp = &r->resp;
    virtio_scsi_debug("%s: target %d, lun %d, response %d, status %d\n",
                      func_ss, target, lun, resp->response, resp->status);
    if (resp->response != VIRTIO_SCSI_S_OK)
        goto out;
    if (resp->status != SCSI_STATUS_OK) {
        scsi_dump_sense(resp->sense, sizeof(resp->sense));
        goto out;
    }
    virtio_scsi_disk d;
    spin_lock(&s->lock);
    vector_foreach(s->disks, d) {
        if (d->target == target && d->lun == lun) {
            spin_unlock(&s->lock);
            goto out;
        }
    }
    spin_unlock(&s->lock);
    d = allocate(s->v->virtio_dev.general, sizeof(*d));
    if (d == INVALID_ADDRESS) {
        msg_err("virtio_scsi: cannot allocate disk");
        goto out;
    }

    struct scsi_res_read_capacity_16 *res = (struct scsi_res_read_capacity_16 *) r->data;
    u64 sectors = be64toh(res->addr) + 1; // returns address of last sector
    d->max_xfer_len = bound(max_xfer_len);
    d->block_size = be32toh(res->length);
    d->capacity = sectors * d->block_size;
    d->target = target;
    d->lun = lun;
    d->scsi = s;
    virtio_scsi_debug("%s: target %d, lun %d, block size 0x%lx, capacity 0x%lx\n",
                      func_ss, target, lun, d->block_size, d->capacity);

    async_apply(closure(s->v->virtio_dev.general, virtio_scsi_init_done,
                        d, bound(attach_id), bound(a)));
  out:
    closure_finish();
}

closure_function(6, 2, void, virtio_scsi_test_unit_ready_done,
                 storage_attach, a, u16, target, u16, lun, int, attach_id, u32, max_xfer_len, int, retry_count,
                 virtio_scsi s, virtio_scsi_request r)
{
    storage_attach a = bound(a);
    u16 target = bound(target);
    u16 lun = bound(lun);
    int retry_count = bound(retry_count);

    struct virtio_scsi_resp_cmd *resp = &r->resp;
    virtio_scsi_debug("%s: target %d, lun %d, response %d, status %d\n",
                      func_ss, target, lun, resp->response, resp->status);
    if (resp->response != VIRTIO_SCSI_S_OK) {
        goto out;
    }

    int attach_id = bound(attach_id);
    u32 max_xfer_len = bound(max_xfer_len);
    heap h = s->v->virtio_dev.general;
    u64 r_phys;
    if (resp->status != SCSI_STATUS_OK) {
        if (retry_count < 3) {
            r = virtio_scsi_alloc_request(s, target, lun, SCSI_CMD_TEST_UNIT_READY, &r_phys);
            virtio_scsi_enqueue_request(s, r, r_phys, r->data, r->alloc_len,
                                        closure(h, virtio_scsi_test_unit_ready_done, a, target, lun,
                                                attach_id, max_xfer_len, retry_count + 1));
        } else {
            scsi_dump_sense(resp->sense, sizeof(resp->sense));
        }
        goto out;
    }

    // read capacity
    r = virtio_scsi_alloc_request(s, target, lun, SCSI_CMD_SERVICE_ACTION, &r_phys);
    struct scsi_cdb_read_capacity_16 *cdb = (struct scsi_cdb_read_capacity_16 *) r->req.cdb;
    cdb->service_action = SRC16_SERVICE_ACTION;
    cdb->alloc_len = htobe32(r->alloc_len);
    virtio_scsi_enqueue_request(s, r, r_phys, r->data, r->alloc_len,
                                closure(h, virtio_scsi_read_capacity_done, a, target, lun,
                                        attach_id, max_xfer_len));
  out:
    closure_finish();
}

closure_function(6, 2, void, virtio_scsi_inquiry_done,
                 storage_attach, a, u16, target, u16, lun, int, attach_id, u32, max_xfer_len, u64, resp_count,
                 virtio_scsi s, virtio_scsi_request r)
{
    u16 target = bound(target);
    u16 lun = bound(lun);
    struct virtio_scsi_resp_cmd *resp = &r->resp;
    virtio_scsi_debug("%s: target %d, lun %d, response %d, status %d\n",
                      func_ss, target, lun, resp->response, resp->status);
    if (resp->response == VIRTIO_SCSI_S_OK && resp->status == SCSI_STATUS_OK) {
        struct scsi_res_inquiry_vpd *common = (struct scsi_res_inquiry_vpd *)r->data;
        switch (common->page_code) {
        case SCSI_VPD_DEVID: {
            struct scsi_res_inquiry_vpd_devid *res = (struct scsi_res_inquiry_vpd_devid *)r->data;
            u16 page_len = MIN(be16toh(res->length),
                               r->alloc_len - offsetof(struct scsi_res_inquiry_vpd_devid *, desc));
            u16 offset = 0;
            int desc_index = 0;
            while (offset < page_len) {
                struct scsi_devid_desc *desc = res->desc + desc_index++;
                offset += offsetof(struct scsi_devid_desc *, id);
                if (offset >= page_len)
                    break;
                u8 id_len = MIN(desc->length, page_len - offset);
                if (id_len > 0)
                    offset += id_len;
                else
                    break;
                buffer desc_id = alloca_wrap_buffer(desc->id, id_len);
                virtio_scsi_debug("%s: descriptor identifier '%b'\n", func_ss, desc_id);
                const char disk_prefix[] = "persistent-disk-";
                if ((id_len >= sizeof(disk_prefix)) &&
                    !runtime_memcmp(buffer_ref(desc_id, 0), disk_prefix, sizeof(disk_prefix) - 1)) {
                    buffer_consume(desc_id, sizeof(disk_prefix) - 1);
                    u64 disk_id;
                    if (parse_int(desc_id, 10, &disk_id)) {
                        bound(attach_id) = disk_id;
                        break;
                    }
                }
            }
            break;
        }
        case SCSI_VPD_BLIM: {
            struct scsi_res_inquiry_vpd_blim *res = (struct scsi_res_inquiry_vpd_blim *)r->data;
            bound(max_xfer_len) = be32toh(res->max_xfer_len);
            virtio_scsi_debug("%s: maximum transfer length %d\n", func_ss, bound(max_xfer_len));
            break;
        }
        }
    }

    if (fetch_and_add(&bound(resp_count), 1) == 1) {
        // test unit ready
        u64 r_phys;
        r = virtio_scsi_alloc_request(s, target, lun, SCSI_CMD_TEST_UNIT_READY, &r_phys);
        virtio_scsi_enqueue_request(s, r, r_phys, r->data, r->alloc_len,
                                    closure(s->v->virtio_dev.general,
                                            virtio_scsi_test_unit_ready_done, bound(a), target, lun,
                                            bound(attach_id), bound(max_xfer_len), 0));
        closure_finish();
    }
}

static void virtio_scsi_inquiry_vpd(virtio_scsi s, u16 target, u16 lun, u8 page_code,
                                    vsr_complete c)
{
    u64 r_phys;
    virtio_scsi_request r = virtio_scsi_alloc_request(s, target, lun, SCSI_CMD_INQUIRY,
        &r_phys);
    struct scsi_cdb_inquiry *cdb = (struct scsi_cdb_inquiry *) r->req.cdb;
    cdb->byte2 = SI_EVPD;
    cdb->page_code = page_code;
    cdb->length = htobe16(r->alloc_len);
    virtio_scsi_enqueue_request(s, r, r_phys, r->data, r->alloc_len, c);
}

static void send_lun_inquiry(virtio_scsi s, u16 target, u16 lun)
{
    vsr_complete completion = closure(s->v->virtio_dev.general, virtio_scsi_inquiry_done, s->sa,
                                      target, lun, -1, 0, 0);
    if (completion == INVALID_ADDRESS) {
        msg_err("virtio_scsi LUN inquiry: failed to allocate completion");
        return;
    }
    virtio_scsi_inquiry_vpd(s, target, lun, SCSI_VPD_DEVID, completion);
    virtio_scsi_inquiry_vpd(s, target, lun, SCSI_VPD_BLIM, completion);
}

closure_function(2, 2, void, virtio_scsi_report_luns_done,
                 storage_attach, a, u16, target,
                 virtio_scsi s, virtio_scsi_request r)
{
    u16 target = bound(target);
    struct virtio_scsi_resp_cmd *resp = &r->resp;
    virtio_scsi_debug("%s: target %d, response %d, status %d\n",
                      func_ss, target, resp->response, resp->status);
    if (resp->response != VIRTIO_SCSI_S_OK || resp->status != SCSI_STATUS_OK) {
        if (resp->status != SCSI_STATUS_OK)
            scsi_dump_sense(resp->sense, sizeof(resp->sense));
        closure_finish();
        return;
    }

    struct scsi_res_report_luns *res = (struct scsi_res_report_luns *) r->data;
    u32 length = be32toh(res->length);
    virtio_scsi_debug("%s: got %d luns\n", func_ss, length / sizeof(res->lundata[0]));
    for (u32 i = 0; i < MIN(s->max_lun, length / sizeof(res->lundata[0])); i++) {
        u16 lun = (res->lundata[i] & 0xffff) >> 8;
        virtio_scsi_debug("%s: got lun %d (lundata 0x%08lx)\n", func_ss, lun, res->lundata[i]);
        send_lun_inquiry(s, target, lun);
    }
    closure_finish();
}

static void virtio_scsi_report_luns(virtio_scsi s, storage_attach a, u16 target)
{
    u64 r_phys;
    virtio_scsi_request r = virtio_scsi_alloc_request(s, target, 0, SCSI_CMD_REPORT_LUNS, &r_phys);
    struct scsi_cdb_report_luns *cdb = (struct scsi_cdb_report_luns *) r->req.cdb;
    cdb->select_report = RPL_REPORT_DEFAULT;
    cdb->length = htobe32(r->alloc_len);
    virtio_scsi_enqueue_request(s, r, r_phys, r->data, r->alloc_len,
        closure(s->v->virtio_dev.general, virtio_scsi_report_luns_done, a, target));
}

static void virtio_scsi_attach(heap general, storage_attach a, backed_heap page_allocator,
                               pci_dev _dev)
{
    virtio_scsi s = allocate(general, sizeof(struct virtio_scsi));
    assert(s != INVALID_ADDRESS);
    s->v = attach_vtpci(general, page_allocator, _dev, VIRTIO_SCSI_F_HOTPLUG);

#ifdef VIRTIO_SCSI_DEBUG
    u32 num_queues = pci_bar_read_4(&s->v->device_config, VIRTIO_SCSI_R_NUM_QUEUES);
    virtio_scsi_debug("num queues %d\n", num_queues);

    u32 max_sectors = pci_bar_read_4(&s->v->device_config, VIRTIO_SCSI_R_MAX_SECTORS);
    virtio_scsi_debug("max sectors %d\n", max_sectors);

    u32 cmd_per_lun = pci_bar_read_4(&s->v->device_config, VIRTIO_SCSI_R_CMD_PER_LUN);
    virtio_scsi_debug("cmd per lun %d\n", cmd_per_lun);

    u32 event_info_size = pci_bar_read_4(&s->v->device_config, VIRTIO_SCSI_R_EVENT_INFO_SIZE);
    virtio_scsi_debug("event info size %d\n", event_info_size);

    u32 max_channel = pci_bar_read_2(&s->v->device_config, VIRTIO_SCSI_R_MAX_CHANNEL);
    virtio_scsi_debug("max channel %d\n", max_channel);
#endif

    s->disks = allocate_vector(general, 2);
    s->sa = a;
    spin_lock_init(&s->lock);

    s->seg_max = pci_bar_read_4(&s->v->device_config, VIRTIO_SCSI_R_SEG_MAX);
    virtio_scsi_debug("seg max %d\n", s->seg_max);

    s->max_target = pci_bar_read_2(&s->v->device_config, VIRTIO_SCSI_R_MAX_TARGET);
    virtio_scsi_debug("max target %d\n", s->max_target);

    s->max_lun = pci_bar_read_4(&s->v->device_config, VIRTIO_SCSI_R_MAX_LUN);
    virtio_scsi_debug("max lun %d\n", s->max_lun);

    range cpu_affinity = irange(0, 0);
    status st = vtpci_alloc_virtqueue(s->v, ss("virtio scsi command"), 0, cpu_affinity,
                                      &s->command);
    assert(st == STATUS_OK);
    st = vtpci_alloc_virtqueue(s->v, ss("virtio scsi event"), 1, cpu_affinity, &s->eventq);
    assert(st == STATUS_OK);
    st = vtpci_alloc_virtqueue(s->v, ss("virtio scsi request"), 2, cpu_affinity, &s->requestq);
    assert(st == STATUS_OK);

    // On reset, the device MUST set sense_size to 96 and cdb_size to 32
    pci_bar_write_4(&s->v->device_config, VIRTIO_SCSI_R_SENSE_SIZE, VIRTIO_SCSI_SENSE_SIZE);
    pci_bar_write_4(&s->v->device_config, VIRTIO_SCSI_R_CDB_SIZE, VIRTIO_SCSI_CDB_SIZE);

    // initialization complete
    vtpci_set_status(s->v, VIRTIO_CONFIG_STATUS_DRIVER_OK);

    // enqueue events
    s->events = allocate((heap)page_allocator,
                         VIRTIO_SCSI_NUM_EVENTS * sizeof(struct virtio_scsi_event));
    if (s->events != INVALID_ADDRESS)
        for (int i = 0; i < VIRTIO_SCSI_NUM_EVENTS; i++)
            virtio_scsi_enqueue_event(s, s->events + i, 0);
    else
        msg_err("%s: failed to allocate events", func_ss);

    // scan bus
    for (u16 target = 0; target <= s->max_target; target++)
        virtio_scsi_report_luns(s, a, target);
}

closure_function(3, 1, boolean, virtio_scsi_probe,
                 heap, general, storage_attach, a, backed_heap, page_allocator,
                 pci_dev d)
{
    if (!vtpci_probe(d, VIRTIO_ID_SCSI))
        return false;

    virtio_scsi_attach(bound(general), bound(a), bound(page_allocator), d);
    return true;
}

void init_virtio_scsi(kernel_heaps kh, storage_attach a)
{
    heap h = heap_locked(kh);
    register_pci_driver(closure(h, virtio_scsi_probe, h, a, heap_linear_backed(kh)), 0);
}
