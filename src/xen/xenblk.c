#include <kernel.h>
#include <drivers/storage.h>
#include <page.h>
#include <storage.h>

#include "xen_internal.h"

#include "io/blkif.h"
#include "io/protocols.h"

#define XENBLK_RING_SIZE                                                \
  (__RD32(((PAGESIZE) - __builtin_offsetof(struct blkif_sring, ring)) / \
          sizeof(((struct blkif_sring *)0)->ring[0])))
#define XENBLK_SECTORS_PER_PAGE (PAGESIZE / SECTOR_SIZE)

//#define XENBLK_DEBUG
#ifdef XENBLK_DEBUG
#define xenblk_debug(x, ...) do {rprintf("XBLK: " x "\n", ##__VA_ARGS__);} while(0)
#else
#define xenblk_debug(x, ...)
#endif

typedef struct xenblk_dev *xenblk_dev;

declare_closure_struct(2, 3, void, xenblk_io,
                       xenblk_dev, xbd, boolean, write,
                       void *, buf, range, blocks, status_handler, sh);

declare_closure_struct(1, 0, void, xenblk_event_handler,
                       xenblk_dev, xbd);

declare_closure_struct(1, 0, void, xenblk_bh_service,
                       xenblk_dev, xbd);

struct xenblk_dev {
    struct xen_dev dev;
    heap h;
    heap contiguous;
    u64 capacity;
    blkif_front_ring_t ring;
    grant_ref_t ring_gntref;
    evtchn_port_t evtchn;
    closure_struct(xenblk_io, read);
    closure_struct(xenblk_io, write);
    closure_struct(xenblk_event_handler, event_handler);
    closure_struct(xenblk_bh_service, bh_service);
    vector rreqs;   /* xenblk_ring_req */
    struct list pending, done, free;    /* xenblk_req */
    struct list free_rreqs; /* xenblk_ring_req */
    struct spinlock lock;
};

typedef struct xenblk_req {
    struct list l;
    u8 operation;   /* BLKIF_OP_xxx */
    void *buf;
    range remain;
    u64 pending;
    status_handler sh;
    status s;
} *xenblk_req;

typedef struct xenblk_ring_req {
    struct list l;
    u64 id;
    xenblk_req req;
    u8 segments;
    grant_ref_t grefs[BLKIF_MAX_SEGMENTS_PER_REQUEST];
} *xenblk_ring_req;

static xenblk_req xenblk_get_req(xenblk_dev xbd)
{
    xenblk_req req;
    spin_lock(&xbd->lock);
    list l = list_get_next(&xbd->free);
    if (l) {
        list_delete(l);
        req = struct_from_list(l, xenblk_req, l);
    } else {
        xenblk_debug("new request allocation");
        req = allocate(xbd->h, sizeof(*req));
        if (req == INVALID_ADDRESS)
            req = 0;
    }
    spin_unlock(&xbd->lock);
    return req;
}

/* Called with mutex locked */
static xenblk_ring_req xenblk_get_rreq(xenblk_dev xbd)
{
    list l = list_get_next(&xbd->free_rreqs);
    if (l) {
        list_delete(l);
        return struct_from_list(l, xenblk_ring_req, l);
    }
    xenblk_debug("new ring request allocation");
    xenblk_ring_req req = allocate(xbd->h, sizeof(*req));
    if (req != INVALID_ADDRESS) {
        req->id = vector_length(xbd->rreqs);
        vector_push(xbd->rreqs, req);
    } else {
        req = 0;
    }

    return req;
}

/* Called with the mutex locked. */
static void xenblk_service_pending(xenblk_dev xbd)
{
    RING_IDX prod = xbd->ring.req_prod_pvt;
    RING_IDX prod_end = xbd->ring.rsp_cons + XENBLK_RING_SIZE;
    xenblk_debug("%s: prod %d, prod_end %d", __func__, prod, prod_end);
    while (prod < prod_end) {
        blkif_request_t *req = RING_GET_REQUEST(&xbd->ring, prod);
        list l = list_get_next(&xbd->pending);
        if (!l) {
            xenblk_debug("pending empty");
            break;
        }
        xenblk_req xbreq = struct_from_list(l, xenblk_req, l);
        xenblk_debug(" sectors %R", xbreq->remain);
        xenblk_ring_req rreq = xenblk_get_rreq(xbd);
        if (!rreq) {
            xenblk_debug("no available requests");
            break;
        }
        rreq->req = xbreq;
        rreq->segments = 0;
        req->operation = xbreq->operation;
        req->handle = xbd->dev.if_id;
        req->id = rreq->id;
        req->sector_number = xbreq->remain.start;
        req->nr_segments = 0;
        boolean out_of_grants = false;
        do {
            u64 sectors = range_span(xbreq->remain);
            if (sectors == 0) {
                list_delete(l);
                break;
            }
            struct blkif_request_segment *seg = &req->seg[req->nr_segments];
            u64 phys = physical_from_virtual(xbreq->buf);
            assert(phys != INVALID_PHYSICAL);
            seg->gref = xen_grant_page_access(xbd->dev.backend_id, phys,
                req->operation == BLKIF_OP_WRITE);
            if (!seg->gref) {
                out_of_grants = true;
                break;
            }
            rreq->grefs[req->nr_segments] = seg->gref;
            seg->first_sect = (phys & MASK(PAGELOG)) >> SECTOR_OFFSET;
            if (seg->first_sect + sectors > XENBLK_SECTORS_PER_PAGE)
                sectors = XENBLK_SECTORS_PER_PAGE - seg->first_sect;
            seg->last_sect = seg->first_sect + sectors - 1;
            xenblk_debug("  segment %d [%d, %d]", req->nr_segments,
                         seg->first_sect, seg->last_sect);
            xbreq->remain.start += sectors;
            xbreq->buf += sectors * SECTOR_SIZE;
        } while (++req->nr_segments < BLKIF_MAX_SEGMENTS_PER_REQUEST);
        if (req->nr_segments > 0) {
            rreq->segments = req->nr_segments;
            xbreq->pending++;
            prod++;
        }
        if (out_of_grants)
            break;
    }
    xbd->ring.req_prod_pvt = prod;
    int notify;
    RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&xbd->ring, notify);
    if (notify)
        xen_notify_evtchn(xbd->evtchn);
}

/* Called with the mutex locked. */
static void xenblk_service_ring(xenblk_dev xbd)
{
    int more;

    do {
        RING_IDX cons = xbd->ring.rsp_cons;
        RING_IDX prod = xbd->ring.sring->rsp_prod;
        read_barrier();
        xenblk_debug("%s: cons %d, prod %d", __func__, cons, prod);
        while (cons < prod) {
            blkif_response_t *resp = RING_GET_RESPONSE(&xbd->ring, cons);
            xenblk_ring_req rreq = vector_get(xbd->rreqs, resp->id);
            assert(rreq);
            for (u8 segment = 0; segment < rreq->segments; segment++)
                xen_revoke_page_access(rreq->grefs[segment]);
            list_insert_before(list_begin(&xbd->free_rreqs), &rreq->l);
            xenblk_req req = rreq->req;
            if ((resp->status != BLKIF_RSP_OKAY) && (req->s == STATUS_OK)) {
                req->s = timm("result", "xenblk error %d", resp->status);
            }
            if ((--req->pending == 0) && (range_span(req->remain) == 0))
                list_push_back(&xbd->done, &req->l);
            cons++;
        }
        xbd->ring.rsp_cons = cons;
        RING_FINAL_CHECK_FOR_RESPONSES(&xbd->ring, more);
    } while (more);
}

define_closure_function(2, 3, void, xenblk_io,
                        xenblk_dev, xbd, boolean, write,
                        void *, buf, range, blocks, status_handler, sh)
{
    xenblk_dev xbd = bound(xbd);
    boolean write = bound(write);
    xenblk_debug("[%d] %s %R", xbd->dev.if_id, write ? "write" : "read",
            blocks);
    xenblk_req req = xenblk_get_req(xbd);
    if (!req) {
        apply(sh, timm("result", "request allocation failed"));
        return;
    }
    req->operation = write ? BLKIF_OP_WRITE : BLKIF_OP_READ;
    req->buf = buf;
    req->remain = blocks;
    req->pending = 0;
    req->sh = sh;
    req->s = STATUS_OK;
    u64 irqflags = spin_lock_irq(&xbd->lock);
    list_push_back(&xbd->pending, &req->l);
    xenblk_service_pending(xbd);
    spin_unlock_irq(&xbd->lock, irqflags);
}

define_closure_function(1, 0, void, xenblk_event_handler,
                        xenblk_dev, xbd)
{
    xenblk_dev xbd = bound(xbd);
    xenblk_debug("[%d] %s", xbd->dev.if_id, __func__);
    spin_lock(&xbd->lock);
    boolean done_empty = list_empty(&xbd->done);
    xenblk_service_ring(xbd);
    xenblk_service_pending(xbd);
    if (done_empty && !list_empty(&xbd->done))
        enqueue(bhqueue, &xbd->bh_service);
    spin_unlock(&xbd->lock);
}

define_closure_function(1, 0, void, xenblk_bh_service,
                        xenblk_dev, xbd)
{
    xenblk_dev xbd = bound(xbd);
    xenblk_debug("[%d] %s", xbd->dev.if_id, __func__);
    list l;
    u64 irqflags = spin_lock_irq(&xbd->lock);
    while ((l = list_get_next(&xbd->done))) {
        list_delete(l);
        spin_unlock_irq(&xbd->lock, irqflags);
        xenblk_req req = struct_from_list(l, xenblk_req, l);
        apply(req->sh, req->s);
        irqflags = spin_lock_irq(&xbd->lock);
        list_insert_before(list_begin(&xbd->free), l);
    }
    spin_unlock(&xbd->lock);
}

#define XENBLK_INFORM_BACKEND_RETRIES   64

static status xenblk_inform_backend(xenblk_dev xbd)
{
    status s = STATUS_OK;
    xen_dev xd = &xbd->dev;
    xenblk_debug("%s: dev id %d", __func__, xd->if_id);
    u32 tx_id;
    char *node;
    int retries = XENBLK_INFORM_BACKEND_RETRIES;

  again:
    s = xenstore_transaction_start(&tx_id);
    if (!is_ok(s))
        return s;
    node = "protocol";
    s = xenstore_sync_printf(tx_id, xd->frontend, node, "%s",
        XEN_IO_PROTO_ABI_NATIVE);
    if (!is_ok(s))
        goto abort;
    node = "ring-ref";
    s = xenstore_sync_printf(tx_id, xd->frontend, node, "%d", xbd->ring_gntref);
    if (!is_ok(s))
        goto abort;
    node = "event-channel";
    s = xenstore_sync_printf(tx_id, xd->frontend, node, "%d", xbd->evtchn);
    if (!is_ok(s))
        goto abort;
    s = xenstore_transaction_end(tx_id, false);
    if (!is_ok(s)) {
        value v = table_find(s, sym(errno));
        if (v) {
            if (!buffer_strcmp((buffer)v, "EAGAIN")) {
                deallocate_tuple(s);
                if (retries-- == 0)
                    return timm("result", "%s failed after %d tries", __func__,
                        XENBLK_INFORM_BACKEND_RETRIES);
                goto again;
            }
        }
        return timm_up(s, "result", "%s: transaction end failed", __func__);
    }
    return xenbus_set_state(0, xd->frontend, XenbusStateInitialised);
  abort:
    xenstore_transaction_end(tx_id, true);
    return timm_up(s, "result", "%s: transaction aborted; step \"%s\" failed",
                   __func__, node);
}

static status xenblk_enable(xenblk_dev xbd)
{
    xen_dev xd = &xbd->dev;
    blkif_sring_t *ring = allocate_zero(xbd->contiguous, PAGESIZE);
    if (ring == INVALID_ADDRESS)
        return timm("result", "cannot allocate ring");
    SHARED_RING_INIT(ring);
    FRONT_RING_INIT(&xbd->ring, ring, PAGESIZE);
    status s;
    xbd->ring_gntref = xen_grant_page_access(xd->backend_id,
        physical_from_virtual(ring), false);
    if (xbd->ring_gntref == 0) {
        s = timm("result", "failed to obtain grant reference for ring");
        goto out_dealloc;
    }
    s = xen_allocate_evtchn(xd->backend_id, &xbd->evtchn);
    if (!is_ok(s))
        goto out_revoke;
    init_closure(&xbd->bh_service, xenblk_bh_service, xbd);
    xen_register_evtchn_handler(xbd->evtchn, init_closure(&xbd->event_handler,
        xenblk_event_handler, xbd));
    s = xenblk_inform_backend(xbd);
    if (!is_ok(s))
        goto out_revoke;
    XenbusState backend_state = XenbusStateUnknown;
    for (int retries = 0; retries < 8; retries++) {
        s = xenbus_get_state(xd->backend, &backend_state);
        if (!is_ok(s)) {
            s = timm_up(s, "result", "cannot read backend state");
            goto out_revoke;
        }
        if (backend_state == XenbusStateConnected)
            break;
        kernel_delay(milliseconds(1 << retries));
    }
    if (backend_state != XenbusStateConnected) {
        s = timm("result", "backend not connected");
        goto out_revoke;
    }
    u64 sector_size;
    s = xenstore_read_u64(0, xd->backend, "sector-size", &sector_size);
    if (!is_ok(s)) {
        s = timm_up(s, "result", "cannot read sector size");
        goto out_revoke;
    } else if (sector_size != SECTOR_SIZE) {
        s = timm("result", "unsupported sector size %ld", sector_size);
        goto out_revoke;
    }
    s = xenstore_read_u64(0, xd->backend, "physical-sector-size",
        &sector_size);
    if (!is_ok(s)) {
        /* physical sector size is the same as logical sector size */
        timm_dealloc(s);
    } else if (sector_size != SECTOR_SIZE) {
        s = timm("result", "unsupported physical sector size %ld", sector_size);
        goto out_revoke;
    }
    u64 sectors;
    s = xenstore_read_u64(0, xd->backend, "sectors", &sectors);
    if (!is_ok(s)) {
        s = timm_up(s, "result", "cannot read number of sectors");
        goto out_revoke;
    }
    xbd->capacity = sector_size * sectors;
    s = xenbus_set_state(0, xd->frontend, XenbusStateConnected);
    if (!is_ok(s)) {
        s = timm_up(s, "result", "cannot set frontend state to connected");
        goto out_revoke;
    }
    int rv = xen_unmask_evtchn(xbd->evtchn);
    if (rv < 0) {
        s = timm("result", "failed to unmask event channel %d: rv %d",
            xbd->evtchn, rv);
        goto out_revoke;
    }
    return STATUS_OK;
  out_revoke:
    xen_revoke_page_access(xbd->ring_gntref);
  out_dealloc:
    deallocate(xbd->contiguous, ring, PAGESIZE);
    return s;
}

closure_function(2, 3, boolean, xenblk_probe,
                 kernel_heaps, kh, storage_attach, sa,
                 int, id, buffer, frontend, tuple, meta)
{
    xenblk_debug("probe for id %d, frontend %b, meta %v", id, frontend, meta);
    kernel_heaps kh = bound(kh);
    heap h = heap_locked(kh);
    xenblk_dev xbd = allocate(h, sizeof(*xbd));
    if (xbd == INVALID_ADDRESS) {
        msg_err("%s: cannot allocate device structure\n", __func__);
        return false;
    }
    xen_dev xd = &xbd->dev;
    xbd->h = h;
    xbd->contiguous = heap_backed(kh);
    status s = xendev_attach(xd, id, frontend, meta);
    if (!is_ok(s)) {
        msg_err("%s: cannot attach Xen device: %v\n", __func__, s);
        timm_dealloc(s);
        goto dealloc_xbd;
    }
    xbd->rreqs = allocate_vector(h, XENBLK_RING_SIZE);
    if (xbd->rreqs == INVALID_ADDRESS) {
        msg_err("%s: cannot allocate request vector\n", __func__);
        goto dealloc_xbd;
    }
    list_init(&xbd->pending);
    list_init(&xbd->done);
    list_init(&xbd->free);
    list_init(&xbd->free_rreqs);
    spin_lock_init(&xbd->lock);
    s = xenblk_enable(xbd);
    if (!is_ok(s)) {
        msg_err("%s: cannot enable device: %v\n", __func__, s);
        timm_dealloc(s);
        goto dealloc_reqs;
    }
    xenblk_debug("attaching disk, capacity %ld bytes", xbd->capacity);
    apply(bound(sa), init_closure(&xbd->read, xenblk_io, xbd, false),
          init_closure(&xbd->write, xenblk_io, xbd, true), xbd->capacity);
    return true;
  dealloc_reqs:
    deallocate_vector(xbd->rreqs);
  dealloc_xbd:
    deallocate(h, xbd, sizeof(*xbd));
    return false;
}

void init_xenblk(kernel_heaps kh, storage_attach sa)
{
    register_xen_driver("vbd", closure(heap_locked(kh), xenblk_probe, kh, sa));
}
