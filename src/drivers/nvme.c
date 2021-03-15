#include <kernel.h>
#include <pci.h>
#include <storage.h>

#include "nvme.h"

#define NVME_REG_BAR    0

#define NVME_CAP    0x0
#define NVME_CAP_DSTRD(cap) (((cap) >> 32) & 0xF)
#define NVME_CAP_MQES(cap) (((cap) & 0xFFFF) + 1)

#define NVME_VS 0x8
#define NVME_VS_MJR(vs) ((vs) >> 16)
#define NVME_VS_MNR(vs) (((vs) >> 8) & 0xFF)
#define NVME_VS_TER(vs) ((vs) & 0xFF)
#define NVME_VER(mjr, mnr, ter) (((mjr) << 16) | ((mnr) << 8) | (ter))

#define NVME_CC     0x14
#define NVME_CC_IOCQES(es)  ((es) << 20)
#define NVME_CC_IOSQES(es)  ((es) << 16)
#define NVME_CC_EN          0x01

#define NVME_CSTS   0x1C
#define NVME_CSTS_RDY   0x01

#define NVME_AQA    0x24
#define NVME_AQA_ACQS(s)    (((s) - 1) << 16)
#define NVME_AQA_ASQS(s)    (((s) - 1) << 0)

#define NVME_ASQ    0x28
#define NVME_ACQ    0x30

#define NVME_AQ_IDX     0   /* admin queue index */
#define NVME_AQ_MSIX    0   /* admin queue MSI-X slot */

#define NVME_IOQ_IDX    1   /* I/O queue index and identifier */
#define NVME_IOQ_MSIX   1   /* I/O queue MSI-X slot */

/* command Dword 0 */
#define NVME_CID(id)    ((id) << 16)
#define NVME_CMD_PRP    (0 << 14)
#define NVME_SGL_B      (1 << 14)
#define NVME_SGL_S      (2 << 14)

/* Completion Dword 2 */
#define NVME_SQ_ID(dw2)     (((dw2) >> 16) & 0xFFFF)
#define NVME_SQ_HEAD(dw2)   ((dw2) & 0xFFFF)

/* Completion Dword 3 */
#define NVME_STATUS_CODE(dw3)   (((dw3) >> 17) & 0xFF)
#define NVME_PHASE_TAG(dw3)     (((dw3) >> 16) & 0x1)
#define NVME_CMD_ID(dw3)        ((dw3) & 0xFFFF)
#define NVME_SC_OK  0

/* Admin command set opcodes */
#define NVME_OPC_DEL_IOSQ   0x00
#define NVME_OPC_CRE_IOSQ   0x01
#define NVME_OPC_GET_LP     0x02
#define NVME_OPC_DEL_IOCQ   0x04
#define NVME_OPC_CRE_IOCQ   0x05
#define NVME_OPC_IDENTIFY   0x06
#define NVME_OPC_ABORT      0x08
#define NVME_OPC_SET_FEAT   0x09
#define NVME_OPC_GET_FEAT   0x0A
#define NVME_OPC_AE_REQ     0x0C
#define NVME_OPC_NS_MGMT    0x0D
#define NVME_OPC_FW_COMMIT  0x10
#define NVME_OPC_FW_DWNLD   0x11
#define NVME_OPC_D_SELFTEST 0x14
#define NVME_OPC_NS_ATTACH  0x15
#define NVME_OPC_KEEP_ALIVE 0x18
#define NVME_OPC_DIR_SEND   0x19
#define NVME_OPC_DIR_RECV   0x1A
#define NVME_OPC_VIRT_MGMT  0x1C
#define NVME_OPC_MI_SEND    0x1D
#define NVME_OPC_MI_RECV    0x1E
#define NVME_OPC_DBL_CFG    0x7C

/* Identify command */
#define CNS_IDENTIFY_NAMESPACE  0
#define CNS_IDENTIFY_CONTROLLER 1
#define CNS_ACTIVE_NAMESPACES   2
#define CNS_NAMESPACE_ID_DESC   3
#define CNS_NVM_SET_LIST        4
#define NVME_IDENTIFY_RESP_SIZE 4096

/* NVM command set opcodes */
#define NVME_OPC_FLUSH      0x00
#define NVME_OPC_WRITE      0x01
#define NVME_OPC_READ       0x02
#define NVME_OPC_WRITE_UNC  0x04
#define NVME_OPC_COMPARE    0x05
#define NVME_OPC_WRITE_Z    0x08
#define NVME_OPC_DS_MGMT    0x09
#define NVME_OPC_VERIFY     0x0C
#define NVME_OPC_RSV_REG    0x0D
#define NVME_OPC_RSV_REP    0x0E
#define NVME_OPC_RSV_ACQ    0x11
#define NVME_OPC_RSV_REL    0x15

#define NVME_ASQ_ORDER  1
#define NVME_ACQ_ORDER  1

#define NVME_CID_MAX    0xFFFE

//#define NVME_DEBUG
#ifdef NVME_DEBUG
#define nvme_debug(x, ...) do {rprintf("NVMe: " x "\n", ##__VA_ARGS__);} while(0)
#else
#define nvme_debug(x, ...)
#endif

struct nvme_sgl {
/* Scatter-gather list: can be a Data Block Descriptor, Bit Bucket Descriptor,
 * Segment Descriptor, Last Segment Descriptor, Keyed Data Block Descriptor, or
 * Transport Data Block Descriptor. */
    u64 addr;
    u32 len;
    u8 reserved[3];
    u8 id;
} __attribute__((packed));

struct nvme_sqe {   /* submission queue entry */
    u32 cdw0;
    u32 nsid;
    u64 reserved;
    u64 mptr;
    union {
        struct {
            u64 prp1;
            u64 prp2;
        };
        struct nvme_sgl sgl1;
    } dptr;
    u32 cdw10;
    u32 cdw11;
    u32 cdw12;
    u32 cdw13;
    u32 cdw14;
    u32 cdw15;
} __attribute__((packed));

struct nvme_cqe {   /* completion queue entry */
    u32 dw0;
    u32 dw1;
    u32 dw2;
    u32 dw3;
} __attribute__((packed));

typedef struct nvme_sq {
    struct nvme_sqe *ring;
    int order;
    int head, tail;
} *nvme_sq;

typedef struct nvme_cq {
    struct nvme_cqe *ring;
    int order;
    int head;
    boolean phase;
} *nvme_cq;

declare_closure_struct(1, 0, void, nvme_admin_irq,
                       struct nvme *, n);
declare_closure_struct(1, 0, void, nvme_io_irq,
                       struct nvme *, n);
declare_closure_struct(1, 0, void, nvme_bh_service,
                       struct nvme *, n);

typedef struct nvme {
    heap general, contiguous;
    pci_dev d;
    struct pci_bar bar;
    u32 vs; /* controller version */
    int dstrd;  /* doorbell stride */
    struct nvme_sq asq; /* admin submission queue */
    struct nvme_cq acq; /* admin completion queue */
    closure_struct(nvme_admin_irq, admin_irq);
    thunk ac_handler;   /* admin completion handler */
    int ioq_order;     /* I/O queue size */
    struct nvme_sq iosq;    /* I/O submission queue */
    struct nvme_cq iocq;    /* I/O completion queue */
    closure_struct(nvme_io_irq, io_irq);
    struct list pending_reqs, free_reqs, done_reqs;
    vector cmds;
    struct list free_cmds;
    closure_struct(nvme_bh_service, bh_service);
    struct spinlock lock;
} *nvme;

typedef struct nvme_ioreq {
    struct list l;
    u32 namespace;
    boolean write;
    void *buf;
    range blocks;
    u64 pending_cmds;
    status_handler sh;
    int sc;
} *nvme_ioreq;

typedef struct nvme_iocmd {
    struct list l;
    u16 id;
    nvme_ioreq req;
} *nvme_iocmd;

static boolean nvme_init_sq(nvme n, nvme_sq sq, int order)
{
    sq->ring = allocate(n->contiguous, U64_FROM_BIT(order) * sizeof(struct nvme_sqe));
    if (sq->ring == INVALID_ADDRESS)
        return false;
    sq->order = order;
    sq->head = sq->tail = 0;
    return true;
}

static void nvme_deinit_sq(nvme n, nvme_sq sq)
{
    deallocate(n->contiguous, sq->ring, U64_FROM_BIT(sq->order) * sizeof(struct nvme_sqe));
}

static boolean nvme_init_cq(nvme n, nvme_cq cq, int order)
{
    u64 num_entries = U64_FROM_BIT(order);
    cq->ring = allocate(n->contiguous, num_entries * sizeof(struct nvme_cqe));
    if (cq->ring == INVALID_ADDRESS)
        return false;
    for (int i = 0; i < num_entries; i++)
        cq->ring[i].dw3 = 0;    /* initialize phase tag to 0 */
    cq->order = order;
    cq->head = 0;
    cq->phase = 0;
    return true;
}

static void nvme_deinit_cq(nvme n, nvme_cq cq)
{
    deallocate(n->contiguous, cq->ring, U64_FROM_BIT(cq->order) * sizeof(struct nvme_cqe));
}

static struct nvme_sqe *nvme_get_sqe(nvme_sq q)
{
    if (((q->tail + 1) & MASK(q->order)) == q->head) {
        nvme_debug("submission queue full (head %d, tail %d, order %d)",
            q->head, q->tail, q->order);
        return 0;
    }
    struct nvme_sqe *sqe = q->ring + q->tail;
    q->tail = (q->tail + 1) & MASK(q->order);
    return sqe;
}

static inline void nvme_sq_doorbell(nvme n, int q_idx, nvme_sq q)
{
    /* Submission queue tail doorbell register offset */
    u64 sqtdbl = 0x1000 + 2 * q_idx * n->dstrd;

    write_barrier();
    pci_bar_write_4(&n->bar, sqtdbl, q->tail);
}

static struct nvme_cqe *nvme_get_cqe(nvme_cq q)
{
    struct nvme_cqe *cqe = q->ring + q->head;
    if (NVME_PHASE_TAG(cqe->dw3) == q->phase) {
        nvme_debug("completion queue empty (head %d, order %d, phase %d)",
            q->head, q->order, q->phase);
        return 0;
    }
    if (++q->head == U64_FROM_BIT(q->order)) {
        q->head = 0;
        q->phase = !q->phase;
    }
    return cqe;
}

static inline void nvme_cq_doorbell(nvme n, int q_idx, nvme_cq q)
{
    /* Completion queue head doorbell register offset */
    u64 cqhdbl = 0x1000 + (2 * q_idx + 1) * n->dstrd;

    pci_bar_write_4(&n->bar, cqhdbl, q->head);
}

static nvme_ioreq nvme_get_ioreq(nvme n)
{
    nvme_ioreq req;
    spin_lock(&n->lock);
    list l = list_get_next(&n->free_reqs);
    if (l) {
        list_delete(l);
        req = struct_from_list(l, nvme_ioreq, l);
    } else {
        nvme_debug("new request allocation");
        req = allocate(n->general, sizeof(*req));
    }
    spin_unlock(&n->lock);
    return req;
}

/* Called with the lock held. */
static nvme_iocmd nvme_get_iocmd(nvme n, boolean allocate)
{
    list l = list_get_next(&n->free_cmds);
    if (l) {
        list_delete(l);
        return struct_from_list(l, nvme_iocmd, l);
    } else if (allocate && (vector_length(n->cmds) <= NVME_CID_MAX)) {
        nvme_debug("new command allocation");
        nvme_iocmd cmd = allocate(n->general, sizeof(*cmd));
        if (cmd == INVALID_ADDRESS) {
            nvme_debug("command allocation failed");
            return cmd;
        }
        cmd->id = vector_length(n->cmds);
        vector_push(n->cmds, cmd);
        return cmd;
    } else {
        nvme_debug("no available commands");
        return INVALID_ADDRESS;
    }
}

/* Called with the lock held. */
static void nvme_service_pending(nvme n, boolean allocate)
{
    boolean new_reqs = false;
    list l;
    while ((l = list_get_next(&n->pending_reqs))) {
        nvme_iocmd cmd = nvme_get_iocmd(n, allocate);
        if (cmd == INVALID_ADDRESS)
            break;
        struct nvme_sqe *sqe = nvme_get_sqe(&n->iosq);
        if (!sqe) {
            list_insert_before(list_begin(&n->free_cmds), &cmd->l);
            break;
        }
        new_reqs = true;
        nvme_ioreq req = struct_from_list(l, nvme_ioreq, l);
        sqe->cdw0 = NVME_CID(cmd->id) | NVME_CMD_PRP |
                (req->write ? NVME_OPC_WRITE : NVME_OPC_READ);
        sqe->nsid = req->namespace;
        u64 buf_start = physical_from_virtual(req->buf);
        u64 nlb = range_span(req->blocks);
        u64 buf_end = buf_start + nlb * SECTOR_SIZE;
        sqe->dptr.prp1 = buf_start;
        if (buf_end > (buf_start & ~PAGEMASK) + PAGESIZE) {
            sqe->dptr.prp2 = (buf_start & ~PAGEMASK) + PAGESIZE;
            if (buf_end > sqe->dptr.prp2 + PAGESIZE) {
                nlb = (sqe->dptr.prp2 + PAGESIZE - buf_start) / SECTOR_SIZE;
                req->buf += nlb * SECTOR_SIZE;
            }
        }
        if (nlb == range_span(req->blocks))
            list_delete(l);
        nvme_debug("request sectors [0x%x, 0x%x), cmd ID 0x%0x",
                   req->blocks.start, req->blocks.start + nlb, cmd->id);
        sqe->cdw10 = req->blocks.start;
        sqe->cdw12 = nlb - 1;
        cmd->req = req;
        req->pending_cmds++;
        req->blocks.start += nlb;
        new_reqs = true;
    }
    if (new_reqs)
        nvme_sq_doorbell(n, NVME_IOQ_IDX, &n->iosq);
}

closure_function(3, 3, void, nvme_io,
                 nvme, n, u32, namespace, boolean, write,
                 void *, buf, range, blocks, status_handler, sh)
{
    nvme n = bound(n);
    u32 namespace = bound(namespace);
    boolean write = bound(write);
    nvme_debug("[%d] %s %R", namespace, write ? "write" : "read", blocks);
    nvme_ioreq req = nvme_get_ioreq(n);
    if (req == INVALID_ADDRESS) {
        apply(sh, timm("result", "request allocation failed"));
        return;
    }
    req->namespace = namespace;
    req->write = write;
    req->buf = buf;
    req->blocks = blocks;
    req->pending_cmds = 0;
    req->sh = sh;
    req->sc = NVME_SC_OK;
    u64 irqflags = spin_lock_irq(&n->lock);
    list_push_back(&n->pending_reqs, &req->l);
    nvme_service_pending(n, true);
    spin_unlock_irq(&n->lock, irqflags);
}

define_closure_function(1, 0, void, nvme_io_irq,
                        nvme, n)
{
    nvme_debug("%s", __func__);
    nvme n = bound(n);
    spin_lock(&n->lock);
    boolean done_empty = list_empty(&n->done_reqs);
    struct nvme_cqe *cqe;
    while ((cqe = nvme_get_cqe(&n->iocq))) {
        n->iosq.head = NVME_SQ_HEAD(cqe->dw2);
        nvme_iocmd cmd = vector_get(n->cmds, NVME_CMD_ID(cqe->dw3));
        nvme_debug("  cmd ID 0x%0x complete", cmd->id);
        nvme_ioreq req = cmd->req;
        list_insert_before(list_begin(&n->free_cmds), &cmd->l);
        int sc = NVME_STATUS_CODE(cqe->dw3);
        u64 remaining = range_span(req->blocks);
        if ((sc != NVME_SC_OK) && (remaining != 0))
            list_delete(&req->l);   /* remove from pending list */
        if (sc != NVME_SC_OK)
            req->sc = sc;
        boolean req_complete = !(--req->pending_cmds) && (!remaining || (sc != NVME_SC_OK));
        if (req_complete)
            list_push_back(&n->done_reqs, &req->l);
    }
    nvme_cq_doorbell(n, NVME_IOQ_IDX, &n->iocq);
    nvme_service_pending(n, false);
    if (done_empty && !list_empty(&n->done_reqs))
        enqueue(bhqueue, &n->bh_service);
    spin_unlock(&n->lock);
}

define_closure_function(1, 0, void, nvme_bh_service,
                        nvme, n)
{
    nvme_debug("%s", __func__);
    nvme n = bound(n);
    list l;
    u64 irqflags = spin_lock_irq(&n->lock);
    while ((l = list_get_next(&n->done_reqs))) {
        list_delete(l);
        spin_unlock_irq(&n->lock, irqflags);
        nvme_ioreq req = struct_from_list(l, nvme_ioreq, l);
        apply(req->sh, (req->sc == NVME_SC_OK) ? STATUS_OK :
                timm("result", "NVMe status code 0x%x", req->sc));
        irqflags = spin_lock_irq(&n->lock);
        list_insert_before(list_begin(&n->free_reqs), l);
    }
    nvme_service_pending(n, true);
    spin_unlock_irq(&n->lock, irqflags);
}

closure_function(4, 0, void, nvme_ns_attach,
                 nvme, n, u32, ns_id, u64, disk_size, storage_attach, a)
{
    nvme n = bound(n);
    u32 ns_id = bound(ns_id);
    u64 disk_size = bound(disk_size);
    block_io r = closure(n->general, nvme_io, n, ns_id, false);
    if (r == INVALID_ADDRESS) {
        msg_err("failed to allocate read closure\n");
        goto done;
    }
    block_io w = closure(n->general, nvme_io, n, ns_id, true);
    if (w != INVALID_ADDRESS) {
        nvme_debug("attaching disk (NS ID %d, capacity %ld bytes)", ns_id, disk_size);
        apply(bound(a), r, w, disk_size);
    } else {
        msg_err("failed to allocate write closure\n");
        deallocate_closure(r);
    }
  done:
    closure_finish();
}

static void nvme_ns_resp_parse(nvme n, u32 ns_id, void *ns_resp,
                               struct nvme_cqe *cqe, storage_attach a)
{
    nvme_debug("identify namespace response (cmd ID %d)", NVME_CMD_ID(cqe->dw3));
    n->asq.head = NVME_SQ_HEAD(cqe->dw2);
    int sc = NVME_STATUS_CODE(cqe->dw3);
    if (sc != NVME_SC_OK) {
        msg_err("failed to identify namespace: status code 0x%x\n", sc);
        for (int i = 0; i < U64_FROM_BIT(n->asq.order); i++) {
            struct nvme_sqe *sqe = &n->asq.ring[i];
            rprintf("sqe %x %x %x %x %x %x %x %x %x %x %x %x\n",
                    sqe->cdw0, sqe->nsid, sqe->reserved, sqe->mptr, sqe->dptr.prp1, sqe->dptr.prp2,
                    sqe->cdw10, sqe->cdw11, sqe->cdw12, sqe->cdw13, sqe->cdw14, sqe->cdw15);
        }
        for (int i = 0; i < U64_FROM_BIT(n->acq.order); i++) {
            struct nvme_cqe *cqe = &n->acq.ring[i];
            rprintf("cqe %x %x %x %x\n", cqe->dw0, cqe->dw1, cqe->dw2, cqe->dw3);
        }
        return;
    }
    int flbas = *(u8 *)(ns_resp + 26) & 0xF;    /* formatted LBA size */
    u32 lbaf = *(u32 *)(ns_resp + 128 + flbas); /* LBA format */
    int lbads = 1 << ((lbaf >> 16) & 0xFF);     /* LBA data size */
    if (lbads != SECTOR_SIZE) {
        msg_err("unsupported sector size %ld", lbads);
        return;
    }
    u64 disk_size = *(u64 *)ns_resp * lbads;
    thunk ns_attach = closure(n->general, nvme_ns_attach, n, ns_id, disk_size, a);
    if (ns_attach == INVALID_ADDRESS)
        msg_err("failed to allocate NS attach closure\n");
    else
        enqueue(runqueue, ns_attach);
}

static void nvme_ns_query(nvme n, u32 ns_id, void *ns_resp)
{
    struct nvme_sqe *cmd = nvme_get_sqe(&n->asq);
    assert(cmd);
    zero(cmd, sizeof(*cmd));
    int cid = n->asq.tail;
    nvme_debug("identifying namespace %d, cmd ID %d", ns_id, cid);
    cmd->cdw0 = NVME_CID(cid) | NVME_CMD_PRP | NVME_OPC_IDENTIFY;
    cmd->dptr.prp1 = physical_from_virtual(ns_resp);
    cmd->nsid = ns_id;
    cmd->cdw10 = CNS_IDENTIFY_NAMESPACE;
    nvme_sq_doorbell(n, NVME_AQ_IDX, &n->asq);
}

static void nvme_ns_query_next(nvme n, u32 ns_id, u32 nn, void *ns_resp)
{
    if (ns_id <= nn) {
        nvme_ns_query(n, ns_id, ns_resp);
    } else {
        deallocate(n->contiguous, ns_resp, NVME_IDENTIFY_RESP_SIZE);
        deallocate_closure(n->ac_handler);
    }
}

closure_function(5, 0, void, nvme_ns_query_resp,
                 nvme, n, u32, ns_id, u32, nn, void *, ns_resp, storage_attach, a)
{
    nvme n = bound(n);
    struct nvme_cqe *cqe = nvme_get_cqe(&n->acq);
    if (cqe) {
        void *ns_resp = bound(ns_resp);
        nvme_ns_resp_parse(n, bound(ns_id), ns_resp, cqe, bound(a));
        nvme_cq_doorbell(n, NVME_AQ_IDX, &n->acq);
        nvme_ns_query_next(n, ++bound(ns_id), bound(nn), ns_resp);
    }
    else {
        for (int i = 0; i < U64_FROM_BIT(n->asq.order); i++) {
            struct nvme_sqe *sqe = &n->asq.ring[i];
            rprintf("sqe %x %x %x %x %x %x %x %x %x %x %x %x\n",
                    sqe->cdw0, sqe->nsid, sqe->reserved, sqe->mptr, sqe->dptr.prp1, sqe->dptr.prp2,
                    sqe->cdw10, sqe->cdw11, sqe->cdw12, sqe->cdw13, sqe->cdw14, sqe->cdw15);
        }
        for (int i = 0; i < U64_FROM_BIT(n->acq.order); i++) {
            struct nvme_cqe *cqe = &n->acq.ring[i];
            rprintf("cqe %x %x %x %x\n", cqe->dw0, cqe->dw1, cqe->dw2, cqe->dw3);
        }
    }
}

static void nvme_ns_query_next_active(nvme n, u32 *ns_list, int index, void *ns_resp)
{
    u32 ns_id = ns_list[index];
    if (ns_id != 0) {
        nvme_ns_query(n, ns_id, ns_resp);
    } else {
        nvme_debug("no more active namespaces");
        deallocate(n->contiguous, ns_list, NVME_IDENTIFY_RESP_SIZE);
        deallocate(n->contiguous, ns_resp, NVME_IDENTIFY_RESP_SIZE);
        deallocate_closure(n->ac_handler);
    }
}

closure_function(5, 0, void, nvme_ns_query_resp_active,
                 nvme, n, u32 *, ns_list, int, index, void *, ns_resp, storage_attach, a)
{
    nvme n = bound(n);
    struct nvme_cqe *cqe = nvme_get_cqe(&n->acq);
    if (cqe) {
        u32 *ns_list = bound(ns_list);
        void *ns_resp = bound(ns_resp);
        nvme_ns_resp_parse(n, ns_list[bound(index)], ns_resp, cqe, bound(a));
        nvme_cq_doorbell(n, NVME_AQ_IDX, &n->acq);
        nvme_ns_query_next_active(n, ns_list, ++bound(index), ns_resp);
    }
}

closure_function(3, 0, void, nvme_identify_controller_resp,
                 nvme, n, void *, resp, storage_attach, a)
{
    nvme n = bound(n);
    struct nvme_cqe *cqe = nvme_get_cqe(&n->acq);
    if (cqe) {
        void *resp = bound(resp);
        n->asq.head = NVME_SQ_HEAD(cqe->dw2);
        int sc = NVME_STATUS_CODE(cqe->dw3);
        nvme_cq_doorbell(n, NVME_AQ_IDX, &n->acq);
        if (sc != NVME_SC_OK) {
            msg_err("failed to identify controller: status code 0x%x\n", sc);
            goto error;
        }
        u32 nn = *(u32 *)(resp + 516);  /* number of namespaces */
        nvme_debug("controller reports %d namespace(s)", nn);
        n->ac_handler = closure(n->general, nvme_ns_query_resp, n, 1, nn, resp, bound(a));
        if (n->ac_handler != INVALID_ADDRESS) {
            nvme_ns_query_next(n, 1, nn, resp);
            goto done;
        } else {
            msg_err("failed to allocate completion handler\n");
        }
  error:
        deallocate(n->contiguous, resp, NVME_IDENTIFY_RESP_SIZE);
    }
  done:
    closure_finish();
}

static boolean nvme_identify_controller(nvme n, storage_attach a)
{
    void *resp = allocate(n->contiguous, NVME_IDENTIFY_RESP_SIZE);
    if (resp == INVALID_ADDRESS) {
        msg_err("failed to allocate response\n");
        return false;
    }
    n->ac_handler = closure(n->general, nvme_identify_controller_resp, n, resp, a);
    if (n->ac_handler == INVALID_ADDRESS) {
        msg_err("failed to allocate completion handler\n");
        deallocate(n->contiguous, resp, NVME_IDENTIFY_RESP_SIZE);
        return false;
    }
    struct nvme_sqe *cmd = nvme_get_sqe(&n->asq);
    assert(cmd);
    zero(cmd, sizeof(*cmd));
    cmd->cdw0 = NVME_CID(n->asq.tail) | NVME_CMD_PRP | NVME_OPC_IDENTIFY;
    cmd->dptr.prp1 = physical_from_virtual(resp);
    cmd->cdw10 = CNS_IDENTIFY_CONTROLLER;
    nvme_sq_doorbell(n, NVME_AQ_IDX, &n->asq);
    return true;
}

closure_function(3, 0, void, nvme_get_active_namespaces_resp,
                 nvme, n, void *, resp, storage_attach, a)
{
    nvme n = bound(n);
    struct nvme_cqe *cqe = nvme_get_cqe(&n->acq);
    if (cqe) {
        void *resp = bound(resp);
        n->asq.head = NVME_SQ_HEAD(cqe->dw2);
        int sc = NVME_STATUS_CODE(cqe->dw3);
        nvme_cq_doorbell(n, NVME_AQ_IDX, &n->acq);
        if (sc != NVME_SC_OK) {
            msg_err("failed to get active namespaces: status code 0x%x\n", sc);
            goto error;
        }
        void *ns_resp = allocate(n->contiguous, NVME_IDENTIFY_RESP_SIZE);
        if (ns_resp == INVALID_ADDRESS) {
            msg_err("failed to allocate namespace data response\n");
            goto error;
        }
        n->ac_handler = closure(n->general, nvme_ns_query_resp_active, n, resp,
            0, ns_resp, bound(a));
        if (n->ac_handler != INVALID_ADDRESS) {
            nvme_ns_query_next_active(n, resp, 0, ns_resp);
            goto done;
        } else {
            msg_err("failed to allocate completion handler\n");
            deallocate(n->contiguous, ns_resp, NVME_IDENTIFY_RESP_SIZE);
        }
  error:
        deallocate(n->contiguous, resp, NVME_IDENTIFY_RESP_SIZE);
    }
  done:
    closure_finish();
}

static boolean nvme_get_active_namespaces(nvme n, u32 start_id, storage_attach a)
{
    void *resp = allocate(n->contiguous, NVME_IDENTIFY_RESP_SIZE);
    if (resp == INVALID_ADDRESS) {
        msg_err("failed to allocate response\n");
        return false;
    }
    n->ac_handler = closure(n->general, nvme_get_active_namespaces_resp, n, resp, a);
    if (n->ac_handler == INVALID_ADDRESS) {
        msg_err("failed to allocate completion handler\n");
        deallocate(n->contiguous, resp, NVME_IDENTIFY_RESP_SIZE);
        return false;
    }
    struct nvme_sqe *cmd = nvme_get_sqe(&n->asq);
    assert(cmd);
    zero(cmd, sizeof(*cmd));
    cmd->cdw0 = NVME_CID(n->asq.tail) | NVME_CMD_PRP | NVME_OPC_IDENTIFY;
    cmd->nsid = start_id;
    cmd->dptr.prp1 = physical_from_virtual(resp);
    cmd->cdw10 = CNS_ACTIVE_NAMESPACES;
    nvme_sq_doorbell(n, NVME_AQ_IDX, &n->asq);
    return true;
}

closure_function(2, 0, void, nvme_create_iosq_resp,
                 nvme, n, storage_attach, a)
{
    nvme n = bound(n);
    storage_attach a = bound(a);
    struct nvme_cqe *cqe = nvme_get_cqe(&n->acq);
    if (cqe) {
        n->asq.head = NVME_SQ_HEAD(cqe->dw2);
        int sc = NVME_STATUS_CODE(cqe->dw3);
        nvme_cq_doorbell(n, NVME_AQ_IDX, &n->acq);
        if (sc == NVME_SC_OK) {
            nvme_debug("I/O SQ created");
            if (n->vs >= NVME_VER(1, 1, 0))
                nvme_get_active_namespaces(n, 0, a);
            else
                nvme_identify_controller(n, a);
        } else {
            msg_err("failed to create I/O SQ: status code 0x%x\n", sc);
        }
    }
    closure_finish();
}

static boolean nvme_create_iosq(nvme n, storage_attach a)
{
    if (!nvme_init_sq(n, &n->iosq, n->ioq_order)) {
        msg_err("failed to initialize queue\n");
        return false;
    }
    n->ac_handler = closure(n->general, nvme_create_iosq_resp, n, a);
    if (n->ac_handler == INVALID_ADDRESS) {
        msg_err("failed to allocate completion handler\n");
        nvme_deinit_sq(n, &n->iosq);
        return false;
    }

    /* Zero out all submission queue entries, so that when submitting an entry
     * only used fields need to be set. This relies on the fact that all I/O
     * commands use the same set of fields. */
    zero(n->iosq.ring, U64_FROM_BIT(n->iosq.order) * sizeof(struct nvme_sqe));

    struct nvme_sqe *cmd = nvme_get_sqe(&n->asq);
    assert(cmd);
    zero(cmd, sizeof(*cmd));
    cmd->cdw0 = NVME_CID(n->asq.tail) | NVME_CMD_PRP | NVME_OPC_CRE_IOSQ;
    cmd->dptr.prp1 = physical_from_virtual(n->iosq.ring);
    cmd->cdw10 = (MASK(n->ioq_order) << 16) | NVME_IOQ_IDX; /* queue size and queue ID */
    cmd->cdw11 = (NVME_IOQ_IDX << 16) | 0x01;  /* completion queue ID, physically contiguous */
    nvme_sq_doorbell(n, NVME_AQ_IDX, &n->asq);
    return true;
}

closure_function(2, 0, void, nvme_create_iocq_resp,
                 nvme, n, storage_attach, a)
{
    nvme n = bound(n);
    struct nvme_cqe *cqe = nvme_get_cqe(&n->acq);
    if (cqe) {
        n->asq.head = NVME_SQ_HEAD(cqe->dw2);
        int sc = NVME_STATUS_CODE(cqe->dw3);
        nvme_cq_doorbell(n, NVME_AQ_IDX, &n->acq);
        if (sc == NVME_SC_OK) {
            nvme_debug("I/O CQ created");
            nvme_create_iosq(n, bound(a));
        } else {
            msg_err("failed to create I/O CQ: status code 0x%x\n", sc);
        }
    }
    closure_finish();
}

static boolean nvme_create_iocq(nvme n, storage_attach a)
{
    if (!nvme_init_cq(n, &n->iocq, n->ioq_order)) {
        msg_err("failed to initialize queue\n");
        return false;
    }
    n->ac_handler = closure(n->general, nvme_create_iocq_resp, n, a);
    if (n->ac_handler == INVALID_ADDRESS) {
        msg_err("failed to allocate completion handler\n");
        nvme_deinit_cq(n, &n->iocq);
        return false;
    }
    if (pci_setup_msix(n->d, NVME_IOQ_MSIX, init_closure(&n->io_irq, nvme_io_irq, n),
                       "nvme I/O") == INVALID_PHYSICAL) {
        msg_err("failed to allocate MSI-X vector\n");
        return false;
    }
    struct nvme_sqe *cmd = nvme_get_sqe(&n->asq);
    assert(cmd);
    zero(cmd, sizeof(*cmd));
    cmd->cdw0 = NVME_CID(n->asq.tail) | NVME_CMD_PRP | NVME_OPC_CRE_IOCQ;
    cmd->dptr.prp1 = physical_from_virtual(n->iocq.ring);
    cmd->cdw10 = (MASK(n->ioq_order) << 16) | NVME_IOQ_IDX; /* queue size and queue ID */
    cmd->cdw11 = (NVME_IOQ_MSIX << 16) | 0x03;  /* interrupts enabled, physically contiguous */
    nvme_sq_doorbell(n, NVME_AQ_IDX, &n->asq);
    return true;
}

define_closure_function(1, 0, void, nvme_admin_irq,
                        nvme, n)
{
    nvme n = bound(n);
    nvme_debug("%s (%F)", __func__, n->ac_handler);
    apply(n->ac_handler);
}

closure_function(3, 1, boolean, nvme_probe,
                 heap, general, storage_attach, a, heap, contiguous,
                 pci_dev, d)
{
    if ((pci_get_class(d) != PCIC_STORAGE) || (pci_get_subclass(d) != PCIS_STORAGE_NVM) ||
            (pci_get_prog_if(d) != PCIPI_STORAGE_NVME))
        return false;
    heap general = bound(general);
    nvme n = allocate(general, sizeof(*n));
    if (n == INVALID_ADDRESS)
        return false;
    n->general = general;
    n->contiguous = bound(contiguous);
    if (!nvme_init_sq(n, &n->asq, NVME_ASQ_ORDER))
        goto free_nvme;
    if (!nvme_init_cq(n, &n->acq, NVME_ACQ_ORDER))
        goto deinit_asq;
    pci_bar_init(d, &n->bar, NVME_REG_BAR, 0, -1);

    /* reset controller */
    pci_bar_write_4(&n->bar, NVME_CC, 0);
    int retries = 0;
    while (1) {
        if (!(pci_bar_read_4(&n->bar, NVME_CSTS) & NVME_CSTS_RDY))
            break;
        if (retries++ <= 8) {
            kernel_delay(milliseconds(1 << retries));
        } else {
            msg_err("failed to reset controller\n");
            goto deinit_acq;
        }
    }

    n->vs = pci_bar_read_4(&n->bar, NVME_VS);
    u64 cap = pci_bar_read_8(&n->bar, NVME_CAP);
    n->dstrd = 4 << NVME_CAP_DSTRD(cap);
    int mqes = NVME_CAP_MQES(cap);
    n->ioq_order = find_order(mqes);
    if (mqes != U64_FROM_BIT(n->ioq_order))
        n->ioq_order--;
    nvme_debug("new controller (version %d.%d.%d), MQES %d, I/O queue order %d",
               NVME_VS_MJR(n->vs), NVME_VS_MNR(n->vs), NVME_VS_TER(n->vs), mqes, n->ioq_order);
    n->cmds = allocate_vector(general, NVME_CID_MAX + 1);
    if (n->cmds == INVALID_ADDRESS) {
        msg_err("failed to allocate request vector\n");
        goto deinit_acq;
    }
    pci_bar_write_4(&n->bar, NVME_AQA, NVME_AQA_ACQS(U64_FROM_BIT(NVME_ACQ_ORDER)) |
                    NVME_AQA_ASQS(U64_FROM_BIT(NVME_ASQ_ORDER)));
    pci_bar_write_8(&n->bar, NVME_ASQ, physical_from_virtual(n->asq.ring));
    pci_bar_write_8(&n->bar, NVME_ACQ, physical_from_virtual(n->acq.ring));
    pci_bar_write_4(&n->bar, NVME_CC, NVME_CC_IOCQES(find_order(sizeof(struct nvme_cqe)))
                    | NVME_CC_IOSQES(find_order(sizeof(struct nvme_sqe))) | NVME_CC_EN);
    retries = 0;
    while (1) {
        if (pci_bar_read_4(&n->bar, NVME_CSTS) & NVME_CSTS_RDY)
            break;
        if (retries++ <= 8) {
            kernel_delay(milliseconds(1 << retries));
        } else {
            msg_err("failed to enable controller\n");
            goto free_cmds;
        }
    }
    n->d = d;
    pci_enable_msix(d);
    if (pci_setup_msix(d, NVME_AQ_MSIX, init_closure(&n->admin_irq, nvme_admin_irq, n),
                       "nvme admin") == INVALID_PHYSICAL) {
        msg_err("failed to allocate MSI-X vector\n");
        goto free_cmds;
    }
    list_init(&n->pending_reqs);
    list_init(&n->free_reqs);
    list_init(&n->done_reqs);
    list_init(&n->free_cmds);
    spin_lock_init(&n->lock);
    init_closure(&n->bh_service, nvme_bh_service, n);
    if (nvme_create_iocq(n, bound(a)))
        return true;
  free_cmds:
    deallocate_vector(n->cmds);
  deinit_acq:
    nvme_deinit_cq(n, &n->acq);
  deinit_asq:
    nvme_deinit_sq(n, &n->asq);
  free_nvme:
    deallocate(general, n, sizeof(*n));
    return false;
}

void init_nvme(kernel_heaps kh, storage_attach a)
{
    heap h = heap_locked(kh);
    register_pci_driver(closure(h, nvme_probe, h, a, heap_backed(kh)));
}
