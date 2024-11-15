#include <kernel.h>
#include <storage.h>

#include "virtio_internal.h"
#include "virtio_mmio.h"
#include "virtio_pci.h"

//#define VIRTIO_BLK_DEBUG
#ifdef VIRTIO_BLK_DEBUG
#define virtio_blk_debug(x, ...) do {tprintf(sym(vtblk), 0, ss(x), ##__VA_ARGS__);} while(0)
#else
#define virtio_blk_debug(x, ...)
#endif

// this is not really a struct...fix the general encoding problem
typedef struct virtio_blk_req {
    u32 type;
    u32 reserved;
    u64 sector;
    u8 status;
} __attribute__((packed)) *virtio_blk_req;

// device configuration offsets
struct virtio_blk_config {
    u64 capacity;
    u32 size_max;
    u32 seg_max;
    struct virtio_blk_geometry {
        u16 cylinders;
        u8 heads;
        u8 sectors;
   } geometry;
   u32 blk_size;
   struct virtio_blk_topology {
       // # of logical blocks per physical block (log2)
       u8 physical_block_exp;
       // offset of first aligned logical block
       u8 alignment_offset;
       // suggested minimum I/O size in blocks
       u16 min_io_size;
       // optimal (suggested maximum) I/O size in blocks
       u32 opt_io_size;
    } topology;
    u8 writeback;
    u8 unused0[3];
    u32 max_discard_sectors;
    u32 max_discard_seg;
    u32 discard_sector_alignment;
    u32 max_write_zeroes_sectors;
    u32 max_write_zeroes_seg;
    u8 write_zeroes_may_unmap;
    u8 unused1[3];
} __attribute__((packed));

#define VIRTIO_BLK_F_SIZE_MAX   U64_FROM_BIT(1)
#define VIRTIO_BLK_F_SEG_MAX    U64_FROM_BIT(2)
#define VIRTIO_BLK_F_GEOMETRY   U64_FROM_BIT(4)
#define VIRTIO_BLK_F_RO         U64_FROM_BIT(5)
#define VIRTIO_BLK_F_BLK_SIZE   U64_FROM_BIT(6)
#define VIRTIO_BLK_F_FLUSH      U64_FROM_BIT(9)
#define VIRTIO_BLK_F_TOPOLOGY   U64_FROM_BIT(10)
#define VIRTIO_BLK_F_CONFIG_WCE U64_FROM_BIT(11)

#define VIRTIO_BLK_R_CAPACITY_LOW                (offsetof(struct virtio_blk_config *, capacity))
#define VIRTIO_BLK_R_CAPACITY_HIGH               (offsetof(struct virtio_blk_config *, capacity) + 4)
#define VIRTIO_BLK_R_SIZE_MAX                    (offsetof(struct virtio_blk_config *, size_max))
#define VIRTIO_BLK_R_SEG_MAX                     (offsetof(struct virtio_blk_config *, seg_max))
#define VIRTIO_BLK_R_GEOM_CYLINDERS              (offsetof(struct virtio_blk_config *, geometry) + offsetof(struct virtio_blk_geometry *, cylinders))
#define VIRTIO_BLK_R_GEOM_HEADS                  (offsetof(struct virtio_blk_config *, geometry) + offsetof(struct virtio_blk_geometry *, heads))
#define VIRTIO_BLK_R_GEOM_SECTORS                (offsetof(struct virtio_blk_config *, geometry) + offsetof(struct virtio_blk_geometry *, sectors))
#define VIRTIO_BLK_R_BLOCK_SIZE                  (offsetof(struct virtio_blk_config *, blk_size))
#define VIRTIO_BLK_R_TOPOLOGY_PHYSICAL_BLOCK_EXP (offsetof(struct virtio_blk_config *, topology) + offsetof(struct virtio_blk_topology *, physical_block_exp))
#define VIRTIO_BLK_R_TOPOLOGY_ALIGNMENT_OFFSET   (offsetof(struct virtio_blk_config *, topology) + offsetof(struct virtio_blk_topology *, alignment_offset))
#define VIRTIO_BLK_R_TOPOLOGY_MIN_IO_SIZE        (offsetof(struct virtio_blk_config *, topology) + offsetof(struct virtio_blk_topology *, min_io_size))
#define VIRTIO_BLK_R_TOPOLOGY_OPT_IO_SIZE        (offsetof(struct virtio_blk_config *, topology) + offsetof(struct virtio_blk_topology *, opt_io_size))
#define VIRTIO_BLK_R_WRITEBACK                   (offsetof(struct virtio_blk_config *, writeback))
#define VIRTIO_BLK_R_MAX_DISCARD_SECTORS         (offsetof(struct virtio_blk_config *, max_discard_sectors))
#define VIRTIO_BLK_R_MAX_DISCARD_SEG             (offsetof(struct virtio_blk_config *, max_discard_seg))
#define VIRTIO_BLK_R_DISCARD_SECTOR_ALIGNMENT    (offsetof(struct virtio_blk_config *, discard_sector_alignment))
#define VIRTIO_BLK_R_MAX_WRITE_ZEROS_SECTORS     (offsetof(struct virtio_blk_config *, max_write_zeroes_sectors))
#define VIRTIO_BLK_R_MAX_WRITE_ZEROS_SEG         (offsetof(struct virtio_blk_config *, max_write_zeroes_seg))
#define VIRTIO_BLK_R_WRITE_ZEROS_MAY_UNMAP       (offsetof(struct virtio_blk_config *, write_zeroes_may_unmap))

#define VIRTIO_BLK_REQ_HEADER_SIZE      16
#define VIRTIO_BLK_REQ_STATUS_SIZE      1

#define VIRTIO_BLK_T_IN         0
#define VIRTIO_BLK_T_OUT        1
#define VIRTIO_BLK_T_FLUSH      4

#define VIRTIO_BLK_S_OK         0
#define VIRTIO_BLK_S_IOERR      1
#define VIRTIO_BLK_S_UNSUPP     2

#define VIRTIO_BLK_DRIVER_FEATURES  \
    (VIRTIO_BLK_F_SEG_MAX | VIRTIO_BLK_F_BLK_SIZE | VIRTIO_BLK_F_CONFIG_WCE | VIRTIO_BLK_F_FLUSH)

typedef struct storage {
    vtdev v;
    closure_struct(storage_req_handler, req_handler);
    struct virtqueue *command;
    u64 capacity;
    u64 block_size;
    u32 seg_max;
} *storage;

static virtio_blk_req allocate_virtio_blk_req(storage st, u32 type, u64 sector, u64 *phys)
{
    virtio_blk_req req = alloc_map(st->v->contiguous, sizeof(struct virtio_blk_req), phys);
    if (req != INVALID_ADDRESS) {
        req->type = type;
        req->reserved = 0;
        req->sector = sector;
        req->status = 0;
    }
    return req;
}

static void deallocate_virtio_blk_req(storage st, virtio_blk_req req, u64 phys)
{
    dealloc_unmap(st->v->contiguous, req, phys,
                  pad(sizeof(struct virtio_blk_req), st->v->contiguous->h.pagesize));
}

closure_function(4, 1, void, complete,
                 storage, s, status_handler, f, virtio_blk_req, req, u64, phys,
                 u64 len)
{
    status st = 0;
    // 1 is io error, 2 is unsupported operation
    if (bound(req)->status) st = timm("result", "%d", bound(req)->status);
    async_apply_status_handler(bound(f), st);
    deallocate_virtio_blk_req(bound(s), bound(req), bound(phys));
    closure_finish();
}

static inline void storage_rw_internal(storage st, boolean write, void * buf,
                                       range sectors, status_handler sh)
{
    sstring err;
    virtio_blk_debug("%s: block range %R cap %ld\n", write ? ss("write") : ss("read"), sectors,
                     st->capacity);

    u64 start_sector = sectors.start;
    u64 nsectors = range_span(sectors);
    if (nsectors == 0) {
        err = ss("length must be > 0");
        goto out_inval;
    }

    u64 req_phys;
    virtio_blk_req req = allocate_virtio_blk_req(st, write ? VIRTIO_BLK_T_OUT : VIRTIO_BLK_T_IN,
                                                 start_sector, &req_phys);
    if (req == INVALID_ADDRESS) {
        apply(sh, timm_oom);
        return;
    }
    virtqueue vq = st->command;
    vqmsg m = allocate_vqmsg(vq);
    assert(m != INVALID_ADDRESS);
    vqmsg_push(vq, m, req_phys, VIRTIO_BLK_REQ_HEADER_SIZE, false);
    vqmsg_push(vq, m, physical_from_virtual(buf), nsectors * st->block_size, !write);
    u64 statusp = req_phys + VIRTIO_BLK_REQ_HEADER_SIZE;
    vqmsg_push(vq, m, statusp, VIRTIO_BLK_REQ_STATUS_SIZE, true);
    vqfinish c = closure(st->v->general, complete, st, sh, req, req_phys);
    vqmsg_commit(vq, m, c);
    return;
  out_inval:
    msg_err("vtblk R/W error: %s", err);
    apply(sh, timm("result", "%s", err));
}

static void virtio_storage_io_commit(storage st, virtqueue vq, vqmsg msg, virtio_blk_req req,
                                     u64 req_phys, status_handler completion)
{
    vqmsg_push(vq, msg, req_phys + VIRTIO_BLK_REQ_HEADER_SIZE, VIRTIO_BLK_REQ_STATUS_SIZE, true);
    vqfinish c = closure(st->v->general, complete, st, completion, req, req_phys);
    assert(c != INVALID_ADDRESS);
    vqmsg_commit(vq, msg, c);
}

static void virtio_storage_io_sg(storage st, boolean write, sg_list sg, range blocks,
                                 status_handler sh)
{
    virtio_blk_debug("SG %c, blocks %R, sh %F\n", write ? 'w' : 'r', blocks, sh);
    virtio_blk_req req = 0;
    u64 req_phys;
    heap h = st->v->general;
    virtqueue vq = st->command;
    vqmsg msg;
    u32 desc_count;
    merge m = 0;
    while (range_span(blocks)) {
        if (!req) {
            req = allocate_virtio_blk_req(st, write ? VIRTIO_BLK_T_OUT : VIRTIO_BLK_T_IN,
                                          blocks.start, &req_phys);
            if (req == INVALID_ADDRESS) {
                apply(sh, timm_oom);
                return;
            }
            msg = allocate_vqmsg(vq);
            assert(msg != INVALID_ADDRESS);
            vqmsg_push(vq, msg, req_phys, VIRTIO_BLK_REQ_HEADER_SIZE, false);
            desc_count = 0;
        }
        sg_buf sgb = sg_list_head_peek(sg);
        u64 length = sg_buf_len(sgb);
        assert((length & (st->block_size - 1)) == 0);
        length = MIN(range_span(blocks) * st->block_size, length);
        vqmsg_push(vq, msg, physical_from_virtual(sgb->buf + sgb->offset), length, !write);
        sg_consume(sg, length);
        blocks.start += length / st->block_size;
        if (++desc_count == st->seg_max) {
            if (!m && range_span(blocks)) {
                m = allocate_merge(h, sh);
                sh = apply_merge(m);
            }
            virtio_storage_io_commit(st, vq, msg, req, req_phys, m ? apply_merge(m) : sh);
            req = 0;
        }
    }
    if (req) {
        virtio_storage_io_commit(st, vq, msg, req, req_phys, m ? apply_merge(m) : sh);
    }
    if (m)
        apply(sh, STATUS_OK);
}

static void storage_flush(storage st, status_handler s)
{
    virtio_blk_debug("%s: handler %p (%F)\n", func_ss, s, s);
    u64 req_phys;
    virtio_blk_req req = allocate_virtio_blk_req(st, VIRTIO_BLK_T_FLUSH, 0, &req_phys);
    if (req == INVALID_ADDRESS) {
        apply(s, timm_oom);
        return;
    }
    virtqueue vq = st->command;
    vqmsg m = allocate_vqmsg(vq);
    assert(m != INVALID_ADDRESS);
    vqmsg_push(vq, m, req_phys, VIRTIO_BLK_REQ_HEADER_SIZE, false);
    vqmsg_push(vq, m, req_phys + VIRTIO_BLK_REQ_HEADER_SIZE, VIRTIO_BLK_REQ_STATUS_SIZE, true);
    vqfinish c = closure(st->v->general, complete, st, s, req, req_phys);
    assert(c != INVALID_ADDRESS);
    vqmsg_commit(vq, m, c);
}

closure_func_basic(storage_req_handler, void, virtio_storage_req_handler,
                   storage_req req)
{
    storage st = struct_from_field(closure_self(), storage, req_handler);
    switch (req->op) {
    case STORAGE_OP_READSG:
        virtio_storage_io_sg(st, false, req->data, req->blocks, req->completion);
        break;
    case STORAGE_OP_WRITESG:
        virtio_storage_io_sg(st, true, req->data, req->blocks, req->completion);
        break;
    case STORAGE_OP_FLUSH:
        if (st->v->features & VIRTIO_BLK_F_FLUSH)
            storage_flush(st, req->completion);
        else
            async_apply_status_handler(req->completion, STATUS_OK);
        break;
    case STORAGE_OP_READ:
        storage_rw_internal(st, false, req->data, req->blocks, req->completion);
        break;
    case STORAGE_OP_WRITE:
        storage_rw_internal(st, true, req->data, req->blocks, req->completion);
        break;
    }
}

static void virtio_blk_attach(heap general, storage_attach a, vtdev v)
{
    storage s = allocate(general, sizeof(struct storage));
    assert(s != INVALID_ADDRESS);
    s->v = v;

    s->block_size = (v->features & VIRTIO_BLK_F_BLK_SIZE) ?
            vtdev_cfg_read_4(v, VIRTIO_BLK_R_BLOCK_SIZE) : SECTOR_SIZE;
    s->capacity = (vtdev_cfg_read_4(v, VIRTIO_BLK_R_CAPACITY_LOW) |
		   ((u64) vtdev_cfg_read_4(v, VIRTIO_BLK_R_CAPACITY_HIGH) << 32)) * s->block_size;
    virtio_blk_debug("%s: capacity 0x%lx, block size 0x%x\n", func_ss, s->capacity, s->block_size);
    virtio_alloc_virtqueue(v, ss("virtio blk"), 0, &s->command);

    s->seg_max = (v->features & VIRTIO_BLK_F_SEG_MAX) ?
            vtdev_cfg_read_4(v, VIRTIO_BLK_R_SEG_MAX) : 1;
    if (v->features & VIRTIO_BLK_F_FLUSH) {
        if (v->features & VIRTIO_BLK_F_CONFIG_WCE)
            vtdev_cfg_write_1(v, VIRTIO_BLK_R_WRITEBACK, 1 /* writeback */);
    }
    vtdev_set_status(v, VIRTIO_CONFIG_STATUS_DRIVER_OK);

    apply(a, init_closure_func(&s->req_handler, storage_req_handler, virtio_storage_req_handler),
          s->capacity, -1);
}

closure_function(3, 1, boolean, vtpci_blk_probe,
                 heap, general, storage_attach, a, backed_heap, page_allocator,
                 pci_dev d)
{
    virtio_blk_debug("%s\n", func_ss);
    if (!vtpci_probe(d, VIRTIO_ID_BLOCK))
        return false;

    virtio_blk_debug("   attaching\n");
    heap general = bound(general);
    vtdev v = (vtdev)attach_vtpci(general, bound(page_allocator), d, VIRTIO_BLK_DRIVER_FEATURES);
    virtio_blk_attach(general, bound(a), v);
    return true;
}

closure_function(3, 1, void, vtmmio_blk_probe,
                 heap, general, storage_attach, a, backed_heap, page_allocator,
                 vtmmio d)
{
    virtio_blk_debug("%s\n", __func__);
    if ((vtmmio_get_u32(d, VTMMIO_OFFSET_DEVID) != VIRTIO_ID_BLOCK) ||
            (d->memsize < VTMMIO_OFFSET_CONFIG +
            sizeof(struct virtio_blk_config)))
        return;
    virtio_blk_debug("   attaching\n");
    heap general = bound(general);
    if (attach_vtmmio(general, bound(page_allocator), d, VIRTIO_BLK_DRIVER_FEATURES))
        virtio_blk_attach(general, bound(a), (vtdev)d);
}

void init_virtio_blk(kernel_heaps kh, storage_attach a)
{
    virtio_blk_debug("%s\n", func_ss);
    heap h = heap_locked(kh);
    backed_heap page_allocator = heap_linear_backed(kh);
    register_pci_driver(closure(h, vtpci_blk_probe, h, a, page_allocator), 0);
    vtmmio_probe_devs(stack_closure(vtmmio_blk_probe, h, a, page_allocator));
}
