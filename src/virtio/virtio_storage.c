#include <kernel.h>
#include <drivers/storage.h>
#include <io.h>
#include <storage.h>

#include "virtio_internal.h"
#include "virtio_mmio.h"
#include "virtio_pci.h"

//#define VIRTIO_BLK_DEBUG

// this is not really a struct...fix the general encoding problem
typedef struct virtio_blk_req {
    u32 type;
    u32 reserved;
    u64 sector;
    u64 data; // phys? spec had u8 data[][512]
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
    u8 reserved;
} __attribute__((packed));

#define VIRTIO_BLK_F_SIZE_MAX   U64_FROM_BIT(1)
#define VIRTIO_BLK_F_SEG_MAX    U64_FROM_BIT(2)
#define VIRTIO_BLK_F_GEOMETRY   U64_FROM_BIT(4)
#define VIRTIO_BLK_F_RO         U64_FROM_BIT(5)
#define VIRTIO_BLK_F_BLK_SIZE   U64_FROM_BIT(6)
#define VIRTIO_BLK_F_FLUSH      U64_FROM_BIT(9)
#define VIRTIO_BLK_F_TOPOLOGY   U64_FROM_BIT(10)
#define VIRTIO_BLK_F_CONFIG_WCE U64_FROM_BIT(11)

#define VIRTIO_BLK_R_CAPACITY_LOW		(offsetof(struct virtio_blk_config *, capacity))
#define VIRTIO_BLK_R_CAPACITY_HIGH		(offsetof(struct virtio_blk_config *, capacity) + 4)
#define VIRTIO_BLK_R_SIZE_MAX			(offsetof(struct virtio_blk_config *, size_max))
#define VIRTIO_BLK_R_SEG_MAX			(offsetof(struct virtio_blk_config *, seg_max))
#define VIRTIO_BLK_R_GEOM_CYLINDERS		(offsetof(struct virtio_blk_config *, geometry) + offsetof(struct virtio_blk_geometry *, cylinders))
#define VIRTIO_BLK_R_GEOM_HEADS			(offsetof(struct virtio_blk_config *, geometry) + offsetof(struct virtio_blk_geometry *, heads))
#define VIRTIO_BLK_R_GEOM_SECTORS		(offsetof(struct virtio_blk_config *, geometry) + offsetof(struct virtio_blk_geometry *, sectors))
#define VIRTIO_BLK_R_BLOCK_SIZE			(offsetof(struct virtio_blk_config *, blk_size))
#define VIRTIO_BLK_R_TOPOLOGY_PHYSICAL_BLOCK_EXP (offsetof(struct virtio_blk_config *, topology) + offsetof(struct virtio_blk_topology *, physical_block_exp))
#define VIRTIO_BLK_R_TOPOLOGY_ALIGNMENT_OFFSET	(offsetof(struct virtio_blk_config *, topology) + offsetof(struct virtio_blk_topology *, alignment_offset))
#define VIRTIO_BLK_R_TOPOLOGY_MIN_IO_SIZE	(offsetof(struct virtio_blk_config *, topology) + offsetof(struct virtio_blk_topology *, min_io_size))
#define VIRTIO_BLK_R_TOPOLOGY_OPT_IO_SIZE	(offsetof(struct virtio_blk_config *, topology) + offsetof(struct virtio_blk_topology *, opt_io_size))
#define VIRTIO_BLK_R_RESERVED			(offsetof(struct virtio_blk_config *, reserved))

#define VIRTIO_BLK_REQ_HEADER_SIZE      16
#define VIRTIO_BLK_REQ_STATUS_SIZE      1

#define VIRTIO_BLK_T_IN         0
#define VIRTIO_BLK_T_OUT        1
#define VIRTIO_BLK_T_FLUSH      4

#define VIRTIO_BLK_S_OK         0
#define VIRTIO_BLK_S_IOERR      1
#define VIRTIO_BLK_S_UNSUPP     2

#ifdef VIRTIO_BLK_DEBUG
# define virtio_blk_debug rprintf
#else
# define virtio_blk_debug(...) do { } while(0)
#endif /* defined(VIRTIO_BLK_DEBUG) */

typedef struct storage {
    vtdev v;
    struct virtqueue *command;
    u64 capacity;
    u64 block_size;
} *storage;

static virtio_blk_req allocate_virtio_blk_req(storage st, u32 type, u64 sector)
{
    virtio_blk_req req = allocate(st->v->contiguous, sizeof(struct virtio_blk_req));
    req->type = type;
    req->reserved = 0;
    req->sector = sector;
    req->status = 0;
    return req;
}

static void deallocate_virtio_blk_req(storage st, virtio_blk_req req)
{
    deallocate(st->v->contiguous, req,
               pad(sizeof(struct virtio_blk_req), st->v->contiguous->pagesize));
}

closure_function(4, 1, void, complete,
                 storage, s, status_handler, f, u8 *, result, virtio_blk_req, req,
                 u64, len)
{
    status st = 0;
    // 1 is io error, 2 is unsupported operation
    if (*bound(result)) st = timm("result", "%d", *bound(result));
    apply(bound(f), st);
    deallocate_virtio_blk_req(bound(s), bound(req));
    // s->command->avail->flags &= ~VRING_AVAIL_F_NO_INTERRUPT;
    closure_finish();
}

static inline void storage_rw_internal(storage st, boolean write, void * buf,
                                       range sectors, status_handler sh)
{
    char * err = 0;
    virtio_blk_debug("virtio_%s: block range %R cap %ld\n", write ? "write" : "read", sectors, st->capacity);

    /* XXX so no, not page aligned but what? 16? */
    if ((u64_from_pointer(buf) & 15)) {
        msg_err("misaligned buf: %p\n", buf);
        err = "write buffer not properly aligned";
        goto out_inval;
    }

    u64 start_sector = sectors.start;
    u64 nsectors = range_span(sectors);
    if (nsectors == 0) {
        err = "length must be > 0";
        goto out_inval;
    }

    virtio_blk_req req = allocate_virtio_blk_req(st, write ? VIRTIO_BLK_T_OUT : VIRTIO_BLK_T_IN,
                                                 start_sector);
    virtqueue vq = st->command;
    vqmsg m = allocate_vqmsg(vq);
    assert(m != INVALID_ADDRESS);
    vqmsg_push(vq, m, req, VIRTIO_BLK_REQ_HEADER_SIZE, false);
    vqmsg_push(vq, m, buf, nsectors * st->block_size, !write);
    void * statusp = ((void *)req) + VIRTIO_BLK_REQ_HEADER_SIZE;
    vqmsg_push(vq, m, statusp, VIRTIO_BLK_REQ_STATUS_SIZE, true);
    vqfinish c = closure(st->v->general, complete, st, sh, statusp, req);
    vqmsg_commit(vq, m, c);
    return;
  out_inval:
    msg_err("%s", err);               /* yes, bark */
    apply(sh, timm("result", "%s", err));
}

closure_function(1, 3, void, storage_write,
                 storage, st,
                 void *, source, range, blocks, status_handler, s)
{
    storage_rw_internal(bound(st), true, source, blocks, s);
}

closure_function(1, 3, void, storage_read,
                 storage, st,
                 void *, target, range, blocks, status_handler, s)
{
    storage_rw_internal(bound(st), false, target, blocks, s);
}

static void virtio_blk_attach(heap general, storage_attach a, vtdev v)
{
    storage s = allocate(general, sizeof(struct storage));
    s->v = v;

    s->block_size = (v->features & VIRTIO_BLK_F_BLK_SIZE) ?
            vtdev_cfg_read_4(v, VIRTIO_BLK_R_BLOCK_SIZE) : SECTOR_SIZE;
    s->capacity = (vtdev_cfg_read_4(v, VIRTIO_BLK_R_CAPACITY_LOW) |
		   ((u64) vtdev_cfg_read_4(v, VIRTIO_BLK_R_CAPACITY_HIGH) << 32)) * s->block_size;
    virtio_blk_debug("%s: capacity 0x%lx, block size 0x%x\n", __func__, s->capacity, s->block_size);
    virtio_alloc_virtqueue(v, "virtio blk", 0, &s->command);
    // initialization complete
    vtdev_set_status(v, VIRTIO_CONFIG_STATUS_DRIVER_OK);

    block_io in = closure(general, storage_read, s);
    block_io out = closure(general, storage_write, s);
    apply(a, in, out, s->capacity);
}

closure_function(3, 1, boolean, vtpci_blk_probe,
                 heap, general, storage_attach, a, heap, page_allocator,
                 pci_dev, d)
{
    rprintf("%s\n", __func__);
    if (!vtpci_probe(d, VIRTIO_ID_BLOCK))
        return false;

    rprintf("%s: attaching\n", __func__);
    heap general = bound(general);
    vtdev v = (vtdev)attach_vtpci(general, bound(page_allocator), d,
        VIRTIO_BLK_F_BLK_SIZE);
    virtio_blk_attach(general, bound(a), v);
    return true;
}

closure_function(3, 1, void, vtmmio_blk_probe,
                 heap, general, storage_attach, a, heap, page_allocator,
                 vtmmio, d)
{
    rprintf("%s\n", __func__);
    if ((vtmmio_get_u32(d, VTMMIO_OFFSET_DEVID) != VIRTIO_ID_BLOCK) ||
            (d->memsize < VTMMIO_OFFSET_CONFIG +
            sizeof(struct virtio_blk_config)))
        return;
    rprintf("%s: attaching\n", __func__);
    heap general = bound(general);
    if (attach_vtmmio(general, bound(page_allocator), d, VIRTIO_BLK_F_BLK_SIZE))
        virtio_blk_attach(general, bound(a), (vtdev)d);
}

void virtio_register_blk(kernel_heaps kh, storage_attach a)
{
    rprintf("%s\n", __func__);
    heap h = heap_general(kh);
    heap page_allocator = heap_backed(kh);
    register_pci_driver(closure(h, vtpci_blk_probe, h, a, page_allocator));
    vtmmio_probe_devs(stack_closure(vtmmio_blk_probe, h, a, page_allocator));
}
