#include <virtio_internal.h>
#include <runtime.h>
#include <tfs.h>

//#define VIRTIO_BLK_DEBUG

// this is not really a struct...fix the general encoding problem
typedef struct virtio_blk_req {
    u32 type;
    u32 reserved;
    u64 sector;
    u64 data; // phys? spec had u8 data[][512]
    u8 status;
} __attribute__((packed)) *virtio_blk_req;

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
    heap h;
    vtpci v;
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

static CLOSURE_4_1(complete, void, storage, status_handler, u8 *, virtio_blk_req, u64);
static void complete(storage s, status_handler f, u8 *result, virtio_blk_req req, u64 len)
{
    status st = 0;
    // 1 is io error, 2 is unsupported operation
    if (*result) st = timm("result", "%d", *result);
    apply(f, st);
    deallocate_virtio_blk_req(s, req);
    //    s->command->avail->flags &= ~VRING_AVAIL_F_NO_INTERRUPT;
    // used isn't valid?
    //    rprintf("used: %d\n",  s->command->vq_ring.used->idx);    
}

static inline void storage_rw_internal(storage st, boolean write, void * buf,
                                       range sectors, status_handler sh)
{
    char * err = 0;
    virtio_blk_debug("virtio_%s: block range %R cap %d\n", write ? "write" : "read", sectors, st->capacity);

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

    void *address[3];
    boolean writables[3];
    bytes lengths[3];
    int index = 0;
    
    address[index] = req;
    writables[index] = false;
    lengths[index] = VIRTIO_BLK_REQ_HEADER_SIZE;
    index++;

    address[index] = buf;
    writables[index] = !write;
    lengths[index] = nsectors * st->block_size;
    index++;

    address[index] = ((void *)req) + VIRTIO_BLK_REQ_HEADER_SIZE;
    writables[index] = true;
    lengths[index] = VIRTIO_BLK_REQ_STATUS_SIZE;
    index++;

    vqfinish c = closure(st->v->general, complete, st, sh, (u8 *)address[2], req);
    status s = virtqueue_enqueue(st->command, address, lengths, writables, index, c);
    if (!is_ok(s))
        halt("storage_rw_internal: storage command virtqueue enqueue failed: %v\n", st);
    return;
  out_inval:
    msg_err("%s", err);               /* yes, bark */
    apply(sh, timm("result", "%s", err));
}

static CLOSURE_1_3(storage_write, void, storage, void *, range, status_handler);
static void storage_write(storage st, void * source, range blocks, status_handler s)
{
    storage_rw_internal(st, true, source, blocks, s);
}

static CLOSURE_1_3(storage_read, void, storage, void *, range, status_handler);
static void storage_read(storage st, void * target, range blocks, status_handler s)
{
    storage_rw_internal(st, false, target, blocks, s);
}

static CLOSURE_4_3(attach, void, heap, storage_attach, heap, heap, int, int, int);
static void attach(heap general, storage_attach a, heap page_allocator, heap pages, int bus, int slot, int function)
{

    storage s = allocate(general, sizeof(struct storage));
    s->v = attach_vtpci(general, page_allocator, bus, slot, function, 0);
    u32 len;
    // bar 1 is is a 4k memory region in the pci gap - to what end?

    u32 base = pci_readbar(bus, slot, function, 0, &len);
    base &=~1;
    s->block_size = in32(44 + base);
    s->capacity = (in32(24 + base) | ((u64)in32(28 + base)  << 32)) * s->block_size;
    pci_set_bus_master(bus, slot, function);
    vtpci_alloc_virtqueue(s->v, 0, &s->command);
    block_read in = closure(general, storage_read, s);
    block_write out = closure(general, storage_write, s);
    apply(a, in, out, s->capacity);
}

void init_virtio_storage(kernel_heaps kh, storage_attach a)
{
    heap h = heap_general(kh);
    register_pci_driver(VIRTIO_PCI_VENDORID, VIRTIO_PCI_DEVICEID_STORAGE,
                        closure(h, attach, h, a, heap_backed(kh), heap_pages(kh)));
}
