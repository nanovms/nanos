#include <virtio_internal.h>

static CLOSURE_4_3(attach, void, heap, heap, heap, heap, int, int, int);

// this is not really a struct...fix the general encoding problem
struct virtio_blk_req {
    u32 type;
    u32 reserved;
    u64 sector;
    u64 data; // phys? spec had u8 data[][512]
    u8 status;
};

#define VIRTIO_BLK_T_IN           0
#define VIRTIO_BLK_T_OUT          1
#define VIRTIO_BLK_T_FLUSH        4

#define VIRTIO_BLK_S_OK        0
#define VIRTIO_BLK_S_IOERR     1
#define VIRTIO_BLK_S_UNSUPP    2

typedef struct storage {
    vtpci v;
    struct virtqueue *command;
    u64 capacity;
    u64 block_size;
} *storage;

// close
static storage st;


static CLOSURE_3_1(complete, void, storage, thunk, u8 *, u64);
static void complete(storage s, thunk f, u8 *status, u64 len)
{
    console("storage complete interrupt\n");
    rprintf("a %x %d\n", len, *status);
    apply(f);
    //    s->command->avail->flags &= ~VRING_AVAIL_F_NO_INTERRUPT;
    // used isn't valid?
    //    rprintf("used: %d\n",  s->command->vq_ring.used->idx);    
}

void storage_read(void *target, u64 offset, u64 size, thunk complete)
{
    console("storage read\n");
    rprintf("len: %x %x\n", offset, size);
    // what size is this really?
    int status_size = 1;
    struct virtio_blk_req *r = allocate(st->v->contiguous, sizeof(struct virtio_blk_req) + status_size);
    r->type = VIRTIO_BLK_T_IN;
    r->sector = 0;
    
    void *address[3];
    boolean writables[3];
    bytes lengths[3];
    int index = 0;
    
    address[index] = r;
    writables[index] = false;
    lengths[index] = 16;
    index++;

    address[index] = target;
    writables[index] = true;
    lengths[index] = size;
    index++;
    
    address[index] = (void *)r + 16;
    writables[index] = true;
    lengths[index] = status_size;
    index++;

    virtqueue_enqueue(st->command, address, lengths, writables, index,
                      closure(st->v->general, complete, st,  complete, (u8 *)address[2]));
}

static void attach(heap general, heap page_allocator, heap pages, heap virtual, int bus, int slot, int function)
{
    storage s = allocate(general, sizeof(struct virtio_blk_req));
    s->v = attach_vtpci(general, page_allocator, bus, slot, function);
    u32 len;
    // bar 1 is is a 4k memory region in the pci gap - to what end?

    u32 base = pci_readbar(bus, slot, function, 0, &len);
    base &=~1;
    s->block_size = in32(44 + base);
    s->capacity = (in32(24 + base) | ((u64)in32(28 + base)  << 32)) * s->block_size;
    pci_set_bus_master(bus, slot, function);
    vtpci_alloc_virtqueue(s->v, 0, &s->command);
    st = s;
}

void init_virtio_storage(heap h, heap page_allocator, heap pages, heap virtual)
{
    register_pci_driver(VIRTIO_PCI_VENDORID, VIRTIO_PCI_DEVICEID_STORAGE, closure(h, attach, h, page_allocator, pages, virtual));
}
