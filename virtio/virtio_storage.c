#include <virtio_internal.h>

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
    heap h;
    vtpci v;
    struct virtqueue *command;
    u64 capacity;
    u64 block_size;
} *storage;

static CLOSURE_3_1(complete, void, storage, status_handler, u8 *, u64);
static void complete(storage s, status_handler f, u8 *result, u64 len)
{
    status st = 0;
    // 1 is io error, 2 is unsupported operation
    if (*result) st = timm("result", "%d", *result);
    apply(f, st);
    //    s->command->avail->flags &= ~VRING_AVAIL_F_NO_INTERRUPT;
    // used isn't valid?
    //    rprintf("used: %d\n",  s->command->vq_ring.used->idx);    
}

static CLOSURE_1_3(storage_write, void, storage, buffer, u64, status_handler);
static void storage_write(storage st, buffer b, u64 offset, status_handler s)
{
}

static CLOSURE_1_4(storage_read, void, storage, void *, u64, u64, status_handler);
static void storage_read(storage st, void *target, u64 length, u64 offset, status_handler c)
{
    u64 sector_size = 512; // get from fs, fix config block read
    int status_size = 1;
    int header_size = 16;
    void *r = allocate(st->v->contiguous, header_size + status_size);
    *(u32 *)r = VIRTIO_BLK_T_IN;
    *(u32 *)(r + 4) = 0;
    *(u64 *)(r + 8) = offset/sector_size;
    
    void *address[3];
    boolean writables[3];
    bytes lengths[3];
    int index = 0;
    
    address[index] = r;
    writables[index] = false;
    lengths[index] = header_size;
    index++;

    address[index] = target;
    writables[index] = true;
    lengths[index] = pad(length, sector_size);
    index++;
    
    address[index] = r + header_size;
    writables[index] = true;
    lengths[index] = status_size;
    index++;
    vqfinish s = closure(st->v->general, complete, st, c, (u8 *)address[2]);
    virtqueue_enqueue(st->command, address, lengths, writables, index, s);
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
