#include <sruntime.h>
#include <pci.h>
#include <virtio.h>

// move this
typedef struct virtual_heap {
    heap physical;
    heap pages;
    u64 offset;
    u64 length;
} *virtual_heap;


u64 allocate_virtual(heap h, bytes size)
{
    virtual_heap v = (void *)h;
    int len = pad(size, v->physical->pagesize);
    u64 phy = allocate_u64(v->physical, len);
    map(v->offset, phy, size, v->pages);
    u64 result = v->offset;
    v->offset += len;
    v->length -= len;
    return result;
}


heap virtual_allocator(heap physical, heap metadata, heap pages, u64 start_address, u64 length)
{
    // construct a virtual map from this and the region data
    virtual_heap v = allocate(metadata, sizeof(struct virtual_heap));
    v->physical = physical;
    v->pages = pages;
    v->length = length;
    v->offset = start_address;
    return (heap)v;
}

extern void startup();
extern void start_interrupts();

extern void *_fs_start;
extern void *_fs_end;

static u8 bootstrap_region[1024];
static u64 bootstrap_base = (unsigned long long)bootstrap_region;
static u64 bootstrap_alloc(heap h, bytes length)
{
    // check limit
    u64 result = bootstrap_base;
    if (result >=  (u64_from_pointer(bootstrap_region) + sizeof(bootstrap_region)))
        return INVALID_PHYSICAL;
    bootstrap_base += length;
    return result;
}

typedef struct backed {
    struct heap h;
    heap physical;
    heap virtual;
    heap pages;
} *backed;
    

static u64 physically_backed_alloc(heap h, bytes length)
{
    backed b = (backed)h;
    u64 p = allocate_u64(b->physical, length);
    if (p != INVALID_PHYSICAL) {
        u64 v = allocate_u64(b->virtual, length);
        if (v != INVALID_PHYSICAL) {
            // map should return allocation status
            map(v, p, length, b->pages);
            return v;
        }
    }
    return INVALID_PHYSICAL; 
}

static heap physically_backed(heap meta, heap virtual, heap physical, heap pages)
{
    backed b = allocate(meta, sizeof(struct backed));
    b->h.alloc = physically_backed_alloc;
    // freelist
    b->h.dealloc = null_dealloc;
    b->physical = physical;
    b->virtual = virtual;
    b->pages = pages;
    return (heap)b;
}


// init linker set
void init_service(u64 passed_base)
{
    struct heap bootstrap;
    
    bootstrap.alloc = bootstrap_alloc;
    bootstrap.dealloc = null_dealloc;
    heap pages = region_allocator(&bootstrap, PAGESIZE, REGION_IDENTITY);
    heap physical = region_allocator(&bootstrap, PAGESIZE, REGION_PHYSICAL);    
    //node filesystem = {&_fs_start,  0};
    node filesystem;

    heap virtual = create_id_heap(&bootstrap, HUGE_PAGESIZE, 0, HUGE_PAGESIZE);
    heap backed = physically_backed(&bootstrap, virtual, physical, pages);
    
    // on demand stack allocation
    u64 stack_size = 4*PAGESIZE;
    u64 stack_location = allocate_u64(backed, stack_size);
    stack_location += stack_size -8;
    asm ("mov %0, %%rsp": :"m"(stack_location));
    
    init_clock(backed);
    heap misc = allocate_rolling_heap(backed);
    start_interrupts(pages, misc, physical);
    init_pci(misc);
    // can pass contiguous page allocator, I think this is assuming identity
    init_virtio_storage(misc, physical, pages);
    init_virtio_network(misc, physical, pages);        
    pci_discover(&bootstrap, filesystem);
    startup(pages, backed, physical, filesystem);
}
