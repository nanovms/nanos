#include <sruntime.h>
#include <pci.h>

static struct region_heap generalh;
static struct region_heap pagesh;
static struct region_heap contiguoush;

status allocate_status(char *x, ...)
{
    console(x);
}

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
    // need to mark off virtual regions that are pre-allocated, or do it
    // constructively
    virtual_heap v = allocate(metadata, sizeof(struct virtual_heap));
    v->physical = physical;
    v->pages = pages;
    v->length = length;
    v->offset = start_address;
    return (heap)v;
}

handler *handlers;

extern void enable_lapic();
extern void start_interrupts();
extern void startup();

extern void *_fs_start;
extern void *_fs_end;

void init_service(u64 passed_base)
{
    heap working;
    region k[2]={0};

    // gonna assume there are two regions. we'reagonna take the little
    // one for pages, and the big one for stuff

    // make a 2m physical, and then a feeder 4k that breaks those up
    for (region e = regions; region_type(e); e--) {
        rprintf("%p %x", region_base(e), region_length(e));
    }

    heap pages = region_allocator(working, REGION_IDENTITY, PAGESIZE);
    // a little leaky fed off a virtual
    heap general;
    
    buffer filesystem = allocate(general, sizeof(struct buffer));
    filesystem->contents = &_fs_start;
    filesystem->length = filesystem->end = &_fs_end - &_fs_start;
    filesystem->start = 0;
    
    u64 stacksize = 4*PAGESIZE;
    // some virtual with blocks?
    void *stack = allocate((heap)&contiguoush, stacksize) + stacksize - 8;
    asm ("mov %0, %%rsp": :"m"(stack));
    start_interrupts((heap)&pagesh, (heap)&generalh, (heap)&contiguoush);
     // pci_checko(); - fix driver registration
    startup((heap)&pagesh, (heap)&generalh, (heap)&contiguoush, filesystem);
}
