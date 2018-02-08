#include <sruntime.h>
#include <pci.h>

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

static u8 bootstrap[256];
static struct heap generalh;
static u64 general_base;
static u64 general_length;

static u64 leaky_alloc(heap h, bytes length)
{
    // check limit
    u64 result = general_base;
    general_base += length;
    return result;
}

static void leaky_dealloc(heap h, u64 x, bytes length)
{
}
    

void init_service(u64 passed_base)
{
    region k[2]={0};
    
    generalh.alloc = leaky_alloc;
    generalh.dealloc = leaky_dealloc;
    general_base = u64_from_pointer(bootstrap);
    general_length = sizeof(bootstrap);
    heap pages = region_allocator(&generalh, PAGESIZE, REGION_IDENTITY);
    heap physical = region_allocator(&generalh, PAGESIZE, REGION_PHYSICAL);    
    node filesystem = {&_fs_start,  0};

    u64 stack_location = 0x200000000;
    u64 stack_size = 4*PAGESIZE;
    map(stack_location, allocate_u64(physical, stack_size), stack_size, pages);    
    stack_location += stack_size -8;
    asm ("mov %0, %%rsp": :"m"(stack_location));

    general_base = 0x30000000;
    general_length = 2*1024*1024;
    map(general_base, allocate_u64(physical, general_length), general_length, pages);        

    for (region e = regions; region_type(e); e--) {
        rprintf("region: %p %p %x %d\n", e, region_base(e), region_length(e), region_type(e));
    }

    start_interrupts(pages, &generalh, physical);
     // pci_checko(); - fix driver registration
    startup(pages, (heap)&generalh, physical, filesystem);
}
