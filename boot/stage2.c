#include <runtime.h>
#include <tfs.h>
#include <kvm_platform.h>

extern void run64(u32 entry);

//we think this is above the stack we're currently running on, and
// that it runs right up to the boot block load address at 0x7c00,
// so 27kB
u64 working = 0x1000; 


static u64 stage2_allocator(heap h, bytes b)
{
    // tag requires 4 byte aligned addresses
    u64 result = working;
    working += pad(b, 4);
    return result;
}

static CLOSURE_1_4(stage2_read_disk, void, u64, void *, u64, u64, status_handler);
static void stage2_read_disk(u64 base, void *dest, u64 offset, u64 length, status_handler completion)
{
    u32 k, z;
    read_sectors(dest, base+offset, length);
    apply(completion, STATUS_OK);
}

static CLOSURE_0_3(stage2_empty_write, void, buffer, u64, status_handler);
static void stage2_empty_write(buffer b, u64 offset, status_handler completion)
{
}

CLOSURE_2_1(kernel_read_complete, void, heap, heap, buffer);
void kernel_read_complete(heap physical, heap working, buffer kb)
{
    console("kernel read complete\n");

    // read from the filesystem?
    // move this to the end of memory or the beginning of the pci gap
    // (under the begining of the kernel)
    u64 identity_length = 0x300000;
    u64 pmem = allocate_u64(physical, identity_length);
    
    heap pages = region_allocator(working, PAGESIZE, REGION_IDENTITY);

    create_region(pmem, identity_length, REGION_IDENTITY);
    
    void *vmbase = allocate_zero(pages, PAGESIZE);
    mov_to_cr("cr3", vmbase);
    map(pmem, pmem, identity_length, pages);

    // should drop this in stage3? ... i think we just need
    // service32 and the stack.. this doesn't show up in the e820 regions
    // stack is currently in the first page, so lets leave it mapped
    // and take it out later...ideally move the stack here
    map(0, 0, 0xa000, pages);

    void *k = load_elf(kb, 0, pages, physical);

    if (!k) {
        halt("kernel elf parse failed\n");
    }

    run64(u64_from_pointer(k));
}

typedef struct tagged_allocator {
    struct heap h;
    u8 tag;
    heap parent;
} *tagged_allocator;

static u64 tagged_allocate(heap h, bytes length)
{
    
    tagged_allocator ta = (void *)h;
    u64 base = allocate_u64(ta->parent, length);
    return base | ta->tag;
}

heap allocate_tagged_region(heap h, u64 tag)
{
    tagged_allocator ta = allocate(h, sizeof(struct tagged_allocator));
    ta->h.alloc = tagged_allocate;
    ta->tag = tag;
    ta->parent = h;
    return (heap)ta;
}

void newstack(heap h, heap physical, u32 fsbase)
{
    tuple root = allocate_tuple();    

    filesystem fs = create_filesystem(h,
                                      512,
                                      2*1024*1024, // fix,
                                      closure(h, stage2_read_disk, fsbase),
                                      closure(h, stage2_empty_write),
                                      root);

    rprintf("filesystem read complete %v\n", root);
    rprintf("filesystem read complete %v\n", lookup(root, sym(kernel)));    
    
    filesystem_read_entire(fs, lookup(root, sym(kernel)),
                           physical, 
                           closure(h, kernel_read_complete, physical, h));
    halt("shouldn't arrive\n");
}

u32 filesystem_base()
{
    u32 fsbase = 0;
    for_regions(r) 
        if (region_type(r) == REGION_FILESYSTEM) fsbase = region_base(r);
    if (fsbase == 0) {
        halt("invalid filesystem offset\n");
    }
    return fsbase;
}


struct heap workings;

extern void init_extra_prints();

// consider passing region area as argument to disperse magic
void centry()
{
    workings.alloc = stage2_allocator;
    init_runtime(&workings);
    void *x = allocate(&workings, 10);
    u32 fsb = filesystem_base();

        
    // need to ignore the bios area and the area we're running in
    // could reclaim stage2 before entering stage3
    for_regions (r) {
        if ((region_type(r) == REGION_PHYSICAL)  && (region_base(r) == 0)) {
            region_base(r) = 0x7c00 + fsb;
        }
    }
    
    heap physical = region_allocator(&workings, PAGESIZE, REGION_PHYSICAL);
    
    // this can be trashed
    u32 ss = 8192;
    u32 s = allocate_u64(physical, ss);
    s += ss - 4;
    asm("mov %0, %%esp": :"g"(s));
    rprintf ("stack: %p\n", s);
    init_extra_prints(); //
    
    newstack(&workings, physical, fsb);
}
