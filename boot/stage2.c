#include <runtime.h>
#include <tfs.h>
#include <kvm_platform.h>

extern void run64(u32 entry);

/* We're placing the working heap base at the beginning of extended
   memory. Use of this heap is tossed out in the move to stage3, thus
   no mapping set up for it.

   XXX grub support: Figure out how to probe areas used by grub modules, etc.
   XXX can check e820 regions
*/
#define WORKING_BASE 0x100000
#define WORKING_LEN (4*MB)  /* arbitrary, must be enough for any fs meta */
static u64 working = WORKING_BASE;

#define STACKLEN (8 * PAGESIZE)
static struct heap workings;
static struct kernel_heaps kh;
static u32 stack;

// xxx - should have a general wrapper/analysis thingly
static u64 stage2_allocator(heap h, bytes b)
{
    // tag requires 4 byte aligned addresses
    u64 result = working;
    working += pad(b, 4);
    if (working > (WORKING_BASE + WORKING_LEN))
        halt("stage2 working heap out of memory\n");
    return result;
}

static CLOSURE_1_4(stage2_read_disk, void, u64, void *, u64, u64, status_handler);
static void stage2_read_disk(u64 base, void *dest, u64 length, u64 offset, status_handler completion)
{
    read_sectors(dest, base+offset, length);
    apply(completion, STATUS_OK);
}

static CLOSURE_0_4(stage2_empty_write, void, void *, u64, u64, status_handler);
static void stage2_empty_write(void * src, u64 length, u64 offset, status_handler completion)
{
}

extern void init_extra_prints();

CLOSURE_0_1(fail, void, status);
void fail(status s)
{
    halt("filesystem_read_entire failed: %v\n", s);
}

static CLOSURE_0_1(kernel_read_complete, void, buffer);
static void __attribute__((noinline)) kernel_read_complete(buffer kb)
{
    heap physical = heap_physical(&kh);
    heap working = heap_general(&kh);

    // should be the intersection of the empty physical and virtual
    // up to some limit, 2M aligned
    u64 identity_length = 0x300000;
    u64 pmem = allocate_u64(physical, identity_length);
    heap pages = region_allocator(working, PAGESIZE, REGION_IDENTITY);
    kh.pages = pages;
    create_region(pmem, identity_length, REGION_IDENTITY);
    void *vmbase = allocate_zero(pages, PAGESIZE);
    mov_to_cr("cr3", vmbase);
    map(pmem, pmem, identity_length, pages);
    // going to some trouble to set this up here, but its barely
    // used in stage3
    stack -= (STACKLEN - 4);	/* XXX b0rk b0rk b0rk */
    map(stack, stack, (u64)STACKLEN, pages);
    map(0, 0, INITIAL_MAP_SIZE, pages);

    // stash away kernel elf image for use in stage3
    create_region(u64_from_pointer(buffer_ref(kb, 0)), pad(buffer_length(kb), PAGESIZE), REGION_KERNIMAGE);

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
    u64 base = allocate_u64(ta->parent, length + 1);
    return base + 1;    
}

heap allocate_tagged_region(kernel_heaps kh, u64 tag)
{
    heap h = heap_general(kh);
    tagged_allocator ta = allocate(h, sizeof(struct tagged_allocator));
    ta->h.alloc = tagged_allocate;
    ta->tag = tag;
    ta->parent = h;
    return (heap)ta;
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


static CLOSURE_4_2 (filesystem_initialized, void, heap, heap, tuple, buffer_handler, filesystem, status);
static void filesystem_initialized(heap h, heap physical, tuple root, buffer_handler complete, filesystem fs, status s)
{
    filesystem_read_entire(fs, lookup(root, sym(kernel)),
                           physical,
                           complete, 
                           closure(h, fail));
}

void newstack()
{
    u32 fsb = filesystem_base();
    tuple root = allocate_tuple();
    heap h = heap_general(&kh);
    heap physical = heap_physical(&kh);
    buffer_handler bh = closure(h, kernel_read_complete);
    create_filesystem(h,
                      SECTOR_SIZE,
                      1024 * MB, /* XXX change to infinity with new rtrie */
                      closure(h, stage2_read_disk, fsb),
                      closure(h, stage2_empty_write),
                      root,
                      closure(h, filesystem_initialized, h, physical, root, bh));
    
    halt("kernel failed to execute\n");
}

// consider passing region area as argument to disperse magic
void centry()
{
    workings.alloc = stage2_allocator;
    workings.dealloc = leak;
    kh.general = &workings;
    init_runtime(&kh);		/* we know only general is used */
    init_extra_prints();
    u32 fsb = filesystem_base();

    u32 cr0, cr4;
    mov_from_cr("cr0", cr0);
    mov_from_cr("cr4", cr4);
    cr0 &= ~(1<<2); // clear EM
    cr0 |= 1<<1; // set MP EM
    cr4 |= 1<<9; // set osfxsr
    cr0 |= 1<<10; // set osxmmexcpt
    mov_to_cr("cr0", cr0);
    mov_to_cr("cr4", cr4);    

    // need to ignore the bios area and the area we're running in
    // could reclaim stage2 before entering stage3
    for_regions (r) {
        // range intersect free memory with bios
        u32 b = region_base(r);        
        if (region_type(r) == REGION_PHYSICAL) {
            if (b == 0) region_base(r) = pad (0x7c00 + fsb, PAGESIZE);
            region_length(r) -= region_base(r) - b;
        }
    }
    
    kh.physical = region_allocator(&workings, PAGESIZE, REGION_PHYSICAL);
    assert(kh.physical);
    
    stack = allocate_u64(kh.physical, STACKLEN) + STACKLEN - 4;
    asm("mov %0, %%esp": :"g"(stack));
    newstack();
}
