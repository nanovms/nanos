#include <runtime.h>
#include <tfs.h>
#include <kvm_platform.h>
#include <pci.h>
#include <virtio.h>

extern void run64(u32 entry);

//we think this is above the stack we're currently running on, and
// that it runs right up to the boot block load address at 0x7c00,
// so 27kB
u64 working = 0x1000;

static CLOSURE_2_3(offset_block_write, void, block_write, u64, buffer, u64, status_handler);
static void offset_block_write(block_write w, u64 start, buffer b, u64 offset, status_handler h)
{
    apply(w, b, start + offset, h);
}

static CLOSURE_2_4(offset_block_read, void, block_read, u64, void *, u64, u64, status_handler);
static void offset_block_read(block_read r, u64 start, void *dest, u64 length, u64 offset, status_handler h)
{
    apply(r, dest, length, start + offset, h);
}



// xxx - should have a general wrapper/analysis thingly
static u64 stage2_allocator(heap h, bytes b)
{
    // tag requires 4 byte aligned addresses
    u64 result = working;
    working += pad(b, 4);
    return result;
}

CLOSURE_0_1(fail, void, status);
void fail(status s)
{
    halt("%v", s);
}


// could be a different stack
CLOSURE_4_1(kernel_read_complete, void, heap, heap, u64, u32, buffer);
void kernel_read_complete(heap physical, heap working, u64 stack, u32 stacklen, buffer kb)
{
    console("kernel complete\n");
    u32 *e = (u32 *)kb->contents;

    // should be the intersection of the empty physical and virtual
    // up to some limit, 2M aligned
    u64 identity_length = 0x300000;
    // could move this up
    u64 pmem = allocate_u64(physical, identity_length);
    heap pages = region_allocator(working, PAGESIZE, REGION_IDENTITY);
    create_region(pmem, identity_length, REGION_IDENTITY);
    void *vmbase = allocate_zero(pages, PAGESIZE);
    mov_to_cr("cr3", vmbase);
    map(pmem, pmem, identity_length, pages);
    // going to some trouble to set this up here, but its barely
    // used in stage3
    stack -= (stacklen - 4);	/* XXX b0rk b0rk b0rk */
    map(stack, stack, (u64)stacklen, pages);

    // should drop this in stage3? ... i think we just need
    // service32 and the stack.. this doesn't show up in the e820 regions
    // stack is currently in the first page, so lets leave it mapped
    // and take it out later...ideally move the stack here
    // could put the stack at the top of the page region?
    map(0, 0, 0xa000, pages);

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


CLOSURE_3_3(attach_storage, void, heap, heap, filesystem_complete, block_read, block_write, u64);
void attach_storage(heap h, heap physical, filesystem_complete fc, block_read r, block_write w, u64 length)
{
    tuple root = allocate_tuple();
    u64 fs_offset = 0;

    // with filesystem...should be hidden as functional handlers on the tuplespace
    create_filesystem(h,
                      512, // from the device please
                      length,
                      closure(h, offset_block_read, r, fs_offset),
                      closure(h, offset_block_write, w, fs_offset),
                      root,
                      fc);
    while(1);
}

void newstack(heap h, heap physical, u64 stack, u32 stacklength)
{
    buffer_handler bh = closure(h, kernel_read_complete, physical, h, stack, stacklength);
    filesystem_complete fc;
    init_pci(h);
    init_virtio_storage(h, h, physical, closure(h, attach_storage, h, physical, fc));
    while(1);
}


struct heap workings;

// consider passing region area as argument to disperse magic
void centry()
{
    workings.alloc = stage2_allocator;
    init_runtime(&workings);
    void *x = allocate(&workings, 10);
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
    
    heap physical = region_allocator(&workings, PAGESIZE, REGION_PHYSICAL);
    
    // this can be trashed
    u32 ss = 8192;
    u32 s = allocate_u64(physical, ss);
    s += ss - 4;
    asm("mov %0, %%esp": :"g"(s));
    // shouldn't really pass at all across this interface,
    // values on the stack are trash
    newstack(&workings, physical, s, ss);
}
