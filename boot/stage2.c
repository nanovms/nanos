#include <basic_runtime.h>
#include <x86_64.h>
#include <booto.h>
#include <storage.h>

// fix headers
void *load_elf(void *base, u64 offset, heap pages, heap bss);

static void print_block(void *addr, int length)
{
    for (int i = 0; i< length; i+=8){
        print_u64(*(u64 *)(addr+i));
        console ("\n");
    }
}

extern void run64(u32 entry);

// there are a few of these little allocators
u64 working = 0x1000;

static u64 stage2_allocator(heap h, bytes b)
{
    u64 result = working;
    working += b;
    return working;
}

// xxx - instead of pulling the thread on generic storage support,
// we hardwire in the kernel resolution. revisit - it may be
// better to start populating the node tree here.
boolean lookup_kernel(snode metadata, u32 *offset, u32 *length)
{
    if (!storage_lookup(metadata, "files", offset, length)) return false;
    if (!storage_lookup(metadata, "kernel", offset, length)) return false;
    return true;
}

// pass the memory parameters (end of load, end of mem)
void centry()
{
    console("stage2\n");
    struct heap workings;
    workings.alloc = stage2_allocator;
    heap working = &workings;
    int sector_offset = (STAGE2SIZE>>sector_log) + (STAGE1SIZE>>sector_log);
    
    // move this to the end of memory or the beginning of the pci gap
    // (under the begining of the kernel)
    u64 identity_start = 0x100000;
    u64 identity_length = 0x300000;

    for (region e = regions; region_type(e); e -= 1) {
        if (identity_start == region_base(e)) 
            region_base(e) = identity_start + identity_length;
    }

    create_region(identity_start, identity_length, REGION_IDENTITY);
        
    heap pages = region_allocator(working, PAGESIZE, REGION_IDENTITY);
    heap physical = region_allocator(working, PAGESIZE, REGION_PHYSICAL);
    void *vmbase = allocate_zero(pages, PAGESIZE);
    mov_to_cr("cr3", vmbase);
    map(identity_start, identity_start, identity_length, pages);

    // lose a page, and assume ph is in the first page
    void *header = allocate(working, PAGESIZE);
    read_sectors(header, sector_offset, PAGESIZE);

    // should drop this in stage3? ... i think we just need
    // service32 and the stack.. this doesn't show up in the e820 regions
    // stack is currently in the first page, so lets leave it mapped
    // and take it out later...ideally move the stack here
    map(0, 0, 0xa000, pages);
    create_region(0, 0xa0000, REGION_VIRTUAL);

    // lookup in fileystem
    void *kernel;
    run64(u64_from_pointer(load_elf(kernel, 0, pages, physical)));
}

