#include <runtime.h>
#include <tfs.h>
#include <kvm_platform.h>

extern void run64(u32 entry);

// there are a few of these little allocators
u64 working = 0x1000;

static u64 stage2_allocator(heap h, bytes b)
{
    u64 result = working;
    working += b;
    return working;
}

static CLOSURE_0_4(stage2_read_disk, void, void *, u64, u64, thunk);
static void stage2_read_disk(void *dest, u64 offset, u64 length, thunk completion)
{
    read_sectors(dest, offset, length);
    apply(completion);
}

static CLOSURE_0_4(stage2_empty_write, void, void *, u64, u64, thunk);
static void stage2_empty_write(void *dest, u64 offset, u64 length, thunk completion)
{
}

CLOSURE_3_0(kernel_read_complete, void, buffer, heap, heap);
void kernel_read_complete(buffer kb, heap physical, heap working)
{
    // move this to the end of memory or the beginning of the pci gap
    // (under the begining of the kernel)
    u64 identity_start = 0x100000;
    u64 identity_length = 0x300000;
    
    heap pages = region_allocator(working, PAGESIZE, REGION_IDENTITY);

    create_region(identity_start, identity_length, REGION_IDENTITY);

    // just throw out the bios area up to 1M
    for (region e = regions; region_type(e); e -= 1) {    
        if (region_base(e) < identity_start) region_type(e) =REGION_FREE; 
        if (identity_start == region_base(e)) 
            region_base(e) = identity_start + identity_length;
    }

    void *vmbase = allocate_zero(pages, PAGESIZE);
    mov_to_cr("cr3", vmbase);
    map(identity_start, identity_start, identity_length, pages);

    // should drop this in stage3? ... i think we just need
    // service32 and the stack.. this doesn't show up in the e820 regions
    // stack is currently in the first page, so lets leave it mapped
    // and take it out later...ideally move the stack here
    map(0, 0, 0xa000, pages);

    void *k = load_elf(kb, 0, pages, physical);
    run64(u64_from_pointer(k));
}

// consider passing region area as argument to disperse magic
void centry()
{
    struct heap workings;
    workings.alloc = stage2_allocator;

    console("stage2\n");

    heap physical = region_allocator(&workings, PAGESIZE, REGION_PHYSICAL);
    filesystem fs = create_filesystem(&workings,
                                      512,
                                      2*1024*1024, // fix,
                                      closure(&workings, stage2_read_disk),
                                      closure(&workings, stage2_empty_write));


    fsfile kf = file_lookup(fs, build_vector(&workings, "kernel"));
    if (!kf) {
        halt("unable to find kernel\n");
    }
    u64 len = file_length(kf);
    void *kernel = allocate(physical, len);
    buffer kb = alloca_wrap_buffer(kernel, len);
    fs_read(kf, kernel, 0, len, closure(&workings, kernel_read_complete, kb, physical, &workings));
}
