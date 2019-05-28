#include <runtime.h>
#include <tfs.h>
#include <kvm_platform.h>

extern void run64(u32 entry);

#define BOOT_BASE 0x7c00

/* We're placing the working heap base at the beginning of extended
   memory. Use of this heap is tossed out in the move to stage3, thus
   no mapping set up for it.

   XXX grub support: Figure out how to probe areas used by grub modules, etc.
   XXX can check e820 regions
*/
#define WORKING_BASE 0x100000
#define WORKING_LEN (4*MB)  /* arbitrary, must be enough for any fs meta */
static u64 working = WORKING_BASE;

#define SCRATCH_BASE 0x2000
#define SCRATCH_LEN (BOOT_BASE - SCRATCH_BASE)

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

static u64 s[2] = { 0xa5a5beefa5a5cafe, 0xbeef55aaface55aa };

u64 random_u64()
{
    u64 s0 = s[0];
    u64 s1 = s[1];
    u64 result = s0 + s1;

    s1 ^= s0;
    s[0] = ROL(s0, 55) ^ s1 ^ (s1 << 14); // a, b
    s[1] = ROL(s1, 36); // c
    return result;
}

extern void bios_read_sectors(int offset, int count);

static void read_sectors(char *dest, u64 start_sector, u64 nsectors)
{
    while (nsectors > 0) {
        int read_sectors = MIN(nsectors, SCRATCH_LEN >> SECTOR_OFFSET);
	bios_read_sectors(start_sector, read_sectors);
	runtime_memcpy(dest, pointer_from_u64(SCRATCH_BASE), read_sectors << SECTOR_OFFSET);
	dest += read_sectors << SECTOR_OFFSET;
	start_sector += read_sectors;
	nsectors -= read_sectors;
    }
}

static CLOSURE_1_3(stage2_read_disk, void, u64, void *, range, status_handler);
static void stage2_read_disk(u64 base, void *dest, range blocks, status_handler completion)
{
    assert(pad(base, SECTOR_SIZE) == base);
    read_sectors(dest, (base >> SECTOR_OFFSET) + blocks.start, range_span(blocks));
    apply(completion, STATUS_OK);
}

static CLOSURE_0_3(stage2_empty_write, void, void *, range, status_handler);
static void stage2_empty_write(void * src, range blocks, status_handler completion)
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
    map(pmem, pmem, identity_length, PAGE_WRITABLE | PAGE_PRESENT, pages);
    // going to some trouble to set this up here, but its barely
    // used in stage3
    stack -= (STACKLEN - 4);	/* XXX b0rk b0rk b0rk */
    map(stack, stack, (u64)STACKLEN, PAGE_WRITABLE, pages);
    map(0, 0, INITIAL_MAP_SIZE, PAGE_WRITABLE | PAGE_PRESENT, pages);

    // stash away kernel elf image for use in stage3
    create_region(u64_from_pointer(buffer_ref(kb, 0)), pad(buffer_length(kb), PAGESIZE), REGION_KERNIMAGE);

    void *k = load_elf(kb, 0, pages, physical, false);
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
                      0,         /* ignored in boot */
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

    u32 cr0, cr4;
    mov_from_cr("cr0", cr0);
    mov_from_cr("cr4", cr4);
    cr0 &= ~(1<<2); // clear EM
    cr0 |= 1<<1; // set MP EM
    cr4 |= 1<<9; // set osfxsr
    cr4 |= 1<<10; // set osxmmexcpt
//    cr4 |= 1<<20; // set smep - use once we do kernel / user split
    mov_to_cr("cr0", cr0);
    mov_to_cr("cr4", cr4);    

    /* Validate support for no-exec (NX) bits in ptes. */
    u32 v[4];
    cpuid(0x80000001, 0, v);
    if (!(v[3] & (1 << 20))) {     /* EDX.NX */
        /* Note: It seems unlikely that we'd ever run into a platform
           that doesn't support no-exec, but if we did and still
           wanted to run, we could let this pass here and leave a
           cookie for the page table code to mask out any attempt to
           set NX. Otherwise, a page fault for use of reserved bits
           will be thrown, or worse a sudden exit if a map() with NX
           occurs before exception handler setup. NXE is set in
           service32.s:run64. */
        halt("halt: platform doesn't support no-exec page protection\n");
    }

    // need to ignore the area we're running in
    // could reclaim stage2 before entering stage3
    for_regions (r) {
        if (region_type(r) == REGION_PHYSICAL && region_base(r) == 0) {
            u64 reserved = pad(BOOT_BASE + filesystem_base(), PAGESIZE);
            region_base(r) = reserved;
            region_length(r) -= reserved;
        }
    }
    
    kh.physical = region_allocator(&workings, PAGESIZE, REGION_PHYSICAL);
    assert(kh.physical);
    
    stack = allocate_u64(kh.physical, STACKLEN) + STACKLEN - 4;
    asm("mov %0, %%esp": :"g"(stack));
    newstack();
}
