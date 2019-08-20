#include <runtime.h>
#include <tfs.h>
#include <elf64.h>
#include <page.h>
#include <region.h>
#include <x86_64.h>
#include <serial.h>
#include <drivers/ata.h>

#ifdef STAGE2_DEBUG
# define stage2_debug rprintf
#else
# define stage2_debug(...) do { } while(0)
#endif // STAGE2_DEBUG

extern void run64(u32 entry);

/*
 * low memory map:
 * 0x0000..0x03ff - real mode IDT
 * 0x0400..0x04ff - BDA (BIOS data area)
 * 0x0500..0x6bff - bios_read_sectors() buffer
 * 0x6c00..0x7dff - stage2 real mode stack
 * 0x7c00..0x7dff - MBR (stage1)
 * 0x7e00..0x7fff - unused
 * 0x8000..       - stage2 code
 */

#define EARLY_WORKING_SIZE   KB
#define STACKLEN             (8 * PAGESIZE)

#define REAL_MODE_STACK_SIZE 0x1000
#define SCRATCH_BASE         0x500
#define BOOT_BASE            0x7c00
#define SCRATCH_LEN          (BOOT_BASE - REAL_MODE_STACK_SIZE)

static struct kernel_heaps kh;
static u32 stack_base;
static u32 identity_base;

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

// defined in service32.s
extern void bios_tty_write(char *s, bytes count);
extern void bios_read_sectors(void *buffer, int start_sector, int sector_count);

void console_write(char *s, bytes count)
{
    // BIOS console
    bios_tty_write(s, count);

    // serial console
    for (; count--; s++) {
        serial_putchar(*s);
    }
}

static CLOSURE_1_3(stage2_bios_read, void, u64, void *, range, status_handler);
static void stage2_bios_read(u64 offset, void *dest, range blocks, status_handler completion)
{
    u64 start_sector = (offset >> SECTOR_OFFSET) + blocks.start;
    u64 nsectors = range_span(blocks);

    void *read_buffer = pointer_from_u64(SCRATCH_BASE);
    stage2_debug("%s: %p <- 0x%lx (0x%lx)\n", __func__, dest, start_sector, nsectors);

    while (nsectors > 0) {
        int read_sectors = MIN(nsectors, SCRATCH_LEN >> SECTOR_OFFSET);
        stage2_debug("bios_read_sectors: %p <- 0x%lx (0x%x)\n", dest, start_sector, read_sectors);
        bios_read_sectors(read_buffer, start_sector, read_sectors);
        runtime_memcpy(dest, read_buffer, read_sectors << SECTOR_OFFSET);
        dest += read_sectors << SECTOR_OFFSET;
        start_sector += read_sectors;
        nsectors -= read_sectors;
    }

    apply(completion, STATUS_OK);
}

static CLOSURE_2_3(stage2_ata_read, void, struct ata *, u64, void *, range, status_handler);
static void stage2_ata_read(struct ata *dev, u64 offset, void *dest, range blocks, status_handler completion)
{
    stage2_debug("%s: %R (offset 0x%lx)\n", __func__, blocks, offset);

    u64 sector_offset = (offset >> SECTOR_OFFSET);
    blocks.start += sector_offset;
    blocks.end += sector_offset;

    ata_io_cmd(dev, ATA_READ48, dest, blocks, completion);
}

void kern_sleep(timestamp delta)
{
    // TODO: implement
}

static block_io get_stage2_disk_read(heap general, u64 fs_offset)
{
    assert(pad(fs_offset, SECTOR_SIZE) == fs_offset);

    void *dev = ata_alloc(general);
    if (!ata_probe(dev)) {
        ata_dealloc(dev);
        return closure(general, stage2_bios_read, fs_offset);
    }

    return closure(general, stage2_ata_read, dev, fs_offset);
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

static void setup_page_tables()
{
    stage2_debug("%s\n", __func__);

    /* identity heap alloc */
    stage2_debug("identity heap at [0x%x,  0x%x)\n", identity_base, identity_base + IDENTITY_HEAP_SIZE);
    create_region(identity_base, IDENTITY_HEAP_SIZE, REGION_IDENTITY);
    create_region(identity_base, IDENTITY_HEAP_SIZE, REGION_IDENTITY_RESERVED);
    heap pages = region_allocator(heap_general(&kh), PAGESIZE, REGION_IDENTITY);
    kh.pages = pages;

    /* page table setup */
    void *vmbase = allocate_zero(pages, PAGESIZE);
    mov_to_cr("cr3", vmbase);

    /* initial map, page tables and stack */
    map(0, 0, INITIAL_MAP_SIZE, PAGE_WRITABLE | PAGE_PRESENT, pages);
    map(identity_base, identity_base, IDENTITY_HEAP_SIZE, PAGE_WRITABLE | PAGE_PRESENT, pages);
    map(stack_base, stack_base, (u64)STACKLEN, PAGE_WRITABLE, pages);
}

static u64 working_saved_base;

static CLOSURE_0_1(kernel_read_complete, void, buffer);
static void __attribute__((noinline)) kernel_read_complete(buffer kb)
{
    stage2_debug("%s\n", __func__);

    /* save kernel elf image for use in stage3 (for symbol data) */
    create_region(u64_from_pointer(buffer_ref(kb, 0)), pad(buffer_length(kb), PAGESIZE), REGION_KERNIMAGE);

    void *k = load_elf(kb, 0, heap_pages(&kh), heap_physical(&kh), false);
    if (!k) {
        halt("kernel elf parse failed\n");
    }

    /* tell stage3 that pages from the stage2 working heap can be reclaimed */
    assert(working_saved_base);
    create_region(working_saved_base, STAGE2_WORKING_HEAP_SIZE, REGION_PHYSICAL);

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

static void tagged_deallocate(heap h, u64 a, bytes length)
{
    tagged_allocator ta = (void *)h;
    deallocate_u64(ta->parent, a - 1, length + 1);
}

heap allocate_tagged_region(kernel_heaps kh, u64 tag)
{
    heap h = heap_general(kh);
    tagged_allocator ta = allocate(h, sizeof(struct tagged_allocator));
    ta->h.alloc = tagged_allocate;
    ta->h.dealloc = tagged_deallocate;
    ta->tag = tag;
    ta->parent = h;
    return (heap)ta;
}

region fsregion()
{
    for_regions(r) {
        if (r->type == REGION_FILESYSTEM)
            return r;
    }
    halt("invalid filesystem offset\n");
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
    stage2_debug("%s\n", __func__);
    u32 fs_offset = SECTOR_SIZE + fsregion()->length; // MBR + stage2
    tuple root = allocate_tuple();
    heap h = heap_general(&kh);
    heap physical = heap_physical(&kh);
    buffer_handler bh = closure(h, kernel_read_complete);

    setup_page_tables();

    create_filesystem(h,
                      SECTOR_SIZE,
                      infinity,
                      0,         /* ignored in boot */
                      get_stage2_disk_read(h, fs_offset),
                      closure(h, stage2_empty_write),
                      root,
                      closure(h, filesystem_initialized, h, physical, root, bh));
    
    halt("kernel failed to execute\n");
}

static struct heap working_heap;
static u8 early_working[EARLY_WORKING_SIZE] __attribute__((aligned(8)));
static u64 working_p;
static u64 working_end;

static u64 stage2_allocator(heap h, bytes b)
{
    if (working_p + b > working_end)
        halt("stage2 working heap out of memory\n");
    u64 result = working_p;
    working_p += pad(b, 4);       /* tags require alignment */
#ifdef DEBUG_STAGE2_ALLOC
    console("stage2 alloc ");
    print_u64(result);
    console(", ");
    print_u64(working_p);
    console("\n");
#endif
    return result;
}

void centry()
{
    working_heap.alloc = stage2_allocator;
    working_heap.dealloc = leak;
    working_p = u64_from_pointer(early_working);
    working_end = working_p + EARLY_WORKING_SIZE;
    kh.general = &working_heap;
    init_runtime(&kh); /* we know only general is used */
    init_extra_prints();
    stage2_debug("%s\n", __func__);

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
    // TODO: could reclaim stage2 before entering stage3
    for_regions (r) {
        if (r->type == REGION_PHYSICAL && r->base == 0) {
            region fs = fsregion();
            u64 reserved = pad(fs->base + fs->length, PAGESIZE);
            r->base = reserved;
            r->length -= reserved;
        }
    }

    kh.physical = region_allocator(&working_heap, PAGESIZE, REGION_PHYSICAL);
    assert(kh.physical);

    /* allocate identity region for page tables */
    identity_base = allocate_u64(kh.physical, IDENTITY_HEAP_SIZE);
    assert(identity_base != INVALID_PHYSICAL);

    /* allocate stage2 (and early stage3) stack */
    stack_base = allocate_u64(kh.physical, STACKLEN);
    assert(stack_base != INVALID_PHYSICAL);
    create_region(stack_base, STACKLEN, REGION_RECLAIM);

    /* allocate larger space for stage2 working (to accomodate tfs meta, etc.) */
    working_p = allocate_u64(kh.physical, STAGE2_WORKING_HEAP_SIZE);
    assert(working_p != INVALID_PHYSICAL);
    working_saved_base = working_p;
    working_end = working_p + STAGE2_WORKING_HEAP_SIZE;

    u32 stacktop = stack_base + STACKLEN - 4;
    asm("mov %0, %%esp": :"g"(stacktop));
    newstack();
}
