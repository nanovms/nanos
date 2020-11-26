#include <runtime.h>
#include <kernel_machine.h>
#include <kernel_heaps.h>
#include <pagecache.h>
#include <tfs.h>
#include <elf64.h>
#include <page.h>
#include <region.h>
#include <kvm_platform.h>
#include <serial.h>
#include <drivers/ata.h>
#include <storage.h>

//#define STAGE2_DEBUG
//#define DEBUG_STAGE2_ALLOC

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

#define REAL_MODE_STACK_SIZE 0x1000
#define SCRATCH_BASE         0x500
#define BOOT_BASE            0x7c00
#define SCRATCH_LEN          (BOOT_BASE - REAL_MODE_STACK_SIZE)

static struct kernel_heaps kh;
static u64 stack_base;
static u64 initial_pages_base;

static u64 s[2] = { 0xa5a5beefa5a5cafe, 0xbeef55aaface55aa };

timestamp rtc_offset = 0;

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
extern void bios_tty_write(const char *s, bytes count);
extern int bios_read_sectors(void *buffer, int start_sector, int sector_count);

void console_write(const char *s, bytes count)
{
    // BIOS console
    bios_tty_write(s, count);

    // serial console
    for (; count--; s++) {
        serial_putchar(*s);
    }
}

closure_function(1, 3, void, stage2_bios_read,
                 u64, offset,
                 void *, dest, range, blocks, status_handler, completion)
{
    u64 offset = bound(offset);
    assert((offset & (SECTOR_SIZE - 1)) == 0);
    u64 start_sector = (offset >> SECTOR_OFFSET) + blocks.start;
    u64 nsectors = range_span(blocks);

    void *read_buffer = pointer_from_u64(SCRATCH_BASE);
    stage2_debug("%s: %p <- 0x%lx (0x%lx)\n", __func__, dest, start_sector, nsectors);

    while (nsectors > 0) {
        int read_sectors = MIN(nsectors, SCRATCH_LEN >> SECTOR_OFFSET);
        stage2_debug("bios_read_sectors: %p <- 0x%lx (0x%x)\n", dest, start_sector, read_sectors);
        int ret = bios_read_sectors(read_buffer, start_sector, read_sectors);
        if (ret != 0)
            halt("bios_read_sectors: error 0x%x\n", ret);
        runtime_memcpy(dest, read_buffer, read_sectors << SECTOR_OFFSET);
        dest += read_sectors << SECTOR_OFFSET;
        start_sector += read_sectors;
        nsectors -= read_sectors;
    }

    apply(completion, STATUS_OK);
}

#define MAX_BLOCK_IO_SIZE (64 * 1024)

closure_function(2, 3, void, stage2_ata_read,
                 struct ata *, dev, u64, offset,
                 void *, dest, range, blocks, status_handler, completion)
{
    u64 offset = bound(offset);
    stage2_debug("%s: %R (offset 0x%lx)\n", __func__, blocks, offset);
    assert((offset & (SECTOR_SIZE - 1)) == 0);
    u64 ds = offset >> SECTOR_OFFSET;
    blocks.start += ds;
    blocks.end += ds;

    // split I/O to MAX_BLOCK_IO_SIZE requests
    heap h = heap_general(&kh);
    merge m = allocate_merge(h, completion);
    status_handler k = apply_merge(m);
    while (blocks.start < blocks.end) {
        u64 span = MIN(range_span(blocks), MAX_BLOCK_IO_SIZE >> SECTOR_OFFSET);
        ata_io_cmd(bound(dev), ATA_READ48, dest, irange(blocks.start, blocks.start + span), apply_merge(m));

        // next block
        blocks.start += span;
        dest = (char *) dest + (span << SECTOR_OFFSET);
    }
    apply(k, STATUS_OK);
}

static inline u64 stage2_rdtsc(void)
{
    u32 a, d;
    asm volatile("rdtsc" : "=a" (a), "=d" (d));
    return (((u64)a) | (((u64)d) << 32));
}

/* This doesn't need to be accurate. We presently only use kern_sleep
   in stage2 for ATA probe and command timeouts.

   Treating the timestamp as a cycle count, where 1s == 2^32, would be
   accurate if the TSC advances at 2^32 / s. Any rate less than that
   (which is likely, unless we're on >4 GHz CPUs and the TSC advances
   with CPU clock) would mean we are over-shooting the given interval,
   but that's fine for stage2.
*/
void kernel_delay(timestamp delta)
{
    u64 end = stage2_rdtsc() + delta;
    while (stage2_rdtsc() < end)
        kern_pause();
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

closure_function(0, 3, void, stage2_empty_write,
                 void *, src, range, blocks, status_handler, completion)
{
}

extern void init_extra_prints();

closure_function(0, 1, void, fail,
                 status, s)
{
    halt("filesystem_read_entire failed: %v\n", s);
}

static region initial_pages_region;

static void setup_page_tables()
{
    stage2_debug("%s\n", __func__);

    /* initial page tables, carried into stage3 init */
    stage2_debug("initial page tables at [0x%lx,  0x%lx)\n", initial_pages_base,
                 initial_pages_base + INITIAL_PAGES_SIZE);
    initial_pages_region = create_region(initial_pages_base, INITIAL_PAGES_SIZE, REGION_INITIAL_PAGES);
    init_page_tables(region_allocator(heap_general(&kh), PAGESIZE, REGION_INITIAL_PAGES));

    /* initial map, page tables and stack */
    map(0, 0, INITIAL_MAP_SIZE, PAGE_WRITABLE | PAGE_PRESENT);
    map(PAGES_BASE, initial_pages_base, INITIAL_PAGES_SIZE, PAGE_WRITABLE | PAGE_PRESENT);
    map(stack_base, stack_base, (u64)STAGE2_STACK_SIZE, PAGE_WRITABLE);
}

static u64 working_saved_base;

closure_function(0, 4, void, kernel_elf_map,
                 u64, vaddr, u64, paddr, u64, size, u64, flags)
{
    stage2_debug("%s: vaddr 0x%lx, paddr 0x%lx, size 0x%lx, flags 0x%lx\n",
                 __func__, vaddr, paddr, size, flags);

    if (paddr == INVALID_PHYSICAL) {
        /* bss */
        paddr = allocate_u64(heap_backed(&kh), size);
        assert(paddr != INVALID_PHYSICAL);
        zero(pointer_from_u64(paddr), size);
    }
    map(vaddr, paddr, size, flags);
}

closure_function(0, 1, status, kernel_read_complete,
                 buffer, kb)
{
    stage2_debug("%s\n", __func__);

    /* save kernel elf image for use in stage3 (for symbol data) */
    create_region(u64_from_pointer(buffer_ref(kb, 0)), pad(buffer_length(kb), PAGESIZE), REGION_KERNIMAGE);

    /* truncate to 32-bit is ok; we'll move it up in setup64 */
    stage2_debug("%s: load_elf\n", __func__);
    void *k = load_elf(kb, 0, stack_closure(kernel_elf_map));
    if (!k) {
        halt("kernel elf parse failed\n");
    }
    k += KERNEL_BASE - KERNEL_BASE_PHYS;

    /* tell stage3 that pages from the stage2 working heap can be reclaimed */
    assert(working_saved_base);
    create_region(working_saved_base, STAGE2_WORKING_HEAP_SIZE, REGION_PHYSICAL);

    /* reset initial pages length */
    initial_pages_region->length = INITIAL_PAGES_SIZE;
    stage2_debug("%s: run64, start address 0xffffffff%8lx\n", __func__, u64_from_pointer(k));
    run64(u64_from_pointer(k));
    halt("failed to start long mode\n");
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

static heap allocate_tagged_region(heap h, u64 tag)
{
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

closure_function(3, 2, void, filesystem_initialized,
                 heap, h, heap, backed, buffer_handler, complete,
                 filesystem, fs, status, s)
{
    if (!is_ok(s))
        halt("unable to open filesystem: %v\n", s);
    filesystem_read_entire(fs, lookup(filesystem_getroot(fs), sym(kernel)),
                           bound(backed),
                           bound(complete),
                           closure(bound(h), fail));
}

void newstack()
{
    stage2_debug("%s\n", __func__);
    u32 fs_offset = SECTOR_SIZE + fsregion()->length; // MBR + stage2
    heap h = heap_general(&kh);
    buffer_handler bh = closure(h, kernel_read_complete);

    setup_page_tables();

    init_pagecache(h, h, 0, PAGESIZE);
    create_filesystem(h,
                      SECTOR_SIZE,
                      infinity,
                      get_stage2_disk_read(h, fs_offset),
                      closure(h, stage2_empty_write),
                      false,
                      closure(h, filesystem_initialized, h, heap_backed(&kh), bh));
    
    halt("kernel failed to execute\n");
}

void vm_exit(u8 code)
{
    QEMU_HALT(code);
}

void kernel_shutdown(int status)
{
    vm_exit(status);
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
    init_runtime(&working_heap, &working_heap);
    init_tuples(allocate_tagged_region(&working_heap, tag_tuple));
    init_symbols(allocate_tagged_region(&working_heap, tag_symbol), &working_heap);
    init_sg(&working_heap);
    init_extra_prints();
    stage2_debug("%s\n", __func__);

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
           occurs before exception handler setup. NXE is set in stage3. */
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

    kh.backed = region_allocator(&working_heap, PAGESIZE, REGION_PHYSICAL);
    assert(kh.backed != INVALID_ADDRESS);

    /* allocate identity region for page tables */
    initial_pages_base = allocate_u64(kh.backed, INITIAL_PAGES_SIZE);
    assert(initial_pages_base != INVALID_PHYSICAL);

    /* allocate stage2 (and early stage3) stack */
    stack_base = allocate_u64(kh.backed, STAGE2_STACK_SIZE);
    assert(stack_base != INVALID_PHYSICAL);
    create_region(stack_base, STAGE2_STACK_SIZE, REGION_RECLAIM);

    /* allocate larger space for stage2 working (to accomodate tfs meta, etc.) */
    working_p = allocate_u64(kh.backed, STAGE2_WORKING_HEAP_SIZE);
    assert(working_p != INVALID_PHYSICAL);
    working_saved_base = working_p;
    working_end = working_p + STAGE2_WORKING_HEAP_SIZE;

    u32 stacktop = stack_base + STAGE2_STACK_SIZE - 4;
    asm("mov %0, %%esp": :"g"(stacktop));
    newstack();
}
