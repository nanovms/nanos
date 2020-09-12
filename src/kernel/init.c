#include <kernel.h>
#include <pci.h>
#include <pagecache.h>
#include <storage.h>
#include <tfs.h>
#include <virtio/virtio.h>
#include <page.h> // maps should be in machdep
#include <symtab.h>
#include <drivers/console.h>
#include <drivers/storage.h>

#define INIT_DEBUG
#ifdef INIT_DEBUG
#define init_debug(x, ...) do {rprintf("INIT: " x "\n", ##__VA_ARGS__);} while(0)
#else
#define init_debug(x, ...)
#endif

// XXX move to kernel.h or init.h
extern void init_net(kernel_heaps kh);
extern void init_interrupts(kernel_heaps kh);

static tuple root;
static filesystem root_fs;

//#define MAX_BLOCK_IO_SIZE PAGE_SIZE
#define MAX_BLOCK_IO_SIZE (64 * 1024)

closure_function(3, 3, void, offset_block_io,
                 kernel_heaps, kh, u64, offset, block_io, io,
                 void *, dest, range, blocks, status_handler, sh)
{
    assert((bound(offset) & (SECTOR_SIZE - 1)) == 0);
    u64 ds = bound(offset) >> SECTOR_OFFSET;
    blocks.start += ds;
    blocks.end += ds;

    // split I/O to storage driver to PAGESIZE requests
    merge m = allocate_merge(heap_general(bound(kh)), sh);
    status_handler k = apply_merge(m);
    while (blocks.start < blocks.end) {
        u64 span = MIN(range_span(blocks), MAX_BLOCK_IO_SIZE >> SECTOR_OFFSET);
        apply(bound(io), dest, irange(blocks.start, blocks.start + span), apply_merge(m));

        // next block
        blocks.start += span;
        dest = (char *) dest + (span << SECTOR_OFFSET);
    }
    apply(k, STATUS_OK);
}

/* XXX some header reorg in order */
void init_extra_prints();
thunk create_init(kernel_heaps kh, tuple root, filesystem fs);
filesystem_complete bootfs_handler(kernel_heaps kh);

/* will become list I guess */
static pagecache global_pagecache;

closure_function(4, 2, void, fsstarted,
                 kernel_heaps, kh, u8 *, mbr, block_io, r, block_io, w,
                 filesystem, fs, status, s)
{
    rprintf("%s\n", __func__);
    if (!is_ok(s))
        halt("unable to open filesystem: %v\n", s);

    heap h = heap_general(bound(kh));
    u8 *mbr = bound(mbr);
    tuple root = filesystem_getroot(fs);
    if (mbr) {
        struct partition_entry *bootfs_part;
        if (table_find(root, sym(ingest_kernel_symbols)) &&
                (bootfs_part = partition_get(mbr, PARTITION_BOOTFS))) {
            init_debug("loading boot filesystem");
            create_filesystem(h, SECTOR_SIZE,
                              bootfs_part->nsectors * SECTOR_SIZE,
                              closure(h, offset_block_io,
                                      bound(kh), bootfs_part->lba_start * SECTOR_SIZE, bound(r)),
                              0, global_pagecache, false,
                              bootfs_handler(bound(kh)));
        }
        deallocate(h, mbr, SECTOR_SIZE);
    }
    root_fs = fs;
    enqueue(runqueue, create_init(bound(kh), root, fs));
    closure_finish();
}

#if 0
/* This is very simplistic and uses a fixed drain threshold. This
   should also take all cached data in system into account. For now we
   just pick on the single pagecache... */

#ifdef MM_DEBUG
#define mm_debug(x, ...) do {rprintf("MM:   " x, ##__VA_ARGS__);} while(0)
#else
#define mm_debug(x, ...) do { } while(0)
#endif
void mm_service(heap phys)
{
    if (!global_pagecache)
        return;
    u64 free = heap_total(phys) - heap_allocated(phys);
    mm_debug("%s: total %ld, alloc %ld, free %ld\n", __func__, heap_total(phys), heap_allocated(phys), free);
    if (free < PAGECACHE_DRAIN_CUTOFF) {
        u64 drain_bytes = PAGECACHE_DRAIN_CUTOFF - free;
        u64 drained = pagecache_drain(global_pagecache, drain_bytes);
        if (drained > 0)
            mm_debug("   drained %ld / %ld requested...\n", drained, drain_bytes);
    }
}
#endif

static void rootfs_init(kernel_heaps kh, u8 *mbr, u64 offset,
                        block_io r, block_io w, u64 length)
{
    length -= offset;
    heap h = heap_general(kh);
    // XXX for contig too
    pagecache pc = allocate_pagecache(h, h, (heap)heap_physical(kh), PAGESIZE);
    if (pc == INVALID_ADDRESS)
        halt("unable to create pagecache\n");

    /* figure that later pagecaches will register themselves with backing - glue for now */
    global_pagecache = pc;
    create_filesystem(h,
                      SECTOR_SIZE,
                      length,
                      closure(h, offset_block_io, kh, offset, r),
                      closure(h, offset_block_io, kh, offset, w),
                      pc,
                      false,
                      closure(h, fsstarted, kh, mbr, r, w));
}

closure_function(5, 1, void, mbr_read,
                 kernel_heaps, kh, u8 *, mbr, block_io, r, block_io, w, u64, length,
                 status, s)
{
    if (!is_ok(s))
        halt("unable to read partitions: %v\n", s);
    u8 *mbr = bound(mbr);
    struct partition_entry *rootfs_part = partition_get(mbr, PARTITION_ROOTFS);
    if (!rootfs_part)
        halt("filesystem partition not found\n");
    else
        rootfs_init(bound(kh), mbr, rootfs_part->lba_start * SECTOR_SIZE,
                    bound(r), bound(w), bound(length));
    closure_finish();
}

/* XXX can nuke fs_offset */
closure_function(2, 3, void, attach_storage,
                 kernel_heaps, kh, u64, fs_offset,
                 block_io, r, block_io, w, u64, length)
{
    rprintf("%s\n", __func__);
    heap h = heap_general(bound(kh));
    u64 offset = bound(fs_offset);
    if (0 && offset == 0) {
        /* Read partition table from disk */
        u8 *mbr = allocate(h, SECTOR_SIZE);
        assert(mbr != INVALID_ADDRESS);
        apply(r, mbr, irange(0, SECTOR_SIZE),
              closure(h, mbr_read, bound(kh), mbr, r, w, length));
    } else {
        rootfs_init(bound(kh), 0, offset, r, w, length);
    }
    closure_finish();
}

closure_function(0, 0, timestamp, dummy_clock_now)
{
    return 0;
}

closure_function(0, 1, void, dummy_deadline_timer,
                 timestamp, interval)
{
}

closure_function(0, 0, void, dummy_timer_percpu_init)
{
}

// XXX stub
void init_platform_clock(heap h)
{
    register_platform_clock_now(closure(h, dummy_clock_now), VDSO_CLOCK_PVCLOCK);
    register_platform_clock_timer(closure(h, dummy_deadline_timer), closure(h, dummy_timer_percpu_init));
}

void kernel_runtime_init(kernel_heaps kh)
{
    heap misc = heap_general(kh);

    /* runtime and console init */
    init_debug("in init_service_new_stack");
    init_debug("runtime");
    init_runtime(misc);
    init_sg(misc);
    unmap(0, PAGESIZE);         /* unmap zero page */
//    reclaim_regions();          /* unmap and reclaim stage2 stack */
    init_extra_prints();
#if 0 // XXX
    if (xsave_frame_size() == 0){
        halt("xsave not supported\n");
    }
#endif
    init_pci(kh);
    init_console(kh);
    init_symtab(kh);
//    read_kernel_syms();
    init_debug("pci_discover (for VGA)");
    pci_discover(); // early PCI discover to configure VGA console
    init_kernel_contexts(heap_backed(kh));
    init_interrupts(kh);

    init_debug("init_scheduler");
    init_scheduler(misc);
    init_clock();
    init_platform_clock(misc);

    /* platform detection and early init */
//    init_debug("probing for KVM");

    /* if (!kvm_detect(kh)) { */
    /*     halt("no kvm\n"); */
    /* } */

    /* RNG, stack canaries */
    /* init_debug("RNG"); */
    /* init_hwrand(); */
    /* init_random(); */
    /* __stack_chk_guard_init(); */

    /* networking */
    init_debug("LWIP init");
    init_net(kh);

    init_debug("probe fs, register storage drivers");
    root = allocate_tuple();
 
#if 0
    init_debug("...partition get:");
    struct partition_entry *rootfs_part = partition_get(MBR_ADDRESS,
                                                        PARTITION_ROOTFS);
    init_debug("...");
    u64 fs_offset;
    if (!rootfs_part)
        fs_offset = 0;
    else
        fs_offset = rootfs_part->lba_start * SECTOR_SIZE;
    init_debug("...");
#endif
    storage_attach sa = closure(misc, attach_storage, kh, 0);

    init_virtio_network(kh);

    init_debug("init_storage");
    init_storage(kh, sa, false);

    init_debug("pci_discover (for virtio & ata)");
    pci_discover(); // do PCI discover again for other devices
    init_debug("discover done");

    runloop();
}

