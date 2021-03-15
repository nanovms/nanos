#include <kernel.h>
#include <pci.h>
#include <pagecache.h>
#include <storage.h>
#include <tfs.h>
#include <log.h>
#include <net.h>
#include <symtab.h>
#include <drivers/console.h>

//#define INIT_DEBUG
#ifdef INIT_DEBUG
#define init_debug(x, ...) do {rprintf("INIT: " x "\n", ##__VA_ARGS__);} while(0)
#else
#define init_debug(x, ...)
#endif

filesystem root_fs;
static kernel_heaps init_heaps;

//#define MAX_BLOCK_IO_SIZE PAGE_SIZE
#define MAX_BLOCK_IO_SIZE (64 * 1024)

static struct kernel_heaps heaps;

closure_function(2, 3, void, offset_block_io,
                 u64, offset, block_io, io,
                 void *, dest, range, blocks, status_handler, sh)
{
    assert((bound(offset) & (SECTOR_SIZE - 1)) == 0);
    u64 ds = bound(offset) >> SECTOR_OFFSET;
    blocks.start += ds;
    blocks.end += ds;

    // split I/O to storage driver to PAGESIZE requests
    merge m = allocate_merge(heap_locked(init_heaps), sh);
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

/* stage3 */
extern thunk create_init(kernel_heaps kh, tuple root, filesystem fs);
extern filesystem_complete bootfs_handler(kernel_heaps kh, tuple root,
                                          boolean klibs_in_bootfs,
                                          boolean ingest_kernel_syms);

closure_function(3, 2, void, fsstarted,
                 u8 *, mbr, block_io, r, block_io, w,
                 filesystem, fs, status, s)
{
    init_debug("%s\n", __func__);
    heap h = heap_locked(init_heaps);
    if (!is_ok(s)) {
        buffer b = allocate_buffer(h, 128);
        bprintf(b, "unable to open filesystem: ");
        print_tuple(b, s);
        buffer_print(b);
        halt("\n");
    }

    if (root_fs)
        halt("multiple root filesystems found\n");

    u8 *mbr = bound(mbr);
    tuple root = filesystem_getroot(fs);
    root_fs = fs;
    storage_set_root_fs(fs);
    tuple mounts = table_find(root, sym(mounts));
    if (mounts && (tagof(mounts) == tag_tuple))
        storage_set_mountpoints(mounts);
    value klibs = table_find(root, sym(klibs));
    boolean klibs_in_bootfs = klibs && tagof(klibs) != tag_tuple &&
        buffer_compare_with_cstring(klibs, "bootfs");

    if (mbr) {
        boolean ingest_kernel_syms = table_find(root, sym(ingest_kernel_symbols)) != 0;
        struct partition_entry *bootfs_part;
        if ((ingest_kernel_syms || klibs_in_bootfs) &&
            (bootfs_part = partition_get(mbr, PARTITION_BOOTFS))) {
            create_filesystem(h, SECTOR_SIZE,
                              bootfs_part->nsectors * SECTOR_SIZE,
                              closure(h, offset_block_io,
                                      bootfs_part->lba_start * SECTOR_SIZE, bound(r)),
                              0, false,
                              bootfs_handler(init_heaps, root, klibs_in_bootfs,
                                             ingest_kernel_syms));
        }
        deallocate(h, mbr, SECTOR_SIZE);
    }

    if (klibs && !klibs_in_bootfs)
        init_klib(init_heaps, fs, root, root);

    enqueue(runqueue, create_init(init_heaps, root, fs));
    closure_finish();
    symbol booted = sym(booted);
    if (!table_find(root, booted))
        filesystem_write_eav(fs, root, booted, null_value);
    config_console(root);
}

/* This is very simplistic and uses a fixed drain threshold. This
   should also take all cached data in system into account. For now we
   just pick on the single pagecache... */

#ifdef MM_DEBUG
#define mm_debug(x, ...) do {rprintf("MM:   " x, ##__VA_ARGS__);} while(0)
#else
#define mm_debug(x, ...) do { } while(0)
#endif

void mm_service(void)
{
    heap phys = (heap)heap_physical(init_heaps);
    u64 free = heap_total(phys) - heap_allocated(phys);
    mm_debug("%s: total %ld, alloc %ld, free %ld\n", __func__,
             heap_total(phys), heap_allocated(phys), free);
    if (free < PAGECACHE_DRAIN_CUTOFF) {
        u64 drain_bytes = PAGECACHE_DRAIN_CUTOFF - free;
        u64 drained = pagecache_drain(drain_bytes);
        if (drained > 0)
            mm_debug("   drained %ld / %ld requested...\n", drained, drain_bytes);
    }
}

kernel_heaps get_kernel_heaps(void)
{
    return &heaps;
}
KLIB_EXPORT(get_kernel_heaps);

tuple get_root_tuple(void)
{
    return filesystem_getroot(root_fs);
}
KLIB_EXPORT(get_root_tuple);

tuple get_environment(void)
{
    return table_find(filesystem_getroot(root_fs), sym(environment));
}
KLIB_EXPORT(get_environment);

boolean first_boot(void)
{
    return !table_find(filesystem_getroot(root_fs), sym(booted));
}
KLIB_EXPORT(first_boot);

static void rootfs_init(u8 *mbr, u64 offset,
                        block_io r, block_io w, u64 length)
{
    init_debug("%s", __func__);
    length -= offset;
    heap h = heap_locked(init_heaps);
    create_filesystem(h,
                      SECTOR_SIZE,
                      length,
                      closure(h, offset_block_io, offset, r),
                      closure(h, offset_block_io, offset, w),
                      false,
                      closure(h, fsstarted, mbr, r, w));
}

closure_function(4, 1, void, mbr_read,
                 u8 *, mbr, block_io, r, block_io, w, u64, length,
                 status, s)
{
    init_debug("%s", __func__);
    if (!is_ok(s)) {
        msg_err("unable to read partitions: %v\n", s);
        goto out;
    }
    u8 *mbr = bound(mbr);
    struct partition_entry *rootfs_part = partition_get(mbr, PARTITION_ROOTFS);
    if (!rootfs_part) {
        u8 uuid[UUID_LEN];
        char label[VOLUME_LABEL_MAX_LEN];
        if (filesystem_probe(mbr, uuid, label))
            volume_add(uuid, label, bound(r), bound(w), bound(length));
        else
            init_debug("unformatted storage device, ignoring");
        deallocate(heap_locked(init_heaps), mbr, SECTOR_SIZE);
    } else {
        /* The on-disk kernel log dump section is immediately before the boot FS partition. */
        struct partition_entry *bootfs_part = partition_get(mbr, PARTITION_BOOTFS);
        klog_disk_setup(bootfs_part->lba_start * SECTOR_SIZE - KLOG_DUMP_SIZE, bound(r), bound(w));

        rootfs_init(mbr, rootfs_part->lba_start * SECTOR_SIZE,
                    bound(r), bound(w), bound(length));
    }
  out:
    closure_finish();
}

closure_function(0, 3, void, attach_storage,
                 block_io, r, block_io, w, u64, length)
{
    heap h = heap_locked(init_heaps);
    /* Read partition table from disk */
    u8 *mbr = allocate(h, SECTOR_SIZE);
    if (mbr == INVALID_ADDRESS) {
        msg_err("cannot allocate memory for MBR sector\n");
        return;
    }
    status_handler sh = closure(h, mbr_read, mbr, r, w, length);
    if (sh == INVALID_ADDRESS) {
        msg_err("cannot allocate MBR read closure\n");
        deallocate(h, mbr, SECTOR_SIZE);
        return;
    }
    apply(r, mbr, irange(0, 1), sh);
}

void kernel_runtime_init(kernel_heaps kh)
{
    heap misc = heap_general(kh);
    heap backed = heap_backed(kh);
    heap locked = heap_locked(kh);
    init_heaps = kh;

    /* runtime and console init */
    init_debug("kernel_runtime_init");
    init_runtime(misc, locked);
    init_sg(locked);
    init_pagecache(locked, locked, (heap)heap_physical(kh), PAGESIZE);
    unmap(0, PAGESIZE);         /* unmap zero page */
    init_extra_prints();
    init_pci(kh);
    init_console(kh);
    init_symtab(kh);
    read_kernel_syms();
    reclaim_regions();          /* for pc: no accessing regions after this point */
    shutdown_completions = allocate_vector(misc, SHUTDOWN_COMPLETIONS_SIZE);
    init_debug("pci_discover (for VGA)");
    pci_discover(); // early PCI discover to configure VGA console
    init_debug("clock");
    init_clock();
    init_debug("init_kernel_contexts");
    init_kernel_contexts(backed);

    /* interrupts */
    init_debug("init_interrupts");
    init_interrupts(kh);

    init_debug("init_scheduler");
    init_scheduler(locked);

    /* platform detection and early init */
    init_debug("probing for hypervisor platform");
    detect_hypervisor(kh);

    /* RNG, stack canaries */
    init_debug("RNG");
    init_random();
    __stack_chk_guard_init();

    /* networking */
    init_debug("LWIP init");
    init_net(kh);

    init_debug("probe fs, register storage drivers");
    init_volumes(locked);

    storage_attach sa = closure(misc, attach_storage);

    init_debug("detect_devices");
    detect_devices(kh, sa);

    init_debug("pci_discover (for other devices)");
    pci_discover();
    init_debug("discover done");

    init_debug("start_secondary_cores");
    start_secondary_cores(kh);

    init_debug("starting runloop");
    runloop();
}

vector shutdown_completions;

closure_function(1, 1, void, sync_complete,
                 u8, code,
                 status, s)
{
    vm_exit(bound(code));
    closure_finish();
}

closure_function(0, 2, void, storage_shutdown, int, status, merge, m)
{
    if (status != 0)
        klog_save(status, apply_merge(m));
    storage_sync(apply_merge(m));
}


closure_function(3, 0, void, do_shutdown_handler,
                 shutdown_handler, h, int, status, merge, m)
{
    apply(bound(h), bound(status), bound(m));
    closure_finish();
}

closure_function(1, 0, void, do_status_handler,
                 status_handler, sh)
{
    apply(bound(sh), STATUS_OK);
    closure_finish();
}

extern boolean shutting_down;
void __attribute__((noreturn)) kernel_shutdown(int status)
{
    heap locked = heap_locked(init_heaps);
    status_handler completion = closure(locked, sync_complete, status);
    merge m = allocate_merge(locked, completion);
    status_handler sh = apply_merge(m);
    shutdown_handler h;

    shutting_down = true;

    if (root_fs)
        vector_push(shutdown_completions,
                    closure(locked, storage_shutdown));

    if (vector_length(shutdown_completions) > 0) {
        if (this_cpu_has_kernel_lock()) {
            vector_foreach(shutdown_completions, h)
                apply(h, status, m);
            apply(sh, STATUS_OK);
            kern_unlock();
        } else {
            vector_push(shutdown_completions,
                        closure(locked, do_status_handler, sh));
            vector_foreach(shutdown_completions, h)
                enqueue_irqsafe(runqueue,
                                closure(locked, do_shutdown_handler, h, status, m));
            cpuinfo ci = current_cpu();
            if (ci->state == cpu_interrupt) {
                interrupt_exit();
                get_running_frame(ci)[FRAME_FULL] = false;
            }
        }
        runloop();
    }
    apply(sh, STATUS_OK);
    while(1);
}
