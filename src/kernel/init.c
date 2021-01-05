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
#ifdef __x86_64__
#include <kvm_platform.h>
#include <xen_platform.h>
#include <hyperv_platform.h>
#include <vmware/vmxnet3.h>
#endif

//#define INIT_DEBUG
#ifdef INIT_DEBUG
#define init_debug(x, ...) do {rprintf("INIT: " x "\n", ##__VA_ARGS__);} while(0)
#else
#define init_debug(x, ...)
#endif

// XXX move to kernel.h or init.h
extern void init_net(kernel_heaps kh);
extern void init_interrupts(kernel_heaps kh);

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

closure_function(4, 2, void, fsstarted,
                 kernel_heaps, kh, u8 *, mbr, block_io, r, block_io, w,
                 filesystem, fs, status, s)
{
    init_debug("%s: status %v", __func__, s);
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
                              0, false, bootfs_handler(bound(kh)));
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
    init_debug("%s", __func__);
    heap h = heap_general(kh);
    length -= offset;
    create_filesystem(h,
                      SECTOR_SIZE,
                      length,
                      closure(h, offset_block_io, kh, offset, r),
                      closure(h, offset_block_io, kh, offset, w),
                      false,
                      closure(h, fsstarted, kh, mbr, r, w));
}

closure_function(5, 1, void, mbr_read,
                 kernel_heaps, kh, u8 *, mbr, block_io, r, block_io, w, u64, length,
                 status, s)
{
    init_debug("%s", __func__);
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
    heap h = heap_general(bound(kh));
    u64 offset = bound(fs_offset);
    if (offset == 0) {
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

void kernel_runtime_init(kernel_heaps kh)
{
    heap misc = heap_general(kh);

    /* runtime and console init */
    init_debug("kernel_runtime_init");
    init_runtime(misc);
    init_sg(misc);
    init_pagecache(misc, misc, (heap)heap_physical(kh), PAGESIZE);
    unmap(0, PAGESIZE);         /* unmap zero page */
    reclaim_regions();
    init_extra_prints();
    init_pci(kh);
    init_console(kh);
    init_symtab(kh);
    read_kernel_syms();
    init_debug("pci_discover (for VGA)");
    pci_discover(); // early PCI discover to configure VGA console
    init_kernel_contexts(heap_backed(kh));

    /* interrupts */
    init_debug("init_interrupts");
    init_interrupts(kh);

    init_debug("init_scheduler");
    init_scheduler(misc);
    init_clock(misc);

    /* platform detection and early init */
    init_debug("probing for KVM");

    /* XXX aarch64 */
#ifdef __x86_64__
    if (!kvm_detect(kh)) {
        init_debug("probing for Xen hypervisor");
        if (!xen_detect(kh)) {
            if (!hyperv_detect(kh)) {
                init_debug("no hypervisor detected; assuming qemu full emulation");
                if (!init_hpet(kh)) {
                    halt("HPET initialization failed; no timer source\n");
                }
            } else {
                init_debug("hyper-v hypervisor detected");
            }
        } else {
            init_debug("xen hypervisor detected");
        }
    } else {
        init_debug("KVM detected");
    }
#endif

    /* RNG, stack canaries */
    init_debug("RNG");
    init_random();
    __stack_chk_guard_init();

    /* networking */
    init_debug("LWIP init");
    init_net(kh);

    init_debug("probe fs, register storage drivers");
    init_volumes(misc);

    storage_attach sa;

    /* XXX need to sort out arch / hv relationship... */

#ifdef __aarch64__
    /* XXX fixed offset...need to add partition despite no boot fs */
    sa = closure(misc, attach_storage, kh, 0x800000);
    init_virtio_network(kh);
#else
    sa = closure(misc, attach_storage, kh, 0);

    boolean hyperv_storvsc_attached = false;
    /* Probe for PV devices */
    if (xen_detected()) {
        init_debug("probing for Xen PV network...");
        init_xennet(kh);
        status s = xen_probe_devices();
        if (!is_ok(s))
            rprintf("xen probe failed: %v\n", s);
    } else if (hyperv_detected()) {
        init_debug("probing for Hyper-V PV network...");
        init_vmbus(kh);
        status s = hyperv_probe_devices(sa, &hyperv_storvsc_attached);
        if (!is_ok(s))
            rprintf("Hyper-V probe failed: %v\n", s);
    } else {
        init_debug("probing for virtio PV network...");
        /* qemu virtio */
        init_virtio_network(kh);
        init_vmxnet3_network(kh);
    }
#endif

    init_debug("init_storage");
    init_storage(kh, sa, false);

    init_debug("pci_discover (for virtio & ata)");
    pci_discover(); // do PCI discover again for other devices
    init_debug("discover done");

#ifdef __x86_64__
    /* Switch to stage3 GDT64, enable TSS and free up initial map */
    init_debug("install GDT64 and TSS");
    install_gdt64_and_tss(0);
    unmap(PAGESIZE, INITIAL_MAP_SIZE - PAGESIZE);

#ifdef SMP_ENABLE
    init_debug("starting APs");
    start_cpu(misc, heap_backed(kh), TARGET_EXCLUSIVE_BROADCAST, new_cpu);
    kernel_delay(milliseconds(200));   /* temp, til we check tables to know what we have */
    init_debug("total CPUs %d\n", total_processors);
#endif
#endif

    init_debug("starting runloop");
    runloop();
}

