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

closure_function(2, 3, void, attach_storage,
                 tuple, root, u64, fs_offset,
                 block_io, r, block_io, w, u64, length)
{
    /* heap h = heap_general(&heaps); */
    /* tuple root = bound(root); */
    /* u64 offset = bound(fs_offset); */
    /* if (offset == 0) { */
    /*     /\* Read partition table from disk *\/ */
    /*     u8 *mbr = allocate(h, SECTOR_SIZE); */
    /*     assert(mbr != INVALID_ADDRESS); */
    /*     apply(r, mbr, irange(0, SECTOR_SIZE), */
    /*           closure(h, mbr_read, h, mbr, root, r, w, length)); */
    /* } else */
    /*     rootfs_init(h, 0, root, offset, r, w, length); */
    rprintf("%s reached\n", __func__);
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
    init_debug("mingus dingus\n");
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
    init_debug("...partition get:");
    struct partition_entry *rootfs_part = 0;
        //= partition_get(MBR_ADDRESS,
    //    PARTITION_ROOTFS);
    init_debug("...");
    u64 fs_offset;
    if (!rootfs_part)
        fs_offset = 0;
    else
        fs_offset = rootfs_part->lba_start * SECTOR_SIZE;
    init_debug("...");
    storage_attach sa = closure(misc, attach_storage, root, fs_offset);

    init_virtio_network(kh);

    init_debug("init_storage");
    init_storage(kh, sa, false);

    init_debug("pci_discover (for virtio & ata)");
    pci_discover(); // do PCI discover again for other devices
    init_debug("discover done");

    runloop();
}

