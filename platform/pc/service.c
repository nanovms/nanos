/* TODO: this file has become a garbage dump ... reorganize */

#include <kernel.h>
#include <pci.h>
#include <pagecache.h>
#include <tfs.h>
#include <pagecache.h>
#include <apic.h>
#include <region.h>
#include <page.h>
#include <storage.h>
#include <symtab.h>
#include <unix.h>
#include <virtio/virtio.h>
#include <vmware/vmxnet3.h>
#include <drivers/acpi.h>
#include <drivers/storage.h>
#include <drivers/console.h>
#include <kvm_platform.h>
#include <xen_platform.h>
#include <hyperv_platform.h>

#define BOOT_PARAM_OFFSET_E820_ENTRIES  0x01E8
#define BOOT_PARAM_OFFSET_BOOT_FLAG     0x01FE
#define BOOT_PARAM_OFFSET_HEADER        0x0202
#define BOOT_PARAM_OFFSET_CMD_LINE_PTR  0x0228
#define BOOT_PARAM_OFFSET_CMDLINE_SIZE  0x0238
#define BOOT_PARAM_OFFSET_E820_TABLE    0x02D0

//#define SMP_DUMP_FRAME_RETURN_COUNT

//#define STAGE3_INIT_DEBUG
//#define MM_DEBUG
#ifdef STAGE3_INIT_DEBUG
#define init_debug(x, ...) do {rprintf("INIT: " x "\n", ##__VA_ARGS__);} while(0)
#else
#define init_debug(x, ...)
#endif

extern void init_net(kernel_heaps kh);
extern void init_interrupts(kernel_heaps kh);

static struct kernel_heaps heaps;
static filesystem root_fs;

static heap allocate_tagged_region(kernel_heaps kh, u64 tag)
{
    heap h = heap_general(kh);
    heap p = (heap)heap_physical(kh);
    assert(tag < U64_FROM_BIT(VA_TAG_WIDTH));
    u64 tag_base = KMEM_BASE | (tag << VA_TAG_OFFSET);
    u64 tag_length = U64_FROM_BIT(VA_TAG_OFFSET);
    heap v = (heap)create_id_heap(h, heap_backed(kh), tag_base, tag_length, p->pagesize, false);
    assert(v != INVALID_ADDRESS);
    heap backed = physically_backed(h, v, p, p->pagesize);
    if (backed == INVALID_ADDRESS)
        return backed;

    /* reserve area in virtual_huge */
    assert(id_heap_set_area(heap_virtual_huge(kh), tag_base, tag_length, true, true));

    /* tagged mcache range of 32 to 1M bytes (131072 table buckets) */
    build_assert(TABLE_MAX_BUCKETS * sizeof(void *) <= 1 << 20);
    return allocate_mcache(h, backed, 5, 20, PAGESIZE_2M);
}

#define BOOTSTRAP_REGION_SIZE_KB	2048
static u8 bootstrap_region[BOOTSTRAP_REGION_SIZE_KB << 10];
static u64 bootstrap_base = (unsigned long long)bootstrap_region;
static u64 bootstrap_alloc(heap h, bytes length)
{
    u64 result = bootstrap_base;
    if ((result + length) >=  (u64_from_pointer(bootstrap_region) + sizeof(bootstrap_region))) {
	console("*** bootstrap heap overflow! ***\n");
        return INVALID_PHYSICAL;
    }
    bootstrap_base += length;
    return result;
}

//#define MAX_BLOCK_IO_SIZE PAGE_SIZE
#define MAX_BLOCK_IO_SIZE (64 * 1024)

closure_function(2, 3, void, offset_block_io,
                 u64, offset, block_io, io,
                 void *, dest, range, blocks, status_handler, sh)
{
    assert((bound(offset) & (SECTOR_SIZE - 1)) == 0);
    u64 ds = bound(offset) >> SECTOR_OFFSET;
    blocks.start += ds;
    blocks.end += ds;

    // split I/O to storage driver to PAGESIZE requests
    heap h = heap_general(&heaps);
    merge m = allocate_merge(h, sh);
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
filesystem_complete bootfs_handler(kernel_heaps kh, tuple root,
                                   boolean klibs_in_bootfs,
                                   boolean ingest_kernel_syms);

closure_function(4, 2, void, fsstarted,
                 heap, h, u8 *, mbr, block_io, r, block_io, w,
                 filesystem, fs, status, s)
{
    if (!is_ok(s))
        halt("unable to open filesystem: %v\n", s);
    if (root_fs)
        halt("multiple root filesystems found\n");

    heap h = bound(h);
    u8 *mbr = bound(mbr);
    tuple root = filesystem_getroot(fs);
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
                              bootfs_handler(&heaps, root, klibs_in_bootfs,
                                             ingest_kernel_syms));
        }
        deallocate(h, mbr, SECTOR_SIZE);
    }

    if (klibs && !klibs_in_bootfs)
        init_klib(&heaps, fs, root, root);

    root_fs = fs;
    enqueue(runqueue, create_init(&heaps, root, fs));
    closure_finish();
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
    heap p = (heap)heap_physical(&heaps);
    u64 free = heap_total(p) - heap_allocated(p);
    mm_debug("%s: total %ld, alloc %ld, free %ld\n", __func__, heap_total(p), heap_allocated(p), free);
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

tuple get_environment(void)
{
    return table_find(filesystem_getroot(root_fs), sym(environment));
}
KLIB_EXPORT(get_environment);

static void rootfs_init(heap h, u8 *mbr, u64 offset,
                        block_io r, block_io w, u64 length)
{
    length -= offset;
    create_filesystem(h,
                      SECTOR_SIZE,
                      length,
                      closure(h, offset_block_io, offset, r),
                      closure(h, offset_block_io, offset, w),
                      false,
                      closure(h, fsstarted, h, mbr, r, w));
}

closure_function(5, 1, void, mbr_read,
                 heap, h, u8 *, mbr, block_io, r, block_io, w, u64, length,
                 status, s)
{
    if (!is_ok(s)) {
        msg_err("unable to read partitions: %v\n", s);
        goto out;
    }
    heap h = bound(h);
    u8 *mbr = bound(mbr);
    struct partition_entry *rootfs_part = partition_get(mbr, PARTITION_ROOTFS);
    if (!rootfs_part) {
        u8 uuid[UUID_LEN];
        char label[VOLUME_LABEL_MAX_LEN];
        if (filesystem_probe(mbr, uuid, label))
            volume_add(uuid, label, bound(r), bound(w), bound(length));
        else
            init_debug("unformatted storage device, ignoring");
        deallocate(h, mbr, SECTOR_SIZE);
    }
    else
        rootfs_init(h, mbr, rootfs_part->lba_start * SECTOR_SIZE,
            bound(r), bound(w), bound(length));
  out:
    closure_finish();
}

closure_function(0, 3, void, attach_storage,
                 block_io, r, block_io, w, u64, length)
{
    heap h = heap_locked(&heaps); /* to create fs under locked heap */

    /* Look for partition table */
    u8 *mbr = allocate(h, SECTOR_SIZE);
    if (mbr == INVALID_ADDRESS) {
        msg_err("cannot allocate memory for MBR sector\n");
        return;
    }
    status_handler sh = closure(h, mbr_read, h, mbr, r, w, length);
    if (sh == INVALID_ADDRESS) {
        msg_err("cannot allocate MBR read closure\n");
        deallocate(h, mbr, SECTOR_SIZE);
        return;
    }
    apply(r, mbr, irange(0, 1), sh);
}

static void read_kernel_syms()
{
    u64 kern_base = INVALID_PHYSICAL;
    u64 kern_length;

    /* add kernel symbols */
    for_regions(e) {
	if (e->type == REGION_KERNIMAGE) {
	    kern_base = e->base;
	    kern_length = e->length;

	    u64 v = allocate_u64((heap)heap_virtual_huge(&heaps), kern_length);
	    map(v, kern_base, kern_length, 0);
#ifdef ELF_SYMTAB_DEBUG
	    rprintf("kernel ELF image at 0x%lx, length %ld, mapped at 0x%lx\n",
		    kern_base, kern_length, v);
#endif
	    add_elf_syms(alloca_wrap_buffer(v, kern_length), 0);
            unmap(v, kern_length);
	    break;
	}
    }
}

static boolean have_rdseed = false;
static boolean have_rdrand = false;

static boolean hw_seed(u64 * seed, boolean rdseed)
{
    u64 c;
    int attempts = 128; /* arbitrary */
    do {
        if (rdseed)
            asm volatile("rdseed %0; sbb %1, %1" : "=r" (*seed), "=r" (c));
        else
            asm volatile("rdrand %0; sbb %1, %1" : "=r" (*seed), "=r" (c));
        if (c)
            return true;
    } while (attempts-- > 0);

    return false;
}

u64 random_seed(void)
{
    u64 seed = 0;
    if (have_rdseed && hw_seed(&seed, true))
        return seed;
    if (have_rdrand && hw_seed(&seed, false))
        return seed;
    return (u64)now(CLOCK_ID_MONOTONIC);
}

static void init_hwrand(void)
{
    u32 v[4];
    cpuid(0x7, 0, v);
    if ((v[1] & (1 << 18))) /* EBX.RDSEED */
        have_rdseed = true;
    cpuid(0x1, 0, v);
    if ((v[2] & (1 << 30))) /* ECX.RDRAND */
        have_rdrand = true;
}

static void reclaim_regions(void)
{
    for_regions(e) {
        if (e->type == REGION_RECLAIM) {
            unmap(e->base, e->length);
            if (!id_heap_add_range(heap_physical(&heaps), e->base, e->length))
                halt("%s: add range for physical heap failed (%R)\n",
                     __func__, irange(e->base, e->base + e->length));
        }
    }
}

void vm_exit(u8 code)
{
#ifdef SMP_DUMP_FRAME_RETURN_COUNT
    rprintf("cpu\tframe returns\n");
    for (int i = 0; i < MAX_CPUS; i++) {
        cpuinfo ci = cpuinfo_from_id(i);
        if (ci->frcount)
            rprintf("%d\t%ld\n", i, ci->frcount);
    }
#endif

#ifdef DUMP_MEM_STATS
    buffer b = allocate_buffer(heap_general(&heaps), 512);
    if (b != INVALID_ADDRESS) {
        dump_mem_stats(b);
        buffer_print(b);
    }
#endif

    /* TODO MP: coordinate via IPIs */
    tuple root = root_fs ? filesystem_getroot(root_fs) : 0;
    if (root && table_find(root, sym(reboot_on_exit))) {
        triple_fault();
    } else {
        QEMU_HALT(code);
    }
}

closure_function(1, 1, void, sync_complete,
                 u8, code,
                 status, s)
{
    vm_exit(bound(code));
}

extern boolean shutting_down;
void kernel_shutdown(int status)
{
    shutting_down = true;
    if (root_fs) {
        storage_sync(closure(heap_general(&heaps), sync_complete, status));
        kern_unlock();
        runloop();
    }
    vm_exit(status);
}

void kernel_shutdown_ex(status_handler completion)
{
    shutting_down = true;
    if (root_fs) {
        storage_sync(completion);
        kern_unlock();
        runloop();
    }
    apply(completion, 0);
    while(1);
}

u64 total_processors = 1;

#ifdef SMP_ENABLE
static void new_cpu()
{
    if (platform_timer_percpu_init)
        apply(platform_timer_percpu_init);

    /* For some reason, we get a spurious wakeup from hlt on linux/kvm
       after AP start. Spin here to cover it (before moving on to runloop). */
    while (1)
        kernel_sleep();
}
#endif

u64 xsave_features();
u64 xsave_frame_size();

static void __attribute__((noinline)) init_service_new_stack()
{
    kernel_heaps kh = &heaps;
    heap misc = heap_general(kh);
    heap locked = heap_locked(kh);
    heap backed = heap_backed(kh);

    /* runtime and console init */
    init_debug("in init_service_new_stack");
    init_debug("runtime");    
    init_runtime(misc, locked);
    init_tuples(allocate_tagged_region(kh, tag_tuple));
    init_symbols(allocate_tagged_region(kh, tag_symbol), misc);
    init_sg(locked);
    init_pagecache(locked, locked, (heap)heap_physical(kh), PAGESIZE);
    unmap(0, PAGESIZE);         /* unmap zero page */
    reclaim_regions();          /* unmap and reclaim stage2 stack */
    init_extra_prints();
#if 0 // XXX
    if (xsave_frame_size() == 0){
        halt("xsave not supported\n");
    }
#endif
    init_pci(kh);
    init_console(kh);
    init_symtab(kh);
    read_kernel_syms();
    init_debug("pci_discover (for VGA)");
    pci_discover(); // early PCI discover to configure VGA console
    init_kernel_contexts(backed);

    /* interrupts */
    init_debug("init_interrupts");
    init_interrupts(kh);
    // xxx - we depend on interrupts being initialized in order to allocate the
    // ipi..i guess this is safe because they are disabled?
    init_debug("init_scheduler");    
    init_scheduler(misc);
    init_clock();               /* must precede platform init */

    /* platform detection and early init */
    init_debug("probing for KVM");

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

    /* RNG, stack canaries */
    init_debug("RNG");
    init_hwrand();
    init_random();
    __stack_chk_guard_init();

    /* networking */
    init_debug("LWIP init");
    init_net(kh);

    init_debug("probe fs, register storage drivers");
    init_volumes(locked);
    storage_attach sa = closure(misc, attach_storage);

    boolean hyperv_storvsc_attached = false;
    /* Probe for PV devices */
    if (xen_detected()) {
        init_debug("probing for Xen PV network...");
        init_xennet(kh);
        init_xenblk(kh, sa);
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

    init_storage(kh, sa, !xen_detected() && !hyperv_storvsc_attached);
    init_acpi(kh);

    init_debug("pci_discover (for virtio & ata)");
    pci_discover(); // do PCI discover again for other devices

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
    init_debug("starting runloop");
    runloop();
}

static range find_initial_pages(void)
{
    for_regions(e) {
	if (e->type == REGION_INITIAL_PAGES) {
	    u64 base = e->base;
	    u64 length = e->length;
            return irange(base, base + length);
        }
    }
    halt("no initial pages region found; halt\n");
}

static id_heap init_physical_id_heap(heap h)
{
    /* XXX change to locking after removing wrapper in page.c */
    id_heap physical = allocate_id_heap(h, h, PAGESIZE, false);
    boolean found = false;
    init_debug("physical memory:");
    for_regions(e) {
	if (e->type == REGION_PHYSICAL) {
	    /* Align for 2M pages */
	    u64 base = e->base;
	    u64 end = base + e->length - 1;
	    u64 page2m_mask = MASK(PAGELOG_2M);
	    base = (base + page2m_mask) & ~page2m_mask;
	    end &= ~page2m_mask;
	    if (base >= end)
		continue;
	    u64 length = end - base;
#ifdef STAGE3_INIT_DEBUG
	    console("INIT:  [");
	    print_u64(base);
	    console(", ");
	    print_u64(base + length);
	    console(")\n");
#endif
	    if (!id_heap_add_range(physical, base, length))
		halt("    - id_heap_add_range failed\n");
	    found = true;
	}
    }
    if (!found) {
	halt("no valid physical regions found; halt\n");
    }
    return physical;
}

static void init_kernel_heaps()
{
    static struct heap bootstrap;
    bootstrap.alloc = bootstrap_alloc;
    bootstrap.dealloc = leak;

    heaps.virtual_huge = create_id_heap(&bootstrap, &bootstrap, KMEM_BASE,
                                        KMEM_LIMIT - KMEM_BASE, HUGE_PAGESIZE, true);
    assert(heaps.virtual_huge != INVALID_ADDRESS);

    heaps.virtual_page = create_id_heap_backed(&bootstrap, &bootstrap, (heap)heaps.virtual_huge, PAGESIZE, true);
    assert(heaps.virtual_page != INVALID_ADDRESS);

    heaps.physical = init_page_tables(&bootstrap, init_physical_id_heap(&bootstrap), find_initial_pages());
    assert(heaps.physical != INVALID_ADDRESS);

    heaps.backed = locking_heap_wrapper(&bootstrap, physically_backed(&bootstrap, (heap)heaps.virtual_page, (heap)heaps.physical, PAGESIZE), PAGESIZE);
    assert(heaps.backed != INVALID_ADDRESS);

    heaps.general = allocate_mcache(&bootstrap, heaps.backed, 5, 20, PAGESIZE_2M);
    assert(heaps.general != INVALID_ADDRESS);

    heaps.locked = locking_heap_wrapper(&bootstrap, allocate_mcache(&bootstrap, heaps.backed, 5, 20, PAGESIZE_2M), 1);
    assert(heaps.general != INVALID_ADDRESS);
}

static void jump_to_virtual(u64 kernel_size, u64 *pdpt, u64 *pdt) {
    /* Set up a temporary mapping of kernel code virtual address space, to be
     * able to run from virtual addresses (which is needed to properly access
     * things such as literal strings, static variables and function pointers).
     */
    assert(pdpt);
    assert(pdt);
    map_setup_2mbpages(KERNEL_BASE, KERNEL_BASE_PHYS,
                       pad(kernel_size, PAGESIZE_2M) >> PAGELOG_2M,
                       PAGE_WRITABLE, pdpt, pdt);

    /* Jump to virtual address */
    asm("movq $1f, %rdi \n\
        jmp *%rdi \n\
        1: \n");
}

static void cmdline_parse(const char *cmdline)
{
    init_debug("parsing cmdline");
    const char *opt_end, *prefix_end;
    while (*cmdline) {
        opt_end = runtime_strchr(cmdline, ' ');
        if (!opt_end)
            opt_end = cmdline + runtime_strlen(cmdline);
        prefix_end = runtime_strchr(cmdline, '.');
        if (prefix_end && (prefix_end < opt_end)) {
            int prefix_len = prefix_end - cmdline;
            if ((prefix_len == sizeof("virtio_mmio") - 1) &&
                    !runtime_memcmp(cmdline, "virtio_mmio", prefix_len))
                virtio_mmio_parse(&heaps, prefix_end + 1,
                    opt_end - (prefix_end + 1));
        }
        cmdline = opt_end + 1;
    }
}

// init linker set
void init_service(u64 rdi, u64 rsi)
{
    init_debug("init_service");
    u8 *params = pointer_from_u64(rsi);
    const char *cmdline = 0;
    u32 cmdline_size;
    if (params && (*(u16 *)(params + BOOT_PARAM_OFFSET_BOOT_FLAG) == 0xAA55) &&
            (*(u32 *)(params + BOOT_PARAM_OFFSET_HEADER) == 0x53726448)) {
        /* The kernel has been loaded directly by the hypervisor, without going
         * through stage1 and stage2. */
        u8 e820_entries = *(params + BOOT_PARAM_OFFSET_E820_ENTRIES);
        region e820_r = (region)(params + BOOT_PARAM_OFFSET_E820_TABLE);
        extern u8 END;
        u64 kernel_size = u64_from_pointer(&END) - KERNEL_BASE;
        u64 *pdpt = 0;
        u64 *pdt = 0;
        for (u8 entry = 0; entry < e820_entries; entry++) {
            region r = &e820_r[entry];
            if (r->base == 0)
                continue;
            if ((r->type = REGION_PHYSICAL) && (r->base <= KERNEL_BASE_PHYS) &&
                    (r->base + r->length > KERNEL_BASE_PHYS)) {
                /* This is the memory region where the kernel has been loaded:
                 * adjust the region boundaries so that the memory occupied by
                 * the kernel code does not appear as free memory. */
                u64 new_base = pad(KERNEL_BASE_PHYS + kernel_size, PAGESIZE);

                /* Check that there is a gap between start of memory region and
                 * start of kernel code, then use part of this gap as storage
                 * for a set of temporary page tables that we need to set up an
                 * initial mapping of the kernel virtual address space, and make
                 * the remainder a new memory region. */
                assert(KERNEL_BASE_PHYS - r->base >= 2 * PAGESIZE);
                pdpt = pointer_from_u64(r->base);
                pdt = pointer_from_u64(r->base + PAGESIZE);
                create_region(r->base + 2 * PAGESIZE,
                              KERNEL_BASE_PHYS - (r->base + 2 * PAGESIZE),
                              r->type);

                r->length -= new_base - r->base;
                r->base = new_base;
            }
            create_region(r->base, r->length, r->type);
        }
        jump_to_virtual(kernel_size, pdpt, pdt);

        cmdline = pointer_from_u64((u64)*((u32 *)(params +
                BOOT_PARAM_OFFSET_CMD_LINE_PTR)));
        cmdline_size = *((u32 *)(params + BOOT_PARAM_OFFSET_CMDLINE_SIZE));
        if (u64_from_pointer(cmdline) + cmdline_size >= INITIAL_MAP_SIZE) {
            /* Command line is outside the memory space we are going to map:
             * move it at the beginning of the boot parameters (it's OK to
             * overwrite the boot params, since we already parsed what we need).
             */
            assert(u64_from_pointer(params) + cmdline_size < MBR_ADDRESS);
            runtime_memcpy(params, cmdline, cmdline_size);
            params[cmdline_size] = '\0';
            cmdline = (char *)params;
        }

        /* Set up initial mappings in the same way as stage2 does. */
        struct region_heap rh;
        region_heap_init(&rh, PAGESIZE, REGION_PHYSICAL);
        u64 initial_pages_base = allocate_u64(&rh.h, INITIAL_PAGES_SIZE);
        assert(initial_pages_base != INVALID_PHYSICAL);
        region initial_pages_region = create_region(initial_pages_base,
            INITIAL_PAGES_SIZE, REGION_INITIAL_PAGES);
        heap pageheap = region_allocator(&rh.h, PAGESIZE, REGION_INITIAL_PAGES);
        void *pgdir = bootstrap_page_tables(pageheap);
        map(0, 0, INITIAL_MAP_SIZE, PAGE_WRITABLE);
        map(PAGES_BASE, initial_pages_base, INITIAL_PAGES_SIZE, PAGE_WRITABLE);
        map(KERNEL_BASE, KERNEL_BASE_PHYS, pad(kernel_size, PAGESIZE), 0);
        initial_pages_region->length = INITIAL_PAGES_SIZE;
        mov_to_cr("cr3", pgdir);
    }
    u64 cr;
    mov_from_cr("cr0", cr);
    cr |= C0_MP;
    cr &= ~C0_EM;
    mov_to_cr("cr0", cr);
    mov_from_cr("cr4", cr);
    cr |= CR4_OSFXSR | CR4_OSXMMEXCPT /* | CR4_OSXSAVE */;
    mov_to_cr("cr4", cr);
    init_kernel_heaps();
    if (cmdline)
        cmdline_parse(cmdline);
    u64 stack_size = 32*PAGESIZE;
    u64 stack_location = allocate_u64(heap_backed(&heaps), stack_size);
    stack_location += stack_size - STACK_ALIGNMENT;
    *(u64 *)stack_location = 0;
    switch_stack(stack_location, init_service_new_stack);
}
