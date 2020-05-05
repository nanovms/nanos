/* TODO: this file has become a garbage dump ... reorganize */

#include <kernel.h>
#include <pci.h>
#include <tfs.h>
#include <pagecache.h>
#include <apic.h>
#include <region.h>
#include <page.h>
#include <symtab.h>
#include <virtio/virtio.h>
#include <vmware/vmxnet3.h>
#include <drivers/storage.h>
#include <drivers/console.h>
#include <kvm_platform.h>
#include <xen_platform.h>

//#define SMP_ENABLE
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

static heap allocate_tagged_region(kernel_heaps kh, u64 tag)
{
    heap h = heap_general(kh);
    heap p = (heap)heap_physical(kh);
    assert(tag < U64_FROM_BIT(VA_TAG_WIDTH));
    u64 tag_base = KMEM_BASE | (tag << VA_TAG_OFFSET);
    u64 tag_length = U64_FROM_BIT(VA_TAG_OFFSET);
    heap v = (heap)create_id_heap(h, heap_backed(kh), tag_base, tag_length, p->pagesize);
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

closure_function(1, 2, void, fsstarted,
                 tuple, root,
                 filesystem, fs, status, s)
{
    if (!is_ok(s))
        halt("unable to open filesystem: %v\n", s);

    enqueue(runqueue, create_init(&heaps, bound(root), fs));
    closure_finish();
}

/* will become list I guess */
static pagecache global_pagecache;

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
    if (!global_pagecache)
        return;
    heap p = (heap)heap_physical(&heaps);
    u64 free = heap_total(p) - heap_allocated(p);
    mm_debug("%s: total %ld, alloc %ld, free %ld\n", __func__, heap_total(p), heap_allocated(p), free);
    if (free < CACHE_DRAIN_CUTOFF) {
        u64 drain_bytes = CACHE_DRAIN_CUTOFF - free;
        u64 drained = pagecache_drain(global_pagecache, drain_bytes);
        if (drained > 0)
            mm_debug("   drained %ld / %ld requested...\n", drained, drain_bytes);
    }
}

closure_function(2, 3, void, attach_storage,
                 tuple, root, u64, fs_offset,
                 block_io, r, block_io, w, u64, length)
{
    // with filesystem...should be hidden as functional handlers on the tuplespace
    heap h = heap_general(&heaps);
    u64 offset = bound(fs_offset);
    length -= offset;
    pagecache pc = allocate_pagecache(h, heap_backed(&heaps), length, PAGESIZE_2M, SECTOR_SIZE,
                                      0 /* XXX mapper */,
                                      closure(h, offset_block_io, bound(fs_offset), r),
                                      closure(h, offset_block_io, bound(fs_offset), w));
    if (pc == INVALID_ADDRESS)
        halt("unable to create pagecache\n");

    /* figure that later pagecaches will register themselves with backing - glue for now */
    global_pagecache = pc;
    create_filesystem(h,
                      SECTOR_SIZE,
                      SECTOR_SIZE,
                      length,
                      heap_backed(&heaps),
                      pagecache_reader_sg(pc),
                      pagecache_writer(pc),
                      bound(root),
                      false,
                      closure(h, fsstarted, bound(root)));
    closure_finish();
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
	    add_elf_syms(alloca_wrap_buffer(v, kern_length));
            unmap(v, kern_length);
	    break;
	}
    }
    
    if (kern_base == INVALID_PHYSICAL) {
	console("kernel elf image region not found; no debugging symbols\n");
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

static tuple root;

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

    /* TODO MP: coordinate via IPIs */
    if (root && table_find(root, sym(reboot_on_exit))) {
        triple_fault();
    } else {
        QEMU_HALT(code);
    }
}

struct cpuinfo cpuinfos[MAX_CPUS];

static void init_cpuinfos(kernel_heaps kh)
{
    heap h = heap_general(kh);
    heap backed = heap_backed(kh);

    /* We're stuck with a hard limit of 64 for now due to bitmask... */
    build_assert(MAX_CPUS <= 64);

    /* We'd like the aps to allocate for themselves, but we don't have
       per-cpu heaps just yet. */
    for (int i = 0; i < MAX_CPUS; i++) {
        cpuinfo ci = cpuinfo_from_id(i);
        ci->self = ci;

        /* state */
        ci->running_frame = 0;
        ci->id = i;
        ci->state = cpu_not_present;
        ci->have_kernel_lock = false;
        ci->frcount = 0;
        /* frame and stacks */
        ci->kernel_frame = allocate_frame(h);
        ci->kernel_stack = allocate_stack(backed, KERNEL_STACK_SIZE);
        ci->exception_stack = allocate_stack(backed, EXCEPT_STACK_SIZE);
        ci->int_stack = allocate_stack(backed, INT_STACK_SIZE);
        //        init_debug("cpu %2d: kernel_frame %p, kernel_stack %p", i, ci->kernel_frame, ci->kernel_stack);
        //        init_debug("        fault_stack  %p, int_stack    %p", ci->fault_stack, ci->int_stack);
    }

    cpu_setgs(0);
}

u64 total_processors = 1;

#ifdef SMP_ENABLE
static void new_cpu()
{
    fetch_and_add(&total_processors, 1);
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

    /* runtime and console init */
    init_debug("in init_service_new_stack");
    init_debug("runtime");    
    init_runtime(misc);
    init_tuples(allocate_tagged_region(kh, tag_tuple));
    init_symbols(allocate_tagged_region(kh, tag_symbol), misc);
    init_sg(misc);
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
    init_debug("init_cpuinfos");
    init_cpuinfos(kh);
    current_cpu()->state = cpu_kernel;

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
            init_debug("neither KVM nor Xen detected; assuming qemu full emulation");
            if (!init_hpet(kh)) {
                halt("HPET initialization failed; no timer source\n");
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
    root = allocate_tuple();
    u64 fs_offset = 0;
    for_regions(e) {
        if (e->type == REGION_FILESYSTEM)
            fs_offset = SECTOR_SIZE + e->length;
    }
    if (fs_offset == 0)
        halt("filesystem region not found; halt\n");
    init_storage(kh, closure(misc, attach_storage, root, fs_offset));

    /* Probe for PV devices */
    if (xen_detected()) {
        init_debug("probing for Xen PV network...");
        init_xennet(kh);
        status s = xen_probe_devices();
        if (!is_ok(s))
            rprintf("xen probe failed: %v\n", s);
    } else {
        init_debug("probing for virtio PV network...");
        /* qemu virtio */
        init_virtio_network(kh);
        init_vmxnet3_network(kh);
    }

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
    id_heap physical = allocate_id_heap(h, h, PAGESIZE);
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
                                        KMEM_LIMIT - KMEM_BASE, HUGE_PAGESIZE);
    assert(heaps.virtual_huge != INVALID_ADDRESS);

    heaps.virtual_page = create_id_heap_backed(&bootstrap, &bootstrap, (heap)heaps.virtual_huge, PAGESIZE);
    assert(heaps.virtual_page != INVALID_ADDRESS);

    heaps.physical = init_page_tables(&bootstrap, init_physical_id_heap(&bootstrap), find_initial_pages());
    assert(heaps.physical != INVALID_ADDRESS);

    heaps.backed = physically_backed(&bootstrap, (heap)heaps.virtual_page, (heap)heaps.physical, PAGESIZE);
    assert(heaps.backed != INVALID_ADDRESS);

    heaps.general = allocate_mcache(&bootstrap, heaps.backed, 5, 20, PAGESIZE_2M);
    assert(heaps.general != INVALID_ADDRESS);
}

// init linker set
void init_service()
{
    init_debug("init_service");
    init_kernel_heaps();
    u64 stack_size = 32*PAGESIZE;
    u64 stack_location = allocate_u64(heap_backed(&heaps), stack_size);
    stack_location += stack_size - STACK_ALIGNMENT;
    *(u64 *)stack_location = 0;
    switch_stack(stack_location, init_service_new_stack);
}
