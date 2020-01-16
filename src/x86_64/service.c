#include <runtime.h>
#include <pci.h>
#include <tfs.h>
#include <x86_64.h>
#include <apic.h>
#include <region.h>
#include <page.h>
#include <symtab.h>
#include <virtio/virtio.h>
#include <drivers/storage.h>
#include <drivers/console.h>
#include <unix_internal.h>
#include <kvm_platform.h>
#include <xen_platform.h>

//#define SMP_TEST

//#define STAGE3_INIT_DEBUG
#ifdef STAGE3_INIT_DEBUG
#define init_debug(x) do {console("INIT: " x "\n");} while(0)
#else
#define init_debug(x)
#endif

extern void init_net(kernel_heaps kh);
extern void start_interrupts(kernel_heaps kh);

static struct kernel_heaps heaps;

heap allocate_tagged_region(kernel_heaps kh, u64 tag)
{
    heap h = heap_general(kh);
    heap p = heap_physical(kh);
    u64 tag_base = tag << va_tag_offset;
    u64 tag_length = U64_FROM_BIT(va_tag_offset);
    heap v = create_id_heap(h, tag_base, tag_length, p->pagesize);
    assert(v != INVALID_ADDRESS);
    heap backed = physically_backed(h, v, p, heap_pages(kh), p->pagesize);
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

queue runqueue;                 /* dispatched in runloop */
queue bhqueue;                  /* dispatched to exhaustion in process_bhqueue */
queue deferqueue;               /* same as bhqueue, but only for previously queued items */

static timestamp runloop_timer_min;
static timestamp runloop_timer_max;

static void timer_update(void)
{
    /* find timer interval from timer heap, bound by configurable min and max */
    timestamp timeout = MAX(MIN(timer_check(), runloop_timer_max), runloop_timer_min);
    runloop_timer(timeout);
}

extern void interrupt_exit(void);

/* could make a generic hook/register if more users... */
thunk unix_interrupt_checks;

NOTRACE
void process_bhqueue()
{
    /* XXX - we're on bh frame & stack; re-enable ints here */
    thunk t;
    int defer_waiters = queue_length(deferqueue);
    while ((t = dequeue(bhqueue)) != INVALID_ADDRESS) {
        assert(t);
        apply(t);
    }

    /* only process deferred items that were queued prior to call -
       this allows bhqueue and deferqueue waiters to re-schedule for
       subsequent bh processing */
    while (defer_waiters > 0 && (t = dequeue(deferqueue)) != INVALID_ADDRESS) {
        assert(t);
        apply(t);
        defer_waiters--;
    }

    timer_update();

    /* XXX - and disable before frame pop */
    frame_pop();

    if (unix_interrupt_checks)
        apply(unix_interrupt_checks);

    current_cpu()->in_bh = false;
    interrupt_exit();
}

void runloop()
{
    thunk t;

    while(1) {
        while((t = dequeue(runqueue)) != INVALID_ADDRESS) {
            assert(t);
            apply(t);
            disable_interrupts();
        }
        if (current) {
            proc_pause(current->p);
        }
        timer_update();
        set_running_frame(current_cpu()->misc_frame);
        kernel_sleep();
        if (current) {
            proc_resume(current->p);
        }
    }
}

//#define MAX_BLOCK_IO_SIZE PAGE_SIZE
#define MAX_BLOCK_IO_SIZE (256 * 1024)

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
    assert(s == STATUS_OK);
    enqueue(runqueue, create_init(&heaps, bound(root), fs));
    closure_finish();
}

closure_function(2, 3, void, attach_storage,
                 tuple, root, u64, fs_offset,
                 block_io, r, block_io, w, u64, length)
{
    // with filesystem...should be hidden as functional handlers on the tuplespace
    heap h = heap_general(&heaps);
    create_filesystem(h,
                      SECTOR_SIZE,
                      length,
                      heap_backed(&heaps),
                      closure(h, offset_block_io, bound(fs_offset), r),
                      closure(h, offset_block_io, bound(fs_offset), w),
                      bound(root),
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

	    u64 v = allocate_u64(heap_virtual_huge(&heaps), kern_length);
	    map(v, kern_base, kern_length, 0, heap_pages(&heaps));
#ifdef ELF_SYMTAB_DEBUG
	    rprintf("kernel ELF image at 0x%lx, length %ld, mapped at 0x%lx\n",
		    kern_base, kern_length, v);
#endif
	    add_elf_syms(alloca_wrap_buffer(v, kern_length));
            unmap(v, kern_length, heap_pages(&heaps));
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
            unmap(e->base, e->length, heap_pages(&heaps));
            if (!id_heap_add_range(heap_physical(&heaps), e->base, e->length))
                halt("%s: add range for physical heap failed (%R)\n",
                     __func__, irange(e->base, e->base + e->length));
        }
    }
}

static void init_runloop_timer(void)
{
    runloop_timer_min = microseconds(RUNLOOP_TIMER_MIN_PERIOD_US);
    runloop_timer_max = microseconds(RUNLOOP_TIMER_MAX_PERIOD_US);
}

static tuple root;

void vm_exit(u8 code)
{
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
    heap pages = heap_pages(kh);

    /* We'd like the aps to allocate for themselves, but we don't have
       per-cpu heaps just yet. */
    for (int i = 0; i < MAX_CPUS; i++) {
        cpuinfo ci = &cpuinfos[i];
        ci->self = ci;

        /* state */
        ci->running_frame = 0;
        ci->id = i;
        ci->in_bh = false;
        ci->in_int = false;
        ci->online = false;
        ci->ipi_wakeup = false;

        /* frame and stacks */
        ci->misc_frame = allocate_frame(h);
        ci->bh_frame = allocate_frame(h);
        ci->syscall_stack = allocate_stack(pages, SYSCALL_STACK_PAGES);
        ci->fault_stack = allocate_stack(pages, FAULT_STACK_PAGES);
        ci->int_stack = allocate_stack(pages, INT_STACK_PAGES);
        ci->bh_stack = allocate_stack(pages, BH_STACK_PAGES);
    }

    cpu_setgs(0);
}

#ifdef SMP_TEST
static queue idle_cpu_queue;
static u64 ipi_vector;
static u64 aps_online = 0;

closure_function(0, 0, void, ipi_interrupt)
{
    cpuinfo ci = get_cpuinfo();
    ci->online = true;
    fetch_and_add(&aps_online, 1);
}

static void new_cpu()
{
    cpuinfo ci = get_cpuinfo();
    enqueue(idle_cpu_queue, pointer_from_u64((u64)ci->id));
    while (1) {
        kernel_sleep();
    }
}
#endif

static void __attribute__((noinline)) init_service_new_stack()
{
    kernel_heaps kh = &heaps;
    heap misc = heap_general(kh);
    heap pages = heap_pages(kh);

    /* runtime and console init */
    init_debug("in init_service_new_stack");
    unmap(0, PAGESIZE, pages);  /* unmap zero page */
    reclaim_regions();          /* unmap and reclaim stage2 stack */
    init_debug("runtime");
    init_runtime(kh);
    init_extra_prints();
    init_pci(kh);
    init_console(kh);
    init_symtab(kh);
    read_kernel_syms();
    init_debug("pci_discover (for VGA)");
    pci_discover(); // early PCI discover to configure VGA console

    /* scheduling queues init */
    runqueue = allocate_queue(misc, 64);
    /* XXX bhqueue is large to accomodate vq completions; explore batch processing on vq side */
    bhqueue = allocate_queue(misc, 2048);
    deferqueue = allocate_queue(misc, 64);
    unix_interrupt_checks = 0;

    init_debug("init_cpuinfos");
    init_cpuinfos(kh);

    /* interrupts */
    init_debug("start_interrupts");
    start_interrupts(kh);

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
            /* XXX temporary: We're falling back to HPET until we get PV timer working correctly. */
            if (!init_hpet(kh)) {
                halt("HPET initialization failed; no timer source\n");
            }
        }
    } else {
        init_debug("KVM detected");
    }

    /* clock, timer, RNG, stack canaries */
    init_clock();
    init_runloop_timer();
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
    }

    init_debug("pci_discover (for virtio & ata)");
    pci_discover(); // do PCI discover again for other devices

    /* Switch to stage3 GDT64, enable TSS and free up initial map */
    init_debug("install GDT64 and TSS");
    install_gdt64_and_tss(0);
    unmap(PAGESIZE, INITIAL_MAP_SIZE - PAGESIZE, pages);

#ifdef SMP_TEST
    ipi_vector = allocate_interrupt();
    assert(ipi_vector != INVALID_PHYSICAL);
    register_interrupt(ipi_vector, closure(heap_general(kh), ipi_interrupt));

    init_debug("performing SMP test");
    idle_cpu_queue = allocate_queue(misc, 64);
    start_cpu(misc, pages, TARGET_EXCLUSIVE_BROADCAST, new_cpu);

    kernel_delay(seconds(1));
    for (int i = 1; i < MAX_CPUS; i++)
        apic_ipi(i, 0, ipi_vector);
    kernel_delay(seconds(1));
    rprintf("SMP test: %d APs online\n", aps_online);
#endif
    init_debug("starting runloop");
    runloop();
}

static heap init_pages_id_heap(heap h)
{
    boolean found = false;
    heap pages = allocate_id_heap(h, PAGESIZE);
    for_regions(e) {
	if (e->type == REGION_IDENTITY) {
            assert(!found);     /* should only be one... */
	    u64 base = e->base;
	    u64 length = e->length;
	    if ((base & (PAGESIZE-1)) | (length & (PAGESIZE-1))) {
		console("identity region unaligned!\nbase: ");
		print_u64(base);
		console(", length: ");
		print_u64(length);
		halt("\nhalt");
	    }

#ifdef STAGE3_INIT_DEBUG
	    console("INIT: pages heap: [");
	    print_u64(base);
	    console(", ");
	    print_u64(base + length);
	    console(")\n");
#endif
	    if (!id_heap_add_range(pages, base, length))
		halt("    - id_heap_add_range failed\n");
	    found = true;
	} else if (e->type == REGION_IDENTITY_RESERVED) {
            assert(heaps.identity_reserved_start == 0);     /* should only be one... */
            heaps.identity_reserved_start = e->base;
            heaps.identity_reserved_end = e->base + e->length;
        }
    }
    if (!found)
        halt("no identity region found; halt\n");
    if (heaps.identity_reserved_start == 0)
        halt("reserved identity region not found; halt\n");
    return pages;
}

static heap init_physical_id_heap(heap h)
{
    heap physical = allocate_id_heap(h, PAGESIZE);
    boolean found = false;
    init_debug("physical memory:");
    for_regions(e) {
	if (e->type == REGION_PHYSICAL) {
	    /* Align for 2M pages */
	    u64 base = e->base;
	    u64 end = base + e->length - 1;
	    u64 page2m_mask = (2 << 20) - 1;
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

    heaps.pages = init_pages_id_heap(&bootstrap);
    heaps.physical = init_physical_id_heap(&bootstrap);

    heaps.virtual_huge = create_id_heap(&bootstrap, HUGE_PAGESIZE,
				      (1ull<<VIRTUAL_ADDRESS_BITS)- HUGE_PAGESIZE, HUGE_PAGESIZE);
    assert(heaps.virtual_huge != INVALID_ADDRESS);

    heaps.virtual_page = create_id_heap_backed(&bootstrap, heaps.virtual_huge, PAGESIZE);
    assert(heaps.virtual_page != INVALID_ADDRESS);

    heaps.backed = physically_backed(&bootstrap, heaps.virtual_page, heaps.physical, heaps.pages, PAGESIZE);
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
