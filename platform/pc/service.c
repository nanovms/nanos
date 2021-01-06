// XXX trim headers after move to init.c
#include <kernel.h>
#include <pci.h>
#include <pagecache.h>
#include <tfs.h>
#include <apic.h>
#include <region.h>
#include <page.h>
#include <storage.h>
#include <symtab.h>
#include <unix.h>
#include <aws/aws.h>
#include <virtio/virtio.h>
#include <vmware/vmxnet3.h>
#include <drivers/acpi.h>
#include <drivers/storage.h>
#include <drivers/console.h>
#include <kvm_platform.h>
#include <log.h>
#include <xen_platform.h>
#include <hyperv_platform.h>
#include "serial.h"

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
vector shutdown_completions;

kernel_heaps get_kernel_heaps(void)
{
    return &heaps;
}
KLIB_EXPORT(get_kernel_heaps);

#define BOOTSTRAP_REGION_SIZE_KB	2048
static u8 bootstrap_region[BOOTSTRAP_REGION_SIZE_KB << 10];
static u64 bootstrap_base = (unsigned long long)bootstrap_region;
static u64 bootstrap_alloc(heap h, bytes length)
{
    u64 result = bootstrap_base;
    if ((result + length) >=  (u64_from_pointer(bootstrap_region) + sizeof(bootstrap_region))) {
        rputs("*** bootstrap heap overflow! ***\n");
        return INVALID_PHYSICAL;
    }
    bootstrap_base += length;
    return result;
}

/* XXX some header reorg in order */
void init_extra_prints(); 
thunk create_init(kernel_heaps kh, tuple root, filesystem fs);
filesystem_complete bootfs_handler(kernel_heaps kh, tuple root,
                                   boolean klibs_in_bootfs,
                                   boolean ingest_kernel_syms);

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

void read_kernel_syms(void)
{
    u64 kern_base = INVALID_PHYSICAL;
    u64 kern_length;

    /* add kernel symbols */
    for_regions(e) {
	if (e->type == REGION_KERNIMAGE) {
	    kern_base = e->base;
	    kern_length = e->length;

	    u64 v = allocate_u64((heap)heap_virtual_huge(&heaps), kern_length);
	    map(v, kern_base, kern_length, PAGE_READONLY);
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
    return (u64)now(CLOCK_ID_MONOTONIC_RAW);
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

void reclaim_regions(void)
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

halt_handler vm_halt;

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
    } else if (vm_halt) {
        apply(vm_halt, code);
        while (1);  /* to honor noreturn attribute */
    } else {
        QEMU_HALT(code);
    }
}

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
    status_handler completion = closure(heap_locked(&heaps), sync_complete, status);
    merge m = allocate_merge(heap_locked(&heaps), completion);
    status_handler sh = apply_merge(m);
    shutdown_handler h;

    shutting_down = true;

    if (root_fs)
        vector_push(shutdown_completions, closure(heap_locked(&heaps),
                                                  storage_shutdown));

    if (vector_length(shutdown_completions) > 0) {
        if (this_cpu_has_kernel_lock()) {
            vector_foreach(shutdown_completions, h)
                apply(h, status, m);
            apply(sh, STATUS_OK);
            kern_unlock();
        } else {
            vector_push(shutdown_completions, closure(heap_locked(&heaps),
                                                    do_status_handler, sh));
            vector_foreach(shutdown_completions, h)
                enqueue_irqsafe(runqueue, closure(heap_locked(&heaps),
                                                  do_shutdown_handler, h, status, m));
        }
        runloop();
    }
    apply(sh, STATUS_OK);
    while(1);
}

u64 total_processors = 1;

#ifdef SMP_ENABLE
/* Value comes from LDMXCSR instruction reference in Intel Architectures SDM */
#define MXCSR_DEFAULT   0x1f80
/* hvm does not always properly initialize mxcsr register */
static void init_mxcsr() {
    u32 m = MXCSR_DEFAULT;
    asm("ldmxcsr %0":: "m"(m));
}

static void new_cpu()
{
    if (platform_timer_percpu_init)
        apply(platform_timer_percpu_init);

    init_mxcsr();

    /* For some reason, we get a spurious wakeup from hlt on linux/kvm
       after AP start. Spin here to cover it (before moving on to runloop). */
    while (1)
        kernel_sleep();
}
#endif

u64 xsave_features();

static void __attribute__((noinline)) init_service_new_stack()
{
    kernel_heaps kh = &heaps;
    init_debug("in init_service_new_stack");
    init_tuples(allocate_tagged_region(kh, tag_tuple));
    init_symbols(allocate_tagged_region(kh, tag_symbol), heap_general(&heaps));

    init_debug("init_hwrand");
    init_hwrand();

    init_debug("calling kernel_runtime_init");
    kernel_runtime_init(kh);
    while(1);
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
    id_heap physical = allocate_id_heap(h, h, PAGESIZE, true);
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
	    rputs("INIT:  [");
	    print_u64(base);
	    rputs(", ");
	    print_u64(base + length);
	    rputs(")\n");
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

    heaps.physical = init_physical_id_heap(&bootstrap);
    assert(heaps.physical != INVALID_ADDRESS);

    init_page_tables(&bootstrap, heaps.physical, find_initial_pages());

    heaps.backed = physically_backed(&bootstrap, (heap)heaps.virtual_page, (heap)heaps.physical, PAGESIZE, true);
    assert(heaps.backed != INVALID_ADDRESS);

    heaps.general = allocate_mcache(&bootstrap, (heap)heaps.backed, 5, MAX_MCACHE_ORDER, PAGESIZE_2M);
    assert(heaps.general != INVALID_ADDRESS);

    heaps.locked = locking_heap_wrapper(&bootstrap,
        allocate_mcache(&bootstrap, (heap)heaps.backed, 5, MAX_MCACHE_ORDER, PAGESIZE_2M));
    assert(heaps.locked != INVALID_ADDRESS);
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

    serial_init();

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
        map(KERNEL_BASE, KERNEL_BASE_PHYS, pad(kernel_size, PAGESIZE), PAGE_READONLY);
        initial_pages_region->length = INITIAL_PAGES_SIZE;
        mov_to_cr("cr3", pgdir);
    }
    init_kernel_heaps();
    if (cmdline)
        cmdline_parse(cmdline);
    u64 stack_size = 32*PAGESIZE;
    u64 stack_location = allocate_u64(heap_backed(&heaps), stack_size);
    stack_location += stack_size - STACK_ALIGNMENT;
    *(u64 *)stack_location = 0;
    switch_stack(stack_location, init_service_new_stack);
}
