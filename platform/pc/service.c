#include <kernel.h>
#include <region.h>
#include <symtab.h>
#include <pagecache.h>
#include <tfs.h>
#include <management.h>
#include <apic.h>
#include <aws/aws.h>
#include <drivers/acpi.h>
#include <drivers/ata-pci.h>
#include <drivers/console.h>
#include <drivers/dmi.h>
#include <drivers/nvme.h>
#include <drivers/vga.h>
#include <hyperv_platform.h>
#include <kvm_platform.h>
#include <pci.h>
#include <xen_platform.h>
#include <virtio/virtio.h>
#include <vmware/vmware.h>
#include "serial.h"

#define BOOT_PARAM_OFFSET_E820_ENTRIES  0x01E8
#define BOOT_PARAM_OFFSET_BOOT_FLAG     0x01FE
#define BOOT_PARAM_OFFSET_HEADER        0x0202
#define BOOT_PARAM_OFFSET_CMD_LINE_PTR  0x0228
#define BOOT_PARAM_OFFSET_CMDLINE_SIZE  0x0238
#define BOOT_PARAM_OFFSET_E820_TABLE    0x02D0

//#define SMP_DUMP_FRAME_RETURN_COUNT

//#define INIT_DEBUG
//#define MM_DEBUG
#ifdef INIT_DEBUG
#define init_debug(x, ...) do {rprintf("INIT: " x "\n", ##__VA_ARGS__);} while(0)
#define early_init_debug(x) early_debug("INIT: " x "\n")
#define early_init_debug_u64(x) early_debug_u64(x)
#else
#define init_debug(x, ...)
#define early_init_debug(x)
#define early_init_debug_u64(x)
#endif

extern filesystem root_fs;

void read_kernel_syms(void)
{
    u64 kern_base = INVALID_PHYSICAL;
    u64 kern_length;

    /* add kernel symbols */
    for_regions(e) {
	if (e->type == REGION_KERNIMAGE) {
	    kern_base = e->base;
	    kern_length = e->length;

	    u64 v = allocate_u64((heap)heap_virtual_huge(get_kernel_heaps()), kern_length);
            pageflags flags = pageflags_noexec(pageflags_readonly(pageflags_memory()));
	    map(v, kern_base, kern_length, flags);
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

BSS_RO_AFTER_INIT static boolean have_rdseed;
BSS_RO_AFTER_INIT static boolean have_rdrand;

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

/* called from init to reclaim physical memory used in stage2 */
void reclaim_regions(void)
{
    for_regions(e) {
        if (e->type == REGION_RECLAIM) {
            unmap(e->base, e->length);
            if (!id_heap_add_range(heap_physical(get_kernel_heaps()), e->base, e->length))
                halt("%s: add range for physical heap failed (%R)\n",
                     __func__, irange(e->base, e->base + e->length));
        }
    }
    /* we're done with looking at e820 (and our custom) regions, so
       release the initial map here */
    unmap(PAGESIZE, INITIAL_MAP_SIZE - PAGESIZE);
}

BSS_RO_AFTER_INIT halt_handler vm_halt;

void vm_exit(u8 code)
{
#ifdef SMP_DUMP_FRAME_RETURN_COUNT
    rprintf("cpu\tframe returns\n");
    cpuinfo ci;
    vector_foreach(cpuinfos, ci) {
        if (ci->frcount)
            rprintf("%d\t%ld\n", i, ci->frcount);
    }
#endif

#ifdef DUMP_MEM_STATS
    buffer b = allocate_buffer(heap_locked(get_kernel_heaps()), 512);
    if (b != INVALID_ADDRESS) {
        dump_mem_stats(b);
        buffer_print(b);
    }
#endif

    /* TODO MP: coordinate via IPIs */
    tuple root = get_root_tuple();
    if (root) {
        if (get(root, sym(reboot_on_exit)))
            triple_fault();
        u64 expected_code;
        if (get_u64(root, sym(expected_exit_code), &expected_code) &&
                expected_code == code)
            code = 0;
        if (get(root, sym(debug_exit)))
            goto debug_exit;
    }
    if (vm_halt) {
        apply(vm_halt, code);
        while (1);  /* to honor noreturn attribute */
    }
  debug_exit:
    QEMU_HALT(code);
}

u64 total_processors = 1;
BSS_RO_AFTER_INIT u64 present_processors;

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
    run_percpu_init();

    init_mxcsr();

    /* For some reason, we get a spurious wakeup from hlt on linux/kvm
       after AP start. Spin here to cover it (before moving on to runloop). */
    while (1)
        kernel_sleep();
}

closure_function(0, 2, void, count_processors_handler,
                 u8, type, void *, p)
{
    switch (type) {
    case ACPI_MADT_LAPIC:
        if (((acpi_lapic)p)->flags & MADT_LAPIC_ENABLED)
            present_processors++;
        break;
    case ACPI_MADT_LAPICx2:
        if (((acpi_lapic_x2)p)->flags & MADT_LAPIC_ENABLED)
            present_processors++;
        break;
    }
}

static void count_processors()
{
    if (acpi_walk_madt(stack_closure(count_processors_handler))) {
        init_debug("ACPI reports %d processors", present_processors);
    } else {
        present_processors = 1;
        rprintf("warning: ACPI MADT not found, default to 1 processor\n");
    }
}

void count_cpus_present(void)
{
    count_processors();
}

void start_secondary_cores(kernel_heaps kh)
{
    memory_barrier();
    init_debug("init_mxcsr");
    init_mxcsr();
    init_debug("starting APs");
    allocate_apboot((heap)heap_page_backed(kh), new_cpu);
    for (int i = 1; i < present_processors; i++)
        start_cpu(i);
    deallocate_apboot((heap)heap_page_backed(kh));
    init_flush(heap_locked(kh));
    init_debug("started %d total processors", total_processors);
}
#else
void start_secondary_cores(kernel_heaps kh)
{
}

void count_cpus_present(void)
{
}
#endif

u64 xsave_features();

BSS_RO_AFTER_INIT static range initial_pages;

static void __attribute__((noinline)) init_service_new_stack()
{
    kernel_heaps kh = get_kernel_heaps();
    early_init_debug("in init_service_new_stack");
    init_page_tables((heap)heap_linear_backed(kh));
    bytes pagesize = is_low_memory_machine(kh) ? PAGESIZE : PAGESIZE_2M;
    init_tuples(locking_heap_wrapper(heap_general(kh),
                allocate_tagged_region(kh, tag_table_tuple, pagesize)));
    init_symbols(allocate_tagged_region(kh, tag_symbol, pagesize), heap_locked(kh));

    for_regions(e) {
        if (e->type == REGION_SMBIOS) {
            smbios_entry_point = e->base;
            break;
        }
    }

    init_management(allocate_tagged_region(kh, tag_function_tuple, pagesize), heap_general(kh));
    early_init_debug("init_hwrand");
    init_hwrand();

    early_init_debug("init cpu features");
    init_cpu_features();

    early_init_debug("calling kernel_runtime_init");
    kernel_runtime_init(kh);
    while(1);
}

static void find_initial_pages(void)
{
    for_regions(e) {
	if (e->type == REGION_INITIAL_PAGES) {
	    u64 base = e->base;
	    u64 length = e->length;
            initial_pages = irangel(base, length);
            return;
        }
    }
    halt("no initial pages region found; halt\n");
}

id_heap init_physical_id_heap(heap h)
{
    u64 phys_length = 0;
    for_regions(e) {
        if (e->type == REGION_PHYSICAL) {
            /* Remove low memory area from physical memory regions, so that it can be used for
             * things like starting secondary CPUs. */
            if (e->base < MB) {
                u64 end = e->base + e->length;
                if (end > MB) {
                    e->base = MB;
                    e->length = end - MB;
                } else {
                    e->length = 0;
                }
            }

            phys_length += e->length;
        }
    }
    u64 bootstrap_size = init_bootstrap_heap(phys_length);

    /* Carve the bootstrap heap out of a physical memory region. */
    for_regions(e) {
        if (e->type == REGION_PHYSICAL) {
            u64 base = pad(e->base, PAGESIZE);
            u64 end = e->base + e->length;
            u64 length = (end & ~MASK(PAGELOG)) - base;
            if (length >= bootstrap_size) {
                map(BOOTSTRAP_BASE, base, bootstrap_size, pageflags_writable(pageflags_memory()));
                e->base = base + bootstrap_size;
                e->length = end - e->base;
                break;
            }
        }
    }

    id_heap physical = allocate_id_heap(h, h, PAGESIZE, true);
    boolean found = false;
    early_init_debug("physical memory:");
    for_regions(e) {
	if (e->type == REGION_PHYSICAL) {
	    /* Align for 2M pages */
	    u64 base = e->base;
	    u64 end = base + e->length;
	    u64 page2m_mask = MASK(PAGELOG_2M);
	    base = (base + page2m_mask) & ~page2m_mask;
	    end &= ~MASK(PAGELOG);
	    if (base >= end)
		continue;
	    u64 length = end - base;
#ifdef INIT_DEBUG
	    early_debug("INIT:  [");
	    early_debug_u64(base);
	    early_debug(", ");
	    early_debug_u64(base + length);
	    early_debug(")\n");
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

static void jump_to_virtual(u64 kernel_size, u64 *pdpt, u64 *pdt) {
    /* Set up a temporary mapping of kernel code virtual address space, to be
     * able to run from virtual addresses (which is needed to properly access
     * things such as literal strings, static variables and function pointers).
     */
    assert(pdpt);
    assert(pdt);
    map_setup_2mbpages(KERNEL_BASE, KERNEL_BASE_PHYS,
                       pad(kernel_size, PAGESIZE_2M) >> PAGELOG_2M,
                       pageflags_writable(pageflags_exec(pageflags_memory())), pdpt, pdt);

    /* Jump to virtual address */
    asm("movq $1f, %rdi \n\
        jmp *%rdi \n\
        1: \n");
}

static void cmdline_parse(const char *cmdline)
{
    early_init_debug("parsing cmdline");
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
                virtio_mmio_parse(get_kernel_heaps(), prefix_end + 1,
                    opt_end - (prefix_end + 1));
        }
        cmdline = opt_end + 1;
    }
}

extern void *READONLY_END;

// init linker set
void init_service(u64 rdi, u64 rsi)
{
    u8 *params = pointer_from_u64(rsi);
    const char *cmdline = 0;
    u32 cmdline_size;

    /* NOTE: Do not call any non-inlined functions before this if-block because
     * direct load boot methods (firecracker) do not have virtual address space
     * set up for the kernel before this point! */
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

        /* Enable NXE bit now to avoid page faults when mapping a noexec page */
        write_msr(EFER_MSR, read_msr(EFER_MSR) | EFER_NXE);
        pageflags flags = pageflags_writable(pageflags_memory());
        pageflags roflags = pageflags_exec(pageflags_readonly(pageflags_memory()));
        map(0, 0, INITIAL_MAP_SIZE, flags);
        map(PAGES_BASE, initial_pages_base, INITIAL_PAGES_SIZE, flags);
        u64 roend_offset = pad(u64_from_pointer(&READONLY_END) - KERNEL_BASE, PAGESIZE);
        map(KERNEL_BASE, KERNEL_BASE_PHYS, roend_offset, roflags);
        map(KERNEL_BASE + roend_offset, KERNEL_BASE_PHYS + roend_offset,
               pad(kernel_size - roend_offset, PAGESIZE), flags);
        initial_pages_region->length = INITIAL_PAGES_SIZE;
        mov_to_cr("cr3", pgdir);
        bootstrapping = false;
    }

    serial_init();
    early_init_debug("init_service");

    find_initial_pages();
    init_mmu();
    init_page_initial_map(pointer_from_u64(PAGES_BASE), initial_pages);
    init_kernel_heaps();
    if (cmdline)
        cmdline_parse(cmdline);
    u64 stack_size = 32*PAGESIZE;
    u64 stack_location = allocate_u64((heap)heap_page_backed(get_kernel_heaps()), stack_size);
    stack_location += stack_size - STACK_ALIGNMENT;
    *(u64 *)stack_location = 0;
    switch_stack(stack_location, init_service_new_stack);
}

void init_platform_devices(kernel_heaps kh)
{
    RO_AFTER_INIT static struct console_driver serial_console_driver = {
        .name = "serial",
        .write = serial_console_write,
    };

    attach_console_driver(&serial_console_driver);
    vga_pci_register(kh);
    pci_discover(); // early PCI discover to configure VGA console
}

extern boolean init_hpet(kernel_heaps kh);
extern boolean init_tsc_timer(kernel_heaps kh);

void detect_hypervisor(kernel_heaps kh)
{
    if (!kvm_detect(kh)) {
        init_debug("probing for Xen hypervisor");
        if (!xen_detect(kh)) {
            if (!hyperv_detect(kh)) {
                init_debug("no hypervisor detected; assuming qemu full emulation");
                if (init_tsc_timer(kh))
                    init_debug("using calibrated TSC as timer source");
                else if (init_hpet(kh))
                    init_debug("using HPET as timer source");
                else
                    halt("timer initialization failed; no timer source");
            } else {
                init_debug("hyper-v hypervisor detected");
            }
        } else {
            init_debug("xen hypervisor detected");
        }
    } else {
        init_debug("KVM detected");
    }
}

void detect_devices(kernel_heaps kh, storage_attach sa)
{
    /* Probe for PV devices */
    if (xen_detected()) {
        init_debug("probing for Xen PV network...");
        init_xennet(kh);
        init_xenblk(kh, sa);
        status s = xen_probe_devices();
        if (!is_ok(s))
            halt("xen probe failed: %v\n", s);
    } else if (hyperv_detected()) {
        boolean hyperv_storvsc_attached = false;
        init_debug("probing for Hyper-V PV network...");
        init_vmbus(kh);
        status s = hyperv_probe_devices(sa, &hyperv_storvsc_attached);
        if (!is_ok(s))
            halt("Hyper-V probe failed: %v\n", s);
        if (!hyperv_storvsc_attached)
            init_ata_pci(kh, sa); /* hvm ata fallback */
    } else {
        init_debug("hypervisor undetected or HVM platform; registering all PCI drivers...");

        /* net */
        init_virtio_network(kh);
        init_vmxnet3_network(kh);
        init_aws_ena(kh);

        /* storage */
        init_virtio_blk(kh, sa);
        init_virtio_scsi(kh, sa);
        init_pvscsi(kh, sa);
        init_nvme(kh, sa);
        init_ata_pci(kh, sa);
    }

    /* misc / platform */
    init_acpi(kh);

    init_virtio_balloon(kh);
}
