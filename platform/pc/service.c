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
#include <drivers/gve.h>
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

#define HVM_START_MAGIC_VALUE   0x336ec578

#define HVM_MEMMAP_TYPE_RAM     1

typedef struct hvm_start_info {
    u32 magic;
    u32 version;
    u32 flags;
    u32 nr_modules;
    u64 modlist_paddr;
    u64 cmdline_paddr;
    u64 rsdp_paddr;
    u64 memmap_paddr;
    u32 memmap_entries;
    u32 reserved;
} *hvm_start_info;

typedef struct hvm_memmap_entry {
    u64 addr;
    u64 size;
    u32 type;
    u32 reserved;
} *hvm_memmap_entry;

extern u8 START, END;

range kern_get_elf(void)
{
    for_regions(e) {
        if (e->type == REGION_KERNIMAGE)
            return irangel(e->base, e->length);
    }
    return irange(INVALID_PHYSICAL, INVALID_PHYSICAL);
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

u64 machine_random_seed(void)
{
    u64 seed = 0;
    if (have_rdseed && hw_seed(&seed, true))
        return seed;
    if (have_rdrand && hw_seed(&seed, false))
        return seed;
    return 0;
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
            if (!pageheap_add_range(e->base, e->length))
                halt("%s: add range for physical heap failed (%R)\n",
                     func_ss, irange(e->base, e->base + e->length));
        }
    }
    /* we're done with looking at e820 (and our custom) regions, so
       release the initial map here */
    unmap(0, INITIAL_MAP_SIZE);

    unmap(u64_from_pointer(&START) - kas_kern_offset, pad(&END - &START, PAGESIZE));
}

void vm_shutdown(u8 code)
{
    QEMU_HALT(code);
}

void vm_reset(void)
{
    triple_fault();
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

closure_func_basic(madt_handler, void, count_processors_handler,
                   u8 type, void *p)
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

#endif

void count_cpus_present(void)
{
    /* Read ACPI tables for MADT access */
    init_acpi_tables(get_kernel_heaps());

#ifdef SMP_ENABLE
    if (acpi_walk_madt(stack_closure_func(madt_handler, count_processors_handler))) {
        init_debug("ACPI reports %d processors", present_processors);
        return;
    }
    msg_warn("ACPI MADT not found, default to 1 processor");
#endif

    present_processors = 1;
}

u64 xsave_features();

BSS_RO_AFTER_INIT static range initial_pages;

static void __attribute__((noinline)) init_service_new_stack()
{
    kernel_heaps kh = get_kernel_heaps();
    early_init_debug("in init_service_new_stack");

    for_regions(e) {
        switch (e->type) {
        case REGION_INITIAL_PAGES:
            unmap(e->base, INITIAL_PAGES_SIZE);
            break;
        case REGION_SMBIOS:
            smbios_entry_point = e->base;
            break;
        case REGION_RSDP:
            acpi_save_rsdp(e->base);
            break;
        }
    }

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

void init_physical_heap(void)
{
    /* Carve the bootstrap heap out of a physical memory region. */
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

            u64 base = pad(e->base, PAGESIZE);
            u64 end = e->base + e->length;
            u64 length = (end & ~MASK(PAGELOG)) - base;
            if (length >= BOOTSTRAP_SIZE) {
                map(BOOTSTRAP_BASE, base, BOOTSTRAP_SIZE, pageflags_writable(pageflags_memory()));
                e->base = base + BOOTSTRAP_SIZE;
                e->length = end - e->base;
                break;
            }
        }
    }

    boolean found = false;
    early_init_debug("physical memory:");
    for_regions(e) {
	if (e->type == REGION_PHYSICAL) {
	    u64 base = e->base;
	    u64 length = e->length;
	    if (length == 0)
		continue;
#ifdef INIT_DEBUG
	    early_debug("INIT:  [");
	    early_debug_u64(base);
	    early_debug(", ");
	    early_debug_u64(base + length);
	    early_debug(")\n");
#endif
	    if (!pageheap_add_range(base, length))
		halt("    - id_heap_add_range failed\n");
	    found = true;
	}
    }
    if (!found) {
	halt("no valid physical regions found; halt\n");
    }
}

static void setup_initmap(void)
{
    u64 kernel_size = u64_from_pointer(&END) - KERNEL_BASE_PHYS;
    region page_region = 0;
    for_regions(r) {
        if ((r->type == REGION_PHYSICAL) && (r->base <= KERNEL_BASE_PHYS) &&
                (r->base + r->length > KERNEL_BASE_PHYS)) {
            /* This is the memory region where the kernel has been loaded: adjust the region
             * boundaries so that the memory occupied by the kernel code does not appear as free
             * memory, and possibly and make a new memory region. */
            if (r->base < KERNEL_BASE_PHYS)
                create_region(r->base, KERNEL_BASE_PHYS - r->base, r->type);
            region_resize(r, r->base - pad(KERNEL_BASE_PHYS + kernel_size, PAGESIZE));

            page_region = r;
            break;
        }
    }
    assert(page_region);

    /* Fix up the initial mapping set up by the hypervisor in the first 1GB of virtual memory:
     * - set the 'user' and 'writable' flags on level 1 and level 2 page directory entries (AWS
     *   Firecracker v1.6.0 does not set the 'user' flag, thereby preventing pages referenced by
     *   these directory entries from being mapped for user space access)
     * - unmap the memory area above the kernel, so that new (and properly configured) PTEs will be
     *   used if any mappings are set up later in this area
     */
    u64 *pml4;
    mov_from_cr("cr3", pml4);
    pml4[0] |= PAGE_WRITABLE | PAGE_USER;
    u64 *pdpt = pointer_from_u64(pml4[0] & ~PAGE_FLAGS_MASK);
    pdpt[0] |= PAGE_WRITABLE | PAGE_USER;
    u64 *pdt = pointer_from_u64(pdpt[0] & ~PAGE_FLAGS_MASK);
    u64 offset = pad(u64_from_pointer(&END), PAGESIZE_2M) >> PAGELOG_2M;;
    zero(pdt + offset, PAGESIZE - offset * sizeof(*pdt));

    /* Set up initial mappings in the same way as stage2 does. */
    init_mmu();
    struct region_heap rh;
    region_heap_init(&rh, PAGESIZE, REGION_PHYSICAL);
    u64 initial_pages_base = allocate_u64(&rh.h, INITIAL_PAGES_SIZE);
    assert(initial_pages_base != INVALID_PHYSICAL);
    u64 map_base = initial_pages_base & ~MASK(PAGELOG_2M);
    map_setup_2mbpages(map_base, map_base,
                       pad(initial_pages_base - map_base + INITIAL_PAGES_SIZE, PAGESIZE_2M) >>
                       PAGELOG_2M, pageflags_writable(pageflags_memory()), page_region);
    create_region(initial_pages_base, INITIAL_PAGES_SIZE, REGION_INITIAL_PAGES);
}

// init linker set
void init_service(u64 rdi, u64 rsi)
{
    u8 *params = pointer_from_u64(rsi);
    const char *cmdline = 0;
    u32 cmdline_size;

    if (params && (*(u16 *)(params + BOOT_PARAM_OFFSET_BOOT_FLAG) == 0xAA55) &&
            (*(u32 *)(params + BOOT_PARAM_OFFSET_HEADER) == 0x53726448)) {
        /* The kernel has been loaded directly by the hypervisor, without going
         * through stage1 and stage2. */
        u8 e820_entries = *(params + BOOT_PARAM_OFFSET_E820_ENTRIES);
        region e820_r = (region)(params + BOOT_PARAM_OFFSET_E820_TABLE);
        for (u8 entry = 0; entry < e820_entries; entry++) {
            region r = &e820_r[entry];
            if (r->base == 0)
                continue;
            create_region(r->base, r->length, r->type);
        }

        cmdline = pointer_from_u64((u64)*((u32 *)(params +
                BOOT_PARAM_OFFSET_CMD_LINE_PTR)));
        cmdline_size = *((u32 *)(params + BOOT_PARAM_OFFSET_CMDLINE_SIZE));

        setup_initmap();
    }

    serial_init();
    early_init_debug("init_service");

    find_initial_pages();
    if (!pagebase)
        init_mmu();
    init_page_initial_map(pointer_from_u64(initial_pages.start), initial_pages);
    init_hwrand();
    kaslr();
    init_kernel_heaps();
    if (cmdline)
        create_region(u64_from_pointer(cmdline), cmdline_size, REGION_CMDLINE);
    u64 stack_size = 32*PAGESIZE;
    u64 stack_location = allocate_u64((heap)heap_page_backed(get_kernel_heaps()), stack_size);
    stack_location += stack_size - STACK_ALIGNMENT;
    *(u64 *)stack_location = 0;
    switch_stack(stack_location, init_service_new_stack);
}

void pvh_start(hvm_start_info start_info)
{
    if (start_info->magic != HVM_START_MAGIC_VALUE)
        return;
    regions->type = 0;
    hvm_memmap_entry mem_table = pointer_from_u64(start_info->memmap_paddr);
    for (int i = 0; i < start_info->memmap_entries; i++) {
        if (mem_table[i].type == HVM_MEMMAP_TYPE_RAM)
            create_region(mem_table[i].addr, mem_table[i].size, REGION_PHYSICAL);
    }
    setup_initmap();
    init_service(0, 0);
}

RO_AFTER_INIT static struct console_driver serial_console_driver = {
    .name = ss_static_init("serial"),
    .write = serial_console_write,
};

void init_platform_devices(kernel_heaps kh)
{
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
        virtio_mmio_enum_devs(kh);

        /* net */
        init_virtio_network(kh);
        init_vmxnet3_network(kh);
        init_aws_ena(kh);
        init_gve(kh);

        /* storage */
        init_virtio_blk(kh, sa);
        init_virtio_scsi(kh, sa);
        init_pvscsi(kh, sa);
        init_nvme(kh, sa);
        init_ata_pci(kh, sa);

        init_virtio_9p(kh);
        init_virtio_socket(kh);
    }

    /* misc / platform */
    init_acpi(kh);

    init_virtio_balloon(kh);
    init_virtio_rng(kh);
}

void cmdline_consume(sstring opt_name, cmdline_handler h)
{
    for_regions(e) {
        if (e->type == REGION_CMDLINE) {
            e->length = cmdline_parse(pointer_from_u64(e->base), e->length, opt_name, h);
            return;
        }
    }
}

void boot_params_apply(tuple t)
{
    for_regions(e) {
        if (e->type == REGION_CMDLINE) {
            cmdline_apply(pointer_from_u64(e->base), e->length, t);
            return;
        }
    }
}
