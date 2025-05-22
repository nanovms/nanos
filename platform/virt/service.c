#include <kernel.h>
#include <pagecache.h>
#include <pci.h>
#include <tfs.h>
#include <aws/aws.h>
#include <boot/uefi.h>
#include <drivers/acpi.h>
#include <drivers/console.h>
#include <drivers/dmi.h>
#include <drivers/gve.h>
#include <drivers/ns16550.h>
#include <drivers/nvme.h>
#include <management.h>
#include <virtio/virtio.h>
#include <devicetree.h>
#include <gic.h>
#include <gpio.h>
#include <hyperv_platform.h>
#include "serial.h"

#define SERIAL_16550_COMPATIBLE 0x00
#define SERIAL_16550_SUBSET     0x01
#define SERIAL_ARM_PL011        0x03
#define SERIAL_16550_WITH_GAS   0x12

//#define INIT_DEBUG
#ifdef INIT_DEBUG
#define init_debug early_debug
#define init_debug_u64 early_debug_u64
#define init_dump early_dump
#else
#define init_debug(s)
#define init_debug_u64(n)
#define init_dump(p, len)
#endif

static RO_AFTER_INIT u8 gpio_key_power = -1;

BSS_RO_AFTER_INIT struct uefi_boot_params boot_params;

u64 machine_random_seed(void)
{
#if 0 // gcc not taking +rng feature modifier...encode manually?
    if (field_from_u64(read_psr(ID_AA64ISAR0_EL1), ID_AA64ISAR0_EL1_RNDR)
        == ID_AA64ISAR0_EL1_RNDR_IMPLEMENTED) {
        return read_psr(RNDRRS);
    }
#endif
    return 0;
}

static void uefi_mem_map_iterate(uefi_mem_map mem_map, range_handler h)
{
    int num_desc = mem_map->map_size / mem_map->desc_size;
    for (int i = 0; i < num_desc; i++) {
        efi_memory_desc d = mem_map->map + i * mem_map->desc_size;
        switch (d->type) {
        case efi_loader_code:
        case efi_loader_data:
        case efi_boot_services_code:
        case efi_boot_services_data:
        case efi_conventional_memory:
            if (!apply(h, irangel(d->physical_start, d->number_of_pages * PAGESIZE)))
                return;
            break;
        default:
            break;
        }
    }
}

closure_function(2, 1, boolean, get_bootstrap_base,
                 range, rsvd, u64 *, base,
                 range r)
{
    range r1, r2;
    range_difference(r, bound(rsvd), &r1, &r2);
    if (range_span(r1) >= BOOTSTRAP_SIZE) {
        *bound(base) = r1.start;
        return false;
    }
    if (range_span(r2) >= BOOTSTRAP_SIZE) {
        *bound(base) = r2.start;
        return false;
    }
    return true;
}

static void add_heap_range_internal(range r, range *remainder)
{
    if (remainder) {
        if (range_empty(*remainder)) {
            /* Do not add the current range to the heap yet: it might be mergeable with the next
             * range. */
            remainder->start = r.start;
            remainder->end = r.end;
            return;
        }
        if (r.start == remainder->end) {
            /* Merge current range with remainder. */
            remainder->end = r.end;
            return;
        }
        /* The current range cannot be merged with the remainder: add the remainder to the heap and
         * make the current range the new remainder. */
        range tmp = r;
        r = *remainder;
        *remainder = tmp;
    }
    init_debug("adding range [0x");
    init_debug_u64(r.start);
    init_debug(" 0x");
    init_debug_u64(r.end);
    init_debug(")\n");
    pageheap_add_range(r.start, range_span(r));
}

static inline void add_heap_range_helper(range r, range rsvd, range *remainder)
{
    if (!range_empty(r)) {
        range r1, r2;
        range_difference(r, rsvd, &r1, &r2);
        if (!range_empty(r1))
            add_heap_range_internal(r1, remainder);
        if (!range_empty(r2))
            add_heap_range_internal(r2, remainder);
    }
}

closure_function(3, 1, boolean, add_heap_range,
                 range, rsvd1, range, rsvd2, range *, remainder,
                 range r)
{
    range *remainder = bound(remainder);
    range r1, r2;
    range_difference(r, bound(rsvd1), &r1, &r2);
    add_heap_range_helper(r1, bound(rsvd2), remainder);
    add_heap_range_helper(r2, bound(rsvd2), remainder);
    return true;
}

static u64 get_memory_size(void *dtb)
{
    range r = dtb_read_memory_range(dtb);
    if (r.start == INVALID_PHYSICAL)
        return 1*GB;
    return range_span(r);
}

extern void *START;
void init_physical_heap(void)
{
    init_debug("init_physical_heap\n");

    if (boot_params.mem_map.map) {
        u64 map_base = u64_from_pointer(boot_params.mem_map.map);
        u64 map_size = pad((map_base & PAGEMASK) + boot_params.mem_map.map_size, PAGESIZE);
        map_base &= ~PAGEMASK;
        /* map_base has been identity-mapped in ueft_rt_init_virt() */
        range reserved = irangel(PHYSMEM_BASE + kernel_phys_offset, INIT_IDENTITY_SIZE);
        u64 base = 0;
        uefi_mem_map_iterate(&boot_params.mem_map,
                             stack_closure(get_bootstrap_base, reserved, &base));
        init_debug("\nbootstrap base ");
        init_debug_u64(base);
        init_debug("\n");
        assert(!(base & PAGEMASK));
        map(kvmem.r.start, base, BOOTSTRAP_SIZE, pageflags_writable(pageflags_memory()));
        range remainder = irange(0, 0);
        uefi_mem_map_iterate(&boot_params.mem_map, stack_closure(add_heap_range, reserved,
                                                                 irangel(base, BOOTSTRAP_SIZE),
                                                                 &remainder));
        add_heap_range_internal(remainder, 0);
        unmap(map_base, map_size);
    } else {
        u64 base = PHYSMEM_BASE + INIT_IDENTITY_SIZE;
        u64 end = PHYSMEM_BASE + get_memory_size(pointer_from_u64(DEVICETREE_BLOB_BASE));
        map(kvmem.r.start, base, BOOTSTRAP_SIZE, pageflags_writable(pageflags_memory()));
        base += BOOTSTRAP_SIZE;
        init_debug("\nfree base ");
        init_debug_u64(base);
        init_debug("\nend ");
        init_debug_u64(end);
        init_debug("\n");
        if (!pageheap_add_range(base, end - base)) {
            halt("init_physical_heap: failed to add range %R\n",
                 irange(base, end));
        }
    }
}

range kern_get_elf(void)
{
    return irange(INVALID_PHYSICAL, INVALID_PHYSICAL);
}

void reclaim_regions(void)
{
}

closure_func_basic(halt_handler, void, psci_vm_halt,
                   int status)
{
    psci_shutdown();
}

void vm_shutdown(u8 code)
{
    angel_shutdown(code);
    while (1);
}

void vm_reset(void)
{
    psci_reset();
    while (1);  /* to honor noreturn attribute */
}

u64 total_processors = 1;
BSS_RO_AFTER_INIT u64 present_processors;

static void ueft_rt_init_virt(void)
{
    u64 virt_addr = KERNEL_BASE;
    uefi_mem_map mem_map = &boot_params.mem_map;
    u64 map_base = u64_from_pointer(mem_map->map);
    u64 map_size = pad((map_base & PAGEMASK) + mem_map->map_size, PAGESIZE);
    map_base &= ~PAGEMASK;
    pageflags flags = pageflags_writable(pageflags_memory());
    map(map_base, map_base, map_size, flags);   /* will be unmapped in init_physical_heap() */
    int num_desc = mem_map->map_size / mem_map->desc_size;
    u64 rt_svc_offset = 0;
    for (int i = 0; i < num_desc; i++) {
        efi_memory_desc d = mem_map->map + i * mem_map->desc_size;
        if (d->type == efi_runtime_services_data) {
            u64 phys_addr = d->physical_start;
            u64 mem_len = d->number_of_pages * PAGESIZE;
            map(phys_addr, phys_addr, mem_len, flags);
            virt_addr -= mem_len;
            init_debug("UEFI runtime services data at ");
            init_debug_u64(phys_addr);
            init_debug(", length ");
            init_debug_u64(mem_len);
            init_debug(", mapping at ");
            init_debug_u64(virt_addr);
            init_debug("\n");
            map(virt_addr, phys_addr, mem_len, flags);
            d->virtual_start = pointer_from_u64(virt_addr);
            if (point_in_range(irangel(phys_addr, mem_len),
                               u64_from_pointer(boot_params.efi_rt_svc)))
                rt_svc_offset = virt_addr - phys_addr;
        }
    }
    flags = pageflags_exec(pageflags_memory());

    /* set_virtual_address_map() needs write access to code memory */
    pageflags temp_flags = pageflags_writable(flags);

    for (int i = 0; i < num_desc; i++) {
        efi_memory_desc d = mem_map->map + i * mem_map->desc_size;
        if ((d->attribute & EFI_MEMORY_RUNTIME) == EFI_MEMORY_RUNTIME) {
            u64 phys_addr = d->physical_start;
            u32 mem_type = d->type;
            if (mem_type == efi_memory_mapped_io) { /* already mapped */
                d->virtual_start = pointer_from_u64(DEVICE_BASE + (phys_addr & (DEV_MAP_SIZE - 1)));
                continue;
            } else if (mem_type == efi_runtime_services_code) {
                u64 mem_len = d->number_of_pages * PAGESIZE;
                map(phys_addr, phys_addr, mem_len, temp_flags);
                virt_addr -= mem_len;
                init_debug("UEFI runtime services code at ");
                init_debug_u64(phys_addr);
                init_debug(", length ");
                init_debug_u64(mem_len);
                init_debug(", mapping at ");
                init_debug_u64(virt_addr);
                init_debug("\n");
                d->virtual_start = pointer_from_u64(virt_addr);
                map(virt_addr, phys_addr, mem_len, flags);
            }
        }
    }
    efi_set_virtual_address_map svam = boot_params.efi_rt_svc->set_virtual_address_map;
    assert(svam(mem_map->map_size, mem_map->desc_size, mem_map->desc_version, mem_map->map) ==
           EFI_SUCCESS);

    /* From now on, runtime services will only use virtual addresses: unmap physical addresses. */
    for (int i = 0; i < num_desc; i++) {
        efi_memory_desc d = mem_map->map + i * mem_map->desc_size;
        u32 mem_type = d->type;
        if ((mem_type == efi_runtime_services_code) || (mem_type == efi_runtime_services_data)) {
            unmap(d->physical_start, d->number_of_pages * PAGESIZE);
        }
    }
    boot_params.efi_rt_svc = (void *)boot_params.efi_rt_svc + rt_svc_offset;
}

static void __attribute__((noinline)) init_service_new_stack(void)
{
    init_debug("in init_service_new_stack\n");
    kernel_heaps kh = get_kernel_heaps();
    init_debug("calling runtime init\n");
    kernel_runtime_init(kh);
    while(1);
}

static void init_setup_stack(void)
{
    serial_set_devbase(DEVICE_BASE);
#if 0
    devicetree_dump(pointer_from_u64(DEVICETREE_BLOB_BASE));
#endif
    if (boot_params.mem_map.map)
        ueft_rt_init_virt();
    kaslr();
    kaslr_fixup_rtc();  /* needed because the RTC is initialized before KASLR */
    init_debug("in init_setup_stack, calling init_kernel_heaps\n");
    init_kernel_heaps();
    init_debug("allocating stack\n");
    u64 stack_size = 32 * PAGESIZE;
    void *stack_base = allocate((heap)heap_page_backed(get_kernel_heaps()), stack_size);
    assert(stack_base != INVALID_ADDRESS);
    init_debug("stack base at ");
    init_debug_u64(u64_from_pointer(stack_base));
    init_debug("\n");
    void *stack_top = stack_base + stack_size - STACK_ALIGNMENT;
    init_debug("stack top at ");
    init_debug_u64(u64_from_pointer(stack_top));
    init_debug("\n");
    *(u64 *)stack_top = 0;
    init_debug("wrote\n");
    switch_stack(stack_top, init_service_new_stack);
}

extern void *bss_start;
extern void *bss_end;

void __attribute__((noreturn)) start(u64 x0, u64 x1)
{
    /* clear bss */
    u64 *p = pointer_from_u64((void *)&bss_start);
    u64 *end = pointer_from_u64((void *)&bss_end);
    do {
        p[0] = 0;
        p[1] = 0;
        p[2] = 0;
        p[3] = 0;
        p += 4;
    } while (p < end);

    init_debug("start\n\n");
    kernel_phys_offset = u64_from_pointer(&START) - KERNEL_PHYS;
    u64 device_base = 0;
    if (x1) {
        struct uefi_boot_params *params = pointer_from_u64(x1);
        smbios_entry_point = params->smbios;
        uefi_mem_map mem_map = &params->mem_map;
        int num_desc = mem_map->map_size / mem_map->desc_size;
        for (int i = 0; i < num_desc; i++) {
            efi_memory_desc d = mem_map->map + i * mem_map->desc_size;
            if (d->type == efi_memory_mapped_io) {
                device_base = d->physical_start & ~(DEV_MAP_SIZE - 1);
                break;
            }
        }
        runtime_memcpy(&boot_params, params, sizeof(boot_params));
    }

    init_debug("calling init_mmu\n");
    init_mmu(device_base, u64_from_pointer(init_setup_stack));

    while (1);
}

closure_func_basic(thunk, void, gpio_key_handler)
{
    kernel_powerdown();
    gpio_irq_clear(U64_FROM_BIT(gpio_key_power));
}

static void platform_dtb_parse(kernel_heaps kh, vector cpu_ids)
{
    struct fdt fdt;
    if (!dtb_parse_init(pointer_from_u64(DEVICETREE_BLOB_BASE + kernel_phys_offset), &fdt))
        return;
    dt_node root = fdt_get_node(&fdt);
    if (!root)
        return;
    u32 root_acells, root_scells;
    fdt_get_cells(&fdt, &root_acells, &root_scells);
    fdt_foreach_node(&fdt, node) {
        sstring name = fdt_node_name(&fdt, node);
        if (runtime_strstr(name, ss("pcie@")) == name.ptr) {
            dt_reg_iterator iter;
            if (fdt_get_reg(&fdt, root_acells, root_scells, &iter)) {
                dt_reg_foreach(iter, r){
                    u64 ecam_base = r.start;
                    boolean highmem = (ecam_base >= (U64_FROM_BIT(32)));
                    u64 ecam_base_virt;
                    if (highmem) {
                        u64 ecam_len = range_span(r);
                        ecam_base_virt = allocate_u64((heap)heap_virtual_page(kh), ecam_len);
                        assert(ecam_base_virt != INVALID_PHYSICAL);
                        map(ecam_base_virt, ecam_base, ecam_len,
                            pageflags_writable(pageflags_device()));
                    } else {
                        ecam_base_virt = DEVICE_BASE + (ecam_base & (DEV_MAP_SIZE - 1));
                    }
                    pci_platform_set_ecam(ecam_base_virt);
                    break;
                }
            }
        } else if (!runtime_strcmp(name, ss("cpus"))) {
            u32 cpus_acells, cpus_scells;
            fdt_get_cells(&fdt, &cpus_acells, &cpus_scells);
            fdt_foreach_node(&fdt, node) {
                dt_reg_iterator iter;
                if (fdt_get_reg(&fdt, cpus_acells, cpus_scells, &iter)) {
                    dt_reg_foreach(iter, r) {
                        present_processors++;
                        vector_push(cpu_ids, pointer_from_u64(r.start));
                        break;
                    }
                }
            }
        } else if (!runtime_strcmp(name, ss("gpio-keys"))) {
            fdt_foreach_node(&fdt, node) {
                if (!runtime_strcmp(fdt_node_name(&fdt, node), ss("poweroff"))) {
                    dt_prop gpio_prop = fdt_get_prop(&fdt, ss("gpios"));
                    if ((gpio_prop != INVALID_ADDRESS) &&
                        (dt_prop_cell_count(gpio_prop) >= 2))
                        /* cell #0: phandle of GPIO controller
                         * cell #1: GPIO number
                         */
                        gpio_key_power = dt_prop_get_cell(gpio_prop, 1);
                }
            }
        }
    }
}

closure_function(2, 2, void, plat_spcr_handler,
                 kernel_heaps, kh, struct console_driver **, driver,
                 u8 type, u64 addr)
{
    switch (type) {
    case SERIAL_16550_COMPATIBLE:
    case SERIAL_16550_SUBSET:
    case SERIAL_16550_WITH_GAS:
        *bound(driver) = ns16550_console_init(bound(kh),
            pointer_from_u64(DEVICE_BASE + (addr & (DEV_MAP_SIZE - 1))));
        break;
    case SERIAL_ARM_PL011:
        *bound(driver) = pl011_console_init(bound(kh),
            pointer_from_u64(DEVICE_BASE + (addr & (DEV_MAP_SIZE - 1))));
        break;
    }
}

void init_platform_devices(kernel_heaps kh)
{
    vector cpu_ids = cpus_init_ids(heap_general(kh));
    platform_dtb_parse(kh, cpu_ids);
    /* the device tree blob is never accessed from now on: reclaim the memory where it is located */
    pageheap_add_range(DEVICETREE_BLOB_BASE + kernel_phys_offset,
                      INIT_PAGEMEM - DEVICETREE_BLOB_BASE);
    struct console_driver *console_driver = 0;
    init_acpi_tables(kh);
    acpi_parse_spcr(stack_closure(plat_spcr_handler, kh, &console_driver));
    if (!console_driver) {
        console_driver = allocate_zero(heap_general(kh), sizeof(*console_driver));
        console_driver->name = ss("serial");
        console_driver->write = serial_console_write;
    }
    attach_console_driver(console_driver);
    pci_platform_init();
}

void detect_hypervisor(kernel_heaps kh)
{
    if (hyperv_detect(kh)) {
        init_debug("Hyper-V detected\n");
    }
}

void detect_devices(kernel_heaps kh, storage_attach sa)
{
    if (gpio_key_power != (typeof(gpio_key_power))-1) {
        thunk handler = closure_func(heap_locked(kh), thunk, gpio_key_handler);
        assert(handler != INVALID_ADDRESS);
        irq_register_handler(GIC_SPI_INTS_START + VIRT_GPIO_IRQ, handler, ss("gpio-keys"),
                             irange(0, 0));
        gpio_irq_enable(U64_FROM_BIT(gpio_key_power));
    }
    init_acpi(kh);
    if (hyperv_detected()) {
        boolean hv_storvsc_attached = false;
        init_vmbus(kh);
        status s = hyperv_probe_devices(sa, &hv_storvsc_attached);
        if (!is_ok(s))
            halt("Hyper-V probe failed: %v\n", s);
        if (!hv_storvsc_attached)
            msg_err("Hyper-V: cannot detect storage device");
    } else {
        init_virtio_network(kh);
        init_aws_ena(kh);
        init_gve(kh);
        init_virtio_blk(kh, sa);
        init_virtio_scsi(kh, sa);
        init_nvme(kh, sa);
        init_virtio_balloon(kh);
        init_virtio_rng(kh);
        init_virtio_9p(kh);
        init_virtio_socket(kh);
    }
    if (!vm_halt) {
        vm_halt = closure_func(heap_locked(kh), halt_handler, psci_vm_halt);
        assert(vm_halt != INVALID_ADDRESS);
    }
}
