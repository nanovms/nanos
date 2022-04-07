#include <kernel.h>
#include <pagecache.h>
#include <pci.h>
#include <tfs.h>
#include <aws/aws.h>
#include <boot/uefi.h>
#include <drivers/acpi.h>
#include <drivers/console.h>
#include <drivers/ns16550.h>
#include <drivers/nvme.h>
#include <management.h>
#include <virtio/virtio.h>
#include "serial.h"

#define SERIAL_16550_COMPATIBLE 0x00
#define SERIAL_16550_SUBSET     0x01
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

BSS_RO_AFTER_INIT struct uefi_boot_params boot_params;

u64 random_seed(void)
{
#if 0 // gcc not taking +rng feature modifier...encode manually?
    if (field_from_u64(read_psr(ID_AA64ISAR0_EL1), ID_AA64ISAR0_EL1_RNDR)
        == ID_AA64ISAR0_EL1_RNDR_IMPLEMENTED) {
        return read_psr(RNDRRS);
    }
#endif
    /* likely not a good fallback - look for another */
    return rdtsc();
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
            apply(h, irangel(d->physical_start, d->number_of_pages * PAGESIZE));
            break;
        default:
            break;
        }
    }
}

closure_function(1, 1, void, get_mem_size,
                 u64 *, mem_size,
                 range, r)
{
    *bound(mem_size) += range_span(r);
}

closure_function(3, 1, void, get_bootstrap_base,
                 range, rsvd, u64, bootstrap_size, u64 *, base,
                 range, r)
{
    if (!*bound(base)) {
        u64 bootstrap_size = bound(bootstrap_size);
        range r1, r2;
        range_difference(r, bound(rsvd), &r1, &r2);
        if (range_span(r1) >= bootstrap_size)
            *bound(base) = r1.start;
        else if (range_span(r2) >= bootstrap_size)
            *bound(base) = r2.start;
    }
}

static void add_heap_range_internal(id_heap h, range r, range *remainder)
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
    r.start = pad(r.start, PAGESIZE_2M);
    if (r.start >= r.end)
        return;
    init_debug("adding range [0x");
    init_debug_u64(r.start);
    init_debug(" 0x");
    init_debug_u64(r.end);
    init_debug(")\n");
    id_heap_add_range(h, r.start, range_span(r));
}

static inline void add_heap_range_helper(id_heap h, range r, range rsvd, range *remainder)
{
    if (!range_empty(r)) {
        range r1, r2;
        range_difference(r, rsvd, &r1, &r2);
        if (!range_empty(r1))
            add_heap_range_internal(h, r1, remainder);
        if (!range_empty(r2))
            add_heap_range_internal(h, r2, remainder);
    }
}

closure_function(4, 1, void, add_heap_range,
                 id_heap, h, range, rsvd1, range, rsvd2, range *, remainder,
                 range, r)
{
    id_heap h = bound(h);
    range *remainder = bound(remainder);
    range r1, r2;
    range_difference(r, bound(rsvd1), &r1, &r2);
    add_heap_range_helper(h, r1, bound(rsvd2), remainder);
    add_heap_range_helper(h, r2, bound(rsvd2), remainder);
}

extern void *START, *END;
id_heap init_physical_id_heap(heap h)
{
    init_debug("init_physical_id_heap\n");
    u64 kernel_size = pad(u64_from_pointer(&END) -
                          u64_from_pointer(&START), PAGESIZE);

    init_debug("init_setup_stack: kernel size ");
    init_debug_u64(kernel_size);

    id_heap physical;
    if (boot_params.mem_map.map) {
        u64 map_base = u64_from_pointer(boot_params.mem_map.map);
        u64 map_size = pad((map_base & PAGEMASK) + boot_params.mem_map.map_size, PAGESIZE);
        map_base &= ~PAGEMASK;
        map(map_base, map_base, map_size, pageflags_memory());
        u64 mem_size = 0;
        uefi_mem_map_iterate(&boot_params.mem_map, stack_closure(get_mem_size, &mem_size));
        init_debug("\nmem size ");
        init_debug_u64(mem_size);
        u64 bootstrap_size = init_bootstrap_heap(mem_size);
        range reserved = irange(INIT_PAGEMEM, KERNEL_PHYS + kernel_size);
        u64 base = 0;
        uefi_mem_map_iterate(&boot_params.mem_map,
                             stack_closure(get_bootstrap_base, reserved, bootstrap_size, &base));
        init_debug("\nbootstrap base ");
        init_debug_u64(base);
        init_debug(", size ");
        init_debug_u64(bootstrap_size);
        init_debug("\n");
        assert(!(base & PAGEMASK));
        map(BOOTSTRAP_BASE, base, bootstrap_size, pageflags_writable(pageflags_memory()));
        physical = allocate_id_heap(h, h, PAGESIZE, true);
        range remainder = irange(0, 0);
        uefi_mem_map_iterate(&boot_params.mem_map, stack_closure(add_heap_range, physical, reserved,
                                                                 irangel(base, bootstrap_size),
                                                                 &remainder));
        add_heap_range_internal(physical, remainder, 0);
        unmap(map_base, map_size);
    } else {
        u64 base = KERNEL_PHYS + kernel_size;
        u64 end = 0x80000000; // XXX 1G fixed til we can parse tree
        u64 bootstrap_size = init_bootstrap_heap(end - base);
        map(BOOTSTRAP_BASE, base, bootstrap_size, pageflags_writable(pageflags_memory()));
        base = pad(base + bootstrap_size, PAGESIZE_2M);
        init_debug("\nfree base ");
        init_debug_u64(base);
        init_debug("\nend ");
        init_debug_u64(end);
        init_debug("\n");
        physical = allocate_id_heap(h, h, PAGESIZE, true);
        if (!id_heap_add_range(physical, base, end - base)) {
            halt("init_physical_id_heap: failed to add range %R\n",
                 irange(base, end));
        }
    }
    return physical;
}

void read_kernel_syms(void)
{
    // XXX TODO
}

void reclaim_regions(void)
{
}

extern filesystem root_fs;

static inline void virt_shutdown(u64 code)
{
    if (root_fs) {
        tuple root = get_root_tuple();
        if (root) {
            u64 expected_code;
            if (get_u64(root, sym(expected_exit_code), &expected_code) &&
                    expected_code == code)
                code = 0;
            if (!get(root, sym(psci)))
                angel_shutdown(code);
        }
    }
    psci_shutdown();
}

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

#if 0
    /* TODO MP: coordinate via IPIs */
    tuple root = get_root_tuple();
    if (root && get(root, sym(reboot_on_exit))) {
        triple_fault();
    } else {
        QEMU_HALT(code);
    }
#endif
    virt_shutdown(code);
    while (1);
}

u64 total_processors = 1;
u64 present_processors = 1;

void start_secondary_cores(kernel_heaps kh)
{
}

void count_cpus_present(void)
{
}

static void __attribute__((noinline)) init_service_new_stack(void)
{
    init_debug("in init_service_new_stack\n");
    kernel_heaps kh = get_kernel_heaps();
    init_page_tables((heap)heap_linear_backed(kh));
    /* mmu init complete; unmap temporary identity map */
    unmap(PHYSMEM_BASE, INIT_IDENTITY_SIZE);
    bytes pagesize = is_low_memory_machine(kh) ? PAGESIZE : PAGESIZE_2M;
    init_tuples(locking_heap_wrapper(heap_general(kh),
                allocate_tagged_region(kh, tag_table_tuple, pagesize)));
    init_symbols(allocate_tagged_region(kh, tag_symbol, pagesize), heap_locked(kh));
    init_management(allocate_tagged_region(kh, tag_function_tuple, pagesize), heap_general(kh));
    init_debug("calling runtime init\n");
    kernel_runtime_init(kh);
    while(1);
}

void init_setup_stack(void)
{
    serial_set_devbase(DEVICE_BASE);
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

/* avoids pc-relative immediate (must not be static) */
void (*init_mmu_target)(void) = &init_setup_stack;

extern void *bss_start;
extern void *bss_end;
extern void *LOAD_OFFSET;

void __attribute__((noreturn)) start(u64 x0, u64 x1)
{
    /* clear bss */
    u64 *p = pointer_from_u64((void *)&bss_start - (void *)&LOAD_OFFSET);
    u64 *end = pointer_from_u64((void *)&bss_end - (void *)&LOAD_OFFSET);
    do {
        p[0] = 0;
        p[1] = 0;
        p[2] = 0;
        p[3] = 0;
        p += 4;
    } while (p < end);

    init_debug("start\n\n");
#if 0
    init_debug("dtb:\n");
    init_dump(pointer_from_u64(0x40000000), 0x100);
#endif
    if (x1) {
        struct uefi_boot_params *params = pointer_from_u64(x1);
        runtime_memcpy(&boot_params, params, sizeof(boot_params));
    }

    init_debug("calling init_mmu with target ");
    init_debug_u64(u64_from_pointer(init_mmu_target));
    init_debug("\n");
    init_mmu(irangel(INIT_PAGEMEM, PAGESIZE_2M), u64_from_pointer(init_mmu_target));

    while (1);
}

closure_function(2, 2, void, plat_spcr_handler,
                 kernel_heaps, kh, struct console_driver **, driver,
                 u8, type, u64, addr)
{
    switch (type) {
    case SERIAL_16550_COMPATIBLE:
    case SERIAL_16550_SUBSET:
    case SERIAL_16550_WITH_GAS:
        *bound(driver) = ns16550_console_init(bound(kh), pointer_from_u64(DEVICE_BASE + addr));
        break;
    }
}

void init_platform_devices(kernel_heaps kh)
{
    struct console_driver *console_driver = 0;
    init_acpi_tables(kh);
    acpi_parse_spcr(stack_closure(plat_spcr_handler, kh, &console_driver));
    if (!console_driver) {
        console_driver = allocate_zero(heap_general(kh), sizeof(*console_driver));
        console_driver->name = "serial";
        console_driver->write = serial_console_write;
    }
    attach_console_driver(console_driver);
    pci_platform_init();
}

void detect_hypervisor(kernel_heaps kh)
{
}

void detect_devices(kernel_heaps kh, storage_attach sa)
{
    init_virtio_network(kh);
    init_aws_ena(kh);
    init_virtio_blk(kh, sa);
    init_virtio_scsi(kh, sa);
    init_nvme(kh, sa);
    init_virtio_balloon(kh);
}
