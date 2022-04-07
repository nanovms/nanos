#include <kernel.h>
#include <drivers/console.h>
#include <pagecache.h>
#include <tfs.h>
#include <management.h>
#include <virtio/virtio.h>
#include "serial.h"

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

u64 random_seed(void)
{
    // XXX add qemu random device? virtio-rng-device?
    return rdtsc();
}

extern void *START, *END;

id_heap init_physical_id_heap(heap h)
{
    init_debug("init_physical_id_heap\n");
    u64 kernel_size = pad(u64_from_pointer(&END) -
                          u64_from_pointer(&START), PAGESIZE);

    init_debug("init_setup_stack: kernel size ");
    init_debug_u64(kernel_size);

    u64 base = KERNEL_PHYS + kernel_size;
    u64 end = PHYSMEM_BASE + 0x40000000; // XXX 1G fixed til we can parse tree
    u64 bootstrap_size = init_bootstrap_heap(end - base);
    map(BOOTSTRAP_BASE, base, bootstrap_size, pageflags_writable(pageflags_memory()));
    base = pad(base + bootstrap_size, PAGESIZE_2M);
    init_debug("\nfree base ");
    init_debug_u64(base);
    init_debug("\nend ");
    init_debug_u64(end);
    init_debug("\n");
    id_heap physical = allocate_id_heap(h, h, PAGESIZE, true);
    if (!id_heap_add_range(physical, base, end - base)) {
        halt("init_physical_id_heap: failed to add range %R\n",
             irange(base, end));
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

static inline void virt_shutdown(u64 code)
{
    disable_interrupts();
    if (code)
        code = (code<<16)|SYSCON_POWEROFF_FAIL;
    else
        code = SYSCON_POWEROFF;
    mmio_write_32(mmio_base_addr(SYSCON), code);
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
    tuple root = get_root_tuple();
    if (root) {
       u64 expected_code;
       if (get_u64(root, sym(expected_exit_code), &expected_code) &&
                expected_code == code)
            code = 0;
    }
    virt_shutdown(code);

    while (1) asm("wfi");
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

void (*init_mmu_target)(void) = &init_setup_stack;

void __attribute__((noreturn)) start(void *a0, void *dtb)
{
    init_debug("start\n\n");
#if 0
    init_debug("dtb:\n");
    init_dump(dtb, 0x100);
#endif

    init_debug("calling init_mmu with target ");
    init_debug_u64(u64_from_pointer(init_mmu_target));
    init_debug("\n");
    init_mmu(irange(INIT_PAGEMEM, pad(INIT_PAGEMEM,PAGESIZE_2M)), u64_from_pointer(init_mmu_target));

    while (1);
}

void init_platform_devices(kernel_heaps kh)
{
    RO_AFTER_INIT static struct console_driver serial_console_driver = {
        .name = "serial",
        .write = serial_console_write,
    };

    attach_console_driver(&serial_console_driver);
}

void detect_hypervisor(kernel_heaps kh)
{
}

void detect_devices(kernel_heaps kh, storage_attach sa)
{
    /* virtio only at the moment */
    init_virtio_network(kh);
    init_virtio_blk(kh, sa);
    init_virtio_scsi(kh, sa);
    init_virtio_balloon(kh);
}
