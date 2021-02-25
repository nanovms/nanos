#include <kernel.h>
#include <pagecache.h>
#include <tfs.h>
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

static char *hex_digits="0123456789abcdef";

/* TODO make generic / serial.h */
void early_debug(const char *s)
{
    while (*s != '\0')
        serial_putchar(*s++);
}

void early_debug_u64(u64 n)
{
    for (int x = 60; x >= 0; x -= 4)
        serial_putchar(hex_digits[(n >> x) & 0xf]);
}

void early_dump(void *p, unsigned long length)
{
    void *end = p + length;
    for (; p < end; p += 16) {
        early_debug_u64((unsigned long)p);
        early_debug(": ");

        for (int j = 0; j < 16; j++) {
            u8 b = *((u8 *)p + j);
            serial_putchar(hex_digits[(b >> 4) & 0xf]);
            serial_putchar(hex_digits[b & 0xf]);
            serial_putchar(b);
            serial_putchar(' ');
        }

        early_debug("| ");
        for (int j = 0; j < 16; j++) {
            char c = *((u8 *)p + j);
            serial_putchar((c >= ' ' && c < '~') ? c : '.');
        }
        early_debug(" |\n");
    }
    early_debug("\n");
}

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

#define BOOTSTRAP_REGION_SIZE (2 << 20)
static u8 bootstrap_region[BOOTSTRAP_REGION_SIZE];
static u64 bootstrap_base = (u64)bootstrap_region;
static u64 bootstrap_end = (u64)&bootstrap_region[BOOTSTRAP_REGION_SIZE];
static u64 bootstrap_alloc(heap h, bytes length)
{
    u64 result = bootstrap_base;
    if ((result + length) >= bootstrap_end) {
        rputs("*** bootstrap heap overflow! ***\n");
        print_u64(result + length);
        rputs("\n");
        print_u64(bootstrap_end);
        rputs("\n");

        return INVALID_PHYSICAL;
    }
    bootstrap_base += length;
    return result;
}

extern void *START, *END;
static id_heap init_physical_id_heap(heap h)
{
    id_heap physical = allocate_id_heap(h, h, PAGESIZE, true);
    init_debug("init_physical_id_heap\n");
    u64 kernel_size = pad(u64_from_pointer(&END) -
                          u64_from_pointer(&START), PAGESIZE);

    init_debug("init_setup_stack: kernel size ");
    init_debug_u64(kernel_size);

    u64 base = pad(KERNEL_PHYS + kernel_size, PAGESIZE_2M);
    u64 end = 0x80000000; // XXX 1G fixed til we can parse tree
    init_debug("\nfree base ");
    init_debug_u64(base);
    init_debug("\nend ");
    init_debug_u64(end);
    init_debug("\n");
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

extern filesystem root_fs;

extern void arm_hvc(u64 x0, u64 x1, u64 x2, u64 x3);
extern void angel_shutdown(u64 x0);

static void psci_shutdown(void)
{
    u32 psci_fn = 0x84000000 /* fn base */ + 0x8 /* system off */;
    arm_hvc(psci_fn, 0, 0, 0);
}

static inline void virt_shutdown(u64 code)
{
    if (root_fs) {
        tuple root = filesystem_getroot(root_fs);
        if (root && !table_find(root, sym(psci)))
            angel_shutdown(code);

    }
    psci_shutdown();
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
    buffer b = allocate_buffer(heap_general(get_kernel_heaps()), 512);
    if (b != INVALID_ADDRESS) {
        dump_mem_stats(b);
        buffer_print(b);
    }
#endif

#if 0
    /* TODO MP: coordinate via IPIs */
    tuple root = root_fs ? filesystem_getroot(root_fs) : 0;
    if (root && table_find(root, sym(reboot_on_exit))) {
        triple_fault();
    } else {
        QEMU_HALT(code);
    }
#endif
    virt_shutdown(code);
    while (1);
}

void halt(char *format, ...)
{
    vlist a;
    buffer b = little_stack_buffer(512);
    struct buffer f;
    f.start = 0;
    f.contents = format;
    f.end = runtime_strlen(format);

    vstart(a, format);
    vbprintf(b, &f, &a);
    buffer_print(b);
    kernel_shutdown(VM_EXIT_HALT);
}

u64 total_processors = 1;
u64 present_processors = 1;

void start_secondary_cores(kernel_heaps kh)
{
}

static void init_kernel_heaps(void)
{
    static struct heap bootstrap;
    bootstrap.alloc = bootstrap_alloc;
    bootstrap.dealloc = leak;

    kernel_heaps kh = get_kernel_heaps();
    kh->virtual_huge = create_id_heap(&bootstrap, &bootstrap, KMEM_BASE,
                                      KMEM_LIMIT - KMEM_BASE, HUGE_PAGESIZE, true);
    assert(kh->virtual_huge != INVALID_ADDRESS);

    kh->virtual_page = create_id_heap_backed(&bootstrap, &bootstrap, (heap)kh->virtual_huge, PAGESIZE, true);
    assert(kh->virtual_page != INVALID_ADDRESS);

    kh->physical = init_physical_id_heap(&bootstrap);
    assert(kh->physical != INVALID_ADDRESS);

    kh->backed = physically_backed(&bootstrap, (heap)kh->virtual_page, (heap)kh->physical, PAGESIZE, true);
    assert(kh->backed != INVALID_ADDRESS);

    kh->general = allocate_mcache(&bootstrap, (heap)kh->backed, 5, 20, PAGESIZE_2M);
    assert(kh->general != INVALID_ADDRESS);

    kh->locked = locking_heap_wrapper(&bootstrap,
        allocate_mcache(&bootstrap, (heap)kh->backed, 5, 20, PAGESIZE_2M));
    assert(kh->locked != INVALID_ADDRESS);
}

static void __attribute__((noinline)) init_service_new_stack(void)
{
    init_debug("in init_service_new_stack\n");
    kernel_heaps kh = get_kernel_heaps();
    page_heap_init(heap_locked(kh), heap_physical(kh));
    init_tuples(allocate_tagged_region(kh, tag_tuple));
    init_symbols(allocate_tagged_region(kh, tag_symbol), heap_general(kh));
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
    void *stack_base = allocate(heap_backed(get_kernel_heaps()), stack_size);
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

void __attribute__((noreturn)) start(void)
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

    init_debug("calling page_init_mmu with target ");
    init_debug_u64(u64_from_pointer(init_mmu_target));
    init_debug("\n");
    page_init_mmu(irangel(0x40200000, PAGESIZE_2M), u64_from_pointer(init_mmu_target));

    while (1);
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
}
