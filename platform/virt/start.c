/* just a test */
#include <kernel.h>
#include <page.h>
#include "serial.h"
#include <drivers/console.h> // XXX

#define START_DEBUG
#ifdef START_DEBUG
#define start_debug early_debug
#define start_debug_u64 early_debug_u64
#define start_dump early_dump
#else
#define start_debug(s)
#define start_debug_u64(n)
#define start_dump(p, len)
#endif

#define TAG_HEAP_DEBUG
#ifdef TAG_HEAP_DEBUG
#define tag_debug(x, ...) do {rprintf("%s: " x, __func__, ##__VA_ARGS__);} while(0)
#else
#define tag_debug(x, ...)
#endif

boolean runtime_initialized = false;

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
            serial_putchar((c >= ' ' && c < '~') ? *((u8 *)p + j) : '.');
        }
        early_debug(" |\n");
    }
    early_debug("\n");
}

void halt(char *format, ...)
{
    early_debug(format);
    while(1);
}

// XXX TODO stubs...
void print_stack_from_here(void)
{
    
}

void vga_pci_register(kernel_heaps kh, console_attach a)
{
}
    
u64 random_seed(void)
{
    return 1;
}

struct tagheap {
    struct heap h;
    heap mh;
    u64 vtag;
};

static void tag_dealloc(heap h, u64 a, bytes s)
{
    struct tagheap *th = (struct tagheap *)h;
    tag_debug("%s: tag %d, a 0x%lx, s 0x%lx\n", __func__, th->vtag >> VA_TAG_OFFSET, a, s);
    deallocate_u64(th->mh, a & MASK(48), s);
}

static u64 tag_alloc(heap h, bytes s)
{
    struct tagheap *th = (struct tagheap *)h;
    void *p = allocate(th->mh, s);
    if (p == INVALID_ADDRESS)
        return INVALID_PHYSICAL;
    u64 a = u64_from_pointer(p);
    assert((a >> VA_TAG_OFFSET) == 0xff);
    a |= th->vtag;
    tag_debug("%s: tag %d, s 0x%lx, a 0x%lx\n", __func__, th->vtag >> VA_TAG_OFFSET, s, a);
    return a;
}

// XXX TODO move to src/aarch64/
static heap allocate_tagged_region(kernel_heaps kh, u64 tag)
{
    heap h = heap_general(kh);
    struct tagheap *th = allocate(h, sizeof(struct tagheap));
    if (th == INVALID_ADDRESS)
        return INVALID_ADDRESS;
    assert(tag < 256);
    th->mh = h;
    th->vtag = tag << VA_TAG_OFFSET;
    th->h.alloc = tag_alloc;
    th->h.dealloc = tag_dealloc;
    th->h.destroy = 0;
    th->h.pagesize = 32; // XXX
    th->h.allocated = 0;
    th->h.total = 0;
    tag_debug("%s: tag %d, bits 0x%lx, heap %p\n", __func__, tag, th->vtag, th);
    return &th->h;
}

static struct kernel_heaps heaps;

#define BOOTSTRAP_REGION_SIZE (2 << 20)
static u8 bootstrap_region[BOOTSTRAP_REGION_SIZE];
static u64 bootstrap_base = (u64)bootstrap_region;
static u64 bootstrap_end = (u64)&bootstrap_region[BOOTSTRAP_REGION_SIZE];
static u64 bootstrap_alloc(heap h, bytes length)
{
    u64 result = bootstrap_base;
    if ((result + length) >= bootstrap_end) {
	console("*** bootstrap heap overflow! ***\n");
        print_u64(result + length);
        console("\n");
        print_u64(bootstrap_end);
        console("\n");
        
        return INVALID_PHYSICAL;
    }
    bootstrap_base += length;
    return result;
}

extern void *START, *END;
static id_heap init_physical_id_heap(heap h)
{
    id_heap physical = allocate_id_heap(h, h, PAGESIZE);
    start_debug("init_physical_id_heap\n");
    u64 kernel_size = pad(u64_from_pointer(&END) -
                          u64_from_pointer(&START), PAGESIZE);
    
    start_debug("init_setup_stack: kernel size ");
    start_debug_u64(kernel_size);

    u64 base = KERNEL_PHYS + kernel_size;
    u64 end = 0x80000000; // XXX 1G fixed til we can parse tree
    start_debug("\nfree base ");
    start_debug_u64(base);
    start_debug("\nend ");
    start_debug_u64(end);
    start_debug("\n");
    if (!id_heap_add_range(physical, base, end - base)) {
        halt("init_physical_id_heap: failed to add range %R\n",
             irange(base, end));
    }
    return physical;
}

id_heap init_phys_heap(heap h, id_heap physical);

static void init_kernel_heaps(void)
{
    static struct heap bootstrap;
    bootstrap.alloc = bootstrap_alloc;
    bootstrap.dealloc = leak;

    heaps.virtual_huge = create_id_heap(&bootstrap, &bootstrap, KMEM_BASE,
                                        KMEM_LIMIT - KMEM_BASE, HUGE_PAGESIZE);
    assert(heaps.virtual_huge != INVALID_ADDRESS);

    heaps.virtual_page = create_id_heap_backed(&bootstrap, &bootstrap, (heap)heaps.virtual_huge, PAGESIZE);
    assert(heaps.virtual_page != INVALID_ADDRESS);

    heaps.physical = init_phys_heap(&bootstrap, init_physical_id_heap(&bootstrap));
    assert(heaps.physical != INVALID_ADDRESS);

    heaps.backed = physically_backed(&bootstrap, (heap)heaps.virtual_page, (heap)heaps.physical, PAGESIZE);
    assert(heaps.backed != INVALID_ADDRESS);

    heaps.general = allocate_mcache(&bootstrap, heaps.backed, 5, 20, PAGESIZE_2M);
    assert(heaps.general != INVALID_ADDRESS);
}

static void __attribute__((noinline)) init_service_new_stack(void)
{
    start_debug("in init_service_new_stack\n");
    init_tuples(allocate_tagged_region(&heaps, tag_tuple));
    init_symbols(allocate_tagged_region(&heaps, tag_symbol), heap_general(&heaps));

//    start_debug("foo...\n");
//    void *mmio = dev_base_pointer(PCIE_MMIO) + 4;
//    start_debug_u64(u64_from_pointer(mmio));
//    start_debug("...\n");
//    start_debug_u64(*(u32*)mmio);
//    start_debug("done...\n");

    kernel_runtime_init(&heaps);
    while(1);
}

void init_setup_stack(void)
{
    serial_set_devbase(DEVICE_BASE);
    start_debug("in init_setup_stack, calling init_kernel_heaps\n");
    init_kernel_heaps();
    start_debug("allocating stack\n");
    u64 stack_size = 32 * PAGESIZE;
    void *stack_base = allocate(heap_backed(&heaps), stack_size);
    assert(stack_base != INVALID_ADDRESS);
    start_debug("stack base at ");
    start_debug_u64(u64_from_pointer(stack_base));
    start_debug("\n");
    void *stack_top = stack_base + stack_size - STACK_ALIGNMENT;
    start_debug("stack top at ");
    start_debug_u64(u64_from_pointer(stack_top));
    start_debug("\n");
    *(u64 *)stack_top = 0;
    start_debug("wrote\n");
    switch_stack(stack_top, init_service_new_stack);
}

/* avoids pc-relative immediate (must not be static) */
void (*init_mmu_target)(void) = &init_setup_stack;

extern void *bss_start;
extern void *bss_end;
extern void *LOAD_OFFSET;

int start(void)
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

    start_debug("start\n\n");
#if 1
    start_debug("TCR_EL1: ");
    start_debug_u64(read_psr(TCR_EL1));
    start_debug("\nTTBR0_EL1: ");
    start_debug_u64(read_psr(TTBR0_EL1));
    start_debug("\nID_AA64MMFR0_EL1: ");
    start_debug_u64(read_psr(ID_AA64MMFR0_EL1));
    start_debug("\nCPACR_EL1: ");
    start_debug_u64(read_psr(CPACR_EL1));
    start_debug("\n");
#endif
//    write_psr(CPACR_EL1, mask_and_set_field(read_psr(CPACR_EL1), CPACR_EL1_FPEN,
//                                            CPACR_EL1_FPEN_NO_TRAP));
#if 0
    start_debug("dtb:\n");
    start_dump(pointer_from_u64(0x40000000), 0x100);
#endif

//    u64 vtarget = u64_from_pointer(init_mmu_target) + u64_from_pointer(&LOAD_OFFSET);
    start_debug("calling page_init_mmu with target ");
    start_debug_u64(u64_from_pointer(init_mmu_target));
    start_debug("\n");
    page_init_mmu(irangel(0x40200000, PAGESIZE_2M), u64_from_pointer(init_mmu_target));

    while (1) ;
    return 0;
}
