#include <kernel.h>
#include <page.h>
#include <apic.h>

//#define XAPIC_DEBUG
#ifdef XAPIC_DEBUG
#define xapic_debug(x, ...) do {log_printf("XAPIC", x, ##__VA_ARGS__);} while(0)
#else
#define xapic_debug(x, ...)
#endif

#define APIC_BASE        0xfee00000ull

/* x2-style offsets which get converted */
#define APIC_ICRL        0x830
#define APIC_ICRH        0x831

typedef struct xapic_iface {
    struct apic_iface i;
    heap h;
    u64 vbase;
} *xapic_iface;

static int xapic_from_x2apic_reg(int reg)
{
    return (reg & 0xff) << 4;
}

static void xapic_write(apic_iface i, int reg, u64 val)
{
    xapic_debug("write to reg 0x%x, val 0x%x\n", reg, val);
    assert(reg < APIC_LIMIT);
    assert((val & ~MASK(32)) == 0); /* 32 bit only on xapic */
    *(volatile u32 *)(((xapic_iface)i)->vbase +
                      xapic_from_x2apic_reg(reg)) = (u32)val;
}

static u64 xapic_read(apic_iface i, int reg)
{
//    rprintf("i %p, reg 0x%x -> 0x%x\n", i, reg, xapic_from_x2apic_reg(reg));
    assert(reg < APIC_LIMIT);
//    rprintf("addr %p\n", (volatile u32 *)(((xapic_iface)i)->vbase +
//                                          xapic_from_x2apic_reg(reg)));
    u32 d = *(volatile u32 *)(((xapic_iface)i)->vbase +
                              xapic_from_x2apic_reg(reg));
    xapic_debug("read from reg 0x%x: 0x%x\n", reg, d);
    return d;
}

#define XAPIC_READ_TIMEOUT_ITERS 512 /* arbitrary */
static void xapic_ipi(apic_iface i, u32 target, u64 flags, u8 vector)
{
    u64 w;
    u64 icr = (flags & ~0xff) | vector;
    
    if (target == TARGET_EXCLUSIVE_BROADCAST) {
        w = icr | ICR_DEST_ALL_EXC_SELF;
    } else {
        w = icr | (((u64)target) << 56);
    }
    
    xapic_debug("sending ipi: target 0x%x, flags 0x%lx, vector %d (icr 0x%lx)\n",
                target, flags, vector, w);
    xapic_write(i, APIC_ICRH, (w >> 32) & 0xffffffff);
    xapic_write(i, APIC_ICRL, w & 0xffffffff);
    for (int j = 0 ; j < XAPIC_READ_TIMEOUT_ITERS; j++) {
        if ((xapic_read(i, APIC_ICRL) & (1<<12)) == 0)
            return;
        kern_pause();
    }
    console("ipi timed out\n");
    return;
}

static boolean detect_and_init(apic_iface i, kernel_heaps kh)
{
    xapic_iface xi = (xapic_iface)i;
    /* assume we have it in the catch-all case - must be detected last */
    xi->vbase = allocate_u64((heap)heap_virtual_page(kh), PAGESIZE);
    assert(xi->vbase != INVALID_PHYSICAL);
    map(xi->vbase, APIC_BASE, PAGESIZE, PAGE_DEV_FLAGS, heap_pages(kh));
    return true;
}

struct apic_iface xapic_if = {
    "xapic",
    xapic_write,
    xapic_read,
    xapic_ipi,
    detect_and_init,
};

