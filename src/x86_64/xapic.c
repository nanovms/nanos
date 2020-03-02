#include <kernel.h>
#include <page.h>
#include <apic.h>

//#define XAPIC_DEBUG
#ifdef XAPIC_DEBUG
#define xapic_debug(x, ...) do {rprintf("xAPIC: " x, ##__VA_ARGS__);} while(0)
#else
#define xapic_debug(x, ...)
#endif

#define APIC_BASE        0xfee00000ull

/* x2-style offsets which get converted */
#define APIC_ICRL        0x830
#define APIC_ICRH        0x831

#define APIC_ICRL_DELIVERY_STATUS (1 << 12)

static u64 xapic_vbase;

static u64 xapic_from_x2apic_reg(int reg)
{
    assert(reg < APIC_LIMIT);
    return (reg & 0xff) << 4;
}

static void xapic_write(apic_iface i, int reg, u64 val)
{
    xapic_debug("write to reg 0x%x, val 0x%x\n", reg, val);
    assert((val & ~MASK(32)) == 0); /* 32 bit only on xapic */
    *(volatile u32 *)(xapic_vbase + xapic_from_x2apic_reg(reg)) = (u32)val;
}

static u64 xapic_read(apic_iface i, int reg)
{
    xapic_debug("read from reg 0x%x\n", reg);
    u32 d = *(volatile u32 *)(xapic_vbase + xapic_from_x2apic_reg(reg));
    xapic_debug(" -> read 0x%x\n", d);
    return d;
}

static u8 xapic_legacy_id(apic_iface i)
{
    return xapic_read(i, APIC_APICID) >> 24;
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
        if ((xapic_read(i, APIC_ICRL) & APIC_ICRL_DELIVERY_STATUS) == 0)
            return;
        kern_pause();
    }
    console("ipi timed out\n");
}

static boolean detect(apic_iface i, kernel_heaps kh)
{
    /* not really a detect, but the default if x2apic isn't
       available...so must be called last */
    xapic_vbase = allocate_u64((heap)heap_virtual_page(kh), PAGESIZE);
    assert(xapic_vbase != INVALID_PHYSICAL);
    map(xapic_vbase, APIC_BASE, PAGESIZE, PAGE_DEV_FLAGS, heap_pages(kh));
    xapic_debug("xAPIC mode initialized\n");
    return true;
}

struct apic_iface xapic_if = {
    "xapic",
    xapic_legacy_id,
    xapic_write,
    xapic_read,
    xapic_ipi,
    detect,
    0,                          /* per_cpu_init, n/a */
};

