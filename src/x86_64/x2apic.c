#include <kernel.h>
#include <page.h>
#include <apic.h>

//#define X2APIC_DEBUG
#ifdef X2APIC_DEBUG
#define x2apic_debug(x, ...) do {rprintf("x2APIC: " x, ##__VA_ARGS__);} while(0)
#else
#define x2apic_debug(x, ...)
#endif

#define IA32_APIC_BASE      0x01b
#define IA32_APIC_BASE_BSP  0x100
#define IA32_APIC_BASE_EXTD 0x400
#define IA32_APIC_BASE_EN   0x800

static void inline check_reg(int reg)
{
    assert(reg < APIC_LIMIT);
    assert(reg != APIC_ICR + 1);
}

static void x2apic_write(apic_iface i, int reg, u64 val)
{
    x2apic_debug("write to reg 0x%x, val 0x%x\n", reg, val);
    check_reg(reg);
    asm volatile("wrmsr" :: "a" (val), "c" (reg), "d" (val >> 32) : "memory");
}

static u64 x2apic_read(apic_iface i, int reg)
{
    x2apic_debug("read from reg 0x%x\n", reg);
    check_reg(reg);
    u32 lo, hi;
    asm volatile("rdmsr" : "=a" (lo), "=d" (hi) : "c" (reg));
    u64 d = ((u64)hi) << 32 | lo;
    x2apic_debug(" -> read 0x%lx\n", d);
    return d;
}

static u8 x2apic_legacy_id(apic_iface i)
{
    return x2apic_read(i, APIC_APICID) & 0xff;
}

#define XAPIC_READ_TIMEOUT_ITERS 512 /* arbitrary */
static void x2apic_ipi(apic_iface i, u32 target, u64 flags, u8 vector)
{
    u64 w;
    u64 icr = (flags & ~0xff) | vector;
    
    if (target == TARGET_EXCLUSIVE_BROADCAST) {
        w = icr | ICR_DEST_ALL_EXC_SELF;
    } else {
        w = icr | (((u64)target) << 32);
    }
    
    x2apic_debug("sending ipi: target 0x%x, flags 0x%lx, vector %d (icr 0x%lx)\n",
                target, flags, vector, w);
    x2apic_write(i, APIC_ICR, w);
}

static boolean detect(apic_iface i, kernel_heaps kh)
{
    u32 v[4];
    cpuid(0x1, 0, v);
    if ((v[2] & (1 << 21)) == 0)
        return false;
    x2apic_debug("x2APIC detected\n");
    return true;
}

static void per_cpu_init(apic_iface i)
{
    u32 d = IA32_APIC_BASE_EN | IA32_APIC_BASE_EXTD;
    x2apic_debug("per cpu init, writing 0x%x\n", d);
    write_msr(IA32_APIC_BASE, d);
    x2apic_debug("apic id %lx, apic ver %lx\n", x2apic_read(i, APIC_APICID),
                 x2apic_read(i, APIC_APICVER));
}

struct apic_iface x2apic_if = {
    "x2apic",
    x2apic_legacy_id,
    x2apic_write,
    x2apic_read,
    x2apic_ipi,
    detect,
    per_cpu_init
};
