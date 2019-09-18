#include <x86_64.h>
#include <page.h>

#define APIC_BASE        0xfee00000ull

#define APIC_APICID      0x20
#define APIC_APICVER     0x30
#define APIC_TASKPRIOR   0x80
#define APIC_EOI         0x0B0
#define APIC_LDR         0x0D0
#define APIC_DFR         0x0E0
#define APIC_SPURIOUS    0x0F0
#define APIC_ESR         0x280
#define APIC_ICRL        0x300
#define APIC_ICRH        0x310
#define APIC_LVT_TMR     0x320
#define APIC_LVT_PERF    0x340
#define APIC_LVT_LINT0   0x350
#define APIC_LVT_LINT1   0x360
#define APIC_LVT_ERR     0x370
#define APIC_TMRINITCNT  0x380
#define APIC_TMRCURRCNT  0x390
#define APIC_TMRDIV      0x3E0
#define APIC_LAST        0x38F
#define APIC_DISABLE     0x10000
#define APIC_SW_ENABLE   0x100
#define APIC_CPUFOCUS    0x200
#define APIC_NMI         (4 << 8)
#define TMR_PERIODIC     0x20000
#define TMR_TSC_DEADLINE 0x40000
#define TMR_BASEDIV      (1 << 20)
#define APIC_LVT_INTMASK 0x00010000

static u64 apic_vbase;

static inline void apic_write(int reg, u32 val)
{
    *(u32 *)(apic_vbase + reg) = val;
}

static inline u32 apic_read(int reg)
{
    return *(u32 *)(apic_vbase + reg);
}

static inline void apic_set(int reg, u32 v)
{
    apic_write(reg, apic_read(reg) | v);
}

static inline void apic_clear(int reg, u32 v)
{
    apic_write(reg, apic_read(reg) & ~v);
}

static u32 apic_timer_cal_sec;

/* We could possibly trim this if the extra delay in boot becomes a concern. */
#define CALIBRATE_DURATION_MS 10
static void calibrate_lapic_timer()
{
    apic_write(APIC_TMRINITCNT, -1u);
    kern_sleep(milliseconds(10));
    u32 delta = -1u - apic_read(APIC_TMRCURRCNT);
    apic_set(APIC_LVT_TMR, APIC_LVT_INTMASK);
    apic_timer_cal_sec = (1000 / CALIBRATE_DURATION_MS) * delta;
}

void lapic_runloop_timer(timestamp interval)
{
    /* interval * apic_timer_cal_sec / second */
    u32 cnt = (((u128)interval) * apic_timer_cal_sec) >> 32;
    apic_clear(APIC_LVT_TMR, APIC_LVT_INTMASK);
    apic_write(APIC_TMRINITCNT, cnt);
}

static CLOSURE_0_0(int_ignore, void);
static void int_ignore(void) {}

void configure_lapic_timer(heap h)
{
    apic_write(APIC_TMRDIV, 3 /* 16 */);
    int v = allocate_interrupt();
    apic_write(APIC_LVT_TMR, v); /* one shot */
    register_interrupt(v, closure(h, int_ignore));
    calibrate_lapic_timer();
}

void lapic_eoi(void)
{
    write_barrier();
    apic_write(APIC_EOI, 0);
    write_barrier();
}

void init_apic(kernel_heaps kh)
{
    apic_vbase = allocate_u64(heap_virtual_page(kh), PAGESIZE);
    assert(apic_vbase != INVALID_PHYSICAL);
    map(apic_vbase, APIC_BASE, PAGESIZE, PAGE_DEV_FLAGS, heap_pages(kh));

    /* enable spurious interrupts */
    apic_set(APIC_SPURIOUS, APIC_SW_ENABLE);
    apic_write(APIC_LVT_LINT0, APIC_DISABLE);
    apic_write(APIC_LVT_LINT1, APIC_DISABLE);

    /* set up error interrupt */
    u64 lvt_err_irq = allocate_interrupt();
    assert(lvt_err_irq != INVALID_PHYSICAL);
    apic_write(APIC_LVT_ERR, lvt_err_irq);
}
