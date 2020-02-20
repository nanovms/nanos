#include <kernel.h>
#include <page.h>
#include <apic.h>

static heap apic_heap;
static apic_iface aif;

static inline void apic_write(int reg, u32 val)
{
    aif->write(aif, reg, val);
}

static inline u32 apic_read(int reg)
{
    return aif->read(aif, reg);
}

void apic_ipi(u32 target, u64 flags, u8 vector)
{
    aif->ipi(aif, target, flags, vector);
}

u32 apic_id()
{
    return apic_read(APIC_APICID) >> 24;
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
    kernel_delay(milliseconds(10));
    u32 delta = -1u - apic_read(APIC_TMRCURRCNT);
    apic_set(APIC_LVT_TMR, APIC_LVT_INTMASK);
    apic_timer_cal_sec = (1000 / CALIBRATE_DURATION_MS) * delta;
}

void lapic_eoi(void)
{
    write_barrier();
    apic_write(APIC_EOI, 0);
    write_barrier();
}

void lapic_set_tsc_deadline_mode(u32 v)
{
    assert(aif);
    write_barrier();
    apic_write(APIC_LVT_TMR, v | TMR_TSC_DEADLINE);
    write_barrier();
}

closure_function(0, 1, void, lapic_timer,
                 timestamp, interval)
{
    /* interval * apic_timer_cal_sec / second */
    u32 cnt = (((u128)interval) * apic_timer_cal_sec) >> 32;
    apic_clear(APIC_LVT_TMR, APIC_LVT_INTMASK);
    apic_write(APIC_TMRINITCNT, cnt);
}

closure_function(1, 0, void, lapic_timer_percpu_init,
                 int, irq)
{
    apic_write(APIC_TMRDIV, 3 /* 16 */);
    apic_write(APIC_LVT_TMR, bound(irq)); /* one shot */
}

boolean init_lapic_timer(clock_timer *ct, thunk *per_cpu_init)
{
    assert(aif);
    *ct = closure(apic_heap, lapic_timer);
    int v = allocate_interrupt();
    register_interrupt(v, ignore, "lapic timer");
    *per_cpu_init = closure(apic_heap, lapic_timer_percpu_init, v);
    apply(*per_cpu_init);
    calibrate_lapic_timer();
    return true;
}

static u64 lvt_err_irq;
extern u32 spurious_int_vector;

void enable_apic(void)
{
    /* enable spurious interrupts */
    apic_set(APIC_SPURIOUS, APIC_SW_ENABLE | spurious_int_vector);
    apic_write(APIC_LVT_LINT0, APIC_DISABLE);
    apic_write(APIC_LVT_LINT1, APIC_DISABLE);

    /* set up error interrupt */
    apic_write(APIC_LVT_ERR, lvt_err_irq);
}

extern struct apic_iface xapic_if, x2apic_if;

void init_apic(kernel_heaps kh)
{
    apic_heap = heap_general(kh);

    if (x2apic_if.detect_and_init(&x2apic_if, kh)) {
        aif = &x2apic_if;
    } else if (xapic_if.detect_and_init(&xapic_if, kh)) {
        aif = &xapic_if;
    } else {
        halt("unable to initialize xapic interface, giving up\n");
    }

    lvt_err_irq = allocate_interrupt();
    assert(lvt_err_irq != INVALID_PHYSICAL);

    enable_apic();
}
