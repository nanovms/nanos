#include <kernel.h>
#include <page.h>
#include <apic.h>

/* In theory, the MMIO base address of I/O APIC(s) should be retrieved from the
 * ACPI MADT, but in practice the first I/O APIC is usually at the address
 * below. */
#define IOAPIC_MEMBASE  0xFEC00000ull

#define IOAPIC_IOREGSEL 0x00
#define IOAPIC_IOWIN    0x10

#define IOAPIC_REG_ID       0x00
#define IOAPIC_REG_VER      0x01
#define IOAPIC_REG_PRIO     0x02
#define IOAPIC_REG_REDIR    0x10

#define IOAPIC_INT_MASK     16

#define IOAPIC_REDIR_DEST   24

//#define APIC_DEBUG
#ifdef APIC_DEBUG
#define apic_debug(x, ...) do {rprintf("APIC: " x, ##__VA_ARGS__);} while(0)
#else
#define apic_debug(x, ...)
#endif

static heap apic_heap;
apic_iface apic_if;

static inline void apic_write(int reg, u32 val)
{
    apic_if->write(apic_if, reg, val);
}

static inline u32 apic_read(int reg)
{
    return apic_if->read(apic_if, reg);
}

void apic_ipi(u32 target, u64 flags, u8 vector)
{
    apic_if->ipi(apic_if, target, flags, vector);
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
static void calibrate_lapic_timer(void)
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
    assert(apic_if);
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
    assert(apic_if);
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

void apic_per_cpu_init(void)
{
    if (apic_if->per_cpu_init)
        apic_if->per_cpu_init(apic_if);
}

void apic_enable(void)
{
    /* enable spurious interrupts */
    apic_write(APIC_SPURIOUS, APIC_SW_ENABLE | spurious_int_vector);
    apic_write(APIC_LVT_LINT0, APIC_DISABLE);
    apic_write(APIC_LVT_LINT1, APIC_DISABLE);

    /* set up error interrupt */
    apic_write(APIC_LVT_ERR, lvt_err_irq);
}

extern struct apic_iface xapic_if, x2apic_if;

static void *ioapic_vbase;

static void ioapic_init(kernel_heaps kh, u64 membase)
{
    ioapic_vbase = allocate((heap)heap_virtual_page(kh), PAGESIZE);
    assert(ioapic_vbase != INVALID_ADDRESS);
    map(u64_from_pointer(ioapic_vbase), membase, PAGESIZE, PAGE_DEV_FLAGS);
}

static u32 ioapic_read(int reg)
{
    *(volatile u32 *)(ioapic_vbase + IOAPIC_IOREGSEL) = reg;
    write_barrier();
    return *(volatile u32 *)(ioapic_vbase + IOAPIC_IOWIN);
}

static void ioapic_write(int reg, u32 data)
{
    *(volatile u32 *)(ioapic_vbase + IOAPIC_IOREGSEL) = reg;
    write_barrier();
    *(volatile u32 *)(ioapic_vbase + IOAPIC_IOWIN) = data;
}

void ioapic_set_int(unsigned int gsi, u64 v)
{
    /* Fixed delivery mode, physical destination, active high polarity,
     * edge-triggered. */
    ioapic_write(IOAPIC_REG_REDIR + 2 * gsi + 1,
        apic_id() << IOAPIC_REDIR_DEST);
    ioapic_write(IOAPIC_REG_REDIR + 2 * gsi, v);
}

boolean ioapic_int_is_free(unsigned int gsi)
{
    unsigned int num_redir = (ioapic_read(IOAPIC_REG_VER) >> 16) & 0xFF;
    if (gsi >= num_redir)
        return false;
    return !!(ioapic_read(IOAPIC_REG_REDIR + 2 * gsi) & (1 << IOAPIC_INT_MASK));
}

void init_apic(kernel_heaps kh)
{
    apic_heap = heap_general(kh);
    apic_debug("detecting apic interface...\n");
    if (x2apic_if.detect(&x2apic_if, kh)) {
        apic_debug("using x2APIC interface\n");
        apic_if = &x2apic_if;
    } else if (xapic_if.detect(&xapic_if, kh)) {
        apic_debug("using xAPIC interface\n");
        apic_if = &xapic_if;
    } else {
        halt("unable to initialize xapic interface, giving up\n");
    }

    lvt_err_irq = allocate_interrupt();
    assert(lvt_err_irq != INVALID_PHYSICAL);

    apic_per_cpu_init();
    apic_enable();
    ioapic_init(kh, IOAPIC_MEMBASE);
}
