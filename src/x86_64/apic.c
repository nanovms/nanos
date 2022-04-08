#include <kernel.h>
#include <apic.h>
#include <drivers/acpi.h>

/* Fallback address for first I/O APIC if MADT is not found */
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

BSS_RO_AFTER_INIT static heap apic_heap;
BSS_RO_AFTER_INIT static u64 ioapic_membase;
BSS_RO_AFTER_INIT apic_iface apic_if;
BSS_RO_AFTER_INIT buffer apic_id_map;

static inline void apic_write(int reg, u32 val)
{
    apic_if->write(apic_if, reg, val);
}

static inline u32 apic_read(int reg)
{
    return apic_if->read(apic_if, reg);
}

static inline u32 apicid_from_cpuid(u32 idx)
{
    if (!apic_id_map)
        return idx;
    return *(u32 *)buffer_ref(apic_id_map, idx * sizeof(u32));
}

void apic_ipi(u64 target, u64 flags, u8 vector)
{
    /* Do not use native "all but self" destination as it is very slow
     * and may target processors not available */
    if (target == TARGET_EXCLUSIVE_BROADCAST) {
        for (int i = 0; i < total_processors; i++) {
            if (current_cpu()->id == i)
                continue;
            apic_if->ipi(apic_if, apicid_from_cpuid(i), flags, vector);
        }
        return;
    }
    apic_if->ipi(apic_if, apicid_from_cpuid(target), flags, vector);
}

static inline void apic_set(int reg, u32 v)
{
    apic_write(reg, apic_read(reg) | v);
}

static inline void apic_clear(int reg, u32 v)
{
    apic_write(reg, apic_read(reg) & ~v);
}

BSS_RO_AFTER_INIT static u32 apic_timer_cal_sec;

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

void msi_format(u32 *address, u32 *data, int vector)
{
    u32 dm = 0;             // destination mode: ignored if rh == 0
    u32 rh = 0;             // redirection hint: 0 - disabled
    u32 destination = 0;    // destination APIC
    *address = (0xfee << 20) | (destination << 12) | (rh << 3) | (dm << 2);

    u32 mode = 0;           // delivery mode: 000 fixed, 001 lowest, 010 smi, 100 nmi, 101 init, 111 extint
    u32 level = 0;          // trigger level: 0 - deassert, 1 - assert
    u32 trigger = 0;        // trigger mode: 0 - edge, 1 - level
    *data = (trigger << 15) | (level << 14) | (mode << 8) | vector;
}

void lapic_set_tsc_deadline_mode(u32 v)
{
    assert(apic_if);
    write_barrier();
    apic_write(APIC_LVT_TMR, v | TMR_TSC_DEADLINE);
    write_barrier();
}

static void lapic_set_timer(timestamp interval)
{
    /* interval * apic_timer_cal_sec / second */
    u32 cnt = (((u128)interval) * apic_timer_cal_sec) >> 32;
    apic_clear(APIC_LVT_TMR, APIC_LVT_INTMASK);
    apic_write(APIC_TMRINITCNT, cnt);
}

closure_function(0, 1, void, lapic_timer,
                 timestamp, interval)
{
    current_cpu()->m.lapic_timer_expiry = now(CLOCK_ID_MONOTONIC_RAW) + interval;
    lapic_set_timer(interval);
}

closure_function(0, 0, void, lapic_timer_int)
{
    cpuinfo ci = current_cpu();
    timestamp here = now(CLOCK_ID_MONOTONIC_RAW);
    if (here < ci->m.lapic_timer_expiry) {
        apic_debug("timer fired %T seconds too early\n", ci->m.lapic_timer_expiry - here);
        lapic_set_timer(ci->m.lapic_timer_expiry - here);
    } else {
        schedule_timer_service();
    }
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
    register_interrupt(v, closure(apic_heap, lapic_timer_int), "lapic timer");
    *per_cpu_init = closure(apic_heap, lapic_timer_percpu_init, v);
    apply(*per_cpu_init);
    calibrate_lapic_timer();
    return true;
}

BSS_RO_AFTER_INIT static u64 lvt_err_irq;
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

BSS_RO_AFTER_INIT static void *ioapic_vbase;

static void ioapic_init(kernel_heaps kh, u64 membase)
{
    ioapic_vbase = allocate((heap)heap_virtual_page(kh), PAGESIZE);
    assert(ioapic_vbase != INVALID_ADDRESS);
    map(u64_from_pointer(ioapic_vbase), membase, PAGESIZE,
        pageflags_writable(pageflags_device()));
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

void ioapic_register_int(unsigned int gsi, thunk h, const char *name)
{
    boolean alloc_vector = ioapic_int_is_free(gsi);
    u64 v;
    if (alloc_vector) {
        v = allocate_shirq();
        assert(v != INVALID_PHYSICAL);
    } else {
        v = ioapic_read(IOAPIC_REG_REDIR + 2 * gsi) & ~(1 << IOAPIC_INT_MASK);
    }
    apic_debug("routing GSI %d to vector %d, handler %F (%s)\n", gsi, v, h, name);
    register_shirq(v, h, name);
    if (alloc_vector)
        ioapic_set_int(gsi, v);
}

int cpuid_from_apicid(u32 aid)
{
    for (int i = 0; i < present_processors; i++) {
        if (aid == apicid_from_cpuid(i))
            return i;
    }
    assert(0);
}

closure_function(1, 2, void, apic_madt_handler,
                 kernel_heaps, kh,
                 u8, type, void *, p)
{
    u32 apic_id;

    switch (type) {
    case ACPI_MADT_LAPIC:
        apic_debug("found xAPIC LAPIC entry\n");
        acpi_lapic l = p;
        /* XXX should eventually deal with online capable */
        if (!(l->flags & MADT_LAPIC_ENABLED))
            break;
        apic_id = l->id;
        assert(buffer_write(apic_id_map, &apic_id, sizeof(apic_id)));
        if (apic_if)
            break;
        apic_debug("using xAPIC interface\n");
        apic_if = &xapic_if;
        /* This is to initialize, not detect */
        xapic_if.detect(&xapic_if, bound(kh));
        break;
    case ACPI_MADT_LAPICx2:
        apic_debug("found x2APIC LAPIC entry\n");
        acpi_lapic_x2 lx2 = p;
        /* XXX should eventually deal with online capable */
        if (!(lx2->flags & MADT_LAPIC_ENABLED))
            break;
        apic_id = lx2->id;
        assert(buffer_write(apic_id_map, &apic_id, sizeof(apic_id)));
        if (apic_if)
            break;
        apic_debug("using x2APIC interface\n");
        apic_if = &x2apic_if;
        break;
    case ACPI_MADT_IOAPIC:
        apic_debug("found IOAPIC entry\n");
        acpi_ioapic io = p;
        if (ioapic_membase)
            break;
        apic_debug("ioapic membase set to %lx\n", io->addr);
        ioapic_membase = (u64)io->addr;
        break;
    }
}

void init_apic(kernel_heaps kh)
{
    apic_heap = heap_general(kh);
    apic_id_map = allocate_buffer(apic_heap, 8);
    assert(apic_id_map != INVALID_ADDRESS);
    apic_debug("walking MADT table...\n");
    if (!acpi_walk_madt(stack_closure(apic_madt_handler, kh))) {
        deallocate_buffer(apic_id_map);
        apic_id_map = 0;
        apic_debug("MADT not found, detecting apic interface...\n");
        if (x2apic_if.detect(&x2apic_if, kh)) {
            apic_debug("using x2APIC interface\n");
            apic_if = &x2apic_if;
        } else if (xapic_if.detect(&xapic_if, kh)) {
            apic_debug("using xAPIC interface\n");
            apic_if = &xapic_if;
        } else {
            halt("unable to initialize xapic interface, giving up\n");
        }
    }
    if (!ioapic_membase)
        ioapic_membase = IOAPIC_MEMBASE;

    lvt_err_irq = allocate_interrupt();
    assert(lvt_err_irq != INVALID_PHYSICAL);

    apic_per_cpu_init();
    apic_enable();
    ioapic_init(kh, ioapic_membase);
}
