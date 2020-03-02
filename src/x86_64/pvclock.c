#include <kernel.h>
#include <pvclock.h>
#include <page.h>
#include <apic.h>

static heap pvclock_heap;
static volatile struct pvclock_vcpu_time_info *vclock = 0;

u64 pvclock_now_ns(void)
{
    return vdso_pvclock_now_ns(vclock);
}

closure_function(0, 0, timestamp, pvclock_now)
{
    return nanoseconds(pvclock_now_ns());
}

void init_pvclock(heap h, struct pvclock_vcpu_time_info *vti)
{
    assert(vti);
    vclock = vti;
    pvclock_heap = h;
    register_platform_clock_now(closure(h, pvclock_now), VDSO_CLOCK_PVCLOCK);
}

physical pvclock_get_physaddr(void)
{
    return (vclock == 0) ? INVALID_PHYSICAL
                         : physical_from_virtual((void *)vclock);
}

closure_function(0, 1, void, tsc_deadline_timer,
                 timestamp, interval)
{
    u32 version;
    u64 count = 0;

    do {
        /* mask update-in-progress so we don't match */
        version = vclock->version & ~1;
        read_barrier();
        timestamp subsec = truncate_seconds(interval);
        count = (nsec_from_timestamp(subsec) << 32) / vclock->tsc_to_system_mul;
        count += (nsec_from_timestamp(interval - subsec) / vclock->tsc_to_system_mul) << 32;
        if (vclock->tsc_shift < 0) {
            count <<= -vclock->tsc_shift;
        } else {
            count >>= vclock->tsc_shift;
        }
        read_barrier();
    } while (version != vclock->version);

    write_msr(TSC_DEADLINE_MSR, rdtsc() + count);
}

closure_function(1, 0, void, tsc_deadline_percpu_init,
                 int, irq)
{
    lapic_set_tsc_deadline_mode(bound(irq));
}

boolean init_tsc_deadline_timer(clock_timer *ct, thunk *per_cpu_init)
{
    u32 v[4];
    assert(vclock);
    cpuid(0x1, 0, v);
    if ((v[2] & (1 << 24)) == 0)
        return false;           /* no TSC-Deadline */

    *ct = closure(pvclock_heap, tsc_deadline_timer);
    int irq = allocate_interrupt();
    register_interrupt(irq, ignore, "tsc deadline timer");
    *per_cpu_init = closure(pvclock_heap, tsc_deadline_percpu_init, irq);
    apply(*per_cpu_init);
    return true;
}
