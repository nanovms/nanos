#include <kernel.h>
#include <gic.h>

#define __vdso_dat (&(VVAR_REF(vdso_dat)))

clock_now platform_monotonic_now;
clock_timer platform_timer;
thunk platform_timer_percpu_init;

void kernel_delay(timestamp delta)
{
    timestamp end = now(CLOCK_ID_MONOTONIC) + delta;
    while (now(CLOCK_ID_MONOTONIC) < end)
        kern_pause();
}

static inline u64 cntfrq(void)
{
    return read_psr(CNTFRQ_EL0);
}

closure_function(0, 0, timestamp, arm_clock_now)
{
    u64 t = rdtsc();
    u64 f = cntfrq();
    return seconds(t / f) | truncate_seconds((t << 32) / f);
}

closure_function(0, 1, void, arm_deadline_timer,
                 timestamp, interval)
{
    write_psr(CNTV_TVAL_EL0, (cntfrq() * interval) >> 32);
    write_psr(CNTV_CTL_EL0, CNTV_CTL_EL0_ENABLE /* and clear imask */);
}

closure_function(0, 0, void, arm_timer_percpu_init)
{
}

closure_function(0, 0, void, arm_timer)
{
    assert(read_psr(CNTV_CTL_EL0) & CNTV_CTL_EL0_ISTATUS);
    write_psr(CNTV_CTL_EL0, 0);
}

void init_clock(heap h)
{
    __vdso_dat->clock_src = VDSO_CLOCK_SYSCALL;
    __vdso_dat->platform_has_rdtscp = 0;
//    __vdso_dat->rtc_offset = rtc_gettimeofday() << 32;
    __vdso_dat->rtc_offset = 0;

    gic_set_int_config(GIC_TIMER_IRQ, GICD_ICFGR_LEVEL);
    gic_set_int_priority(GIC_TIMER_IRQ, 0);
    gic_set_int_target(GIC_TIMER_IRQ, 1);

    register_interrupt(GIC_TIMER_IRQ, closure(h, arm_timer), "arm timer");
    register_platform_clock_now(closure(h, arm_clock_now), VDSO_CLOCK_PVCLOCK);
    register_platform_clock_timer(closure(h, arm_deadline_timer), closure(h, arm_timer_percpu_init));
}
