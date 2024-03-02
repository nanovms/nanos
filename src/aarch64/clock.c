#include <kernel.h>
#include <gic.h>

#define __vdso_dat (&(VVAR_REF(vdso_dat)))

BSS_RO_AFTER_INIT clock_now platform_monotonic_now;
BSS_RO_AFTER_INIT clock_timer platform_timer;

static inline u64 cntfrq(void)
{
    return read_psr(CNTFRQ_EL0);
}

closure_function(0, 0, timestamp, arm_clock_now)
{
    u64 t = rdtsc();
    u64 f = cntfrq();
    u64 secs = t / f;
    u64 frac = t - secs * f;
    return seconds(secs) | ((frac << 32) / f);
}

closure_func_basic(clock_timer, void, arm_deadline_timer,
                   timestamp interval)
{
    write_psr(CNTV_TVAL_EL0, (cntfrq() * interval) >> 32);
    write_psr(CNTV_CTL_EL0, CNTV_CTL_EL0_ENABLE /* and clear imask */);
}

closure_function(0, 0, void, arm_timer_percpu_init)
{
}

BSS_RO_AFTER_INIT closure_struct(arm_clock_now, _clock_now);
BSS_RO_AFTER_INIT closure_struct(clock_timer, _deadline_timer);
BSS_RO_AFTER_INIT closure_struct(arm_timer_percpu_init, _timer_percpu_init);

void init_clock(void)
{
    register_platform_clock_now(init_closure(&_clock_now, arm_clock_now), VDSO_CLOCK_SYSCALL, 0);
    register_platform_clock_timer(init_closure_func(&_deadline_timer, clock_timer,
                                                    arm_deadline_timer),
                                  init_closure(&_timer_percpu_init, arm_timer_percpu_init));
}
