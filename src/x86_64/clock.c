#include <kernel.h>

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

void init_clock(void)
{
    /* detect rdtscp */
    u32 regs[4];
    cpuid(0x80000001, 0, regs);
    __vdso_dat->clock_src = VDSO_CLOCK_SYSCALL;
    __vdso_dat->platform_has_rdtscp = (regs[3] & U64_FROM_BIT(27)) != 0;
}

timestamp kern_now(clock_id id)
{
    return now(id);
}
KLIB_EXPORT_RENAME(kern_now, now);

void clock_adjust(timestamp wallclock_now, s64 temp_cal, timestamp sync_complete, s64 cal)
{
    timestamp here = now(CLOCK_ID_MONOTONIC_RAW);
    if (__vdso_dat->last_raw == 0)
        __vdso_dat->last_raw = here;
    __vdso_dat->temp_cal = temp_cal;
    __vdso_dat->sync_complete = sync_complete;
    __vdso_dat->cal = cal;
    clock_update_drift(here);
    timer_reorder(runloop_timers);
    rtc_settimeofday(sec_from_timestamp(wallclock_now));
}
KLIB_EXPORT(clock_adjust);
