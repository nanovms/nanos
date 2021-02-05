#include <kernel.h>

//#define CLOCK_DEBUG
#ifdef CLOCK_DEBUG
#define clock_debug(x, ...) do {rprintf("CLK:  " x, ##__VA_ARGS__);} while(0)
#else
#define clock_debug(x, ...)
#endif

void kernel_delay(timestamp delta)
{
    timestamp end = now(CLOCK_ID_MONOTONIC) + delta;
    while (now(CLOCK_ID_MONOTONIC) < end)
        kern_pause();
}

timestamp kern_now(clock_id id)
{
    return now(id);
}
KLIB_EXPORT_RENAME(kern_now, now);

void clock_adjust(timestamp wallclock_now, s64 temp_cal, timestamp sync_complete, s64 cal)
{
    clock_debug("%s: wallclock_now %T, temp_cal %ld, sync_complete %T, cal %ld\n",
                __func__, wallclock_now, temp_cal, sync_complete, cal);
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
