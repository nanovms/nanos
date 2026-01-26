#include <kernel.h>

//#define CLOCK_DEBUG
#ifdef CLOCK_DEBUG
#define clock_debug(x, ...) do {tprintf(sym(clock), 0, ss(x), ##__VA_ARGS__);} while(0)
#else
#define clock_debug(x, ...)
#endif

extern void notify_unix_timers_of_rtc_change(void);
/* These should happen in pairs such that odd indicates update in-progress */
#define vdso_update_gen() fetch_and_add((word *)&__vdso_dat->vdso_gen, 1)

BSS_RO_AFTER_INIT clock_now ptp_clock_now;

static struct {
    struct timer raw_update_timer;
    closure_struct(timer_handler, raw_update_func);
} clock;

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

closure_func_basic(timer_handler, void, clock_raw_update_func,
                   u64 expiry, u64 overruns)
{
    /* Periodically update last_raw to avoid numerical errors from big intervals */
    if (__vdso_dat->base_freq) {
        timestamp t = kern_now(CLOCK_ID_MONOTONIC_RAW);
        vdso_update_gen();
        __vdso_dat->rtc_offset += ((s64)(t - __vdso_dat->last_raw) *
            __vdso_dat->base_freq) >> CLOCK_FP_BITS;
        __vdso_dat->last_raw = t;
        vdso_update_gen();
    }
}

void clock_init(void)
{
    __vdso_dat->status = CLK_STA_UNSYNC;
    register_timer(kernel_timers, &clock.raw_update_timer, CLOCK_ID_MONOTONIC_RAW,
                   seconds(CLOCK_RAW_UPDATE_SECONDS), false, seconds(CLOCK_RAW_UPDATE_SECONDS),
                   init_closure_func(&clock.raw_update_func, timer_handler, clock_raw_update_func));
}

void clock_set_freq(s64 freq)
{
    timestamp here = now(CLOCK_ID_MONOTONIC_RAW);
    vdso_update_gen();
    __vdso_dat->rtc_offset += ((s64)(here - __vdso_dat->last_raw) * __vdso_dat->base_freq) >> CLOCK_FP_BITS;
    __vdso_dat->base_freq = freq;
    __vdso_dat->last_raw = here;
    vdso_update_gen();
    timer_reorder(kernel_timers);
}

void clock_set_slew(s64 slewfreq, timestamp start, u64 duration)
{
    vdso_update_gen();
    __vdso_dat->slew_freq = slewfreq;
    __vdso_dat->slew_start = start;
    __vdso_dat->slew_end = start + duration;
    vdso_update_gen();
    timer_reorder(kernel_timers);
}

closure_function(1, 1, boolean, timer_adjust_handler,
                s64, amt,
                void *v)
{
    timer t = v;
    if (t->absolute)
        return true;
    switch (t->id) {
    case CLOCK_ID_REALTIME:
    case CLOCK_ID_REALTIME_COARSE:
    case CLOCK_ID_REALTIME_ALARM:
        t->expiry += bound(amt);
        break;
    default:
        break;
    }
    return true;
}

void clock_step_rtc(s64 step)
{
    timer_adjust_begin(kernel_timers);
    vdso_update_gen();
    __vdso_dat->rtc_offset += step;
    vdso_update_gen();
    timer_adjust_end(kernel_timers, stack_closure(timer_adjust_handler, step));
    rtc_settimeofday(sec_from_timestamp(now(CLOCK_ID_REALTIME)));
    notify_unix_timers_of_rtc_change();
}

void clock_reset_rtc(timestamp wallclock_now)
{
    clock_debug("%s: now %T, wallclock_now %T\n",
                func_ss, now(CLOCK_ID_REALTIME), wallclock_now);
    timestamp n = now(CLOCK_ID_REALTIME);
    rtc_settimeofday(sec_from_timestamp(wallclock_now));
    notify_unix_timers_of_rtc_change();
    timer_adjust_begin(kernel_timers);
    __vdso_dat->rtc_offset = wallclock_now - now(CLOCK_ID_MONOTONIC_RAW);
    reset_clock_vdso_dat();
    timer_adjust_end(kernel_timers, stack_closure(timer_adjust_handler, wallclock_now - n));
}
