#include <unix_internal.h>
#include <util.h>

#define ADJTIME_MAX_FREQ    500 /* ppm */

/* Converts a clockid_t value to a clockid enum value: if the id corresponds to a thread CPU time,
 * looks up the relevant thread, and if found puts a reference to the thread in cputime_thread (if
 * not null); returns whether the conversion is successful.
 */
boolean clockid_get(process p, clockid_t id, boolean timer, clock_id *res, thread *cputime_thread)
{
    if (id < 0) {
        if ((id & CPUCLOCK_CLOCK_MASK) != CPUCLOCK_SCHED)
            return false;
        int pid = ~(id >> 3);
        if (id & CPUCLOCK_PERTHREAD_MASK) {
            thread t = thread_from_tid(p, pid);
            if (t == INVALID_ADDRESS)
                return false;
            *res = CLOCK_THREAD_CPUTIME_ID;
            if (cputime_thread)
                *cputime_thread = t;
            else
                thread_release(t);
        } else {
            /* we can only have the CPU time for the current process */
            if (pid != 0)
                return false;
            *res = CLOCK_PROCESS_CPUTIME_ID;
        }
        return true;
    }
    switch(id) {
    case CLOCK_MONOTONIC_RAW:
    case CLOCK_REALTIME_COARSE:
    case CLOCK_MONOTONIC_COARSE:
        if (timer)
            return false;
        break;
    case CLOCK_REALTIME:
    case CLOCK_MONOTONIC:
    case CLOCK_BOOTTIME:
    case CLOCK_REALTIME_ALARM:
    case CLOCK_BOOTTIME_ALARM:
    case CLOCK_PROCESS_CPUTIME_ID:
        break;
    case CLOCK_THREAD_CPUTIME_ID:
        if (cputime_thread) {
            *cputime_thread = current;
            thread_reserve(*cputime_thread);
        }
        break;
    default:
        return false;
    }
    *res = id;
    return true;
}

sysreturn gettimeofday(struct timeval *tv, void *tz)
{
    context ctx = get_current_context(current_cpu());
    if (!validate_user_memory(tv, sizeof(struct timeval), true) || context_set_err(ctx))
        return -EFAULT;
    timeval_from_time(tv, now(CLOCK_ID_REALTIME));
    context_clear_err(ctx);
    return 0;
}

sysreturn settimeofday(const struct timeval *tv, const void *tz)
{
    if (tv) {
        context ctx = get_current_context(current_cpu());
        if (!validate_user_memory(tv, sizeof(struct timeval), false) || context_set_err(ctx))
            return -EFAULT;
        clock_reset_rtc(time_from_timeval(tv));
        context_clear_err(ctx);
    }
    return 0;
}

closure_function(5, 1, sysreturn, nanosleep_bh,
                 thread, t, timestamp, start, clock_id, id, timestamp, interval, struct timespec *, rem,
                 u64 flags)
{
    thread t = bound(t);
    timestamp elapsed = now(bound(id)) - bound(start);
    sysreturn rv = 0;
    if (flags & BLOCKQ_ACTION_NULLIFY) {
        if (bound(rem)) {
            timestamp remain = elapsed < bound(interval) ? bound(interval) - elapsed : 0;
            context ctx = get_current_context(current_cpu());
            if (context_set_err(ctx)) {
                rv = -EFAULT;
                goto out;
            }
            timespec_from_time(bound(rem), remain);
            context_clear_err(ctx);
        }
        rv = -EINTR;
        goto out;
    }

    if (!(flags & BLOCKQ_ACTION_TIMEDOUT) && elapsed < bound(interval))
        return blockq_block_required(&t->syscall->uc, flags);
  out:
    closure_finish();
    return syscall_return(t, rv);
}

sysreturn nanosleep(const struct timespec *req, struct timespec *rem)
{
    if (rem && !validate_user_memory(rem, sizeof(struct timespec), true))
        return -EFAULT;

    context ctx = get_current_context(current_cpu());
    if (!validate_user_memory(req, sizeof(struct timespec), false) || context_set_err(ctx))
        return -EFAULT;
    timestamp interval = time_from_timespec(req);
    context_clear_err(ctx);
    timestamp tnow = now(CLOCK_ID_MONOTONIC);
    return blockq_check_timeout(current->thread_bq,
                                contextual_closure(nanosleep_bh, current, tnow,
                                                   CLOCK_ID_MONOTONIC, interval, rem), false,
                                CLOCK_ID_MONOTONIC, interval, false);
}

sysreturn clock_nanosleep(clockid_t _clock_id, int flags, const struct timespec *req,
                          struct timespec *rem)
{
    if (rem && !validate_user_memory(rem, sizeof(struct timespec), true))
        return -EFAULT;

    /* Report any attempted use of CLOCK_PROCESS_CPUTIME_ID */
    if (_clock_id == CLOCK_PROCESS_CPUTIME_ID) {
        msg_err("%s: CLOCK_PROCESS_CPUTIME_ID not supported", func_ss);
        return -EINVAL;
    }

    if (_clock_id != CLOCK_REALTIME && _clock_id != CLOCK_MONOTONIC)
        return -EINVAL;

    clock_id id = (clock_id)_clock_id;
    context ctx = get_current_context(current_cpu());
    if (!validate_user_memory(req, sizeof(struct timespec), false) || context_set_err(ctx))
        return -EFAULT;
    timestamp treq = time_from_timespec(req);
    context_clear_err(ctx);
    timestamp tnow = now(id);

    return blockq_check_timeout(current->thread_bq,
                                contextual_closure(nanosleep_bh, current, tnow, id, treq, rem), false,
                                id, treq, (flags & TIMER_ABSTIME) != 0);
}

#ifdef __x86_64__
sysreturn sys_time(time_t *tloc)
{
    sysreturn rv = rtime(0);
    if (tloc && !set_user_value(tloc, rv))
        return -EFAULT;
    return rv;
}
#endif

sysreturn times(struct tms *buf)
{
    context ctx = get_current_context(current_cpu());
    if (!validate_user_memory(buf, sizeof(struct tms), true) || context_set_err(ctx))
        return -EFAULT;
    buf->tms_utime = CLOCKS_PER_SEC * proc_utime(current->p) / TIMESTAMP_SECOND;
    buf->tms_stime = CLOCKS_PER_SEC * proc_stime(current->p) / TIMESTAMP_SECOND;
    buf->tms_cutime = buf->tms_cstime = 0;  /* there are no child processes */
    context_clear_err(ctx);
    return set_syscall_return(current,
            CLOCKS_PER_SEC * uptime() / TIMESTAMP_SECOND);
}

sysreturn clock_gettime(clockid_t clk_id, struct timespec *tp)
{
    process p = current->p;
    clock_id cid;
    thread cputime_thread = 0;
    if (!clockid_get(p, clk_id, false, &cid, &cputime_thread))
        return -EINVAL;
    timestamp t;
    switch (cid) {
    case CLOCK_PROCESS_CPUTIME_ID:
        t = proc_utime(p) + proc_stime(p);
        break;
    case CLOCK_THREAD_CPUTIME_ID:
        t = thread_utime(cputime_thread) + thread_stime(cputime_thread);
        thread_release(cputime_thread);
        break;
    default:
        /* We depend on our system clock IDs to match the posix ones... */
        t = now(clk_id);
        break;
    }
    context ctx = get_current_context(current_cpu());
    if (!validate_user_memory(tp, sizeof(struct timespec), true) || context_set_err(ctx))
        return -EFAULT;
    timespec_from_time(tp, t);
    context_clear_err(ctx);
    return 0;
}

sysreturn clock_settime(clockid_t clk_id, const struct timespec *tp)
{
    context ctx;
    switch (clk_id) {
    case CLOCK_REALTIME:
        ctx = get_current_context(current_cpu());
        if (!validate_user_memory(tp, sizeof(struct timespec), false) || context_set_err(ctx))
            return -EFAULT;
        clock_reset_rtc(time_from_timespec(tp));
        context_clear_err(ctx);
        break;
    default:
        return -EINVAL;
    }
    return 0;
}

sysreturn clock_getres(clockid_t clk_id, struct timespec *res)
{
    clock_id cid;
    if (clockid_get(current->p, clk_id, false, &cid, 0)) {
        if (res) {
            context ctx = get_current_context(current_cpu());
            if (!validate_user_memory(res, sizeof(*res), true) || context_set_err(ctx))
                return -EFAULT;
            res->tv_sec = 0;
            res->tv_nsec = 1;
            context_clear_err(ctx);
        }
    } else {
        return -EINVAL;
    }
    return 0;
}

static s64 adjtime_get_offset(timestamp here, boolean nano)
{
    timestamp slew_end = __vdso_dat->slew_end;
    if (here >= slew_end)
        return 0;
    timestamp remaining = slew_end - here;
    s64 slew_freq = __vdso_dat->slew_freq;
    boolean positive = (slew_freq >= 0);
    if (!positive)
        slew_freq = -slew_freq;
    s64 offset = (slew_freq * remaining) >> CLOCK_FP_BITS;
    offset = nano ? nsec_from_timestamp(offset) : usec_from_timestamp(offset);
    return positive ? offset : -offset;
}

static void adjtime_set_offset(timestamp here, s64 offset, boolean nano)
{
    const s64 max_offset = 500 * MILLION;   /* nanoseconds */
    const s64 slew_freq = PPM_SCALE(ADJTIME_MAX_FREQ);
    boolean positive = (offset >= 0);
    if (!positive)
        offset = -offset;
    if (!nano) {
        /* convert from microseconds to nanoseconds */
        if (offset > max_offset)    /* guard against overflow before multiplication */
            offset = max_offset;
        offset *= THOUSAND;
    }
    if (offset > max_offset)
        offset = max_offset;
    timestamp duration = div128_64(((u128)nanoseconds(offset)) << CLOCK_FP_BITS, slew_freq);
    clock_set_slew(positive ? slew_freq : -slew_freq, here, duration);
}

static void adjtime_set_freq(s64 freq)
{
    const s64 max_freq = ADJTIME_MAX_FREQ << TIMEX_PPM_SHIFT;
    boolean positive = (freq >= 0);
    if (!positive)
        freq = -freq;
    if (freq > max_freq)
        freq = max_freq;
    freq = PPM_SCALE(freq) >> TIMEX_PPM_SHIFT;
    clock_set_freq(positive ? freq : -freq);
}

static sysreturn adjtimex(struct timex *buf)
{
    context ctx = get_current_context(current_cpu());
    if (!validate_user_memory(buf, sizeof(struct timex), true) || context_set_err(ctx))
        return -EFAULT;
    int modes = buf->modes;
    boolean nano = !(modes & ADJ_MICRO);
    timestamp here = now(CLOCK_ID_MONOTONIC_RAW);
    if (modes) {
        if (modes == ADJ_OFFSET_SINGLESHOT) {
            nano = false;
            adjtime_set_offset(here, buf->offset, nano);
        } else if (modes == ADJ_OFFSET_SS_READ) {
            nano = false;
        } else {
            if (modes & ADJ_OFFSET)
                adjtime_set_offset(here, buf->offset, nano);
            if (modes & ADJ_FREQUENCY)
                adjtime_set_freq(buf->freq);
            if (modes & ADJ_STATUS) {
                if (buf->status & CLK_STA_UNSYNC)
                    __vdso_dat->status |= CLK_STA_UNSYNC;
                else
                    __vdso_dat->status &= ~CLK_STA_UNSYNC;
            }
            if (modes & ADJ_SETOFFSET) {
                long nsecs = buf->time.tv_sec * 1000000000 +
                             buf->time.tv_usec * (nano ? 1 : THOUSAND);
                clock_step_rtc((nsecs >= 0) ? nanoseconds(nsecs) : -nanoseconds(-nsecs));
            }
        }
    }
    buf->offset = adjtime_get_offset(here,  nano);
    buf->freq = (__vdso_dat->base_freq * 1000000) >> (CLOCK_FP_BITS - TIMEX_PPM_SHIFT);
    buf->maxerror = 0;
    buf->esterror = 0;
    buf->status = CLK_STA_PLL | CLK_STA_FLL | CLK_STA_FREQHOLD |
                  (__vdso_dat->status & CLK_STA_UNSYNC);
    if (__vdso_dat->base_freq)
        buf->status |= CLK_STA_MODE;
    if (nano)
        buf->status |= CLK_STA_NANO;
    buf->constant = 0;
    buf->precision = 1;
    buf->tolerance = ADJTIME_MAX_FREQ << TIMEX_PPM_SHIFT;
    here = now(CLOCK_ID_REALTIME);
    buf->time.tv_sec = here / TIMESTAMP_SECOND;
    timestamp frac = truncate_seconds(here);
    buf->time.tv_usec = nano ? nsec_from_timestamp(frac) : usec_from_timestamp(frac);
    buf->tick = RUNLOOP_TIMER_MAX_PERIOD_US;
    buf->ppsfreq = 0;
    buf->jitter = 0;
    buf->shift = 0;
    buf->stabil = 0;
    buf->jitcnt = 0;
    buf->calcnt = 0;
    buf->errcnt = 0;
    buf->stbcnt = 0;
    buf->tai = 0;
    context_clear_err(ctx);
    return (buf->status & CLK_STA_UNSYNC) ? TIME_ERROR : TIME_OK;
}

static sysreturn clock_adjtime(clockid_t clk_id, struct timex *buf)
{
    clock_id cid;
    if (clockid_get(current->p, clk_id, false, &cid, 0)) {
        switch (cid) {
        case CLOCK_ID_REALTIME:
            return adjtimex(buf);
        default:
            return -EOPNOTSUPP;
        }
    }
    return -EINVAL;
}

void register_clock_syscalls(struct syscall *map)
{
#ifdef __x86_64__
    register_syscall(map, time, sys_time);
#endif
    register_syscall(map, clock_gettime, clock_gettime);
    register_syscall(map, clock_settime, clock_settime);
    register_syscall(map, clock_getres, clock_getres);
    register_syscall(map, clock_nanosleep, clock_nanosleep);
    register_syscall(map, gettimeofday, gettimeofday);
    register_syscall(map, settimeofday, settimeofday);
    register_syscall(map, nanosleep, nanosleep);
    register_syscall(map, times, times);
    register_syscall(map, adjtimex, adjtimex);
    register_syscall(map, clock_adjtime, clock_adjtime);
}
