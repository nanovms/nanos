#include <unix_internal.h>

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
                 u64, flags)
{
    thread t = bound(t);
    timestamp elapsed = now(bound(id)) - bound(start);
    thread_log(t, "%s: start %T, interval %T, rem %p, elapsed %T, flags 0x%lx",
               func_ss, bound(start), bound(interval), bound(rem), elapsed, flags);
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
    thread_log(current, "nanosleep: req %p (%T) rem %p, now %T", req, interval, rem, tnow);
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
        rprintf("%s: CLOCK_PROCESS_CPUTIME_ID not yet supported\n", func_ss);
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

    thread_log(current, "clock_nanosleep: clock id %d, flags 0x%x, req %p (%T) rem %p, now %T",
               id, flags, req, treq, rem, tnow);

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
    thread_log(current, "times: user %ld, system %ld", buf->tms_utime,
            buf->tms_stime);
    context_clear_err(ctx);
    return set_syscall_return(current,
            CLOCKS_PER_SEC * uptime() / TIMESTAMP_SECOND);
}

sysreturn clock_gettime(clockid_t clk_id, struct timespec *tp)
{
    thread_log(current, "clock_gettime: clk_id %d, tp %p", clk_id, tp);
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
    thread_log(current, "%s: clk_id %d, tp %p", func_ss, clk_id, tp);
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

void register_clock_syscalls(struct syscall *map)
{
#ifdef __x86_64__
    register_syscall(map, time, sys_time, 0);
#endif
    register_syscall(map, clock_gettime, clock_gettime, 0);
    register_syscall(map, clock_settime, clock_settime, 0);
    register_syscall(map, clock_getres, clock_getres, 0);
    register_syscall(map, clock_nanosleep, clock_nanosleep, 0);
    register_syscall(map, gettimeofday, gettimeofday, 0);
    register_syscall(map, settimeofday, settimeofday, 0);
    register_syscall(map, nanosleep, nanosleep, 0);
    register_syscall(map, times, times, 0);
}
