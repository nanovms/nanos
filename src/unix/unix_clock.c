#include <unix_internal.h>

sysreturn gettimeofday(struct timeval *tv, void *tz)
{
    if (!validate_user_memory(tv, sizeof(struct timeval), true))
        return -EFAULT;
    timeval_from_time(tv, now(CLOCK_ID_REALTIME));
    return 0;
}

closure_function(5, 1, sysreturn, nanosleep_bh,
                 thread, t, timestamp, start, clock_id, id, timestamp, interval, struct timespec *, rem,
                 u64, flags)
{
    thread t = bound(t);
    timestamp elapsed = now(bound(id)) - bound(start);
    thread_log(t, "%s: start %T, interval %T, rem %p, elapsed %T, flags 0x%lx",
               __func__, bound(start), bound(interval), bound(rem), elapsed, flags);
    sysreturn rv = 0;
    if (flags & BLOCKQ_ACTION_NULLIFY) {
        if (bound(rem)) {
            timestamp remain = elapsed < bound(interval) ? bound(interval) - elapsed : 0;
            timespec_from_time(bound(rem), remain);
        }
        rv = -EINTR;
        goto out;
    }

    if (!(flags & BLOCKQ_ACTION_TIMEDOUT) && elapsed < bound(interval))
        return BLOCKQ_BLOCK_REQUIRED;
  out:
    if (flags & BLOCKQ_ACTION_BLOCKED)
        thread_wakeup(t);
    closure_finish();
    return set_syscall_return(t, rv);
}

sysreturn nanosleep(const struct timespec *req, struct timespec *rem)
{
    if (!validate_user_memory(req, sizeof(struct timespec), false))
        return -EFAULT;

    if (rem && !validate_user_memory(rem, sizeof(struct timespec), true))
        return -EFAULT;

    timestamp interval = time_from_timespec(req);
    timestamp tnow = now(CLOCK_ID_MONOTONIC);
    thread_log(current, "nanosleep: req %p (%T) rem %p, now %T", req, interval, rem, tnow);
    return blockq_check_timeout(current->thread_bq, current,
                                closure(heap_general(get_kernel_heaps()), nanosleep_bh,
                                        current, tnow, CLOCK_ID_MONOTONIC, interval, rem), false,
                                CLOCK_ID_MONOTONIC, interval, false);
}

sysreturn clock_nanosleep(clockid_t _clock_id, int flags, const struct timespec *req,
                          struct timespec *rem)
{
    if (!validate_user_memory(req, sizeof(struct timespec), false))
        return -EFAULT;

    if (rem && !validate_user_memory(rem, sizeof(struct timespec), true))
        return -EFAULT;

    /* Report any attempted use of CLOCK_PROCESS_CPUTIME_ID */
    if (_clock_id == CLOCK_PROCESS_CPUTIME_ID) {
        rprintf("%s: CLOCK_PROCESS_CPUTIME_ID not yet supported\n", __func__);
        return -EINVAL;
    }

    if (_clock_id != CLOCK_REALTIME && _clock_id != CLOCK_MONOTONIC)
        return -EINVAL;

    clock_id id = (clock_id)_clock_id;
    timestamp treq = time_from_timespec(req);
    timestamp tnow = now(id);

    thread_log(current, "clock_nanosleep: clock id %d, flags 0x%x, req %p (%T) rem %p, now %T",
               id, flags, req, treq, rem, tnow);

    return blockq_check_timeout(current->thread_bq, current,
                                closure(heap_general(get_kernel_heaps()), nanosleep_bh,
                                        current, tnow, id, treq, rem), false,
                                id, treq, (flags & TIMER_ABSTIME) != 0);
}

sysreturn sys_time(time_t *tloc)
{
    if (tloc && !validate_user_memory(tloc, sizeof(time_t), true))
        return -EFAULT;
    time_t t = time_t_from_time(now(CLOCK_ID_REALTIME));

    if (tloc)
        *tloc = t;
    return t;
}

sysreturn times(struct tms *buf)
{
    if (!validate_user_memory(buf, sizeof(struct tms), true))
        return -EFAULT;
    buf->tms_utime = CLOCKS_PER_SEC * proc_utime(current->p) / TIMESTAMP_SECOND;
    buf->tms_stime = CLOCKS_PER_SEC * proc_stime(current->p) / TIMESTAMP_SECOND;
    buf->tms_cutime = buf->tms_cstime = 0;  /* there are no child processes */
    thread_log(current, "times: user %ld, system %ld", buf->tms_utime,
            buf->tms_stime);
    return set_syscall_return(current,
            CLOCKS_PER_SEC * uptime() / TIMESTAMP_SECOND);
}

sysreturn clock_gettime(clockid_t clk_id, struct timespec *tp)
{
    thread_log(current, "clock_gettime: clk_id %d, tp %p", clk_id, tp);
    if (!validate_user_memory(tp, sizeof(struct timespec), true))
        return -EFAULT;
    timestamp t;
    switch (clk_id) {
    case CLOCK_MONOTONIC:
    case CLOCK_MONOTONIC_COARSE:
    case CLOCK_MONOTONIC_RAW:
    case CLOCK_BOOTTIME:
    case CLOCK_REALTIME:
    case CLOCK_REALTIME_COARSE:
        /* We depend on our system clock IDs to match the posix ones... */
        t = now(clk_id);
        break;
    case CLOCK_PROCESS_CPUTIME_ID:
        t = proc_utime(current->p) + proc_stime(current->p);
        break;
    default:
        msg_warn("clock id %d not supported\n", clk_id);
        return -EINVAL;
    }
    timespec_from_time(tp, t);
    return 0;
}

void register_clock_syscalls(struct syscall *map)
{
    register_syscall(map, clock_gettime, clock_gettime);
    register_syscall(map, clock_getres, syscall_ignore);
    register_syscall(map, clock_nanosleep, clock_nanosleep);
    register_syscall(map, gettimeofday, gettimeofday);
    register_syscall(map, nanosleep, nanosleep);
    register_syscall(map, time, sys_time);
    register_syscall(map, times, times);
}
