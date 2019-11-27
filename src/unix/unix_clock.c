#include <unix_internal.h>

sysreturn gettimeofday(struct timeval *tv, void *tz)
{
    timeval_from_time(tv, now(CLOCK_ID_REALTIME));
    return 0;
}

closure_function(4, 1, sysreturn, nanosleep_bh,
                 thread, t, timestamp, start, timestamp, interval, struct timespec*, rem,
                 u64, flags)
{
    thread t = bound(t);
    timestamp elapsed = now(CLOCK_ID_MONOTONIC) - bound(start); /* XXX parameterize */
    thread_log(t, "%s: start %T, interval %T, rem %p, elapsed %T, flags 0x%lx",
               __func__, bound(start), bound(interval), bound(rem), elapsed, flags);
    sysreturn rv = 0;
    if (flags & BLOCKQ_ACTION_NULLIFY) {
        if (bound(rem)) {
            timestamp remain = elapsed < bound(interval) ? bound(interval) - elapsed : 0;
            timespec_from_time(bound(rem), remain);
            rv = -EINTR;
            goto out;
        }
    }

    if (!(flags & BLOCKQ_ACTION_TIMEDOUT) && elapsed < bound(interval))
        return BLOCKQ_BLOCK_REQUIRED;
  out:
    if (flags & BLOCKQ_ACTION_BLOCKED)
        thread_wakeup(t);
    closure_finish();
    return set_syscall_return(t, rv);
}

sysreturn nanosleep(const struct timespec* req, struct timespec* rem)
{
    timestamp start = now(CLOCK_ID_MONOTONIC); /* XXX parameterize later for clock_nanosleep */
    timestamp interval = time_from_timespec(req);
    thread_log(current, "nanosleep: req %p (%T) rem %p, now %T", req, interval, rem, start);
    return blockq_check_timeout(current->thread_bq, current,
                                closure(heap_general(get_kernel_heaps()), nanosleep_bh, current, start, interval, rem),
                                false, time_from_timespec(req));
}

sysreturn sys_time(time_t *tloc)
{
    time_t t = time_t_from_time(now(CLOCK_ID_REALTIME));

    if (tloc)
        *tloc = t;
    return t;
}

sysreturn times(struct tms *buf)
{
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
    thread_log(current, "clock_gettime: clk_id %d", clk_id);
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
    register_syscall(map, gettimeofday, gettimeofday);
    register_syscall(map, nanosleep, nanosleep);
    register_syscall(map, time, sys_time);
    register_syscall(map, times, times);
}
