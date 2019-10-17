#include <unix_internal.h>

// callibration is an issue
sysreturn gettimeofday(struct timeval *tv, void *tz)
{
    timeval_from_time(tv, now());
    return 0;
}

closure_function(4, 3, sysreturn, nanosleep_bh,
                 thread, t, timestamp, start, timestamp, interval, struct timespec*, rem,
                 boolean, blocked, boolean, nullify, boolean, timedout)
{
    thread t = bound(t);
    timestamp elapsed = now() - bound(start); /* XXX parameterize */
    thread_log(t, "%s: start %T, interval %T, rem %p, elapsed %T, blocked %d, nullify %d, timedout %d",
               __func__, bound(start), bound(interval), bound(rem), elapsed, blocked, nullify, timedout);
    sysreturn rv = 0;
    if (nullify) {
        if (bound(rem)) {
            timespec_from_time(bound(rem), elapsed);
            rv = -EINTR;
            goto out;
        }
    }

    if (!timedout && elapsed < bound(interval))
        return infinity;
  out:
    if (blocked)
        thread_wakeup(t);
    closure_finish();
    return set_syscall_return(t, rv);
}

sysreturn nanosleep(const struct timespec* req, struct timespec* rem)
{
    timestamp start = now(); /* XXX parameterize later for clock_nanosleep */
    timestamp interval = time_from_timespec(req);
    thread_log(current, "nanosleep: req %p (%T) rem %p, now %T", req, interval, rem, start);
    return blockq_check_timeout(current->thread_bq, current,
                                closure(heap_general(get_kernel_heaps()), nanosleep_bh, current, start, interval, rem),
                                false, time_from_timespec(req));
}

sysreturn sys_time(time_t *tloc)
{
    time_t t = time_t_from_time(now());

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
    case CLOCK_REALTIME:
    case CLOCK_REALTIME_COARSE:
        t = now();
        break;
    case CLOCK_PROCESS_CPUTIME_ID:
        t = proc_utime(current->p) + proc_stime(current->p);
        break;
    case CLOCK_MONOTONIC:
    case CLOCK_MONOTONIC_COARSE:
    case CLOCK_MONOTONIC_RAW:
        t = uptime();
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
