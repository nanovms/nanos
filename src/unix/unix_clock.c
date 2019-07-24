#include <unix_internal.h>

// callibration is an issue
sysreturn gettimeofday(struct timeval *tv, void *tz)
{
    timeval_from_time(tv, now());
    return 0;
}

static CLOSURE_2_0(nanosleep_timeout, void, thread, boolean *);
static void nanosleep_timeout(thread t, boolean *dead)
{
    set_syscall_return(t, 0);
    thread_wakeup(t);
}

sysreturn nanosleep(const struct timespec* req, struct timespec* rem)
{
    // nanosleep is interpretable and the remaining
    // time is put in rem, but for now this is non interpretable
    // and we sleep for the whole duration before waking up.
    register_timer(time_from_timespec(req),
		closure(heap_general(get_kernel_heaps()), nanosleep_timeout, current, 0));
    thread_sleep_uninterruptible(); /* XXX move to blockq */
    return 0;
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
