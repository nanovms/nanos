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
    thread_sleep(current); 
    return 0;
}

sysreturn sys_time(time_t *tloc)
{
    time_t t = time_t_from_time(now());

    if (tloc)
        *tloc = t;
    return t;
}

sysreturn clock_gettime(clockid_t clk_id, struct timespec *tp)
{
    thread_log(current, "clock_gettime: clk_id %d", clk_id);
    timespec_from_time(tp, now());
    return 0;
}

void register_clock_syscalls(struct syscall *map)
{
    register_syscall(map, clock_gettime, clock_gettime);
    register_syscall(map, clock_getres, syscall_ignore);
    register_syscall(map, gettimeofday, gettimeofday);
    register_syscall(map, nanosleep, nanosleep);
    register_syscall(map, time, sys_time);
}
