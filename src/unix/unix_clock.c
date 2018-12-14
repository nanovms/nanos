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
    if(rem)
    {
        rem->ts_sec = 0;
        rem->ts_nsec = 0;
    }
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

void register_clock_syscalls(void **map)
{
    register_syscall(map, SYS_clock_gettime, syscall_ignore);
    register_syscall(map, SYS_clock_getres, syscall_ignore);
    register_syscall(map, SYS_gettimeofday, gettimeofday);
    register_syscall(map, SYS_nanosleep, nanosleep);
    register_syscall(map, SYS_time, sys_time);
}
