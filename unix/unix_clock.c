#include <unix_internal.h>

// callibration is an issue
int gettimeofday(struct timeval *tv, void *tz)
{
    static u64 seconds;
    static u64 microseconds;
    tv->tv_sec = seconds;
    tv->tv_usec = microseconds++;
    return 0;
}

int nanosleep(const struct timespec* req, struct timespec* rem)
{
    // TODO:
    return 0;
}

void register_clock_syscalls(void **map)
{
    register_syscall(map, SYS_clock_gettime, syscall_ignore);
    register_syscall(map, SYS_clock_getres, syscall_ignore);
    register_syscall(map, SYS_gettimeofday, gettimeofday);
    register_syscall(map, SYS_nanosleep, nanosleep);
}
