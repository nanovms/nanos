#include <sruntime.h>
#include <unix.h>

// callibration is an issue
int gettimeofday(struct timeval *tv, void *tz)
{
    static u64 seconds;
    static u64 microseconds;
    tv->tv_sec = seconds;
    tv->tv_usec = microseconds++;
    return 0;
}


void register_clock_syscalls(void *map)
{
    register_syscall(map, SYS_clock_gettime, syscall_ignore);
    register_syscall(map, SYS_clock_getres, syscall_ignore);
    register_syscall(map, SYS_gettimeofday, gettimeofday);
}
