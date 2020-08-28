#include <kernel.h>
#include <vdso.h>

#define __vdso_dat (&(VVAR_REF(vdso_dat)))

clock_now platform_monotonic_now;
clock_timer platform_timer;
thunk platform_timer_percpu_init;

void kernel_delay(timestamp delta)
{
    timestamp end = now(CLOCK_ID_MONOTONIC) + delta;
    while (now(CLOCK_ID_MONOTONIC) < end)
        kern_pause();
}

void init_clock(void)
{
    __vdso_dat->clock_src = VDSO_CLOCK_SYSCALL;
    __vdso_dat->platform_has_rdtscp = 0;
//    __vdso_dat->rtc_offset = rtc_gettimeofday() << 32;
    __vdso_dat->rtc_offset = 0;
}
