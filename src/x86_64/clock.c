#include <runtime.h>
#include <x86_64.h>
#include <vdso.h>

#define __vdso_dat (&(VVAR_REF(vdso_dat)))

clock_now platform_monotonic_now;
clock_timer platform_timer;

void kernel_delay(timestamp delta)
{
    timestamp end = now(CLOCK_ID_MONOTONIC) + delta;
    while (now(CLOCK_ID_MONOTONIC) < end)
        kern_pause();
}

void init_clock(void)
{
    /* detect rdtscp */
    u32 regs[4];
    cpuid(0x80000001, 0, regs);
    if (regs[3] & U64_FROM_BIT(27))
        __vdso_dat->platform_has_rdtscp = 1;

    __vdso_dat->rtc_offset = rtc_gettimeofday() << 32;
}
