#include <runtime.h>
#include <x86_64.h>
#include <page.h>

typedef __uint128_t u128;

timestamp rtc_offset = 0;
clock_now platform_monotonic_now;
clock_timer platform_timer;
u8 platform_has_rdtscp = 0;

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
        platform_has_rdtscp = 1;

    rtc_offset = rtc_gettimeofday() << 32;
}
