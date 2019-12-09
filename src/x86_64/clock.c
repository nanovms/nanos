/* Implementation of clock functions that can be accessed from both the kernel
 * and from the userspace vdso
 *
 * Note: All functions that can be accessed from the VDSO must be prepended
 * with VDSO or marked static
 */

#include <runtime.h>
#include <x86_64.h>
#include <page.h>
#include <vdso.h>

typedef __uint128_t u128;

#define __vdso_dat (&(VVAR_REF(vdso_dat)))

static u64 
_rdtscp(void)
{
    u32 a, d;
    asm volatile("rdtscp" : "=a" (a), "=d" (d));
    return (((u64)a) | (((u64)d) << 32));
}

static u64 
_rdtsc(void)
{
    u32 a, d;
    asm volatile("rdtsc" : "=a" (a), "=d" (d));
    return (((u64)a) | (((u64)d) << 32));
}

VDSO u64 
rdtsc(void)
{
    if (__vdso_dat->platform_has_rdtscp)
        return _rdtscp();
    return _rdtsc();
}

VDSO u64
rdtsc_precise(void)
{
    if (__vdso_dat->platform_has_rdtscp)
        return _rdtscp();

    asm volatile("cpuid" ::: "%rax", "%rbx", "%rcx", "%rdx"); /* serialize execution */
    return _rdtsc();
}

/* This is all kernel-only below here */
#ifndef BUILD_VDSO
timestamp now(clock_id id)
{
    switch (id) {
    case CLOCK_ID_MONOTONIC:
    case CLOCK_ID_MONOTONIC_RAW:
    case CLOCK_ID_MONOTONIC_COARSE:
    case CLOCK_ID_BOOTTIME:
        return apply(platform_monotonic_now);
    case CLOCK_ID_REALTIME:
    case CLOCK_ID_REALTIME_COARSE:
        return apply(platform_monotonic_now) + __vdso_dat->rtc_offset;
    default:
        return 0; 
    }
}

timestamp uptime(void)
{
    return now(CLOCK_ID_BOOTTIME);
}

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

void register_platform_clock_now(clock_now cn, vdso_clock_id id)
{
    platform_monotonic_now = cn;
    __vdso_dat->clock_src = id;
}
#endif
