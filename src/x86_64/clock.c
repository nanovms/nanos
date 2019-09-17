#include <runtime.h>
#include <x86_64.h>
#include <page.h>
#include "rtc.h"

//#define CLOCK_INIT_DEBUG
#ifdef CLOCK_INIT_DEBUG
#define clock_init_debug(x) do {console(" CLK: " x "\n");} while(0)
#else
#define clock_init_debug(x)
#endif

static timestamp rtc_offset;

typedef __uint128_t u128;

static clock_now platform_now;
static clock_timer platform_timer;

void register_platform_clock_now(clock_now cn)
{
    platform_now = cn;
}

void register_platform_clock_timer(clock_timer ct)
{
    platform_timer = ct;
}

/* system time adjusted by rtc offset */
timestamp now() {
    assert(platform_now);
    return rtc_offset + apply(platform_now);
}

timestamp uptime() {
    assert(platform_now);
    return apply(platform_now);
}

void kern_sleep(timestamp delta)
{
    timestamp end = now() + delta;
    while (now() < end)
        kern_pause();
}

/* system timer that is reserved for processing the global timer heap */
void runloop_timer(timestamp duration)
{
    assert(platform_timer);
    apply(platform_timer, duration);
}

void init_clock(void)
{
    rtc_offset = rtc_gettimeofday() << 32;
}
