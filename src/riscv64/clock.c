#include <kernel.h>

#define RTC_TIME_LOW        0x00
#define RTC_TIME_HIGH       0x04

#define CLINT_TIMEBASE_FREQ 10000000 // XXX should be getting freq from device tree
#define CLINT_MTIME         0xbff8

#define read_rtc_reg(o) mmio_read_32(mmio_base_addr(RTC) + (o))
#define __vdso_dat (&(VVAR_REF(vdso_dat)))

clock_now platform_monotonic_now;
clock_timer platform_timer;

static u64 read_rtc(void)
{
    u64 t = read_rtc_reg(RTC_TIME_LOW);
    read_barrier();
    t |= ((u64)read_rtc_reg(RTC_TIME_HIGH))<<32;
    return t;
}

u64 rtc_gettimeofday(void)
{
    return read_rtc()/BILLION;
}

void rtc_settimeofday(u64 seconds)
{
    // goldfish-rtc documentation says the registers are read-only
}

closure_function(0, 0, timestamp, riscv_clock_now)
{
    u64 t = mmio_read_64(mmio_base_addr(CLINT) + CLINT_MTIME);
    u64 f = CLINT_TIMEBASE_FREQ;
    return seconds(t / f) | truncate_seconds((t << 32) / f);
}

closure_function(0, 1, void, riscv_deadline_timer,
                 timestamp, interval)
{
    u64 tv = mmio_read_64(mmio_base_addr(CLINT) + CLINT_MTIME);
    tv += (interval*CLINT_TIMEBASE_FREQ) >> 32; 
    /* Must set via ecall and not mmio or else opensbi won't trap the timer */
    supervisor_ecall(SBI_SETTIME, tv);
}

closure_function(0, 0, void, riscv_timer_percpu_init)
{
}

closure_struct(riscv_clock_now, _clock_now);
closure_struct(riscv_deadline_timer, _deadline_timer);
closure_struct(riscv_timer_percpu_init, _timer_percpu_init);

void init_clock(void)
{
    __vdso_dat->platform_has_rdtscp = 0;
    register_platform_clock_now(init_closure(&_clock_now, riscv_clock_now), VDSO_CLOCK_SYSCALL);
    register_platform_clock_timer(init_closure(&_deadline_timer, riscv_deadline_timer),
                                  init_closure(&_timer_percpu_init, riscv_timer_percpu_init));
}

