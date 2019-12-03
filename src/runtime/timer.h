#pragma once
typedef u64 timestamp;
typedef struct timer *timer;
typedef closure_type(clock_timer, void, timestamp);

extern clock_timer platform_timer;

static inline void register_platform_clock_timer(clock_timer ct)
{
    platform_timer = ct;
}

static inline void runloop_timer(timestamp duration)
{
    apply(platform_timer, duration);
}

timer register_timer(timestamp interval, clock_id id, thunk n);
timer register_periodic_timer(timestamp interval, clock_id id, thunk n);
timestamp remove_timer(timer t);
void initialize_timers(kernel_heaps kh);
timestamp parse_time();
void print_timestamp(buffer, timestamp);
timestamp timer_check();

#define THOUSAND (1000ull)
#define MILLION (1000000ull)
#define BILLION (1000000000ull)
#define QUADRILLION (1000000000000000ull)
#define TIMESTAMP_SECOND (1ull << 32)

// danger - truncation, should always be subsec

static inline timestamp seconds(u64 n)
{
    return n * TIMESTAMP_SECOND;
}

static inline timestamp milliseconds(u64 n)
{
    u64 sec = n / THOUSAND;
    n -= sec * THOUSAND;
    return seconds(sec) + (seconds(n) / THOUSAND);
}

static inline timestamp microseconds(u64 n)
{
    u64 sec = n / MILLION;
    n -= sec * MILLION;
    return seconds(sec) + (seconds(n) / MILLION);
}

static inline timestamp nanoseconds(u64 n)
{
    u64 sec = n / BILLION;
    n -= sec * BILLION;
    return seconds(sec) + (seconds(n) / BILLION);
}

static inline timestamp femtoseconds(u64 fs)
{
    return fs / (QUADRILLION >> 32);
}

static inline timestamp truncate_seconds(timestamp t)
{
    return t & MASK(32);
}

static inline u64 sec_from_timestamp(timestamp t)
{
    return t / TIMESTAMP_SECOND;
}

static inline u64 nsec_from_timestamp(timestamp t)
{
    u64 sec = sec_from_timestamp(t);
    return (sec * BILLION) +
        ((truncate_seconds(t) * BILLION) / TIMESTAMP_SECOND);
}

static inline u64 usec_from_timestamp(timestamp t)
{
    u64 sec = sec_from_timestamp(t);
    return (sec * MILLION) +
        ((truncate_seconds(t) * MILLION) / TIMESTAMP_SECOND);
}

