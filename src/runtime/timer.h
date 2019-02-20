#pragma once
typedef u64 timestamp;
typedef struct timer *timer;

timer register_timer(timestamp, thunk n);
timer register_periodic_timer(timestamp interval, thunk n);
void remove_timer(timer t);
void initialize_timers(kernel_heaps kh);
timestamp parse_time();
void print_timestamp(buffer, timestamp);
timestamp timer_check();
#ifdef BOOT
static inline timestamp now() { return 0; } /* stub */
#else
timestamp now();
#endif

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
    return seconds(n) / THOUSAND;
}

static inline timestamp microseconds(u64 n)
{
    return seconds(n) / MILLION;
}

static inline timestamp nanoseconds(u64 n)
{
    return seconds(n) / BILLION;
}

static inline timestamp femtoseconds(u64 fs)
{
    return fs / (QUADRILLION >> 32);
}

// without seconds component
static inline u64 nsec_from_timestamp(timestamp n)
{
    return ((n & MASK(32)) * BILLION) / TIMESTAMP_SECOND;
}

static inline u64 usec_from_timestamp(timestamp n)
{
    return ((n & MASK(32)) * MILLION) / TIMESTAMP_SECOND;
}

static inline u64 sec_from_timestamp(timestamp n)
{
    return n / TIMESTAMP_SECOND;
}
