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

#define nano 1000000000ull
#define femto 1000000000000000ull

// danger - truncation, should always be subsec
static inline u64 time_from_nsec(u64 n)
{
    return (n * (1ull<<32)) / nano;
}

// without seconds component
static inline u64 nsec_from_timestamp(timestamp n)
{
    return ((n & MASK(32)) * nano) >> 32;
}

static inline u64 sec_from_timestamp(timestamp n)
{
    return n >> 32;
}

static inline timestamp seconds(int n)
{
    return(((u64)n)<<32);
}

static inline timestamp milliseconds(int n)
{
    return((((u64)n)<<32)/1000ull);
}

static inline timestamp femtoseconds(u64 fs)
{
    return fs / (femto >> 32);
}
