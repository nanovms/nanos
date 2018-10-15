#pragma once
typedef u64 time;
typedef struct timer *timer;
timer register_timer(time, thunk n);
timer register_periodic_timer(time interval, thunk n);
void remove_timer();
void initialize_timers(kernel_heaps kh);
time parse_time();
void print_time(buffer, time);
time timer_check();
#ifdef BOOT
static inline time now() { return 0; } /* stub */
#else
time now();
#endif

#define nano 1000000000ull

// danger - truncation, should always be subsec
static inline u64 time_from_nsec(u64 n)
{
    return (n * (1ull<<32)) / nano;
}

// without seconds component
static inline u64 nsec_from_time(time n)
{
    return ((n & MASK(32)) * nano) >> 32;
}

static inline u64 sec_from_time(time n)
{
    return n >> 32;
}

static inline time seconds(int n)
{
    return(((u64)n)<<32);
}

static inline time milliseconds(int n)
{
    return((((u64)n)<<32)/1000ull);
}
