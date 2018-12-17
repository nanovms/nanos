#pragma once
#ifdef __APPLE__
typedef u64 time_value_t;
#else
typedef u64 time;
#endif
typedef struct timer *timer;
#ifdef __APPLE__
timer register_timer(time_value_t, thunk n);
timer register_periodic_timer(time_value_t interval, thunk n);
#else
timer register_timer(time, thunk n);
timer register_periodic_timer(time interval, thunk n);
#endif
void remove_timer(timer t);
void initialize_timers(kernel_heaps kh);
#ifdef __APPLE__
time_value_t parse_time();
void print_time(buffer, time_value_t);
#else
time parse_time();
void print_time(buffer, time);
#endif
#ifdef __APPLE__
time_value_t timer_check();
#else
time timer_check();
#endif
#ifdef BOOT
static inline time now() { return 0; } /* stub */
#else
#ifdef __APPLE__
time_value_t now();
#else
time now();
#endif
#endif

#define nano 1000000000ull
#define femto 1000000000000000ull

// danger - truncation, should always be subsec
static inline u64 time_from_nsec(u64 n)
{
    return (n * (1ull<<32)) / nano;
}

// without seconds component
#ifdef __APPLE__
static inline u64 nsec_from_time(time_value_t n)
#else
static inline u64 nsec_from_time(time n)
#endif
{
    return ((n & MASK(32)) * nano) >> 32;
}

#ifdef __APPLE__
static inline u64 sec_from_time(time_value_t n)
#else
static inline u64 sec_from_time(time n)
#endif
{
    return n >> 32;
}

#ifdef __APPLE__
static inline time_value_t seconds(int n)
#else
static inline time seconds(int n)
#endif
{
    return(((u64)n)<<32);
}

#ifdef __APPLE__
static inline time_value_t milliseconds(int n)
#else
static inline time milliseconds(int n)
#endif
{
    return((((u64)n)<<32)/1000ull);
}

#ifdef __APPLE__
static inline time_value_t femtoseconds(u64 fs)
#else
static inline time femtoseconds(u64 fs)
#endif
{
    return fs / (femto >> 32);
}
