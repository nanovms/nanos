typedef u64 time;
typedef struct timer *timer;
timer register_timer(time, thunk n);
timer register_periodic_timer(time interval, thunk n);
void remove_timer();
void initialize_timers(heap);
time parse_time();
void print_time(buffer, time);
time timer_check();
time now();

static u64 nano = 1000000000;

// danger - truncation, should always be subsec
static inline u64 time_from_nsec(u64 n)
{
    return (n * (1ull<<32)) / nano;
}


static inline time seconds(int n)
{
    return(((u64)n)<<32);
}

static inline time milliseconds(int n)
{
    return((((u64)n)<<32)/1000ull);
}
