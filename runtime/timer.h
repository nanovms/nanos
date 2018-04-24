typedef u64 time;
typedef struct timer *timer;
timer register_timer(time, thunk n);
void remove_timer();
void initialize_timer();
time parse_time();
time timer_check();
time now();


static inline time seconds(int n)
{
    return(((u64)n)<<32);
}

static inline time milliseconds(int n)
{
    return((((u64)n)<<32)/1000ull);
}
