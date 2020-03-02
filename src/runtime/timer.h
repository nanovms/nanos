typedef u64 timestamp;
typedef struct timer *timer;
typedef closure_type(timer_handler, void, u64);

declare_closure_struct(2, 0, void, timer_free,
                       timer, t, heap, h);

typedef struct timerheap {
    heap h;
    pqueue pq;
    const char *name;
} *timerheap;

struct timer {
    clock_id id;
    timestamp expiry;
    timestamp interval;
    boolean disabled;
    timer_handler t;
    struct refcount refcount;
    closure_struct(timer_free, free);
};

typedef closure_type(clock_timer, void, timestamp);

extern clock_timer platform_timer;
extern thunk platform_timer_percpu_init;

static inline void register_platform_clock_timer(clock_timer ct, thunk percpu_init)
{
    platform_timer = ct;
    platform_timer_percpu_init = percpu_init;
}

static inline void runloop_timer(timestamp duration)
{
    apply(platform_timer, duration);
}

// XXX - maybe timerheap per clocktype, or separate for proc/thread timers
timer register_timer(timerheap th, clock_id id, timestamp val, boolean absolute, timestamp interval, timer_handler n);

#if defined(STAGE3) || defined(BUILD_VDSO)
#define __rtc_offset (&(VVAR_REF(vdso_dat)))->rtc_offset
#else
#define __rtc_offset 0
#endif

/* Convert to monotonic. Not clear yet how to map process and thread
   times to monotonic scale. Should the process have its own timer heap? */
static inline timestamp timer_expiry(timer t)
{
    switch (t->id) {
    case CLOCK_ID_MONOTONIC:
    case CLOCK_ID_MONOTONIC_RAW:
    case CLOCK_ID_MONOTONIC_COARSE:
    case CLOCK_ID_BOOTTIME:
        return t->expiry;
    case CLOCK_ID_REALTIME:
    case CLOCK_ID_REALTIME_COARSE:
        return t->expiry - __rtc_offset;
    default:
        halt("expiry: clock id %d unsupported\n", t->id); /* XXX hmm */
    }
}
#undef __rtc_offset

static inline void timer_get_remaining(timer t, timestamp *remain, timestamp *interval)
{
    timestamp tnow = now(t->id);
    *remain = t->expiry > tnow ? t->expiry - tnow : 0;
    *interval = t->interval;
}

/* returns time remaining or 0 if elapsed */
static inline void remove_timer(timer t, timestamp *remain)
{
    assert(!t->disabled);
    t->disabled = true;
    if (remain) {
        timestamp x = timer_expiry(t);
        timestamp n = now(t->id);
        *remain = x > n ? x - n : 0;
    }
}

/* returns absolute expiry of root timer */
static inline timestamp timer_check(timerheap th)
{
    timer t;
    if ((t = pqueue_peek(th->pq))) {
        timestamp e = timer_expiry(t);
        /* -1ull is a valid timestamp but reserved value here */
    	return e == infinity ? e - 1 : e;
    }
    return infinity;
}

timerheap allocate_timerheap(heap h, const char *name);
void timer_service(timerheap th, timestamp here);
void print_timestamp(buffer, timestamp);

#define THOUSAND         (1000ull)
#define MILLION          (1000000ull)
#define BILLION          (1000000000ull)
#define TRILLION         (1000000000000ull)
#define QUADRILLION      (1000000000000000ull)
#define TIMESTAMP_SECOND (1ull << 32)

// danger - truncation, should always be subsec

static inline timestamp seconds(u64 n)
{
    return n * TIMESTAMP_SECOND;
}

#define TIMESTAMP_CONV_FN(name, factor)                         \
    static inline timestamp name(u64 n)                         \
    {                                                           \
        if (n == 0)                                             \
            return 0;                                           \
        u64 sec = n / factor;                                   \
        n -= sec * factor;                                      \
        return seconds(sec) + (seconds(n) / factor) + 1;        \
    }

#define TIMESTAMP_CONV_FN_2(name, factor)       \
    static inline timestamp name(u64 n)         \
    {                                           \
        if (n == 0)                             \
            return 0;                           \
        return n / (factor >> 32) + 1;          \
    }

TIMESTAMP_CONV_FN(milliseconds, THOUSAND)
TIMESTAMP_CONV_FN(microseconds, MILLION)
TIMESTAMP_CONV_FN(nanoseconds, BILLION)
TIMESTAMP_CONV_FN_2(picoseconds, TRILLION)
TIMESTAMP_CONV_FN_2(femtoseconds, QUADRILLION)

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
