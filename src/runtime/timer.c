#include <runtime.h>
//#define TIMER_DEBUG
#ifdef TIMER_DEBUG
#define timer_debug(x, ...) do {log_printf("TIMER", x, ##__VA_ARGS__);} while(0)
#else
#define timer_debug(x, ...)
#endif

struct timer {
    thunk t;
    timestamp expiry;
    timestamp interval;
    clock_id id;
    boolean disable;
};

// should pass a timer around
static pqueue timers;
static heap theap;

static inline timestamp expiry(timer t)
{
    switch (t->id) {
    case CLOCK_ID_MONOTONIC:
    case CLOCK_ID_MONOTONIC_RAW:
    case CLOCK_ID_MONOTONIC_COARSE:
    case CLOCK_ID_BOOTTIME:
        return t->expiry;
    case CLOCK_ID_REALTIME:
    case CLOCK_ID_REALTIME_COARSE:
        return t->expiry - rtc_offset;
    default:
        halt("expiry: clock id %d unsupported\n");
    }
}

/* The lower time expiry is the higher priority. */
static boolean timer_compare(void *za, void *zb)
{
    return expiry((timer)za) > expiry((timer)zb);
}

/* returns time remaining or 0 if elapsed */
timestamp remove_timer(timer t)
{
    t->disable = true;
    timestamp x = expiry(t);
    timestamp n = now(CLOCK_ID_MONOTONIC);
    return x > n ? x - n : 0;
}

static timer __register_timer(timestamp interval, clock_id id, thunk n, boolean periodic)
{
    timer t=(timer)allocate(theap, sizeof(struct timer));
    if (t == INVALID_ADDRESS) {
        msg_err("failed to allocate timer\n");
        return INVALID_ADDRESS;
    }

    timestamp tn = now(id);
    t->t = n;
    t->disable = false;
    t->expiry = tn + interval;
    t->interval = (periodic) ? interval : 0;
    t->id = id;
    pqueue_insert(timers, t);

    timer_debug("register %s timer: %p, interval %T, now %T, expiry %T\n",
                (periodic) ? "periodic" : "one-shot", t, interval, tn, t->expiry);

    return(t);
}

timer register_timer(timestamp interval, clock_id id, thunk n)
{
    return __register_timer(interval, id, n, false);
}

timer register_periodic_timer(timestamp interval, clock_id id, thunk n)
{
    return __register_timer(interval, id, n, true);
}
    
/* Presently called with ints off. Address thread safety with
   pqueue before using with ints enabled.
*/
timestamp timer_check()
{
    timestamp here = 0;
    timer t = 0;

    while ((t = pqueue_peek(timers)) && (here = now(CLOCK_ID_MONOTONIC), expiry(t) <= here)) {
        pqueue_pop(timers);
        if (!t->disable) {
            apply(t->t);
            if (t->interval) {
                t->expiry += t->interval;
                pqueue_insert(timers, t);
                continue;
            }
        }
        deallocate(theap, t, sizeof(struct timer));
    }
    if (t) {
    	timestamp dt = expiry(t) - here;
    	timer_debug("check returning dt: %d\n", dt);
    	return dt;
    }
    return infinity;
}

timestamp parse_time(string b)
{
    u64 s = 0, frac = 0, fracnorm = 0;

    foreach_character (_, c, b) {
        if (c == '.')  {
            fracnorm = 1;
        } else {
            if (fracnorm) {
                frac = frac*10 + digit_of(c);
                fracnorm *= 10;
            } else s = s *10 + digit_of(c);
        }
    }
    timestamp result = s << 32;

    if (fracnorm) result |= (frac<<32)/fracnorm;
    return(result);
}

void print_timestamp(string b, timestamp t)
{
    u32 s= t>>32;
    u64 f= t&MASK(32);

    bprintf(b, "%d", s);
    if (f) {
        int count=0;

        bprintf(b,".");

        /* should round or something */
        while ((f *= 10) && (count++ < 6)) {
            u32 d = (f>>32);
            bprintf (b, "%d", d);
            f -= ((u64)d)<<32;
        }
    }
}

void initialize_timers(kernel_heaps kh)
{
    heap h = heap_general(kh);
    assert(!timers);
    timers = allocate_pqueue(h, timer_compare);
    theap = h;
}
