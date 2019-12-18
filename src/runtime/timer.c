#include <runtime.h>
//#define TIMER_DEBUG
#ifdef TIMER_DEBUG
#define timer_debug(x, ...) do {log_printf("TIMER", x, ##__VA_ARGS__);} while(0)
#else
#define timer_debug(x, ...)
#endif

// should pass a timer around
static pqueue timers;
static heap theap;

/* The lower time expiry is the higher priority. */
static boolean timer_compare(void *za, void *zb)
{
    return timer_expiry((timer)za) > timer_expiry((timer)zb);
}

define_closure_function(1, 0, void, timer_free,
                        timer, t)
{
    deallocate(theap, bound(t), sizeof(struct timer));
}

timer register_timer(clock_id id, timestamp val, boolean absolute, timestamp interval, timer_handler n)
{
    timer t = allocate(theap, sizeof(struct timer));
    if (t == INVALID_ADDRESS) {
        msg_err("failed to allocate timer\n");
        return INVALID_ADDRESS;
    }

    t->id = id;
    t->expiry = absolute ? val : now(id) + val;
    t->interval = interval;
    t->disabled = false;
    t->t = n;

    init_refcount(&t->refcount, 1, init_closure(&t->free, timer_free, t));
    pqueue_insert(timers, t);
    timer_debug("register timer: %p, expiry %T, interval %T, handler %p\n", t, t->expiry, interval, n);
    return t;
}

timestamp timer_check()
{
    timer t;
    s64 delta;
    timestamp here = now(CLOCK_ID_MONOTONIC);

    while ((t = pqueue_peek(timers)) && (delta = here - timer_expiry(t), delta >= 0)) {
        pqueue_pop(timers);
        if (!t->disabled) {
            if (t->interval) {
                u64 overruns = delta > t->interval ? delta / t->interval + 1 : 1;
                apply(t->t, overruns);
                if (!t->disabled) {
                    t->expiry += t->interval * overruns;
                    pqueue_insert(timers, t);
                    continue;
                }
            } else {
                apply(t->t, 1);
            }
        }
        refcount_release(&t->refcount);
    }

    if (t) {
    	timestamp dt = timer_expiry(t) - here;
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
