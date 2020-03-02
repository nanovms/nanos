#include <runtime.h>

//#define TIMER_DEBUG
#ifdef TIMER_DEBUG
#define timer_debug(x, ...) do {log_printf("TIMER", x, ##__VA_ARGS__);} while(0)
#else
#define timer_debug(x, ...)
#endif

/* The lower time expiry is the higher priority. */
static boolean timer_compare(void *za, void *zb)
{
    return timer_expiry((timer)za) > timer_expiry((timer)zb);
}

define_closure_function(2, 0, void, timer_free,
                        timer, t, heap, h)
{
    deallocate(bound(h), bound(t), sizeof(struct timer));
}

timer register_timer(timerheap th, clock_id id, timestamp val, boolean absolute, timestamp interval, timer_handler n)
{
    timer t = allocate(th->h, sizeof(struct timer));
    if (t == INVALID_ADDRESS) {
        msg_err("failed to allocate timer\n");
        return INVALID_ADDRESS;
    }

    t->id = id;
    t->expiry = absolute ? val : now(id) + val;
    t->interval = interval;
    t->disabled = false;
    t->t = n;

    init_refcount(&t->refcount, 1, init_closure(&t->free, timer_free, t, th->h));
    pqueue_insert(th->pq, t);
    timer_debug("register timer: %p, expiry %T, interval %T, handler %p\n", t, t->expiry, interval, n);
    return t;
}

// XXX change to support multiple timer heaps - might help us clean up
// clocksource interface later

void timer_service(timerheap th, timestamp here)
{
    timer t;
    s64 delta;

    timer_debug("timer_service enter for heap \"%s\" at %T\n", th->name, here);
    while ((t = pqueue_peek(th->pq)) && (delta = here - timer_expiry(t), delta >= 0)) {
        pqueue_pop(th->pq);
        if (!t->disabled) {
            if (t->interval) {
                u64 overruns = delta > t->interval ? delta / t->interval + 1 : 1;
                timer_debug("apply %p (%F), overruns %ld\n", t, t->t, overruns);
                apply(t->t, overruns);
                if (!t->disabled) {
                    t->expiry += t->interval * overruns;
                    pqueue_insert(th->pq, t);
                    continue;
                }
            } else {
                apply(t->t, 1);
            }
        }
        refcount_release(&t->refcount);
    }
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

timerheap allocate_timerheap(heap h, const char *name)
{
    timerheap th = allocate(h, sizeof(struct timerheap));
    th->pq = allocate_pqueue(h, timer_compare);
    if (th->pq == INVALID_ADDRESS) {
        deallocate(h, th, sizeof(struct timerheap));
        return INVALID_ADDRESS;
    }
    th->h = h;
    th->name = name;
    return th;
}
