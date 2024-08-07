#ifdef KERNEL
#include <kernel.h>
#define timer_lock(tq) spin_lock(&(tq)->lock)
#define timer_unlock(tq) spin_unlock(&(tq)->lock)
#else
#include <runtime.h>
#define timer_lock(tq)
#define timer_unlock(tq)
#endif

//#define TIMER_DEBUG
#ifdef TIMER_DEBUG
#define timer_debug(x, ...) do {log_printf(ss("TIMER"), ss(x), ##__VA_ARGS__);} while(0)
#else
#define timer_debug(x, ...)
#endif

/* The lower time expiry is the higher priority. */
static boolean timer_compare(void *za, void *zb)
{
    /* XXX FIXME This will fail if monotonic now ever wraps. From the
       clock_gettime(2) manpage, the clock starts at some "unspecified
       starting point." This could be resolved by comparing deltas to some
       reference point, perhaps even set once on boot (good for ~68 years). */
    return timer_expiry((timer)za) > timer_expiry((timer)zb);
}

static boolean timer_compare_simple(void *za, void *zb)
{
    return ((timer)za)->expiry > ((timer)zb)->expiry;
}

void register_timer(timerqueue tq, timer t, clock_id id,
                    timestamp val, boolean absolute, timestamp interval, timer_handler n)
{
    t->id = id;
    t->expiry = absolute ? val : timerqueue_now(tq, t) + val;
    t->interval = interval;
    t->absolute = absolute;
    assert(!t->queued);
    t->active = true;
    t->queued = true;
    t->handler = n;

    timer_lock(tq);
    pqueue_insert(tq->pq, t);
    timer next = pqueue_peek(tq->pq);
    refresh_timer_update_locked(tq, next);
    timer_unlock(tq);
    timer_debug("register timer: %p, expiry %T, interval %T, handler %p\n", t, t->expiry, interval, n);
}

boolean remove_timer(timerqueue tq, timer t, timestamp *remain)
{
    timer_lock(tq);
    timestamp x = t->expiry;

    if (!t->active) {
        assert(!t->queued);
        timer_unlock(tq);
        return false;
    }

    t->active = false;
    if (t->queued) {
        /* We are able to remove the timer from the queue, so we can safely
           invoke the timer handler here. */
        t->queued = false;
        assert(pqueue_remove(tq->pq, t));
        timer_unlock(tq);
        apply(t->handler, 0, timer_disabled);
    } else {
        /* This is an interval timer that was removed from tq and is amidst
           handler servicing. Calling the handler here would risk the two
           invocations happening out-of-sequence, with the actual timer expiry
           occurring after the call with timer_disabled. This is dangerous, so
           let timer_service() to do the terminal invocation for us. */
        assert(t->interval != 0);
        timer_unlock(tq);
    }

    if (remain) {
        timestamp n = timerqueue_now(tq, t);
        *remain = x > n ? x - n : 0;
    }
    return true;
}

void timer_service(timerqueue tq, timestamp here)
{
    timer t;
    s64 delta;
    u64 overruns;

    timer_debug("timer_service enter for heap \"%s\" at %T\n", tq->name, here);
    timer_lock(tq);
    while (((t = pqueue_peek(tq->pq)) != INVALID_ADDRESS) &&
           (delta = here - timerqueue_expiry(tq, t), delta >= 0)) {
        pqueue_pop(tq->pq);
        assert(t->active && t->queued);
        boolean interval = t->interval != 0;
        if (interval) {
            overruns = delta > t->interval ? delta / t->interval + 1 : 1;
            t->expiry += t->interval * overruns;
        } else {
            overruns = 1;
            t->active = false;
        }
        t->queued = false;
        timer_unlock(tq);
        timer_debug("timer %p: expiry %T, overruns %ld, delta %T, apply handler %p (%F)\n",
                    t, timerqueue_expiry(tq, t), overruns, delta, t->handler, t->handler);
        apply(t->handler, t->expiry, overruns);
        timer_lock(tq);
        if (interval) {
            if (t->active) {
                t->queued = true;
                pqueue_insert(tq->pq, t);
            } else {
                /* The timer was removed while this routine was in the process
                   of invoking the handler on expiry. The handler invocation
                   with timer_disabled should happen here to insure that it is
                   the final handler callback. */
                timer_unlock(tq);
                apply(t->handler, 0, timer_disabled);
                timer_lock(tq);
            }
        }
    }
    refresh_timer_update_locked(tq, t);
    timer_unlock(tq);
}

void timer_reorder(timerqueue tq)
{
    timer_lock(tq);
    pqueue_reorder(tq->pq);
    timer_unlock(tq);
}

void timer_adjust_begin(timerqueue tq)
{
    timer_lock(tq);
}

void timer_adjust_end(timerqueue tq, pqueue_element_handler h)
{
    pqueue_walk(tq->pq, h);
    pqueue_reorder(tq->pq);
    timer_unlock(tq);
}

timerqueue allocate_timerqueue(heap h, clock_now now, sstring name)
{
    timerqueue tq = allocate(h, sizeof(struct timerqueue));
    tq->pq = allocate_pqueue(h, now ? timer_compare_simple : timer_compare);
    if (tq->pq == INVALID_ADDRESS) {
        deallocate(h, tq, sizeof(struct timerqueue));
        return INVALID_ADDRESS;
    }
    tq->h = h;
    tq->now = now;
    tq->name = name;
#ifdef KERNEL
    spin_lock_init(&tq->lock);
    tq->service_scheduled = tq->update = false;
    tq->empty = true;
    tq->next_expiry = 0;
    tq->service = 0;
#endif
    return tq;
}

void deallocate_timerqueue(timerqueue tq)
{
    deallocate_pqueue(tq->pq);
    deallocate(tq->h, tq, sizeof(struct timerqueue));
}

s64 rtime(s64 *result)
{
    s64 t = (s64)(sec_from_timestamp(now(CLOCK_ID_REALTIME)));
    if (result)
        *result = t;
    return t;
}
