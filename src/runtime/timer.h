#ifdef KERNEL
#include <lock.h>
#endif

typedef struct timer *timer;

/* On timer expiration, the registered timer handler will be invoked with the
   associated timer expiry and a count of timer overruns (or a value of
   timer_disabled (-1ull) if the timer was canceled; see below). The expiry
   value may be used by the handler to track a number of events without the
   need to allocate a separate handler for each event.

   An overruns value of timer_disabled indicates that a timer has been
   canceled. Every timer registration must result in at least one callback:
   for one-shot timers, there is a terminal callback for either timer
   expiration or cancellation. Periodic timers will run indefinitely until
   canceled, with the last callback signalling timer_disabled. Therefore, a
   timer handler may be deallocated only on one of these terminal conditions,
   and not simply after a call to remove_timer(). Naturally, if multiple
   timers are registered for the same handler, even if for the same expiry
   (which is valid and will be treated as multiple expiration events), the
   handler must keep track of these registrations and only deallocate the
   handler and associated resources after the last terminal callback.
*/

#define timer_disabled (-1ull)

closure_type(timer_handler, void, u64 expiry, u64 overruns);

typedef struct timerqueue {
#ifdef KERNEL
    struct spinlock lock;
#endif
    heap h;
    pqueue pq;
    timestamp next_expiry;      /* adjusted */
    thunk service;

    /* If non-null, it is used to get the current timestamp (which does not depend on a timer id
     * because all timers are of the same type and their expiry value is given by the 'expiry' timer
     * struct field).
     * If null, a timer id determines both its current timestamp (retrieved by calling the global
     * now() function) and its expiry value (retrieved via the timer_expiry() function). */
    clock_now now;

    u32 service_scheduled;  /* CAS */
    u32 update;             /* CAS; timer re-programming needed */
    boolean empty;          /* indicating the queue is empty */
    sstring name;
} *timerqueue;

struct timer {
    clock_id id;
    timestamp expiry;
    timestamp interval;
    boolean absolute;
    boolean active;
    boolean queued;
    timer_handler handler;
};

static inline void init_timer(timer t)
{
    t->active = false;
    t->queued = false;
}

static inline boolean timer_is_active(timer t)
{
    return t->active;
}

static inline timer allocate_timer(heap h)
{
    timer t = allocate(h, sizeof(struct timer));
    if (t != INVALID_ADDRESS)
        init_timer(t);
    return t;
}

static inline void deallocate_timer(heap h, timer t)
{
    deallocate(h, t, sizeof(struct timer));
}

void register_timer(timerqueue tq, timer t, clock_id id,
                    timestamp val, boolean absolute, timestamp interval, timer_handler n);

#if defined(KERNEL) || defined(BUILD_VDSO)
#define __vdso_dat (&(VVAR_REF(vdso_dat)))
#endif

/* Convert to monotonic raw. Only used for system time (not for process or thread CPU time). */
static inline timestamp timer_expiry(timer t)
{
    timestamp expiry = t->expiry;

#if defined(KERNEL) || defined(BUILD_VDSO)
    u64 gen;
    do {
        gen = __vdso_dat->vdso_gen & ~1;
        s64 interval = expiry - __vdso_dat->last_raw;
        switch (t->id) {
        case CLOCK_ID_MONOTONIC_RAW:
            return expiry;
        case CLOCK_ID_REALTIME:
        case CLOCK_ID_REALTIME_COARSE:
            expiry -= __vdso_dat->rtc_offset;
            expiry -= clock_phase_adjust(expiry, interval);
            break;
        default:
            break;
        }
        expiry -= clock_freq_adjust(interval);
        read_barrier();
    } while (gen != __vdso_dat->vdso_gen);
#endif

    return expiry;
}

static inline timestamp timerqueue_now(timerqueue tq, timer t)
{
    return (tq->now ? apply(tq->now) : now(t->id));
}

static inline timestamp timerqueue_expiry(timerqueue tq, timer t)
{
    return (tq->now ? t->expiry : timer_expiry(t));
}

static inline void timer_get_remaining(timerqueue tq, timer t, timestamp *remain, timestamp *interval)
{
    timestamp tnow = timerqueue_now(tq, t);
    *remain = t->expiry > tnow ? t->expiry - tnow : 0;
    *interval = t->interval;
}

static inline void refresh_timer_update_locked(timerqueue tq, timer next)
{
    if (next == INVALID_ADDRESS) {
        tq->empty = true;
        return;
    }
    timestamp n = timerqueue_expiry(tq, next);
    if (n != tq->next_expiry)
        tq->next_expiry = n;
    tq->empty = false;
    tq->update = true;
}

/* Returns true if timer was successfully removed from the timer queue. A
   return value of false means that the timer was not found in the queue.
   This could mean that the timer already fired or was previously
   canceled. Callers should not assume that the timer's handler was invoked
   synchronously in such a case; it could be waiting in a queue, pending
   execution.

   If remain is nonzero and removal was successful, *remain is set to the time
   remaining until timer elapse. */
boolean remove_timer(timerqueue tq, timer t, timestamp *remain);

timerqueue allocate_timerqueue(heap h, clock_now now, sstring name);
void deallocate_timerqueue(timerqueue tq);
void timer_service(timerqueue tq, timestamp here);
void timer_reorder(timerqueue tq);

void timer_adjust_begin(timerqueue tq);
void timer_adjust_end(timerqueue tq, pqueue_element_handler h);

s64 rtime(s64 *result);
