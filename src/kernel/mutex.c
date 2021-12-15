#include <kernel.h>

//#define MUTEX_DEBUG
#ifdef MUTEX_DEBUG
#define mutex_debug(x, ...) do {log_printf(" MTX", "%s: " x, __func__, ##__VA_ARGS__);} while(0)
#else
#define mutex_debug(x, ...)
#endif

#ifdef KERNEL
#define mutex_pause kern_pause
#else
#define mutex_pause()
#endif

/* This implements a two-phase mutex which optionally allows a degree for
   spinning when aquiring the lock. A limitation of this is that the spinning
   is only for an uncondended lock, and the waiter does not enter the queue of
   waiters until the second phase (context suspend). As such, waiters for a
   mutex are not strictly processed in FIFO order.

   Linux uses an MCS lock for the first phase, but the unqueueing (removal)
   operation is complex (yet necessary in order to migrate waiters into the
   queue of suspended tasks). It may be worth implementing something similar
   here, perhaps moreso for the lessened bus contention than the FIFO
   property. */

static inline void mutex_acquired(mutex m, context ctx)
{
    assert(!m->turn);
    m->turn = ctx;
    ctx->waiting_on = 0;
}

static inline boolean mutex_cas_take(mutex m, context ctx)
{
    if (compare_and_swap_32(&m->count, 0, 1)) {
        mutex_acquired(m, ctx);
        return true;
    }
    return false;
}

static inline boolean mutex_lock_internal(mutex m, boolean wait)
{
    cpuinfo ci = current_cpu();
    context ctx = get_current_context(ci);

    mutex_debug("cpu %d, mutex %p, wait %d, ra %p\n", ci->id, m, wait,
                __builtin_return_address(0));
    mutex_debug("   ctx %p, turn %p, count %d\n", ctx, m->turn, m->count);

    /* not preemptable (but could become so if needed) */
    if (m->turn == ctx)
        halt("%s: lock already held - cpu %d, mutex %p, ctx %p, ra %p\n", __func__,
             ci->id, m, ctx, __builtin_return_address(0));

    if (!wait)
        return mutex_cas_take(m, ctx);

    u64 spins_remain = m->spin_iterations;
    while (spins_remain-- > 0) {
        if (mutex_cas_take(m, ctx))
            return true;
        mutex_pause();
    }

    if (fetch_and_add_32(&m->count, 1) == 0) {
        mutex_acquired(m, ctx);
        return true;
    }

    /* race covered by dequeue loop in unlock */
    assert(!frame_is_full(ctx->frame));

    mutex_debug("ctx %p about to wait, count %d\n", ctx, m->count);
    ctx->waiting_on = m;
    while (!enqueue(m->waiters, ctx)) {
        mutex_pause();      /* XXX timeout */
    }
    context_pre_suspend(ctx);
    context_suspend();
    return true;
}

boolean mutex_try_lock(mutex m)
{
    return mutex_lock_internal(m, false);
}

void mutex_lock(mutex m)
{
    assert(mutex_lock_internal(m, true));
}

void mutex_unlock(mutex m)
{
    cpuinfo ci = current_cpu();
    context ctx = get_current_context(ci);
    mutex_debug("cpu %d, mutex %p, ra %p\n", ci->id, m, __builtin_return_address(0));
    mutex_debug("   ctx %p turn %p, count %d\n", ctx, m->turn, m->count);
    assert(ctx == m->turn);
    context next = INVALID_ADDRESS;
  retry:
    /* loop to cover race between fetch_and_add and enqueue */
    while (m->count > 1) {
        next = dequeue(m->waiters);
        if (next != INVALID_ADDRESS)
            break;
    }

    if (next != INVALID_ADDRESS) {
        assert(fetch_and_add_32(&m->count, -1) > 1);
        m->turn = next;
        assert(next->waiting_on == m);
        next->waiting_on = 0;
        /* cover race between enqueue and context_suspend() */
        while (!frame_is_full(next->frame))
            kern_pause();
        mutex_debug("returning to %p, type %d\n", next, next->type);
        context_schedule_return(next);
        return;
    }

    m->turn = 0;

    /* cover race between dequeue and final release */
    if (!compare_and_swap_32(&m->count, 1, 0))
        goto retry;
}

mutex allocate_mutex(heap h, u64 depth, u64 spin_iterations)
{
    u64 msize = sizeof(struct mutex);
    mutex m = allocate(h, msize);
    if (m == INVALID_ADDRESS)
        return m;

    m->count = 0;
    m->turn = 0;
    m->spin_iterations = spin_iterations;
    m->waiters = allocate_queue(h, depth);
    if (m->waiters == INVALID_ADDRESS) {
        deallocate(h, m, msize);
        return INVALID_ADDRESS;
    }
    return m;
}
