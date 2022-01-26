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
    assert(!ctx->waiting_on);
    assert(!m->turn);
    m->turn = ctx;
}

static inline boolean mutex_cas_take(mutex m, context ctx)
{
    boolean acquired = compare_and_swap_64((u64*)&m->waiters_tail, 0,
                                           u64_from_pointer(ctx));
    if (acquired)
        mutex_acquired(m, ctx);
    return acquired;
}

static inline boolean mutex_lock_internal(mutex m, boolean wait)
{
    cpuinfo ci = current_cpu();
    context ctx = get_current_context(ci);

    mutex_debug("cpu %d, mutex %p, wait %d, ra %p\n", ci->id, m, wait,
                __builtin_return_address(0));
    mutex_debug("   ctx %p, turn %p\n", ctx, m->turn);

    /* not preemptable (could become option on allocate) */
    if (m->turn == ctx)
        halt("%s: lock already held - cpu %d, mutex %p, ctx %p, ra %p\n", __func__,
             ci->id, m, ctx, __builtin_return_address(0));

    assert(!ctx->next_waiter);
    if (!wait)
        return mutex_cas_take(m, ctx);

    u64 spins_remain = m->spin_iterations;
    while (spins_remain-- > 0) {
        if (mutex_cas_take(m, ctx))
            return true;
        mutex_pause();
    }

    assert(!frame_is_full(ctx->frame));
    ctx->waiting_on = m;
    context prev_tail = pointer_from_u64(atomic_swap_64((u64*)&m->waiters_tail,
                                                        u64_from_pointer(ctx)));
    mutex_debug("   add ctx %p to tail, prev_tail %p\n", ctx, prev_tail);
    if (!prev_tail) {
        mutex_acquired(m, ctx);
        return true;
    }
    prev_tail->next_waiter = ctx;
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
    mutex_debug("   ctx %p, next_waiter %p\n", ctx, ctx->next_waiter);
    assert(ctx == m->turn);
    if (!ctx->next_waiter) {
        /* cover race between m->waiters_tail swap and write to ctx->next_waiter */
        m->turn = 0;
        if (compare_and_swap_64((u64*)&m->waiters_tail, u64_from_pointer(ctx), 0))
            return;        /* no successor */

        /* enqueue pending; spin until next waiter is set */
        while (!ctx->next_waiter)
            mutex_pause();
    }

    context next = ctx->next_waiter;
    ctx->next_waiter = 0;
    m->turn = next;
    assert(next->waiting_on == m);
    next->waiting_on = 0;

    /* cover race between enqueue and context_suspend() */
    while (!frame_is_full(next->frame))
        kern_pause();

    mutex_debug("scheduling return to %p, type %d\n", next, next->type);
    context_schedule_return(next);
}

mutex allocate_mutex(heap h, u64 depth, u64 spin_iterations)
{
    u64 msize = sizeof(struct mutex);
    mutex m = allocate(h, msize);
    if (m == INVALID_ADDRESS)
        return m;

    m->spin_iterations = spin_iterations;
    m->turn = 0;
    m->waiters_tail = 0;
    return m;
}
