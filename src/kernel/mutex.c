#include <kernel.h>

//#define MUTEX_DEBUG
#ifdef MUTEX_DEBUG
#define mutex_debug(x, ...) do {tprintf(sym(mutex), 0, x, ##__VA_ARGS__);} while(0)
#else
#define mutex_debug(x, ...)
#endif

#ifdef KERNEL
#define mutex_pause kern_pause
#else
#define mutex_pause()
#endif

/* This implements a two-phase mutex which optionally allows a degree for
   spinning when aquiring the lock. The spinning phase is implemented using a
   cancelable MCS (Mellor-Crummey and Scott) lock, which allows only one spin
   waiter to contend for the mutex at a time. After spinning the specified
   number of times (m->spin_iterations), the cpuinfo is removed from the MCS,
   and the corresponding context is added to the mutex's queue of waiters and
   suspended. If the MCS lock is acquired, then the mutex itself is then
   acquired (looped CAS on m->turn) and the MCS lock is released, passing
   ownership to the next queued spinner, if there is one.

   On an unlock, the mutex is released by zeroing m->turn. This may allow the
   current holder of the MCS lock, which is spinning while trying to acquire
   m->turn, to proceed with taking the mutex. If there is a (suspended)
   context waiting on the mutex, it is treated with equal priority to the MCS
   owner and is scheduled to be resumed. The resumed context then spins to
   acquire the mutex.

   While MCS is relatively straightforward to implement, the ability to exit
   the MCS queue - critical to prevent cores from spinning indefinitely - is a
   somewhat delicate process that has been adapted from the optimistic spin
   queue implementation in Linux by Peter Zijlstra, et al. */

static inline cpuinfo mutex_get_next(mutex m, cpuinfo ci, cpuinfo prev)
{
    do {
        /* If we're removing ci from the list and it is the last item queued,
           try to rewind tail to point to prev.

           If we're unlocking ci and at the end of the list, then this is just
           a simple removal. */
        if (m->mcs_tail == ci &&
            compare_and_swap_64((u64*)&m->mcs_tail, u64_from_pointer(ci),
                                u64_from_pointer(prev)))
            return 0;

        /* If a spin waiter has latched onto us, exchange its next with
           null. This is necessary to keep step A spinning until the node
           being removed gets a new prev link. */
        if (ci->mcs_next) {
            cpuinfo next = pointer_from_u64(atomic_swap_64((u64*)&ci->mcs_next, 0));
            if (next)
                return next;
        }
        mutex_pause();
    } while (1);
}

static inline void mcs_unlock(mutex m, cpuinfo ci)
{
    /* cover race between m->mcs_tail swap and write to ci->mcs_next */
    if (compare_and_swap_64((u64*)&m->mcs_tail, u64_from_pointer(ci), 0))
        return;        /* no successor */

    /* atomic_swap_64 uses __ATOMIC_SEQ_CST; this is safe, though release
       semantics would be sufficient here */
    cpuinfo next = pointer_from_u64(atomic_swap_64((u64*)&ci->mcs_next, 0));
    if (!next)
        next = mutex_get_next(m, ci, 0);

    if (next)
        next->mcs_waiting = false;
}

static inline boolean mutex_lock_internal(mutex m, boolean wait)
{
    cpuinfo ci = current_cpu();
    context ctx = get_current_context(ci);

    mutex_debug("mutex %p, wait %d, ra %p\n", m, wait, __builtin_return_address(0));
    mutex_debug("   ctx %p, turn %p\n", ctx, m->turn);

#ifdef LOCK_STATS
    u64 spins = 0;
    u64 sleeps = 0;
#endif
    /* not preemptable (could become option on allocate) */
    if (m->turn == ctx)
        halt("%s: lock already held - cpu %d, mutex %p, ctx %p, ra %p\n", __func__,
             ci->id, m, ctx, __builtin_return_address(0));

    assert(!ctx->waiting_on);
    if (!wait) {
        boolean acquired = false;
        if (compare_and_swap_64((u64*)&m->mcs_tail, 0, u64_from_pointer(ci))) {
            acquired = compare_and_swap_64((u64*)&m->turn, 0, u64_from_pointer(ctx));
            mcs_unlock(m, ci);
        }
#ifdef LOCK_STATS
        LOCKSTATS_RECORD_LOCK(m->s, true, 0, 0);
#endif
        return acquired;
    }

    assert(!frame_is_full(ctx->frame));
    boolean on_mcs = true;
    ci->mcs_waiting = true;
    cpuinfo prev = pointer_from_u64(atomic_swap_64((u64*)&m->mcs_tail,
                                                   u64_from_pointer(ci)));
    mutex_debug("   add ci %p to tail, prev %p\n", ci, prev);

    if (!prev) {
        ci->mcs_waiting = false;
        goto acquire;
    }

    /* prev write must occur before next */
    ci->mcs_prev = prev;
    write_barrier();
    prev->mcs_next = ci;

    /* limited spin to acquire lock */
    u64 spins_remain = m->spin_iterations;
    while (spins_remain-- > 0) {
        if (!ci->mcs_waiting)
            goto acquire;
#ifdef LOCK_STATS
        spins++;
#endif
        mutex_pause();
    }
    mutex_debug("   spin timeout; removing from MCS list\n");
    fetch_and_add(&m->mcs_spinouts, 1);

    /* spin timed out; extract waiter from list and block

       step A: first undo the setting of prev->mcs_next (unless we are handed
       the lock in the meantime), thus making prev spin wait in
       mutex_get_next() for a valid next pointer */
    while (prev->mcs_next != ci || !compare_and_swap_64((u64*)&prev->mcs_next,
                                                        u64_from_pointer(ci), 0)) {
        /* unlock might hand us the lock */
        if (!ci->mcs_waiting) {
            compiler_barrier(); /* load aquire */
            goto acquire;
        }
#ifdef LOCK_STATS
        spins++;
#endif
        mutex_pause();

        /* re-sample ci->mcs_prev as it may have been updated by a competing deletion */
        prev = ci->mcs_prev;
    }

    /* step B: either wait for ci->mcs_next to be written or, if ci is at tail, rewind to prev */
    cpuinfo next = mutex_get_next(m, ci, prev);
    if (next) {
        /* step C: next will spin wait on the null ci->mcs_next until we
           update next->mcs_prev, and prev is spinning in mutex_get_next()
           awaiting a valid next pointer - this completes the removal */
        next->mcs_prev = prev;
        prev->mcs_next = next;
    }
    ci->mcs_waiting = false;
    on_mcs = false;

  wait:
    /* To cover the race where an unlock occurs between removal from MCS list
       and insertion into waiters, attempt to grab the mutex under waiters_lock. */
    mutex_debug("   removed; taking waiters_lock\n");
    ctx->waiting_on = m;
#ifdef LOCK_STATS
    boolean lsd = ci->lock_stats_disable;
    ci->lock_stats_disable = true;
#endif
    spin_lock(&m->waiters_lock);
    if (compare_and_swap_64((u64*)&m->turn, 0, u64_from_pointer(ctx))) {
        ctx->waiting_on = 0;
        mutex_debug("   mutex acquired; not suspending\n");
        spin_unlock(&m->waiters_lock);
#ifdef LOCK_STATS
        ci->lock_stats_disable = lsd;
        LOCKSTATS_RECORD_LOCK(m->s, true, spins, sleeps);
#endif
        return true;
    }
    mutex_debug("   inserting into waiters list and suspending\n");
    list_insert_before(&m->waiters, &ctx->mutex_l);
    spin_unlock(&m->waiters_lock);
#ifdef LOCK_STATS
    ci->lock_stats_disable = lsd;
    sleeps++;
#endif
    context_pre_suspend(ctx);
    context_suspend();
  acquire:
    spins_remain = MUTEX_ACQUIRE_SPIN_LIMIT;
    while (spins_remain-- > 0) {
        if (m->turn == 0 && compare_and_swap_64((u64*)&m->turn, 0, u64_from_pointer(ctx))) {
            if (on_mcs)
                mcs_unlock(m, ci);
#ifdef LOCK_STATS
            LOCKSTATS_RECORD_LOCK(m->s, true, spins, sleeps);
#endif
            return true;
        }
        mutex_pause();
#ifdef LOCK_STATS
        spins++;
#endif
    }
    fetch_and_add(&m->acquire_spinouts, 1);

    /* we cannot reschedule while holding the mcs lock, so join waiters */
    if (on_mcs) {
        mcs_unlock(m, ci);
        on_mcs = false;
        goto wait;
    }
#ifdef LOCK_STATS
    sleeps++;
#endif
    context_reschedule(ctx);
    goto acquire;
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
    mutex_debug("mutex %p, ctx %p, ra %p\n", m, ctx, __builtin_return_address(0));
    assert(ctx == m->turn);
    m->turn = 0;

    /* MCS owner can grab the mutex now, but we'll also schedule a waiter if we can. */
    context next = 0;
#ifdef LOCK_STATS
    LOCKSTATS_RECORD_UNLOCK(m->s);
    boolean lsd = ci->lock_stats_disable;
    ci->lock_stats_disable = true;
#endif
    spin_lock(&m->waiters_lock);
    list l = list_get_next(&m->waiters);
    if (l) {
        list_delete(l);
        next = struct_from_list(l, context, mutex_l);
    }
    spin_unlock(&m->waiters_lock);
#ifdef LOCK_STATS
    ci->lock_stats_disable = lsd;
#endif
    if (!next)
        return;
    mutex_debug("   dequeued context %p\n", next);
    assert(next->waiting_on == m);
    next->waiting_on = 0;

    /* cover race between enqueue and context_suspend() */
    while (!frame_is_full(next->frame))
        kern_pause();

    mutex_debug("   scheduling return to %p, type %d\n", next, next->type);
    context_schedule_return(next);
}

mutex allocate_mutex(heap h, u64 spin_iterations)
{
    u64 msize = sizeof(struct mutex);
    mutex m = allocate(h, msize);
    if (m == INVALID_ADDRESS)
        return m;

    m->spin_iterations = spin_iterations;
    m->turn = 0;
    m->mcs_tail = 0;
    m->mcs_spinouts = 0;
    m->acquire_spinouts = 0;
    spin_lock_init(&m->waiters_lock);
    list_init(&m->waiters);
#ifdef LOCK_STATS
    m->s.type = LOCK_TYPE_MUTEX;
    m->s.acq_time = 0;
    m->s.trace_hash = 0;
#endif
    return m;
}
