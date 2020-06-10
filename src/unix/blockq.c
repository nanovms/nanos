#include <unix_internal.h>

/* blockq - a facility for queueing up threads waiting for a resource

   Given an action closure, blockq_check() will attempt the action
   while holding the blockq's lock. If it succeeds (rv >= 0), it will
   release the lock and return the result of the action to the
   caller. If rv is negative, an error condition is presumed, the lock
   is released and rv is returned at once. If rv ==
   BLOCKQ_BLOCK_REQUIRED, the action gets added to the blockq's
   waiters queue, an optional timeout is set, the lock is released and
   the thread is finally blocked.

   blockq_wake_one(), meant to be safe for calling from interrupt context,
   takes the blockq lock (really a no-op until SMP support) and
   attempts to apply the action at the head of the waiters queue. If
   it returns BLOCKQ_BLOCK_REQUIRED, it is left at the head of the
   queue, the lock is released and waiting resumes, otherwise it
   causes the action to be removed from the queue, and the lock
   released. In either case, the call returns to the caller. It is up
   to the action to apply results to the thread frame and call
   thread_wakeup() as necessary.

   The action must adhere to the following:

   - It must be safe for calling from the syscall handler or interrupt
     level (including timer expiry).

   - It must be brief, as it will either be called with interrupts
     disabled or from the interrupt handler itself (though not an
     issue in the short term with the bifurcated runloop).

   - Action invocation does not presume any particlar condition or
     state change; a wake up does not guarantee availability of a
     resource nor indicate the source, e.g. I/O event vs timeout
     expiry. As such, it's up to the action to check status and
     resource availability as necessary.

   - A blocked flag will indicate whether the action is being invoked
     within the syscall handler or after blocking. In the latter case,
     should the blocked thread resume execution, it is up to the
     action to call set_syscall_{return,error}() and thread_wakeup().

   - Obviously, it must never call blockq_check() or blockq_wake()
     itself, for it is called while holding the blockq lock.

   In the existing cases right now, the action return value semantics
   mirror those of the syscall itself. Of course, the blocking code
   may interpret this return value as necessary, provided that a value
   >= 0 represents success (no further blocking required), ==
   BLOCKQ_BLOCK_REQUIRED indicates blocking required, and < 0 an error
   condition (and return).

   Note also that this presently serializes requests and handles them
   in that order alone. The action at the head of the queue must
   eventually return a non-zero value before any further actions in
   the queue can be handled (except for blockq_flush, used for
   exceptions on the resource - e.g. a closed connection). Should it
   ever become necessary to allow another waiter in the queue to
   handle the request, we can consider making that an option and
   moving from the queue to a CAS list for fast removal (similar to
   the poll notify list). TBD
 */

//#define BLOCKQ_DEBUG
#ifdef BLOCKQ_DEBUG
#define blockq_debug(x, ...) do {log_printf("  BQ", "%s: " x, __func__, ##__VA_ARGS__);} while(0)
#else
#define blockq_debug(x, ...)
#endif

/* queue of threads waiting for a resource */
#define BLOCKQ_NAME_MAX 20
struct blockq {
    heap h;
    char name[BLOCKQ_NAME_MAX]; /* for debug */
    /* XXX: TBD spinlock lock; */
    struct list waiters_head;   /* of threads and associated timers+actions */
    io_completion completion;
    thread completion_thread;
    sysreturn completion_rv;
};

declare_closure_struct(2, 1, void, blockq_item_timeout,
    blockq, bq, struct blockq_item *, bi,
    u64, overruns);

typedef struct blockq_item {
    thread t;           /* waiting thread */
    timer timeout;      /* timer for this item (could be zero) */
    closure_struct(blockq_item_timeout, timeout_func);
    blockq_action a;    /* action to test for resource avail. */
    struct list l;      /* embedding on blockq->waiters_head */
} *blockq_item;

static inline void free_blockq_item(blockq bq, blockq_item bi)
{
    list_delete(&bi->l);
    deallocate(bq->h, bi, sizeof(struct blockq_item));
}

static void blockq_item_finish(blockq bq, blockq_item bi)
{
    blockq_debug("bq %p (\"%s\") bi %p (tid:%ld) completed\n",
        bq, blockq_name(bq), bi, bi->t->tid);

    if (bi->timeout)
        remove_timer(bi->timeout, 0);

    if (bq->completion) {
        io_completion completion = bq->completion;
        bq->completion = 0;
        /* XXX release spinlock */
        apply(completion, bq->completion_thread, bq->completion_rv);
        /* XXX acquire spinlock */
    }

    thread_release(bi->t);
    free_blockq_item(bq, bi);
}

/*
 * Apply blockq_item action with lock held
 */
static void blockq_apply_bi_locked(blockq bq, blockq_item bi, u64 flags)
{
    sysreturn rv;

    blockq_debug("bq %p (\"%s\") bi %p (tid:%ld) %s %s %s\n",
                 bq, blockq_name(bq), bi, bi->t->tid,
                 (flags & BLOCKQ_ACTION_BLOCKED) ? "blocked " : "",
                 (flags & BLOCKQ_ACTION_NULLIFY) ? "nullify " : "",
                 (flags & BLOCKQ_ACTION_TIMEDOUT) ? "timedout" : "");

    rv = apply(bi->a, flags);
    blockq_debug("   - returned %ld\n", rv);

    /* If the blockq_action returns BLOCKQ_BLOCK_REQUIRED and neither
       nullify or timeout are set in flags, continue blocking. */
    if ((flags & (BLOCKQ_ACTION_NULLIFY | BLOCKQ_ACTION_TIMEDOUT)) ||
        (rv != BLOCKQ_BLOCK_REQUIRED))
        blockq_item_finish(bq, bi);
}

/*
 * A blockq_item timed out.
 *
 * Invoke its action and remove it from the list of waiters,
 * if applicable
 */
define_closure_function(2, 1, void, blockq_item_timeout,
                 blockq, bq, blockq_item, bi,
                 u64, overruns /* ignored */)
{
    blockq bq = bound(bq);
    blockq_item bi = bound(bi);

    blockq_debug("bq %p (\"%s\") bi %p (tid:%ld)\n",
        bq, blockq_name(bq), bi, bi->t->tid);

    bi->timeout = 0;

    /* XXX take irqsafe spinlock */
    blockq_apply_bi_locked(bq, bi, BLOCKQ_ACTION_BLOCKED | BLOCKQ_ACTION_TIMEDOUT);
    /* XXX release lock */
}

/*
 * Wake a single waiter.
 *
 * Returns thread whose bi action was applied
 * Note that there is no guarantee that the thread is actually awake
 * or the bi completed -- this just means its action was applied
 */
thread blockq_wake_one(blockq bq)
{
    blockq_item bi;
    list l;
    thread t;

    blockq_debug("%p (\"%s\") \n", bq, blockq_name(bq));

    /* XXX take irqsafe spinlock */

    l = list_get_next(&bq->waiters_head);
    if (!l)
        return INVALID_ADDRESS;

    bi = struct_from_list(l, blockq_item, l);
    t = bi->t;
    blockq_apply_bi_locked(bq, bi, BLOCKQ_ACTION_BLOCKED);

    /* XXX release lock */

    return t;
}

boolean blockq_wake_one_for_thread(blockq bq, thread t)
{
    blockq_debug("%p (\"%s\") \n", bq, blockq_name(bq));

    /* XXX take irqsafe spinlock */
    list_foreach(&bq->waiters_head, l) {
        blockq_item bi = struct_from_list(l, blockq_item, l);
        if (bi->t != t)
            continue;
        blockq_apply_bi_locked(bq, bi, BLOCKQ_ACTION_BLOCKED);
        return true;
    }
    /* XXX release lock */
    return false;
}

sysreturn blockq_check_timeout(blockq bq, thread t, blockq_action a, boolean in_bh,
                               clock_id clkid, timestamp timeout, boolean absolute)
{
    assert(t);
    assert(a);
    assert(!(in_bh && timeout)); /* no timeout checks in bh */

    blockq_debug("%p \"%s\", tid %ld, action %p, timeout %ld, clock_id %d\n",
                 bq, blockq_name(bq), t->tid, a, timeout, clkid);

    /* XXX irqsafe mutex/spinlock

       We're actually not irq safe here at the moment, and any blockq
       actions "should" only happen in the bhqueue.

       Before we switch on another CPU thread, insert IRQ-safe
       spinlock.
    */
    sysreturn rv = apply(a, 0);
    if (rv != BLOCKQ_BLOCK_REQUIRED) {
        /* XXX release spinlock */
        blockq_debug(" - direct return: %ld\n", rv);
        return rv;
    }

    // XXX make cache
    blockq_item bi = allocate(bq->h, sizeof(struct blockq_item));
    if (bi == INVALID_ADDRESS) {
        msg_err("unable to allocate blockq_item\n");
        return -EAGAIN;
    }

    bi->a = a;
    bi->t = t;
    thread_reserve(t);

    if (timeout > 0) {
        bi->timeout = register_timer(runloop_timers, clkid, timeout, absolute, 0,
            init_closure(&bi->timeout_func, blockq_item_timeout, bq, bi));
        if (bi->timeout == INVALID_ADDRESS) {
            msg_err("failed to allocate blockq timer\n");
            deallocate(bq->h, bi, sizeof(struct blockq_item));
            return -EAGAIN;
        }
    } else {
        bi->timeout = 0;
    }

    blockq_debug("queuing bi %p, a %p, tid %d\n", bi, bi->a, bi->t->tid);
    list_insert_before(&bq->waiters_head, &bi->l);
    if (!in_bh)
        t->blocked_on = bq;

    /* XXX release spinlock */

    /* if we're either in bh or a non-current thread is invoking this,
     * return now
     */
    if (in_bh || (current != t))
        return BLOCKQ_BLOCK_REQUIRED;

    thread_sleep_interruptible();  /* no return */
    assert(0);
}

/* XXX This deserves another pass; blockq_item should really just be embedded into thread. */
boolean blockq_flush_thread(blockq bq, thread t)
{
    boolean unblocked = false;
    blockq_debug("bq %p, name %p\n", bq, blockq_name(bq));

    /* XXX take irqsafe spinlock */

    list_foreach(&bq->waiters_head, l) {
        blockq_item bi = struct_from_list(l, blockq_item, l);
        if (bi->t != t)
            continue;

        blockq_apply_bi_locked(bq, bi, BLOCKQ_ACTION_BLOCKED | BLOCKQ_ACTION_NULLIFY);
        unblocked = true;
    }

    /* XXX release lock */
    return unblocked;
}

/* Wake all waiters and empty queue, typically for error conditions,
   closed pipe/connections, etc. Actions are called with nullify set,
   indicating the last time that the action will be used by the
   blockq, regardless of what the action returns.
*/

void blockq_flush(blockq bq)
{
    blockq_debug("bq %p - \"%s\"\n", bq, blockq_name(bq));

    /* XXX take irqsafe spinlock */
    list_foreach(&bq->waiters_head, l) {
        blockq_item bi = struct_from_list(l, blockq_item, l);
        blockq_apply_bi_locked(bq, bi, BLOCKQ_ACTION_BLOCKED | BLOCKQ_ACTION_NULLIFY);
    }
    /* XXX release lock */
}

int blockq_transfer_waiters(blockq dest, blockq src, int n)
{
    int transferred = 0;

    /* XXX locks for dest and src */
    list_foreach(&src->waiters_head, l) {
        if (transferred >= n)
            break;
        blockq_item bi = struct_from_list(l, blockq_item, l);
        if (bi->timeout) {
            timestamp remain;
            timer_handler t = bi->timeout->t;
            remove_timer(bi->timeout, &remain);
            bi->timeout = remain == 0 ? 0 :
                register_timer(runloop_timers, CLOCK_ID_MONOTONIC, remain, false, 0,
                    init_closure(&bi->timeout_func, blockq_item_timeout, dest,
                        bi));
            assert(t);
            deallocate_closure(t);
        }
        list_delete(&bi->l);
        assert(bi->t->blocked_on == src);
        bi->t->blocked_on = dest;
        list_insert_before(&dest->waiters_head, &bi->l);
        transferred++;
    }
    return transferred;
}

void blockq_set_completion(blockq bq, io_completion completion, thread t, sysreturn rv)
{
    bq->completion = completion;
    bq->completion_thread = t;
    bq->completion_rv = rv;
}

blockq allocate_blockq(heap h, char * name)
{
    blockq_debug("name \"%s\"\n", name);
    blockq bq = allocate(h, sizeof(struct blockq));
    if (bq == INVALID_ADDRESS)
        return bq;

    if (name) {
        runtime_memcpy(bq->name, name, MIN(runtime_strlen(name) + 1, BLOCKQ_NAME_MAX - 1));
        bq->name[BLOCKQ_NAME_MAX - 1] = '\0';
    }

    bq->h = h;
    bq->completion = 0;
    bq->completion_thread = 0;
    bq->completion_rv = 0;
    list_init(&bq->waiters_head);

    return bq;
}

void deallocate_blockq(blockq bq)
{
    blockq_debug("for \"%s\"\n", blockq_name(bq));

    /* XXX what's the right behavior if we have waiters? */
    /* for now err out */
    assert(list_empty(&bq->waiters_head));

    deallocate(bq->h, bq, sizeof(struct blockq));
}

const char * blockq_name(blockq bq)
{
    return bq->name;
}
