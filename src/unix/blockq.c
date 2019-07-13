#include <unix_internal.h>

/* blockq - a facility for queueing up threads waiting for a resource

   Given an action closure, blockq_check() will attempt the action
   while holding the blockq's lock. If it succeeds (rv >= 0), it will
   release the lock and return the result of the action to the
   caller. If rv is negative, an error condition is presumed, the lock
   is released and rv is returned at once. If rv == infinity, the action gets
   added to the blockq's waiters queue, an optional timeout is (re)set,
   the lock is released and the thread is finally blocked.

   blockq_wake(), meant to be safe for calling from interrupt context,
   takes the blockq lock (really a no-op until SMP support) and
   attempts to apply the action at the head of the waiters queue. If
   it returns infinity, it is left at the head of the queue, the timer is
   reset, the lock is released and waiting resumes, otherwise
   it causes the action to be removed from
   the queue, and the lock released. In either case, the call returns
   to the caller. It is up to the action to apply results to the
   thread frame and call thread_wakeup() as necessary.

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
   >= 0 represents success (no further blocking required), == infinity
   indicates blocking required, and < 0 an error condition (and return).

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

static inline char * blockq_name(blockq bq)
{
    return bq->name;
}
#else
#define blockq_debug(x, ...)
#endif

typedef struct blockq_item {
    blockq_action a;
    thread t;
    struct list l;
} *blockq_item;

static inline void blockq_disable_timer(blockq bq)
{
    if (bq->timeout) {
        blockq_debug("for \"%s\"\n", blockq_name(bq));
        remove_timer(bq->timeout);
        bq->timeout = 0;
    }
}

CLOSURE_1_0(blockq_wake_one, void, blockq);

/* caller must hold the lock */
static inline void blockq_restart_timer_locked(blockq bq)
{
    if (bq->timeout_interval == 0)
        return;

    blockq_debug("for \"%s\"\n", blockq_name(bq));
    /* timer facility doesn't presently give us a better way... */
    if (bq->timeout)
        remove_timer(bq->timeout);
    bq->timeout = register_timer(bq->timeout_interval, closure(bq->h, blockq_wake_one, bq));
}

static void blockq_apply_completion_locked(blockq bq)
{
    if (bq->completion) {
        io_completion completion = bq->completion;
        bq->completion = 0;
        /* XXX release spinlock */
        apply(completion, bq->completion_thread, bq->completion_rv);
        /* XXX acquire spinlock */
    }
}

sysreturn blockq_check(blockq bq, thread t, blockq_action a, boolean in_bh)
{
    assert(t);
    blockq_debug("%p \"%s\", tid %ld, action %p, apply:\n", bq, blockq_name(bq), t->tid, a);
    /* XXX irqsafe mutex/spinlock

       We're actually not irq safe here at the moment, and any blockq
       actions "should" only happen in the bhqueue.

       Before we switch on another CPU thread, insert IRQ-safe
       spinlock.
    */
    sysreturn rv = apply(a, false, false);
    if (rv != infinity) {
        /* XXX release spinlock */
        blockq_debug(" - direct return: %ld\n", rv);
        return rv;
    }

    /* If the queue was empty, start the timer */
    if (list_empty(&bq->waiters_head))
        blockq_restart_timer_locked(bq);

    // XXX make cache
    blockq_item bi = allocate(bq->h, sizeof(struct blockq_item));
    if (bi == INVALID_ADDRESS) {
        msg_err("unable to allocate blockq_item\n");
        return -EAGAIN;
    }
    bi->a = a;
    bi->t = t;
    blockq_debug("queue bi %p, a %p, tid %d\n", bi, bi->a, bi->t->tid);
    list_insert_before(&bq->waiters_head, &bi->l);

    blockq_debug(" - check requires block, sleeping\n");
    t->blocked_on = bq;
    t->blocked_on_action = a;
    /* XXX release spinlock */
    if (!in_bh) {
        thread_sleep(t);        /* no return */
    } else {
        return infinity;
    }
}

void blockq_flush_thread(blockq bq, thread t)
{
//    blockq_debug("for \"%s\"\n", blockq_name(bq));
    blockq_debug("bq %p, name %p\n", bq, blockq_name(bq));
    /* XXX take irqsafe spinlock */

    list_foreach(&bq->waiters_head, l) {
        blockq_item bi = struct_from_list(l, blockq_item, l);
        if (bi->t != t)
            continue;
        blockq_debug(" - applying %p:\n", bi->a);
        apply(bi->a, /* blocking */ true, /* nullify */ true);
        blockq_apply_completion_locked(bq);
    }
    blockq_disable_timer(bq);

    /* XXX release lock */
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
        if (bi->a) {
            blockq_debug(" - applying %p:\n", bi->a);
            apply(bi->a, /* blocking */ true, /* nullify */ true);
        }
        list_delete(l);
        blockq_apply_completion_locked(bq);
    }
    blockq_disable_timer(bq);
    /* XXX release lock */
}

void blockq_wake_one(blockq bq)
{
    blockq_debug("bq %p \"%s\"\n", bq, blockq_name(bq));

    /* XXX take irqsafe spinlock */
    list l = list_get_next(&bq->waiters_head);
    if (!l)
        return;
    blockq_item bi = struct_from_list(l, blockq_item, l);
    blockq_debug("bq %p, bi %p, action %p, tid %d\n", bq, bi, bi->a, bi->t->tid);

    if (bi->a) {
        sysreturn rv = apply(bi->a, true, false);
        blockq_debug("   - returned %ld\n", rv);
        if (rv != 0) {
            list_delete(l);
            blockq_apply_completion_locked(bq);
            
            /* clear timer if this was the last entry */
            if (list_empty(&bq->waiters_head))
                blockq_disable_timer(bq);
            
            /* action sets return value */
        } else if (bq->timeout) {
            /* leave at head of queue and reset timer */
            blockq_restart_timer_locked(bq);
        }
    }

    /* XXX release lock */
    
}

void blockq_set_completion(blockq bq, io_completion completion, thread t,
        sysreturn rv)
{
    bq->completion = completion;
    bq->completion_thread = t;
    bq->completion_rv = rv;
}

blockq allocate_blockq(heap h, char * name, u64 size, timestamp timeout_interval)
{
    blockq_debug("name \"%s\", size %ld, timeout_interval %T\n", name, size, timeout_interval);
    blockq bq = allocate(h, sizeof(struct blockq));
    if (bq == INVALID_ADDRESS)
        return bq;

    bq->h = h;
    list_init(&bq->waiters_head);

    if (name) {
        runtime_memcpy(bq->name, name, MIN(runtime_strlen(name) + 1, BLOCKQ_NAME_MAX - 1));
        bq->name[BLOCKQ_NAME_MAX - 1] = '\0';
    }

    bq->timeout = 0;
    bq->timeout_interval = timeout_interval;
    bq->completion = 0;
    bq->completion_thread = 0;
    bq->completion_rv = 0;
    return bq;
}

void deallocate_blockq(blockq bq)
{
    blockq_debug("for \"%s\"\n", blockq_name(bq));

    /* XXX what's the right behavior if we have waiters? */

    blockq_disable_timer(bq);
    deallocate(bq->h, bq, sizeof(struct blockq));
}
