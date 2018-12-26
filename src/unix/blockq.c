#include <unix_internal.h>

/* blockq - a facility for queueing up threads waiting for a resource

   Given an action closure, blockq_check() will attempt the action
   while holding the blockq's lock. If it succeeds (rv > 0), it will
   release the lock and return the result of the action to the
   caller. If rv is negative, an error condition is presumed, the lock
   is released and rv is returned at once. If rv == 0, the action gets
   added to the blockq's waiters queue, an optional timeout is (re)set,
   the lock is released and the thread is finally blocked.

   blockq_wake(), meant to be safe for calling from interrupt context,
   takes the blockq lock (really a no-op until SMP support) and
   attempts to apply the action at the head of the waiters queue. If
   it returns 0, it is left at the head of the queue, the timer is
   reset, the lock is released and waiting resumes. Either < 0 (error
   condition) or > 0 (success) causes the action to be removed from
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
   > 0 represents success (no further blocking required), == 0
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

CLOSURE_1_0(blockq_wake_one, void, blockq);

static inline void blockq_disable_timer(blockq bq)
{
    if (bq->timeout) {
        remove_timer(bq->timeout);
        bq->timeout = 0;
    }
}

/* caller must hold the lock */
static inline void blockq_restart_timer_locked(blockq bq)
{
    if (bq->timeout_interval == 0)
        return;

    /* timer facility doesn't presently give us a better way... */
    if (bq->timeout)
        remove_timer(bq->timeout);
    bq->timeout = register_timer(bq->timeout_interval, closure(bq->h, blockq_wake_one, bq));
}

sysreturn blockq_check(blockq bq, thread t, blockq_action a)
{
    /* XXX grab irqsafe mutex/spinlock

       presently a no-op because
       1) we don't have locks yet and
       2) runqueue handling and interrupt handling are segregated, so

       - before switching on interrupt handling during runqueue,
         disable interrupts during critical section, and

       - before we switch on another CPU thread, insert IRQ-safe
         spinlock.
    */
    sysreturn rv = apply(a, false);
    if (rv != 0) {
        /* XXX release spinlock */
        return rv;
    }

    /* If the queue was empty, start the timer */
    if (queue_length(bq->waiters) == 0)
        blockq_restart_timer_locked(bq);

    if (!enqueue(bq->waiters, a)) {
        /* XXX hmm */
        msg_err("waiter queue full for bq %p\n", bq);
        return 0;
    }

    /* XXX release spinlock */
    thread_sleep(t);
}

/* Wake all waiters and empty queue, typically for error conditions,
   closed pipe/connections, etc. It is up to the called action to
   determine the state of the resource (e.g. socket status) and know
   that it will not remain on the queue regardless - and therefore
   must wake up (or block on something else). The blockq user must do
   its own synchronization / barriers to this end;

   In other words, a zero return value from the action will not cause
   it to remain in the waiters queue to be executed later; it's done.
*/

void blockq_flush(blockq bq)
{
    /* XXX take irqsafe spinlock */

    blockq_action a;
    while ((a = dequeue(bq->waiters)))
        apply(a, true);

    blockq_disable_timer(bq);

    /* XXX release lock */

}

void blockq_wake_one(blockq bq)
{
    blockq_action a;

    /* XXX take irqsafe spinlock */

    a = queue_peek(bq->waiters);
    if (!a)
        return;

    sysreturn rv = apply(a, true);
    if (rv != 0) {
        assert(dequeue(bq->waiters));

        /* clear timer if this was the last entry */
        if (queue_length(bq->waiters) == 0)
            blockq_disable_timer(bq);
    } else if (bq->timeout) {
        /* leave at head of queue and reset timer */
        blockq_restart_timer_locked(bq);
    }

    /* XXX release lock */
    
}

blockq allocate_blockq(heap h, char * name, u64 size, timestamp timeout_interval)
{
    blockq bq = allocate(h, sizeof(struct blockq));
    if (bq == INVALID_ADDRESS)
        return bq;

    bq->h = h;

    bq->waiters = allocate_queue(h, size);
    if (bq->waiters == INVALID_ADDRESS) {
        deallocate(h, bq, sizeof(struct blockq));
        return INVALID_ADDRESS;
    }

    if (name) {
        runtime_memcpy(bq->name, name, MIN(runtime_strlen(name), BLOCKQ_NAME_MAX - 1));
        bq->name[BLOCKQ_NAME_MAX - 1] = '\0';
    }

    bq->timeout = 0;
    bq->timeout_interval = timeout_interval;
    return bq;
}

void deallocate_blockq(blockq bq)
{
    /* XXX what's the right behavior if we have waiters? */

    blockq_disable_timer(bq);
    deallocate_queue(bq->waiters);
    deallocate(bq->h, bq, sizeof(struct blockq));
}
