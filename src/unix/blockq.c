#include <unix_internal.h>

/* blockq - a facility for queueing up threads waiting for a resource

   Given an action closure, blockq_check() will attempt the action at once. If
   it either succeeds (rv >= 0) or fails (rv < 0), it will return the result
   of the action to the caller. If rv == BLOCKQ_BLOCK_REQUIRED, the action
   gets added to the blockq's waiters queue, an optional timeout is set, and
   the thread is finally blocked.

   blockq_wake_one() attempts to apply the action at the head of the waiters
   queue. If it returns BLOCKQ_BLOCK_REQUIRED, the waiter is moved to the
   bottom of the waiters queue and waiting resumes. The waiter is otherwise
   removed from the queue. It is up to the action to apply results to the
   thread frame and call thread_wakeup() as necessary.

   Action invocation only indicates that a wakeup, timeout or nullification
   occurred for the given blockq. It is up to the action to check status and
   resource availability as necessary.

   - BLOCKQ_ACTION_BLOCKED will indicate whether the action is being invoked
     within the syscall handler or after blocking. In the latter case, should
     the blocked thread resume execution, it is up to the action to call
     set_syscall_{return,error}() and thread_wakeup().

   - BLOCKQ_ACTION_NULLIFY signals that any blocking should be immediately
     canceled, that the appropriate return code is set for an interrupted
     blocking operation and that the associated thread is woken (if not
     terminated). The thread may not continue blocking after this flag has
     been applied.

   - BLOCKQ_ACTION_TIMEDOUT indicates that a timeout occurred for the
     respective blocking operation. As with the nullify flag, the thread
     cannot continue blocking for the associated check, and must either be
     woken or terminated.
 */


//#define BLOCKQ_DEBUG
#ifdef BLOCKQ_DEBUG
#define blockq_debug(x, ...) do {tprintf(sym(blockq), 0, ss("%s: " x), func_ss, ##__VA_ARGS__);} while(0)
#else
#define blockq_debug(x, ...)
#endif

#define blockq_lock(bq) spin_lock(&bq->lock)
#define blockq_unlock(bq) spin_unlock(&bq->lock)

/* This applies a blockq action after it has been removed from the waiters
   list. If the action cannot wake the thread and must continue blocking, it
   needs to re-add itself to the queue (and reinstate any remaining timeout). */
static void blockq_apply(blockq bq, unix_context t, u64 bq_flags)
{
    blockq_debug("bq %p (\"%s\") ctx %p %s %s %s\n",
                 bq, blockq_name(bq), t,
                 (bq_flags & BLOCKQ_ACTION_BLOCKED) ? ss("blocked ") : sstring_empty(),
                 (bq_flags & BLOCKQ_ACTION_NULLIFY) ? ss("nullify ") : sstring_empty(),
                 (bq_flags & BLOCKQ_ACTION_TIMEDOUT) ? ss("timedout") : sstring_empty());

    assert(t->blocked_on == bq);
    async_apply_1((async_1)t->bq_action, (void *)bq_flags); /* bq_action retval ignored */
}

/* A blockq_thread timed out. */
define_closure_function(1, 2, void, blockq_thread_timeout,
                        blockq, bq,
                        u64, expiry, u64, overruns)
{
    blockq bq = bound(bq);
    unix_context t = struct_from_field(closure_self(), unix_context, bq_timeout_func);
    blockq_debug("bq %p (\"%s\") ctx %p\n", bq, blockq_name(bq), t);
    if (overruns != timer_disabled) {
        /* Use bq->lock to protect t->bq_timer_pending. */
        blockq_lock(bq);
        assert(t->bq_timer_pending);
        t->bq_timer_pending = false;
        list_delete(&t->bq_l);
        blockq_unlock(bq);
        t->bq_remain_at_wake = 0;
        blockq_apply(bq, t, BLOCKQ_ACTION_BLOCKED | BLOCKQ_ACTION_TIMEDOUT);
    }
}

/* Called with bq and thread locks taken, returns with them released. */
static inline boolean blockq_wake_internal_locked(blockq bq, unix_context t, u64 bq_flags)
{
    boolean timer_pending = t->bq_timer_pending;
    if (timer_pending) {
        if (remove_timer(kernel_timers, &t->bq_timer, &t->bq_remain_at_wake)) {
            t->bq_timer_pending = false;
        } else {
            /* The timeout already fired, so let it proceed and skip the wakeup. */
            goto unlock_fail;
        }
    } else {
        t->bq_remain_at_wake = 0;
    }

    if (!list_inserted(&t->bq_l)) {
        /* If this thread is not on a waiting list, another wakeup beat us to it */
        assert(!timer_pending);
        goto unlock_fail;
    }
    list_delete(&t->bq_l);
    if ((bq_flags & BLOCKQ_ACTION_NULLIFY) && is_syscall_context(&t->kc.context))
        ((syscall_context)t)->t->interrupting_syscall = true;
    thread_unlock(t);
    blockq_unlock(bq);
    blockq_apply(bq, t, bq_flags);
    return true;
  unlock_fail:
    thread_unlock(t);
    blockq_unlock(bq);
    return false;
}

/* Wake a single waiter, returning the thread whose action was applied

   Note that a returned thread does not necessarily mean that the thread was
   actually awoken; this just means an action was applied. However, if the bh
   action will always wake a thread on a call in blocked state, it can be
   assumed the returned thread was awoken (e.g. futex_bh) */

unix_context blockq_wake_one(blockq bq)
{
    blockq_debug("%p (\"%s\") \n", bq, blockq_name(bq));
    blockq_lock(bq);
    list l = list_get_next(&bq->waiters_head);
    if (l) {
        unix_context t = struct_from_list(l, unix_context, bq_l);
        thread_lock(t);
        blockq_wake_internal_locked(bq, t, BLOCKQ_ACTION_BLOCKED);
        return t;
    }

    /* Setting wake covers the case that a wakeup occurs after an action,
       invoked by blockq_check, determines that blocking is required but
       before the blockq lock is taken and the thread is added to the waiter
       list. See blockq_check_timeout() for more detail. */
    bq->wake = true;
    write_barrier();
    blockq_unlock(bq);
    return INVALID_ADDRESS;
}

boolean blockq_wake_one_for_thread(blockq bq, unix_context t, boolean nullify)
{
    thread_log(current, "%s: ctx %p", func_ss, t);
    blockq_lock(bq);
    thread_lock(t);
    if (t->blocked_on != bq) {
        thread_unlock(t);
        blockq_unlock(bq);
        return false;
    }
    return blockq_wake_internal_locked(bq, t, BLOCKQ_ACTION_BLOCKED |
                                       (nullify ? BLOCKQ_ACTION_NULLIFY : 0));
}

void blockq_resume_blocking(blockq bq, unix_context t)
{
    blockq_lock(bq);
    list_insert_before(&bq->waiters_head, &t->bq_l);
    if (t->bq_remain_at_wake) {
        timestamp tr = t->bq_remain_at_wake;
        t->bq_remain_at_wake = 0;
        t->bq_timer_pending = true;
        register_timer(kernel_timers, &t->bq_timer, t->bq_clkid, tr,
                       false, 0, (timer_handler)&t->bq_timeout_func);
    }
    blockq_unlock(bq);
}

sysreturn blockq_check_timeout(blockq bq, blockq_action a, boolean in_bh,
                               clock_id clkid, timestamp timeout, boolean absolute)
{
    assert(a);
    assert(!(in_bh && timeout)); /* no timeout checks in bh */
    unix_context t = (unix_context)context_from_closure(a);
    assert(t);

    blockq_debug("%p \"%s\", ctx %p, action %p (%F), timeout %ld, clock_id %d\n",
                 bq, blockq_name(bq), t, a, a, timeout, clkid);

    /* The wake flag senses whether a wakeup occurred between invoking the
       blockq_action and queueing the waiting thread. We cannot simply take
       the blockq lock prior to calling the action; the action itself may
       invoke functions which take the lock. Also, deferred action invocations
       occur straight from the async dispatch without any locks taken (which
       is ideal, as we don't necessarily want to serialize all processing
       around a blockq). Spinning on a count of waiters being nonzero in
       blockq_wake() is also not an option, for code invoking the wake may be
       holding a lock used by an action, thus leading to a deadlock.

       This solution has blockq_wake_one(), under blockq lock, set the wake
       flag if a waiting thread could not be dequeued. This function first
       clears the flag, invokes the action and then checks, under blockq lock,
       if the flag was set. If it was, a wakeup may (but not necessarily) have
       been missed, and blockq_wake_one() is called after releasing the locks.

       There is the possibility of a spurious wakeup here. This would seem to
       affect only the futex code, however such spurious futex wakeups (a
       FUTEX_WAIT returning 0, not triggered by a FUTEX_WAKE) are explictly
       allowed. (See the FUTEX WAIT entry under the RETURN VALUE section of
       the futex(2) manpage.) In a similar manner, all blockq actions should
       be written to assume that spurious invocations are possible.
    */

    bq->wake = false;
    write_barrier();
    sysreturn rv = apply(a, 0);
    if (rv != BLOCKQ_BLOCK_REQUIRED) {
        blockq_debug(" - direct return: %ld\n", rv);
        return rv;
    }

    blockq_lock(bq);
    thread_lock(t);
    t->bq_action = a;
    if (!in_bh)
        t->blocked_on = bq;
    if (timeout > 0) {
        t->bq_timer_pending = true;
        t->bq_clkid = clkid;
        register_timer(kernel_timers, &t->bq_timer, clkid, timeout, absolute, 0,
                       init_closure(&t->bq_timeout_func, blockq_thread_timeout, bq));
    } else {
        t->bq_timer_pending = false;
    }
    t->bq_remain_at_wake = 0;
    list_insert_before(&bq->waiters_head, &t->bq_l);
    boolean wake = bq->wake;
    thread_unlock(t);
    blockq_unlock(bq);

    /* It is safe to call wake here. Action closures are contextual, so the
       context acquire will wait for this path to terminate at runloop before
       the action runs. */
    if (wake)
        blockq_wake_one(bq);

    /* if we're in bh, return now */
    if (in_bh)
        return BLOCKQ_BLOCK_REQUIRED;

    thread_sleep_interruptible();  /* no return */
    assert(0);
}

/* Wake all waiters and empty queue, typically for error conditions,
   closed pipe/connections, etc. Actions are called with nullify set,
   indicating the last time that the action will be used by the
   blockq, regardless of what the action returns.
*/
void blockq_flush(blockq bq)
{
    blockq_debug("bq %p - \"%s\"\n", bq, blockq_name(bq));
    do {
        blockq_lock(bq);
        list l = list_get_next(&bq->waiters_head);
        if (!l) {
            blockq_unlock(bq);
            return;
        }
        unix_context t = struct_from_list(l, unix_context, bq_l);
        thread_lock(t);
        blockq_wake_internal_locked(bq, t, BLOCKQ_ACTION_BLOCKED | BLOCKQ_ACTION_NULLIFY);
    } while (1);
}

int blockq_transfer_waiters(blockq dest, blockq src, int n, blockq_action_handler handler)
{
    int transferred = 0;
    spin_lock_2(&src->lock, &dest->lock);
    list_foreach(&src->waiters_head, l) {
        if (transferred >= n)
            break;
        unix_context t = struct_from_list(l, unix_context, bq_l);
        thread_lock(t);
        assert(t->blocked_on == src);
        boolean timer_pending = t->bq_timer_pending;
        timestamp remain;
        clock_id id = 0;
        if (timer_pending) {
            id = t->bq_timer.id;
            if (!remove_timer(kernel_timers, &t->bq_timer, &remain)) {
                /* This waiter timed out, but the timeout has yet to be
                   serviced. Instead of moving this waiter to the new queue,
                   leave it to finish timing out. */
                thread_unlock(t);
                continue;
            }
        }
        list_delete(&t->bq_l);
        apply(handler, t->bq_action);
        list_insert_before(&dest->waiters_head, &t->bq_l);
        t->blocked_on = dest;
        if (timer_pending && remain > 0) {
            register_timer(kernel_timers, &t->bq_timer, id, remain, false, 0,
                           init_closure(&t->bq_timeout_func, blockq_thread_timeout,
                                        dest));
        } else {
            t->bq_timer_pending = false;
        }
        thread_unlock(t);
        transferred++;
    }
    blockq_unlock(dest);
    blockq_unlock(src);
    return transferred;
}

void blockq_thread_init(unix_context t)
{
    t->blocked_on = 0;
    t->bq_timer_pending = false;
    t->bq_clkid = 0;
    t->bq_remain_at_wake = 0;
    init_timer(&t->bq_timer);
    t->bq_action = 0;
    t->bq_l.prev = t->bq_l.next = 0;
    spin_lock_init(&t->lock);
}

define_closure_function(1, 0, void, free_blockq,
                        blockq, bq)
{
    blockq bq = bound(bq);
    blockq_debug("for \"%s\"\n", blockq_name(bq));
    assert(list_empty(&bq->waiters_head));
    deallocate(bq->h, bq, sizeof(struct blockq));
}

void blockq_init(blockq bq, sstring name)
{
    bq->name = name;
    bq->wake = false;
    spin_lock_init(&bq->lock);
    list_init(&bq->waiters_head);
    init_refcount(&bq->refcount, 1, init_closure(&bq->free, free_blockq, bq));
}

blockq allocate_blockq(heap h, sstring name)
{
    blockq_debug("name \"%s\"\n", name);
    blockq bq = allocate(h, sizeof(struct blockq));
    if (bq != INVALID_ADDRESS) {
        bq->h = h;
        blockq_init(bq, name);
    }
    return bq;
}

void deallocate_blockq(blockq bq)
{
    blockq_release(bq);
}
