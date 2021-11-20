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
#define blockq_debug(x, ...) do {log_printf("  BQ", "%s: " x, __func__, ##__VA_ARGS__);} while(0)
#else
#define blockq_debug(x, ...)
#endif

#define blockq_lock(bq) spin_lock(&bq->lock)
#define blockq_unlock(bq) spin_unlock(&bq->lock)

// basically this would all have to turn async

/* This applies a blockq action after it has been removed from the waiters
   list. If the action cannot wake the thread and must continue blocking, it
   needs to re-add itself to the queue (and reinstate any remaining timeout). */
static void blockq_apply(blockq bq, thread t, u64 bq_flags)
{
    blockq_debug("bq %p (\"%s\") tid:%ld %s %s %s\n",
                 bq, blockq_name(bq), t->tid,
                 (bq_flags & BLOCKQ_ACTION_BLOCKED) ? "blocked " : "",
                 (bq_flags & BLOCKQ_ACTION_NULLIFY) ? "nullify " : "",
                 (bq_flags & BLOCKQ_ACTION_TIMEDOUT) ? "timedout" : "");

    assert(t->blocked_on == bq);
    async_apply_1((async_1)t->bq_action, (void *)bq_flags); /* retval ignored */
}

/* A blockq_thread timed out. */
define_closure_function(2, 2, void, blockq_thread_timeout,
                        blockq, bq, thread, t,
                        u64, expiry, u64, overruns)
{
    blockq bq = bound(bq);
    thread t = bound(t);
    blockq_debug("bq %p (\"%s\") tid %d\n", bq, blockq_name(bq), t->tid);
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

/* XXX Note semantic changes:
   - bh actions need to reschedule themselves and restart time if cannot wake
     - suspect there are no real cases of this yet
*/

/* Called with bq and thread locks taken, returns with them released. */
static inline boolean blockq_wake_internal_locked(blockq bq, thread t, u64 bq_flags)
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
    if (bq_flags & BLOCKQ_ACTION_NULLIFY)
        t->interrupting_syscall = true;
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

thread blockq_wake_one(blockq bq)
{
    blockq_debug("%p (\"%s\") \n", bq, blockq_name(bq));
    blockq_lock(bq);
    list l = list_get_next(&bq->waiters_head);
    if (l) {
        thread t = struct_from_list(l, thread, bq_l);
        thread_lock(t);
        blockq_wake_internal_locked(bq, t, BLOCKQ_ACTION_BLOCKED);
        return t;
    }
    blockq_unlock(bq);
    return INVALID_ADDRESS;
}

boolean blockq_wake_one_for_thread(blockq bq, thread t, boolean nullify)
{
    thread_log(current, "%s: tid %d", __func__, t->tid);
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

void blockq_resume_blocking(blockq bq, thread t)
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

sysreturn blockq_check_timeout(blockq bq, thread t, blockq_action a, boolean in_bh,
                               clock_id clkid, timestamp timeout, boolean absolute)
{
    assert(t);
    assert(a);
    assert(!(in_bh && timeout)); /* no timeout checks in bh */

    blockq_debug("%p \"%s\", tid %ld, action %p, timeout %ld, clock_id %d\n",
                 bq, blockq_name(bq), t->tid, a, timeout, clkid);

    sysreturn rv = apply(a, 0);
    if (rv != BLOCKQ_BLOCK_REQUIRED) {
        blockq_debug(" - direct return: %ld\n", rv);
        return rv;
    }

    blockq_lock(bq);
    thread_lock(t);
    thread_reserve(t);
    t->bq_action = a;
    if (!in_bh)
        t->blocked_on = bq;
    if (timeout > 0) {
        t->bq_timer_pending = true;
        t->bq_clkid = clkid;
        register_timer(kernel_timers, &t->bq_timer, clkid, timeout, absolute, 0,
                       init_closure(&t->bq_timeout_func, blockq_thread_timeout, bq, t));
    } else {
        t->bq_timer_pending = false;
    }
    t->bq_remain_at_wake = 0;
    list_insert_before(&bq->waiters_head, &t->bq_l);
    thread_unlock(t);
    blockq_unlock(bq);

    /* if we're either in bh or a non-current thread is invoking this, return now */
    if (in_bh || (current != t))
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
        thread t = struct_from_list(l, thread, bq_l);
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
        thread t = struct_from_list(l, thread, bq_l);
        thread_lock(t);
        assert(t->blocked_on == src);
        boolean timer_pending = t->bq_timer_pending;
        timestamp remain;
        clock_id id;
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
                                        dest, t));
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

void blockq_thread_init(thread t)
{
    t->bq_timer_pending = false;
    t->bq_clkid = 0;
    t->bq_remain_at_wake = 0;
    init_timer(&t->bq_timer);
    t->bq_action = 0;
    t->bq_l.prev = t->bq_l.next = 0;
}

define_closure_function(1, 0, void, free_blockq,
                        blockq, bq)
{
    blockq bq = bound(bq);
    blockq_debug("for \"%s\"\n", blockq_name(bq));
    assert(list_empty(&bq->waiters_head));
    deallocate(bq->h, bq, sizeof(struct blockq));
}

blockq allocate_blockq(heap h, char * name)
{
    blockq_debug("name \"%s\"\n", name);
    blockq bq = allocate(h, sizeof(struct blockq));
    if (bq == INVALID_ADDRESS)
        return bq;

    bq->h = h;
    u64 len;
    if (name) {
        len = MIN(runtime_strlen(name), BLOCKQ_NAME_MAX - 1);
        runtime_memcpy(bq->name, name, len);
    } else {
        len = 0;
    }
    bq->name[len] = '\0';
    spin_lock_init(&bq->lock);
    list_init(&bq->waiters_head);
    init_refcount(&bq->refcount, 1, init_closure(&bq->free, free_blockq, bq));
    return bq;
}

void deallocate_blockq(blockq bq)
{
    blockq_release(bq);
}
