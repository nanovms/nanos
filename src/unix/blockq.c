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

/* This applies a blockq action after it has been removed from the
   waiters list. If the action indicates that waiting should continue,
   it re-adds the thread to the waiter list and returns false. If the
   action was terminal, it releases the thread and returns true. */
static boolean blockq_apply(blockq bq, thread t, u64 bq_flags)
{
    sysreturn rv;
    boolean terminal = false;
    blockq_debug("bq %p (\"%s\") tid:%ld %s %s %s\n",
                 bq, blockq_name(bq), t->tid,
                 (bq_flags & BLOCKQ_ACTION_BLOCKED) ? "blocked " : "",
                 (bq_flags & BLOCKQ_ACTION_NULLIFY) ? "nullify " : "",
                 (bq_flags & BLOCKQ_ACTION_TIMEDOUT) ? "timedout" : "");

    thread ot = current;
    thread_resume(t);
    rv = apply(t->bq_action, bq_flags);
    blockq_debug("   - returned %ld\n", rv);

    /* If the blockq_action returns BLOCKQ_BLOCK_REQUIRED and neither
       nullify or timeout are set in bq_flags, continue blocking. */
    if ((bq_flags & (BLOCKQ_ACTION_NULLIFY | BLOCKQ_ACTION_TIMEDOUT)) ||
        (rv != BLOCKQ_BLOCK_REQUIRED)) {
        blockq_debug("   completed\n");
        u64 saved_flags = spin_lock_irq(&bq->lock);
        if (t->bq_timeout) {
            remove_timer(t->bq_timeout, 0);
            t->bq_timeout = 0;
        }
        spin_unlock_irq(&bq->lock, saved_flags);

        io_completion completion = t->bq_completion;
        if (completion) {
            t->bq_completion = 0;
            apply(completion, t, t->bq_completion_rv);
        }
        thread_release(t);
        terminal = true;
    } else {
        u64 saved_flags = spin_lock_irq(&bq->lock);
        list_insert_before(&bq->waiters_head, &t->bq_l);
        spin_unlock_irq(&bq->lock, saved_flags);
    }
    if (ot)
        thread_resume(ot);
    return terminal;
}

/* A blockq_thread timed out. */
define_closure_function(2, 1, void, blockq_thread_timeout,
                        blockq, bq, thread, t,
                        u64, overruns /* ignored */)
{
    blockq bq = bound(bq);
    thread t = bound(t);
    blockq_debug("bq %p (\"%s\") tid %d\n", bq, blockq_name(bq), t->tid);

    /* Take the bq lock here to insure an atomic rmw of t->bq_timeout. */
    u64 saved_flags = spin_lock_irq(&bq->lock);
    if (t->bq_timeout) {
        t->bq_timeout = 0;
        assert(t->bq_l.next && t->bq_l.prev);
        list_delete(&t->bq_l);
        spin_unlock_irq(&bq->lock, saved_flags);
        blockq_apply(bq, t, BLOCKQ_ACTION_BLOCKED | BLOCKQ_ACTION_TIMEDOUT);
    } else {
        spin_unlock_irq(&bq->lock, saved_flags);
    }
}

/* Wake a single waiter, returning the thread whose action was applied

   Note that there is no guarantee that a thread was actually awoken; this
   just means an action was applied. */
thread blockq_wake_one(blockq bq)
{
    blockq_debug("%p (\"%s\") \n", bq, blockq_name(bq));

    u64 saved_flags = spin_lock_irq(&bq->lock);
    list l = list_get_next(&bq->waiters_head);
    if (l) {
        thread t = struct_from_list(l, thread, bq_l);
        list_delete(l);
        spin_unlock_irq(&bq->lock, saved_flags);
        return blockq_apply(bq, t, BLOCKQ_ACTION_BLOCKED) ? t : INVALID_ADDRESS;
    }
    spin_unlock_irq(&bq->lock, saved_flags);
    return INVALID_ADDRESS;
}
KLIB_EXPORT(blockq_wake_one);


static inline boolean blockq_wake_thread_internal(blockq bq, thread t, u64 bq_flags)
{
    blockq_debug("%p (\"%s\"), tid %d\n", bq, blockq_name(bq), t->tid);
    assert(t->bq_l.next && t->bq_l.prev);
    u64 saved_flags = spin_lock_irq(&bq->lock);
    list_delete(&t->bq_l);
    spin_unlock_irq(&bq->lock, saved_flags);
    return blockq_apply(bq, t, bq_flags);
}

boolean blockq_wake_one_for_thread(blockq bq, thread t)
{
    return blockq_wake_thread_internal(bq, t, BLOCKQ_ACTION_BLOCKED);
}

boolean blockq_flush_thread(blockq bq, thread t)
{
    return blockq_wake_thread_internal(bq, t, BLOCKQ_ACTION_BLOCKED | BLOCKQ_ACTION_NULLIFY);
}

sysreturn kern_blockq_check(blockq bq, thread t, blockq_action a, boolean in_bh)
{
    return blockq_check(bq, t, a, in_bh);
}
KLIB_EXPORT_RENAME(kern_blockq_check, blockq_check);

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

    t->bq_action = a;
    thread_reserve(t);

    if (timeout > 0) {
        assert(!t->bq_timeout);
        t->bq_timeout = register_timer(runloop_timers, clkid, timeout, absolute, 0,
                                       init_closure(&t->bq_timeout_func, blockq_thread_timeout, bq, t));
        if (t->bq_timeout == INVALID_ADDRESS) {
            msg_err("failed to allocate blockq timer\n");
            return -EAGAIN;
        }
    } else {
        t->bq_timeout = 0;
    }

    blockq_debug("queuing action %p, tid %d\n", t->bq_action, t->tid);
    u64 saved_flags = spin_lock_irq(&bq->lock);
    list_insert_before(&bq->waiters_head, &t->bq_l);
    spin_unlock_irq(&bq->lock, saved_flags);
    if (!in_bh)
        t->blocked_on = bq;

    /* if we're either in bh or a non-current thread is invoking this, return now */
    if (in_bh || (current != t))
        return BLOCKQ_BLOCK_REQUIRED;

    thread_sleep_interruptible();  /* no return */
    assert(0);
}

void kern_blockq_handle_completion(blockq bq, u64 bq_flags, io_completion completion, thread t,
                                   sysreturn rv)
{
    blockq_handle_completion(bq, bq_flags, completion, t, rv);
}
KLIB_EXPORT_RENAME(kern_blockq_handle_completion, blockq_handle_completion);

/* Wake all waiters and empty queue, typically for error conditions,
   closed pipe/connections, etc. Actions are called with nullify set,
   indicating the last time that the action will be used by the
   blockq, regardless of what the action returns.
*/
void blockq_flush(blockq bq)
{
    blockq_debug("bq %p - \"%s\"\n", bq, blockq_name(bq));
    do {
        u64 saved_flags = spin_lock_irq(&bq->lock);
        list l = list_get_next(&bq->waiters_head);
        if (!l) {
            spin_unlock_irq(&bq->lock, saved_flags);
            return;
        }
        list_delete(l);
        spin_unlock_irq(&bq->lock, saved_flags);
        blockq_apply(bq, struct_from_list(l, thread, bq_l),
                     BLOCKQ_ACTION_BLOCKED | BLOCKQ_ACTION_NULLIFY);
    } while (1);
}

int blockq_transfer_waiters(blockq dest, blockq src, int n)
{
    int transferred = 0;
    u64 saved_flags = spin_lock_irq(&src->lock);
    spin_lock(&dest->lock);
    list_foreach(&src->waiters_head, l) {
        if (transferred >= n)
            break;
        thread t = struct_from_list(l, thread, bq_l);
        if (t->bq_timeout) {
            timestamp remain;
            clock_id id = t->bq_timeout->id;
            remove_timer(t->bq_timeout, &remain);
            t->bq_timeout = remain == 0 ? 0 :
                register_timer(runloop_timers, id, remain, false, 0,
                               init_closure(&t->bq_timeout_func, blockq_thread_timeout,
                                            dest, t));
        }
        list_delete(&t->bq_l);
        thread_lock(t);
        assert(t->blocked_on == src);
        t->blocked_on = dest;
        thread_unlock(t);
        list_insert_before(&dest->waiters_head, &t->bq_l);
        transferred++;
    }
    spin_unlock(&dest->lock);
    spin_unlock_irq(&src->lock, saved_flags);
    return transferred;
}

void blockq_set_completion(blockq bq, io_completion completion, thread t, sysreturn rv)
{
    assert(!t->bq_completion);
    assert(bq == t->blocked_on);
    t->bq_completion = completion;
    t->bq_completion_rv = rv;
}

void blockq_thread_init(thread t)
{
    t->bq_timeout = 0;
    t->bq_action = 0;
    t->bq_l.prev = t->bq_l.next = 0;
    t->bq_completion = 0;
    t->bq_completion_rv = 0;
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
KLIB_EXPORT(allocate_blockq);

void deallocate_blockq(blockq bq)
{
    blockq_release(bq);
}
KLIB_EXPORT(deallocate_blockq);
