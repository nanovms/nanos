#include <unix_internal.h>

struct futex {
    heap h;
    blockq bq;
};

static u64 futex_key_function(void *x)
{
    return u64_from_pointer(x);
}

static boolean futex_key_equal(void *a, void *b)
{
    return a == b;
}

static struct futex * soft_create_futex(process p, u64 key)
{
    heap h = heap_general(get_kernel_heaps());
    struct futex * f;

    // XXX make this all atomic wrt p->futices

    f = table_find(p->futices, pointer_from_u64(key));
    if (f)
        return f;

    f = allocate(h, sizeof(struct futex));
    if (!f) {
        msg_err("failed to allocate futex\n");
        return INVALID_ADDRESS;
    }

    f->h = h;
    f->bq = allocate_blockq(f->h, "futex");
    if (f->bq == INVALID_ADDRESS) {
        msg_err("failed to allocate futex blockq\n");
        deallocate(f->h, f, sizeof(struct futex));
        return INVALID_ADDRESS;
    }

    table_set(p->futices, pointer_from_u64(key), f);
    return f;
}

static thread futex_wake_one(struct futex * f)
{
    thread w;

    w = blockq_wake_one(f->bq);
    if (w == INVALID_ADDRESS)
        return w;

    /* w must be awake */
    assert(w->blocked_on != f->bq);
    return w;
}

/*
 * Wake up to 'val' waiters
 * Return the number woken
 */
static int futex_wake_many(struct futex * f, int val)
{
    int nr_woken;

    for (nr_woken = 0; nr_woken < val; nr_woken++) {
        thread w = futex_wake_one(f);
        if (w == INVALID_ADDRESS)
            break;
    }

    return nr_woken;
}

boolean futex_wake_many_by_uaddr(process p, int *uaddr, int val)
{
    struct futex * f;

    f = table_find(p->futices, (void *)uaddr);
    if (!f)
        return false;

    futex_wake_many(f, val);
    return true;
}

/*
 * futex_bh is invoked either by the bh processor in response
 * to timeout/signal delivery/etc., or by another thread in sys_futex
 *
 * Return:
 *  BLOCKQ_BLOCK_REQUIRED: timer still active
 *  -ETIMEDOUT: if we timed out
 *  -EINTR: if we're being nullified
 *  0: thread woken up
 */
closure_function(2, 1, sysreturn, futex_bh,
                 struct futex *, f, thread, t,
                 u64, flags)
{
    thread t = bound(t);
    sysreturn rv;

    if (flags & BLOCKQ_ACTION_NULLIFY)
        rv = -EINTR;
    else if (flags & BLOCKQ_ACTION_TIMEDOUT)
        rv = -ETIMEDOUT;
    else if (current == t) {
        return BLOCKQ_BLOCK_REQUIRED;
        thread_log(t, "%s: struct futex: %p, blocking\n", __func__, bound(f));
    } else
        rv = 0; /* no timer expire + not us --> actual wakeup */

    thread_log(t, "%s: struct futex: %p, flags 0x%lx, rv %ld\n", __func__, bound(f), flags, rv);
    thread_wakeup(t);
    closure_finish();
    return set_syscall_return(t, rv);
}

static timestamp get_timeout_timestamp(int futex_op, u64 val2)
{
    switch (futex_op) {
    case FUTEX_WAIT:
    case FUTEX_WAIT_BITSET:
        return (val2) 
            ? time_from_timespec((struct timespec *)pointer_from_u64(val2)) 
            : 0;
    default:
        return 0;
    }
}

sysreturn futex(int *uaddr, int futex_op, int val,
                u64 val2, int *uaddr2, int val3)
{
    struct futex * f;
    timestamp ts;
    int op;

    if (!validate_user_memory(uaddr, sizeof(int), false))
        return set_syscall_error(current, EFAULT);
    boolean verbose = table_find(current->p->process_root, sym(futex_trace))
        ? true : false;

    f = soft_create_futex(current->p, u64_from_pointer(uaddr));
    if (f == INVALID_ADDRESS)
        return set_syscall_error(current, ENOMEM);
    
    op = futex_op & 127; // chuck the private bit
    ts = get_timeout_timestamp(op, val2);
    clock_id clkid = (futex_op & FUTEX_CLOCK_REALTIME) ? CLOCK_ID_REALTIME :
            CLOCK_ID_MONOTONIC;

    switch (op) {
    case FUTEX_WAIT: {
        if (verbose)
            thread_log(current, "futex_wait [%ld %p %d] %d 0x%ld",
                current->tid, uaddr, *uaddr, val, val2);

        if (*uaddr != val)
            return set_syscall_error(current, EAGAIN);

        // if we resume we are woken up
        set_syscall_return(current, 0);

        return blockq_check_timeout(f->bq, current, 
                                    closure(f->h, futex_bh, f, current),
                                    false, clkid, ts, false);
    }

    case FUTEX_WAKE: {
        if (verbose)
            thread_log(current, "futex_wake [%ld %p %d] %d",
                current->tid, uaddr, *uaddr, val);
        return set_syscall_return(current, futex_wake_many(f, val));
    }

    case FUTEX_CMP_REQUEUE: {
        int woken, requeued;

        if (!validate_user_memory(uaddr2, sizeof(int), false))
            return set_syscall_error(current, EFAULT);

        if (verbose)
            thread_log(current, "futex_cmp_requeue [%ld %p %d] val: %d val2: %d uaddr2: %p %d val3: %d",
                       current->tid, uaddr, *uaddr, val, val2, uaddr2, *uaddr2, val3);

        if (*uaddr != val3)
            return set_syscall_error(current, EAGAIN);

        woken = futex_wake_many(f, val);

        requeued = 0;
        if (val2 > 0) {
            struct futex * new = soft_create_futex(current->p, u64_from_pointer(uaddr2));
            if (new == INVALID_ADDRESS)
                return set_syscall_error(current, ENOMEM);
            int requeued = blockq_transfer_waiters(new->bq, f->bq, val2);
            if (verbose)
                thread_log(current, " awoken: %d, re-queued %d", woken, requeued);
        }

        return set_syscall_return(current, woken + requeued);
    }

    case FUTEX_WAKE_OP: {
        unsigned int cmparg = val3 & MASK(12);
        unsigned int oparg = (val3 >> 12) & MASK(12);
        unsigned int cmp = (val3 >> 24) & MASK(4);
        unsigned int op = (val3 >> 28) & MASK(4);
        int oldval, wake1, wake2, c;

        if (!validate_user_memory(uaddr2, sizeof(int), true))
            return set_syscall_error(current, EFAULT);

        if (verbose) {
            thread_log(current, "futex_wake_op: [%ld %p %d] %p %d %d %d %d",
                current->tid, uaddr, *uaddr, uaddr2, cmparg, oparg, cmp, op);
        }

        oldval = *(int *) uaddr2;
        
        switch (op) {
        case FUTEX_OP_SET:   *uaddr2 = oparg; break;
        case FUTEX_OP_ADD:   *uaddr2 += oparg; break;
        case FUTEX_OP_OR:    *uaddr2 |= oparg; break;
        case FUTEX_OP_ANDN:  *uaddr2 &= ~oparg; break;
        case FUTEX_OP_XOR:   *uaddr2 ^= oparg; break;
        }

        wake1 = futex_wake_many(f, val);
        
        c = 0;
        switch (cmp) {
        case FUTEX_OP_CMP_EQ: c = (oldval == cmparg) ; break;
        case FUTEX_OP_CMP_NE: c = (oldval != cmparg); break;
        case FUTEX_OP_CMP_LT: c = (oldval < cmparg); break;
        case FUTEX_OP_CMP_LE: c = (oldval <= cmparg); break;
        case FUTEX_OP_CMP_GT: c = (oldval > cmparg) ; break;
        case FUTEX_OP_CMP_GE: c = (oldval >= cmparg) ; break;
        }
        
        wake2 = 0;
        if (c) {
            struct futex * f2 = 
                soft_create_futex(current->p, u64_from_pointer(uaddr2));
            if (f2 == INVALID_ADDRESS)
                return set_syscall_error(current, ENOMEM);

            wake2 = futex_wake_many(f2, val2);
        }

        return set_syscall_return(current, wake1 + wake2);
    }

    case FUTEX_WAIT_BITSET: {
        if (verbose)
            thread_log(current, "futex_wait_bitset [%ld %p %d] %d 0x%ld %d",
                current->tid, uaddr, *uaddr, val, val2, val3);

        if (*uaddr != val)
            return set_syscall_error(current, EAGAIN);

        set_syscall_return(current, 0);
        return blockq_check_timeout(f->bq, current, 
                                    closure(f->h, futex_bh, f, current),
                                    false, clkid, ts, true);
    }

    case FUTEX_REQUEUE: rprintf("futex_requeue not implemented\n"); break;
    case FUTEX_WAKE_BITSET: rprintf("futex_wake_bitset not implemented\n"); break;
    case FUTEX_LOCK_PI: rprintf("futex_lock_pi not implemented\n"); break;
    case FUTEX_TRYLOCK_PI: rprintf("futex_trylock_pi not implemented\n"); break;
    case FUTEX_UNLOCK_PI: rprintf("futex_unlock_pi not implemented\n"); break;
    case FUTEX_CMP_REQUEUE_PI: rprintf("futex_cmp_requeue_pi not implemented\n"); break;
    case FUTEX_WAIT_REQUEUE_PI: rprintf("futex_wait_requeue_pi not implemented\n"); break;
    default: rprintf("futex op %d not implemented\n", op); break;
    }

    return set_syscall_error(current, ENOSYS);
}

void
init_futices(process p)
{
    p->futices = allocate_table(
        heap_general((kernel_heaps)p->uh),
        futex_key_function,
        futex_key_equal
    );
    if (p->futices == INVALID_ADDRESS)
        halt("failed to allocate futex table\n");

}
