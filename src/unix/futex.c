#include <unix_internal.h>

struct futex {
    heap h;
    blockq bq;
    struct spinlock lock;
};

#define futex_lock(f)   spin_lock(&(f)->lock)
#define futex_unlock(f) spin_unlock(&(f)->lock)

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
    heap h = heap_locked(get_kernel_heaps());
    struct futex * f;

    process_lock(p);

    f = table_find(p->futices, pointer_from_u64(key));
    if (f)
        goto out;

    f = allocate(h, sizeof(struct futex));
    if (f == INVALID_ADDRESS) {
        msg_err("failed to allocate futex\n");
        goto out;
    }

    f->h = h;
    f->bq = allocate_blockq(f->h, ss("futex"));
    if (f->bq == INVALID_ADDRESS) {
        msg_err("failed to allocate futex blockq\n");
        deallocate(f->h, f, sizeof(struct futex));
        f = INVALID_ADDRESS;
        goto out;
    }

    spin_lock_init(&f->lock);
    table_set(p->futices, pointer_from_u64(key), f);
  out:
    process_unlock(p);
    return f;
}

static unix_context futex_wake_one(struct futex * f)
{
    unix_context t = blockq_wake_one(f->bq);
    if (t != INVALID_ADDRESS)
        return t;
    kern_pause();
    return t;
}

/*
 * Wake up to 'val' waiters
 * Return the number woken
 */
static int futex_wake_many(struct futex * f, int val)
{
    int nr_woken;

    for (nr_woken = 0; nr_woken < val; nr_woken++) {
        unix_context w = futex_wake_one(f);
        if (w == INVALID_ADDRESS)
            break;
    }

    return nr_woken;
}

boolean futex_wake_many_by_uaddr(process p, int *uaddr, int val)
{
    struct futex * f;

    process_lock(p);
    f = table_find(p->futices, (void *)uaddr);
    process_unlock(p);
    if (!f)
        return false;

    futex_lock(f);
    futex_wake_many(f, val);
    futex_unlock(f);
    return true;
}

/*
 * futex_bh is invoked either by the bh processor in response
 * to timeout/signal delivery/etc., or by another thread in sys_futex
 *
 * Return:
 *  BLOCKQ_BLOCK_REQUIRED: top half, going to block
 *  -ETIMEDOUT: if we timed out
 *  -EINTR: if we're being nullified
 *  0: thread woken up
 */
closure_function(3, 1, sysreturn, futex_bh,
                 struct futex *, f, thread, t, timestamp, timeout,
                 u64 flags)
{
    thread t = bound(t);
    struct futex *f = bound(f);
    sysreturn rv;

    if (!(flags & BLOCKQ_ACTION_BLOCKED)) {
        futex_unlock(f);
        return BLOCKQ_BLOCK_REQUIRED;
    }

    if (flags & (BLOCKQ_ACTION_NULLIFY | BLOCKQ_ACTION_TIMEDOUT)) {
        if (flags & BLOCKQ_ACTION_NULLIFY)
            rv = bound(timeout) ? -EINTR : -ERESTARTSYS;
        else
            rv = -ETIMEDOUT;
    } else {
        rv = 0; /* no timer expire + not us --> actual wakeup */
    }

    closure_finish();
    return syscall_return(t, rv);
}

closure_function(1, 1, void, futex_requeue_handler,
                 struct futex *, dest,
                 blockq_action action)
{
    closure_member(futex_bh, action, f) = bound(dest);
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

    f = soft_create_futex(current->p, u64_from_pointer(uaddr));
    if (f == INVALID_ADDRESS)
        return set_syscall_error(current, ENOMEM);
    
    op = futex_op & 127; // chuck the private bit
    ts = get_timeout_timestamp(op, val2);
    clock_id clkid = (futex_op & FUTEX_CLOCK_REALTIME) ? CLOCK_ID_REALTIME :
            CLOCK_ID_MONOTONIC;

    context ctx = get_current_context(current_cpu());
    switch (op) {
    case FUTEX_WAIT: {
        sysreturn rv;
        futex_lock(f);
        if (context_set_err(ctx))
            rv = -EFAULT;
        else if (*uaddr != val)
            rv = -EAGAIN;
        else
            rv = blockq_check_timeout(f->bq,
                                      contextual_closure(futex_bh, f, current, ts),
                                      false, clkid, ts, false);
        futex_unlock(f);
        if (rv != -EFAULT)
            context_clear_err(ctx);
        return rv;
    }

    case FUTEX_WAKE: {
        futex_lock(f);
        int nr_woken = futex_wake_many(f, val);
        futex_unlock(f);
        return nr_woken;
    }

    case FUTEX_CMP_REQUEUE: {
        int woken, requeued;

        if (!validate_user_memory(uaddr2, sizeof(int), false))
            return set_syscall_error(current, EFAULT);

        sysreturn rv;
        futex_lock(f);
        if (context_set_err(ctx)) {
            rv = -EFAULT;
            goto cmp_requeue_done;
        }
        if (*uaddr != val3) {
            rv = -EAGAIN;
            goto cmp_requeue_done;
        }

        woken = futex_wake_many(f, val);

        requeued = 0;
        if (val2 > 0) {
            struct futex * new = soft_create_futex(current->p, u64_from_pointer(uaddr2));
            if (new == INVALID_ADDRESS) {
                rv = -ENOMEM;
                goto cmp_requeue_done;
            }
            requeued = blockq_transfer_waiters(new->bq, f->bq, val2,
                                               stack_closure(futex_requeue_handler, new));
        }
        rv = woken + requeued;
      cmp_requeue_done:
        futex_unlock(f);
        if (rv != -EFAULT)
            context_clear_err(ctx);
        return rv;
    }

    case FUTEX_WAKE_OP: {
        unsigned int cmparg = val3 & MASK(12);
        unsigned int oparg = (val3 >> 12) & MASK(12);
        unsigned int cmp = (val3 >> 24) & MASK(4);
        unsigned int op = (val3 >> 28) & MASK(4);
        int oldval, wake1, wake2, c;

        if (!validate_user_memory(uaddr2, sizeof(int), true))
            return set_syscall_error(current, EFAULT);

        struct futex *f2 = soft_create_futex(current->p, u64_from_pointer(uaddr2));
        if (f2 == INVALID_ADDRESS)
            return -ENOMEM;
        boolean fault = false;
        spin_lock_2(&f->lock, &f2->lock);
        if (context_set_err(ctx)) {
            fault = true;
            goto wake_op_done;
        }
        oldval = *(int *) uaddr2;
        
        switch (op) {
        case FUTEX_OP_SET:   *uaddr2 = oparg; break;
        case FUTEX_OP_ADD:   *uaddr2 += oparg; break;
        case FUTEX_OP_OR:    *uaddr2 |= oparg; break;
        case FUTEX_OP_ANDN:  *uaddr2 &= ~oparg; break;
        case FUTEX_OP_XOR:   *uaddr2 ^= oparg; break;
        }
        context_clear_err(ctx);

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
            wake2 = futex_wake_many(f2, val2);
        }

      wake_op_done:
        futex_unlock(f2);
        futex_unlock(f);
        return fault ? -EFAULT : wake1 + wake2;
    }

    case FUTEX_WAIT_BITSET: {
        sysreturn rv;
        futex_lock(f);
        if (context_set_err(ctx))
            rv = -EFAULT;
        else if (*uaddr != val)
            rv = -EAGAIN;
        else
            rv = blockq_check_timeout(f->bq,
                                      contextual_closure(futex_bh, f, current, ts),
                                      false, clkid, ts, true);
        futex_unlock(f);
        if (rv != -EFAULT)
            context_clear_err(ctx);
        return rv;
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
    heap h = heap_locked(get_kernel_heaps());
    p->futices = allocate_table(h, futex_key_function, futex_key_equal);
    if (p->futices == INVALID_ADDRESS)
        halt("failed to allocate futex table\n");
}

/* robust mutex handling */

#define FUTEX_OWNER_DIED	0x40000000
#define FUTEX_KEY_ADDR(x, o)    ((int *)((u8 *)(x) + (o)))

typedef struct robust_list {
    struct robust_list *next;
} *robust_list;

typedef struct robust_list_head {
    robust_list list;
    long futex_offset;
    void *list_op_pending;
} *robust_list_head;

void wake_robust_list(process p, void *head)
{
    struct robust_list_head *h = head;
    struct robust_list *l;
    int *pending;
    int *uaddr;

    /* must be very careful accessing the head as well as the list */
    context ctx = get_current_context(current_cpu());
    if (context_set_err(ctx))
        return;

    /* XXX could keep a list of futexes and wake them at the end
     * to let threads acquire multiple locks without blocking */
    pending = h->list_op_pending ? FUTEX_KEY_ADDR(h->list_op_pending, h->futex_offset) : 0;
    for (l = h->list; (void *)l != (void *)h;) {
        uaddr = FUTEX_KEY_ADDR(l, h->futex_offset);
        l = l->next;
        if (uaddr == pending)   /* don't process it twice */
            continue;
        if (!validate_user_memory(l, sizeof(*l), false))
            break;
        if (!validate_user_memory(uaddr, sizeof(*uaddr), true))
            break;
        *uaddr |= FUTEX_OWNER_DIED;
        futex_wake_many_by_uaddr(p, uaddr, 1);
    }
    if (pending && validate_user_memory(pending, sizeof(*pending), true)) {
        *pending |= FUTEX_OWNER_DIED;
        futex_wake_one_by_uaddr(p, pending);
    }
    context_clear_err(ctx);
}

sysreturn get_robust_list(int pid, void *head, u64 *len)
{
    struct robust_list_head **hp = head;
    if (!validate_user_memory(hp, sizeof(*hp), true) ||
        !validate_user_memory(len, sizeof(*len), true))
        return -EFAULT;

    thread t = 0;
    if (pid == 0) {
        t = current;
    } else {
        t = thread_from_tid(current->p, pid);
        if (t == INVALID_ADDRESS)
            return -ESRCH;
    }
    context ctx = get_current_context(current_cpu());
    if (context_set_err(ctx))
        return -EFAULT;
    *hp = t->robust_list;
    if (pid != 0)
        thread_release(t);
    *len = sizeof(**hp);
    context_clear_err(ctx);
    return 0;
}

sysreturn set_robust_list(void *head, u64 len)
{
    if (len != sizeof(struct robust_list_head))
        return -EINVAL;
    if (!validate_process_memory(current->p, head, len, false))
        return -EFAULT;
    current->robust_list = head;

    return 0;
}
