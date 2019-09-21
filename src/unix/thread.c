#include <unix_internal.h>

thread current;

struct futex {
    heap h;
    blockq bq;
};

CLOSURE_1_1(default_fault_handler, context, thread, context);

static u64 futex_key_function(void *x)
{
    return u64_from_pointer(x);
}

static boolean futex_key_equal(void *a, void *b)
{
    return a == b;
}

sysreturn gettid()
{
    return current->tid;
}

sysreturn set_tid_address(int *a)
{
    current->clear_tid = a;
    return current->tid;
}

sysreturn arch_prctl(int code, unsigned long addr)
{    
    thread_log(current, "arch_prctl: code 0x%x, addr 0x%lx", code, addr);
    switch (code) {
    case ARCH_SET_GS:
        current->frame[FRAME_GS] = addr;
        break;
    case ARCH_SET_FS:
        current->frame[FRAME_FS] = addr;
        return 0;
    case ARCH_GET_FS:
	if (!addr)
            return set_syscall_error(current, EINVAL);
	*(u64 *) addr = current->frame[FRAME_FS];
        break;
    case ARCH_GET_GS:
	if (!addr)
            return set_syscall_error(current, EINVAL);
	*(u64 *) addr = current->frame[FRAME_GS];
        break;
    default:
        return set_syscall_error(current, EINVAL);
    }
    return 0;
}

static inline void thread_make_runnable(thread t)
{
    t->blocked_on = 0;
    t->syscall = -1;
    enqueue(runqueue, t->run);
}

sysreturn clone(unsigned long flags, void *child_stack, int *ptid, int *ctid, unsigned long newtls)
{
    thread_log(current, "clone: flags %lx, child_stack %p, ptid %p, ctid %p, newtls %lx",
        flags, child_stack, ptid, ctid, newtls);

    if (!child_stack)   /* this is actually a fork() */
    {
        thread_log(current, "attempted to fork by passing "
                   "null child stack, aborting.");
        return set_syscall_error(current, ENOSYS);
    }

    /* clone thread context up to FRAME_VECTOR */
    thread t = create_thread(current->p);
    runtime_memcpy(t->frame, current->frame, sizeof(u64) * FRAME_ERROR_CODE);

    /* clone behaves like fork at the syscall level, returning 0 to the child */
    set_syscall_return(t, 0);
    t->frame[FRAME_RSP]= u64_from_pointer(child_stack);
    t->frame[FRAME_FS] = newtls;
    if (flags & CLONE_PARENT_SETTID)
        *ptid = t->tid;
    if (flags & CLONE_CHILD_CLEARTID)
        t->clear_tid = ctid;
    thread_make_runnable(t);
    return t->tid;
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

/*
 * futex_bh is invoked either by the bh processor in response
 * to timeout/signal delivery/etc., or by another thread in sys_futex
 *
 * Return:
 *  infinity: timer still active
 *  -ETIMEDOUT: if we timed out
 *  -EINTR: if we're being nullified
 *  0: thread woken up
 */
static CLOSURE_3_2(futex_bh, sysreturn, struct futex *, thread, timestamp,
                   boolean, boolean);
static sysreturn futex_bh(struct futex * f, thread t, timestamp ts,
                          boolean blocked, boolean nullify)
{
    sysreturn rv;

    if (current == t)
        rv = infinity;
    else if (nullify)
        rv = -EINTR;
    else if (ts > 0 && ts < now()) /* has timer expired */
        rv = -ETIMEDOUT;
    else
        rv = 0; /* no timer expire + not us --> actual wakeup */

    if (rv != infinity)
        thread_wakeup(t);

    return set_syscall_return(t, rv);
}

static timestamp get_timeout_timestamp(int futex_op, u64 val2)
{
    switch (futex_op) {
    case FUTEX_WAIT:
    case FUTEX_CMP_REQUEUE:
    case FUTEX_WAIT_BITSET:
        return (val2) 
            ? time_from_timespec((struct timespec *)pointer_from_u64(val2)) 
            : 0;
    default:
        return 0;
    }
}

static sysreturn futex(int *uaddr, int futex_op, int val,
                       u64 val2,
                       int *uaddr2, int val3)
{
    struct futex * f;
    timestamp ts;
    int op;

    boolean verbose = table_find(current->p->process_root, sym(futex_trace))
        ? true : false;

    f = soft_create_futex(current->p, u64_from_pointer(uaddr));
    if (f == INVALID_ADDRESS)
        return set_syscall_error(current, ENOMEM);
    
    op = futex_op & 127; // chuck the private bit
    ts = get_timeout_timestamp(op, val2);

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
            closure(f->h, futex_bh, f, current, ts),
            false, ts
        );
    }
            
    case FUTEX_WAKE: {
        if (verbose)
            thread_log(current, "futex_wake [%ld %p %d] %d",
                current->tid, uaddr, *uaddr, val);
        return set_syscall_return(current, futex_wake_many(f, val));
    }
        
    case FUTEX_CMP_REQUEUE: {
        int wake1, wake2;
        struct futex * f2;
        thread w;

        if (verbose)
            thread_log(current, "futex_cmp_requeue [%ld %p %d] %d %p %d",
                current->tid, uaddr, *uaddr, val3, uaddr2, *uaddr2);

        if (*uaddr != val3)
            return set_syscall_error(current, EAGAIN);

        wake1 = futex_wake_many(f, val);
        for (wake2 = 0, f2 = INVALID_ADDRESS; wake2 < val2; wake2++) {
            w = futex_wake_one(f);
            if (w == INVALID_ADDRESS)
                break;

            if (f2 == INVALID_ADDRESS) {
                f2 = soft_create_futex(current->p, u64_from_pointer(uaddr2));
                if (f2 == INVALID_ADDRESS)
                    return set_syscall_error(current, ENOMEM);
            }

            /* XXX -- what if w has a timeout registered on the old f? should it move
             * to f2??
             * we use the new timeout value, though from man futex it's not clear
             * whether this should be used or not
             */
             (void)blockq_check_timeout(f2->bq, w,
                closure(f2->h, futex_bh, f2, w, ts),
                false, ts
             );
        }

        return set_syscall_return(current, wake1 + wake2);
    }

    case FUTEX_WAKE_OP: {
        unsigned int cmparg = val3 & MASK(12);
        unsigned int oparg = (val3 >> 12) & MASK(12);
        unsigned int cmp = (val3 >> 24) & MASK(4);
        unsigned int op = (val3 >> 28) & MASK(4);
        int oldval, wake1, wake2, c;

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
        // TODO: timeout should be absolute based on CLOCK_REALTIME
        return blockq_check_timeout(f->bq, current, 
            closure(f->h, futex_bh, f, current, ts),
            false, ts
        );
    }

    case FUTEX_REQUEUE: rprintf("futex_requeue not implemented\n"); break;
    case FUTEX_WAKE_BITSET: rprintf("futex_wake_bitset not implemented\n"); break;
    case FUTEX_LOCK_PI: rprintf("futex_lock_pi not implemented\n"); break;
    case FUTEX_TRYLOCK_PI: rprintf("futex_trylock_pi not implemented\n"); break;
    case FUTEX_UNLOCK_PI: rprintf("futex_unlock_pi not implemented\n"); break;
    case FUTEX_CMP_REQUEUE_PI: rprintf("futex_cmp_requeue_pi not implemented\n"); break;
    case FUTEX_WAIT_REQUEUE_PI: rprintf("futex_wait_requeue_pi not implemented\n"); break;
    }

    return set_syscall_error(current, ENOSYS);
}

void register_thread_syscalls(struct syscall *map)
{
    register_syscall(map, futex, futex);
    register_syscall(map, clone, clone);
    register_syscall(map, arch_prctl, arch_prctl);
    register_syscall(map, set_tid_address, set_tid_address);
    register_syscall(map, gettid, gettid);
}

void thread_log_internal(thread t, const char *desc, ...)
{
    if (table_find(t->p->process_root, sym(trace))) {
        if (syscall_notrace(t->syscall))
            return;
        vlist ap;
        vstart (ap, desc);        
        buffer b = allocate_buffer(transient, 100);
        bprintf(b, "%n%d ", (int) ((MAX(MIN(t->tid, 20), 1) - 1) * 4), t->tid);
        if (current->name[0] != '\0')
            bprintf(b, "[%s] ", current->name);
        buffer f = alloca_wrap_buffer(desc, runtime_strlen(desc));
        vbprintf(b, f, &ap);
        push_u8(b, '\n');
        buffer_print(b);
    }
}


CLOSURE_1_0(run_thread, void, thread);
void run_thread(thread t)
{
    current = t;
    thread_log(t, "run frame %p, RIP=%p", t->frame, t->frame[FRAME_RIP]);
    proc_enter_user(current->p);
    running_frame = t->frame;

    /* cover wake-before-sleep situations (e.g. sched yield, fs ops that don't go to disk, etc.) */
    current->blocked_on = 0;

    /* check if we have a pending signal */
    dispatch_signals(t);

    running_frame[FRAME_FLAGS] |= U64_FROM_BIT(FLAG_INTERRUPT);
    IRETURN(running_frame);
}

void thread_sleep_interruptible(void)
{
    assert(current->blocked_on);
    thread_log(current, "sleep interruptible (on \"%s\")", blockq_name(current->blocked_on));
    runloop();
}

void thread_sleep_uninterruptible(void)
{
    assert(!current->blocked_on);
    current->blocked_on = INVALID_ADDRESS;
    thread_log(current, "sleep uninterruptible");
    runloop();
}

void thread_yield(void)
{
    thread_log(current, "yield %d, RIP=0x%lx", current->tid, current->frame[FRAME_RIP]);
    assert(!current->blocked_on);
    current->syscall = -1;
    set_syscall_return(current, 0);
    enqueue(runqueue, current->run);
    runloop();
}

void thread_wakeup(thread t)
{
    thread_log(current, "%s: %ld->%ld blocked_on %p, RIP=0x%lx", __func__, current->tid, t->tid,
               t->blocked_on, t->frame[FRAME_RIP]);
    thread_make_runnable(t);
}

boolean thread_attempt_interrupt(thread t)
{
    thread_log(current, "%s: tid %d\n", __func__, t->tid);
    if (!thread_in_interruptible_sleep(t)) {
        thread_log(current, "uninterruptible or already running");
        return false;
    }

    /* flush pending blockq */
    thread_log(current, "... interrupting blocked thread %d\n", t->tid);
    assert(blockq_flush_thread(t->blocked_on, t));
    assert(thread_is_runnable(t));
    return true;
}

thread create_thread(process p)
{
    // heap I guess
    static int tidcount = 0;
    heap h = heap_general((kernel_heaps)p->uh);

    thread t = allocate(h, sizeof(struct thread));
    if (t == INVALID_ADDRESS) {
        msg_err("failed to allocate thread\n");
        return INVALID_ADDRESS;
    }

    t->dummy_blockq = allocate_blockq(h, "dummy");
    if (t->dummy_blockq == INVALID_ADDRESS) {
        msg_err("failed to allocate blockq\n");
        deallocate(h, t, sizeof(struct thread));
        return INVALID_ADDRESS;
    }

    t->p = p;
    t->syscall = -1;
    t->uh = *p->uh;
    t->select_epoll = 0;
    t->tid = tidcount++;
    t->clear_tid = 0;
    t->name[0] = '\0';
    zero(t->frame, sizeof(t->frame));
    t->frame[FRAME_FAULT_HANDLER] = u64_from_pointer(closure(h, default_fault_handler, t));
    t->run = closure(h, run_thread, t);
    vector_push(p->threads, t);
    t->blocked_on = 0;
    init_sigstate(&t->signals);
    t->dispatch_sigstate = 0;

    // XXX sigframe
    return t;
}

/* XXX this is seriously next */
void exit_thread(thread t)
{
    if (t->clear_tid) {
        *t->clear_tid = 0;
        futex(t->clear_tid, FUTEX_WAKE, 1, 0, 0, 0);
    }

    /* Like an uninterruptible sleep for all eternity. */
    t->blocked_on = INVALID_ADDRESS;

    vector_set(t->p->threads, t->tid - 1, 0);
//    heap h = heap_general((kernel_heaps)t->p->uh);
//    deallocate(h, t, sizeof(struct thread));
}

void init_threads(process p)
{
    heap h = heap_general((kernel_heaps)p->uh);
    p->threads = allocate_vector(h, 5);
    p->futices = allocate_table(h, futex_key_function, futex_key_equal);
}
