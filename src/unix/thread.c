#include <unix_internal.h>

thread current;

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
    thread_wakeup(t);
    return t->tid;
}

typedef struct fut {
    queue waiters;
    timer t;
} *fut;
    
static fut soft_create_futex(process p, u64 key)
{
    fut f;
    heap h = heap_general(get_kernel_heaps());
    // of course this is supossed to be serialized
    if (!(f = table_find(p->futices, pointer_from_u64(key)))) {
        f = allocate(h, sizeof(struct fut));
        f->waiters = allocate_queue(h, 32);
        f->t = 0;
        table_set(p->futices, pointer_from_u64(key), f);
    }
    return f;
}

static void futex_thread_wakeup(fut f, thread t) {
    if (f->t){
        remove_timer(f->t);
    }
    thread_wakeup(t);
}

// return the number of waiters that were woken up
static int futex_wake(fut f, int val, boolean verbose, int *uaddr)
{
    int result = 0;
    thread w;

    while (result < val && (w = dequeue(f->waiters))) {
        result++;
        if (verbose) {
            thread_log(current, "futex_wake [%ld %p %d] %p %d/%d",
                current->tid, uaddr, *uaddr, w, result, val);
        }
        futex_thread_wakeup(f, w);
    }

    return result;
}

static CLOSURE_1_0(futex_timeout, void, thread);
static void futex_timeout(thread t)
{
    set_syscall_return(t, ETIMEDOUT);
    thread_wakeup(t);
}

void register_futex_timer(thread t, fut f, const struct timespec* req)
{
   f->t = register_timer(time_from_timespec(req),
		closure(heap_general(get_kernel_heaps()), futex_timeout, t));
}

static sysreturn futex(int *uaddr, int futex_op, int val,
                       u64 val2,
                       int *uaddr2, int val3)
{
    struct timespec *timeout = pointer_from_u64(val2);
    boolean verbose = table_find(current->p->process_root, sym(futex_trace))?true:false;
    thread w;
    
    fut f = soft_create_futex(current->p, u64_from_pointer(uaddr));
    int op = futex_op & 127; // chuck the private bit
    switch(op) {
    case FUTEX_WAIT:
        if (*uaddr == val) {
            if (verbose) {
                thread_log(current, "futex_wait [%ld %p %d] %d %p",
                    current->tid, uaddr, *uaddr, val, timeout);
            }
            // if we resume we are woken up
            set_syscall_return(current, 0);
            //timeout is relative, measured against the CLOCK_MONOTONIC clock
            if (timeout)
                register_futex_timer(current, f, timeout);
            // atomic 
            enqueue(f->waiters, current);
            thread_sleep(current);
        }
        return -EAGAIN;
            
    case FUTEX_WAKE:
        return futex_wake(f, val, verbose, uaddr);
        
    case FUTEX_REQUEUE: rprintf("futex_requeue not implemented\n"); break;
    case FUTEX_CMP_REQUEUE:
        if (verbose) {
            thread_log(current, "futex_cmp_requeue [%ld %p %d] %d %p %d",
                current->tid, uaddr, *uaddr, val3, uaddr2, *uaddr2);
        }
        if (*uaddr == val3) {
            int result = futex_wake(f, val, verbose, uaddr);

            int result2 = 0;
            if (queue_peek(f->waiters)) {
                fut f2 = soft_create_futex(current->p, u64_from_pointer(uaddr2));
                while (result2 < val2 && (w = dequeue(f->waiters))) {
                    result2++;
                    if (verbose) {
                        thread_log(current, "futex_cmp_requeue [%ld %p %d] %p %d/%d",
                            current->tid, uaddr2, *uaddr2, w, result2, val2);
                    }
                    enqueue(f2->waiters, w);
                }
            }

            return result + result2;
        }
        return -EAGAIN;

    case FUTEX_WAKE_OP:
        {
            unsigned int cmparg = val3 & MASK(12);
            unsigned int oparg = (val3 >> 12) & MASK(12);
            unsigned int cmp = (val3 >> 24) & MASK(4);
            unsigned int op = (val3 >> 28) & MASK(4);

            if (verbose) {
                thread_log(current, "futex_wake_op: [%ld %p %d] %p %d %d %d %d",
                    current->tid, uaddr, *uaddr, uaddr2, cmparg, oparg, cmp, op);
            }

            int oldval = *(int *) uaddr2;
            
            switch (op) {
            case FUTEX_OP_SET:   *uaddr2 = oparg; break;
            case FUTEX_OP_ADD:   *uaddr2 += oparg; break;
            case FUTEX_OP_OR:    *uaddr2 |= oparg; break;
            case FUTEX_OP_ANDN:  *uaddr2 &= ~oparg; break;
            case FUTEX_OP_XOR:   *uaddr2 ^= oparg; break;
            }

            int result = futex_wake(f, val, verbose, uaddr);
            
            int c = 0;
            switch (cmp) {
            case FUTEX_OP_CMP_EQ: c = (oldval == cmparg) ; break;
            case FUTEX_OP_CMP_NE: c = (oldval != cmparg); break;
            case FUTEX_OP_CMP_LT: c = (oldval < cmparg); break;
            case FUTEX_OP_CMP_LE: c = (oldval <= cmparg); break;
            case FUTEX_OP_CMP_GT: c = (oldval > cmparg) ; break;
            case FUTEX_OP_CMP_GE: c = (oldval >= cmparg) ; break;
            }
            
            if (c) {
                fut f2 = soft_create_futex(current->p, u64_from_pointer(uaddr2));
                result += futex_wake(f2, val2, verbose, uaddr2);
            }

            return result;
        }

    case FUTEX_WAIT_BITSET:
        if (*uaddr == val) {
            if (verbose) {
                thread_log(current, "futex_wait_bitset [%ld %p %d] %d %p %d",
                    current->tid, uaddr, *uaddr, val, timeout, val3);
            }
            set_syscall_return(current, 0);
            // TODO: timeout should be absolute based on CLOCK_REALTIME
            if (timeout)
                register_futex_timer(current, f, timeout);                          
            enqueue(f->waiters, current);
            thread_sleep(current);
        }
        return -EAGAIN;

    case FUTEX_WAKE_BITSET: rprintf("futex_wake_bitset not implemented\n"); break;
    case FUTEX_LOCK_PI: rprintf("futex_lock_pi not implemented\n"); break;
    case FUTEX_TRYLOCK_PI: rprintf("futex_trylock_pi not implemented\n"); break;
    case FUTEX_UNLOCK_PI: rprintf("futex_unlock_pi not implemented\n"); break;
    case FUTEX_CMP_REQUEUE_PI: rprintf("futex_cmp_requeue_pi not implemented\n"); break;
    case FUTEX_WAIT_REQUEUE_PI: rprintf("futex_wait_requeue_pi not implemented\n"); break;
    }
    return 0;
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

    /* check if we have a pending signal */
    dispatch_signals(t);

    running_frame[FRAME_FLAGS] |= U64_FROM_BIT(FLAG_INTERRUPT);
    IRETURN(running_frame);
}

// it might be easier, if a little skeezy, to use the return value
// to genericize the handling of suspended threads. given that there
// are already conventions (i.e. negative errors) on the interface
void thread_sleep(thread t)
{
    // config from the filesystem
    thread_log(t, "sleep",  0);
    runloop();
}

void thread_wakeup(thread t)
{
    thread_log(current, "wakeup %ld->%ld %p", current->tid, t->tid, t->frame[FRAME_RIP]);
    enqueue(runqueue, t->run);
}

thread create_thread(process p)
{
    // heap I guess
    static int tidcount = 0;
    heap h = heap_general((kernel_heaps)p->uh);
    thread t = allocate(h, sizeof(struct thread));
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
    t->blocked_on_action = 0;
    t->dummy_blockq = allocate_blockq(h, "dummy", 1, 0);
    t->sigmask = 0;
    t->sigpending = 0;
    t->sigsaved = 0;
    for(int i = 0; i < NSIG; i += 4) {
        list_init(&t->sigheads[i]);
        list_init(&t->sigheads[i + 1]);
        list_init(&t->sigheads[i + 2]);
        list_init(&t->sigheads[i + 3]);
    }
    // XXX sigframe
    return t;
}

void exit_thread(thread t)
{
    if (t->clear_tid) {
        *t->clear_tid = 0;
        futex(t->clear_tid, FUTEX_WAKE, 1, 0, 0, 0);
    }

    /* TODO: remove also from p->threads (but it is not currently used) */
    heap h = heap_general((kernel_heaps)t->p->uh);
    deallocate(h, t, sizeof(struct thread));
}

void init_threads(process p)
{
    heap h = heap_general((kernel_heaps)p->uh);
    p->threads = allocate_vector(h, 5);
    p->futices = allocate_table(h, futex_key_function, futex_key_equal);
}
