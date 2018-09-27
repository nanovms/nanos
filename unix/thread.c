#include <unix_internal.h>

thread current;

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

sysreturn set_tid_address(void *a)
{
    current->set_child_tid = a;
    return current->tid;
}

sysreturn arch_prctl(int code, unsigned long a)
{    
    switch (code) {
    case ARCH_SET_GS:
        break;
    case ARCH_SET_FS:
        current->frame[FRAME_FS] = a;
        return 0;
    case ARCH_GET_FS:
        break;
    case ARCH_GET_GS:
        break;
    default:
        return set_syscall_error(current, EINVAL);
    }
}

sysreturn clone(unsigned long flags, void *child_stack, void *ptid, void *ctid, void *x)
{
    thread t = create_thread(current->p);
    runtime_memcpy(t->frame, current->frame, sizeof(t->frame));
    t->frame[FRAME_RSP]= u64_from_pointer(child_stack);
    // xxx - the interpretation of ctid is dependent on flags
    // and it can be zero
    // t->frame[FRAME_RAX]= *(u32 *)ctid; 
    t->frame[FRAME_FS] = u64_from_pointer(x);
    thread_wakeup(t);
    return t->tid;
}


typedef struct fut {
    queue waiters;
} *fut;
    
static fut soft_create_futex(process p, u64 key)
{
    fut f;
    heap h = heap_general(get_kernel_heaps());
    // of course this is supossed to be serialized
    if (!(f = table_find(p->futices, pointer_from_u64(key)))) {
        f = allocate(h, sizeof(struct fut));
        f->waiters = allocate_queue(h, 32);
        table_set(p->futices, pointer_from_u64(key), f);
    }
    return f;
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
            if (verbose) 
                thread_log(current, "futex wait %p %p %p\n", uaddr, val, current);
            // if we resume we are woken up, no timeout support
            set_syscall_return(current, 0);
            // atomic 
            enqueue(f->waiters, current);
            thread_sleep(current);
        }
        return -EAGAIN;
            
    case FUTEX_WAKE:
        // return the number of waiters that were woken up
        if ((w = dequeue(f->waiters))) {
            if (verbose)
                thread_log(current, "futex_wake [%d %p %d %p]\n", current->tid, uaddr, *uaddr, w);
            thread_wakeup(w);
            set_syscall_return(current, 1);            
        }
        return 0;
        
    case FUTEX_REQUEUE: rprintf("futex_requeue\n"); break;
    case FUTEX_CMP_REQUEUE:
        if (verbose)
            thread_log(current, "futex_cmp_requeue [%d %p %d] %d\n", current->tid, uaddr, *uaddr, val3);
        if (*uaddr == val3) {
            if ((w = dequeue(f->waiters))) {
                set_syscall_return(current, 1);                            
                thread_wakeup(w);
            }
            return 0;
        }
        return -EAGAIN;
    case FUTEX_WAKE_OP:
        {
            unsigned int cmparg = val3 & MASK(12);
            unsigned int oparg = (val3 >> 12) & MASK(12);
            unsigned int cmp = (val3 >> 24) & MASK(4);
            unsigned int op = (val3 >> 28) & MASK(4);

            if (verbose)
                thread_log(current, "futex wake op: [%d %p %d] %p %d %d %d %d\n",  current->tid, uaddr, *uaddr, uaddr2, cmparg, oparg, cmp, op);
            int oldval = *(int *) uaddr2;
            
            switch (cmp) {
            case FUTEX_OP_SET:   *uaddr  = oparg; break;
            case FUTEX_OP_ADD:   *uaddr2 += oparg; break;
            case FUTEX_OP_OR:    *uaddr2 |= oparg; break;
            case FUTEX_OP_ANDN:  *uaddr2 &= ~oparg; break;
            case FUTEX_OP_XOR:   *uaddr2 ^= oparg; break;
            }

            int result = 0;
            while ((w = dequeue(f->waiters))) {
                result++;
                thread_wakeup(w);
            }
            
            int c;
            switch (cmp) {
            case FUTEX_OP_CMP_EQ: c = (oldval == cmparg) ; break;
            case FUTEX_OP_CMP_NE: c = (oldval != cmparg); break;
            case FUTEX_OP_CMP_LT: c = (oldval < cmparg); break;
            case FUTEX_OP_CMP_LE: c = (oldval <= cmparg); break;
            case FUTEX_OP_CMP_GT: c = (oldval > cmparg) ; break;
            case FUTEX_OP_CMP_GE: c = (oldval >= cmparg) ; break;
            }
            
            if (c) {
                fut f = soft_create_futex(current->p, u64_from_pointer(uaddr2));
                if ((w = dequeue(f->waiters))) {                
                    result++;
                    thread_wakeup(w);
                }
            }
            return result;
        }

    case FUTEX_WAIT_BITSET:
        if (verbose)
            thread_log(current, "futex_wait_bitset [%d %p %d] %p %p\n", current->tid, uaddr, *uaddr, val3);
        if (*uaddr == val) {
            set_syscall_return(current, 0);                            
            enqueue(f->waiters, current);
            thread_sleep(current);
        }
        break;
    case FUTEX_WAKE_BITSET: rprintf("FUTEX_wake_bitset unimplemented\n"); break;
    case FUTEX_LOCK_PI: rprintf("FUTEX_lock_pi unimplemented\n"); break;
    case FUTEX_TRYLOCK_PI: rprintf("FUTEX_trylock_pi unimplemented\n"); break;
    case FUTEX_UNLOCK_PI: rprintf("FUTEX_unlock_pi unimplemented\n"); break;
    case FUTEX_CMP_REQUEUE_PI: rprintf("FUTEX_CMP_requeue_pi unimplemented\n"); break;
    case FUTEX_WAIT_REQUEUE_PI: rprintf("FUTEX_WAIT_requeue_pi unimplemented\n"); break;
    }
    return 0;
}

void register_thread_syscalls(void **map)
{
    register_syscall(map, SYS_futex, futex);
    register_syscall(map, SYS_clone, clone);
    register_syscall(map, SYS_arch_prctl, arch_prctl);
    register_syscall(map, SYS_set_tid_address, set_tid_address);
    register_syscall(map, SYS_gettid, gettid);
}

void thread_log_internal(thread t, char *desc, ...)
{
    if (table_find(t->p->process_root, sym(trace))) {
        vlist ap;
        vstart (ap, desc);        
        buffer b = allocate_buffer(transient, 100);
        bprintf (b, "%n %d ", (t->tid - 1)*8, t->tid, desc);
        buffer f = alloca_wrap_buffer(desc, runtime_strlen(desc));
        vbprintf(b, f, &ap);
        push_u8(b, '\n');
        debug(b);
    }
}


CLOSURE_1_0(run_thread, void, thread);
void run_thread(thread t)
{
    current = t;
    thread_log(t, "run",  t->frame[FRAME_RIP]);
    frame  = t->frame;
    IRETURN(frame);    
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
    thread_log(current, "wakeup %d->%d %p", current->tid, t->tid, t->frame[FRAME_RIP]);
    enqueue(runqueue, t->run);
}

thread create_thread(process p)
{
    // heap I guess
    static int tidcount = 0;
    heap h = heap_general((kernel_heaps)p->uh);
    thread t = allocate(h, sizeof(struct thread));
    t->p = p;
    t->uh = *p->uh;
    t->select_epoll = 0;
    t->tid = tidcount++;
    t->set_child_tid = t->clear_child_tid = 0;
    t->frame[FRAME_FAULT_HANDLER] = u64_from_pointer(closure(h, default_fault_handler, t));
    t->run = closure(h, run_thread, t);
    vector_push(p->threads, t);
    return t;
}

void init_threads(process p)
{
    heap h = heap_general((kernel_heaps)p->uh);
    p->threads = allocate_vector(h, 5);
    p->futices = allocate_table(h, futex_key_function, futex_key_equal);
}
