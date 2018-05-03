#include <sruntime.h>
#include <unix.h>

int gettid()
{
    return current->tid;
}

u64 set_tid_address(void *a)
{
    current->set_child_tid = a;
    return current->tid;
}


extern void write_msr(u64 a, u64 b);
static int arch_prctl(int code, unsigned long a)
{    
    switch (code) {
    case ARCH_SET_GS:
        break;
    case ARCH_SET_FS:
        rprintf("set fs: %p\n", a);
        current->frame[FRAME_FS] = a;
        return 0;
    case ARCH_GET_FS:
        break;
    case ARCH_GET_GS:
        break;
    default:
        return -EINVAL;
    }
}

long clone(unsigned long flags, void *child_stack, void *ptid, void *ctid, void *x)
{
    thread t = create_thread(current->p);
    runtime_memcpy(t->frame, current->frame, sizeof(t->frame));
    t->frame[FRAME_RSP]= u64_from_pointer(child_stack);
    t->frame[FRAME_RAX]= *(u32 *)ctid;
    t->frame[FRAME_FS] = u64_from_pointer(x);
    enqueue(runqueue, t->run);
    return t->tid;
}


typedef struct fut {
    queue waiters;
} *fut;
    
static fut soft_create_futex(process p, u64 key)
{
    fut f;
    // of course this is supossed to be serialized
    if (!(f = table_find(p->futices, pointer_from_u64(key)))) {
        f = allocate(p->h, sizeof(struct fut));
        f->waiters = allocate_queue(p->h, 32);
        table_set(p->futices, pointer_from_u64(key), f);
    }
    return f;
}

static int futex(int *uaddr, int futex_op, int val,
                 u64 val2,
                 int *uaddr2, int val3)
{
    struct timespec *timeout = pointer_from_u64(val2);
    int verbose = false;
    thunk w;
    
    fut f = soft_create_futex(current->p, u64_from_pointer(uaddr));
    int op = futex_op & 127; // chuck the private bit
    switch(op) {
    case FUTEX_WAIT:
        if (verbose)
            rprintf("futex_wait [%d %p %d] %p\n", current->tid, uaddr, *uaddr, val);
        if (*uaddr == val) {
            // if we resume we are woken up, no timeout support
            current->frame[FRAME_RAX] = 0;
            enqueue(f->waiters, current->run);
            runloop();
        }
        return -EAGAIN;
            
    case FUTEX_WAKE:
        // return the number of waiters that were woken up
        if (verbose)
            rprintf("futex_wake [%d %p %d]\n", current->tid, uaddr, *uaddr);
        if ((w = dequeue(f->waiters))) {
            current->frame[FRAME_RAX] = 1;
            enqueue(runqueue, w);
        }
        return 0;
        
    case FUTEX_FD: rprintf("futex_fd\n"); break;
    case FUTEX_REQUEUE: rprintf("futex_requeue\n"); break;
    case FUTEX_CMP_REQUEUE:
        if (verbose)
            rprintf("futex_cmp_requeue [%d %p %d] %d\n", current->tid, uaddr, *uaddr, val3);
        if (*uaddr == val3) {
            if ((w = dequeue(f->waiters))) {            
                current->frame[FRAME_RAX] = 1;
                enqueue(runqueue, w);
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
                rprintf("futex wake op: [%d %p %d] %p %d %d %d %d\n",  current->tid, uaddr, *uaddr, uaddr2, cmparg, oparg, cmp, op);
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
                enqueue(runqueue, w);
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
                    enqueue(runqueue, w);                    
                }
            }
            return result;
        }

    case FUTEX_WAIT_BITSET:
        if (verbose)
            rprintf("futex_wait_bitset [%d %p %d] %p %p\n", current->tid, uaddr, *uaddr, val3);
        if (*uaddr == val) {
            current->frame[FRAME_RAX] = 0;
            enqueue(f->waiters, current->run);
            // xxx - go back to sched
        }
        break;
    case FUTEX_WAKE_BITSET: rprintf("FUTEX_wake_bitset\n"); break;
    case FUTEX_LOCK_PI: rprintf("FUTEX_lock_pi\n"); break;
    case FUTEX_TRYLOCK_PI: rprintf("FUTEX_trylock_pi\n"); break;
    case FUTEX_UNLOCK_PI: rprintf("FUTEX_unlock_pi\n"); break;
    case FUTEX_CMP_REQUEUE_PI: rprintf("FUTEX_CMP_requeue_pi\n"); break;
    case FUTEX_WAIT_REQUEUE_PI: rprintf("FUTEX_WAIT_requeue_pi\n"); break;
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

