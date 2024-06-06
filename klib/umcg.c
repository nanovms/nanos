#include <unix_internal.h>

#define SYS_umcg_ctl    450

#define UMCG_WORKER_ID_SHIFT    5
#define UMCG_WORKER_EVENT_MASK  ((1 << UMCG_WORKER_ID_SHIFT) - 1)

enum umcg_cmd {
    UMCG_REGISTER_WORKER = 1,
    UMCG_REGISTER_SERVER,
    UMCG_UNREGISTER,
    UMCG_WAKE,
    UMCG_WAIT,
    UMCG_CTX_SWITCH,
};

#define UMCG_WAIT_FLAG_INTERRUPTED  (1ull)

#define UMCG_CMD_KNOWN_FLAGS    UMCG_WAIT_FLAG_INTERRUPTED

enum umcg_worker_status {
    UMCG_WORKER_IDLE,
    UMCG_WORKER_RUNNABLE,
    UMCG_WORKER_RUNNING,
    UMCG_WORKER_PAUSED,
    UMCG_WORKER_BLOCKED,
    UMCG_WORKER_WAITING,
};

/* flags ORed with worker status enum value */
#define UMCG_WORKER_TIMEOUT U32_FROM_BIT(31)

enum umcg_event_type {
    UMCG_WE_BLOCK = 1,
    UMCG_WE_WAKE,
    UMCG_WE_WAIT,
    UMCG_WE_EXIT,
    UMCG_WE_TIMEOUT,
    UMCG_WE_PREEMPT,
};

#define UMCG_PREEMPT_INTERVAL   microseconds(RUNLOOP_TIMER_MAX_PERIOD_US)

//#define UMCG_DEBUG
#ifdef UMCG_DEBUG
#define umcg_debug(x, ...)  tprintf(sym(umcg), 0, x "\n", ##__VA_ARGS__)
#else
#define umcg_debug(x, ...)
#endif

typedef struct umcg_worker {
    struct rbnode node;
    struct list l;
    thread t;
    u64 id;
    enum umcg_worker_status status;
    timestamp start_time;
    enum umcg_event_type event;
    blockq server_bq;
    u64 *server_event;
    struct timer tmr;
    closure_struct(timer_handler, timeout_handler);
} *umcg_worker;

static struct {
    heap h;
    struct rbtree workers;
    closure_struct(rb_key_compare, worker_compare);
    struct list idle_workers;
    struct spinlock lock;
    struct blockq server_bq;    /* used by idle servers, i.e. servers not attached to any worker */
    void (*thread_pause)(struct context *);
    void (*thread_schedule_return)(struct context *);
    void (*syscall_pause)(struct context *);
    void (*thread_free)(void *);
    u32 wake_idle_server;
} umcg;

#define umcg_lock()     spin_lock(&umcg.lock)
#define umcg_unlock()   spin_unlock(&umcg.lock)

static sysreturn umcg_unregister(umcg_worker worker);

closure_func_basic(rb_key_compare, int, umcg_worker_compare,
                   rbnode a, rbnode b)
{
    thread ta = ((umcg_worker)a)->t;
    thread tb = ((umcg_worker)b)->t;
    return ta == tb ? 0 : (ta < tb ? -1 : 1);
}

static umcg_worker umcg_get_worker(thread t)
{
    struct umcg_worker k = {
        .t = t,
    };
    umcg_lock();
    umcg_worker worker = (umcg_worker)rbtree_lookup(&umcg.workers, &k.node);
    umcg_unlock();
    return worker;

}

static void umcg_worker_event_idle(umcg_worker worker, enum umcg_event_type event)
{
    worker->event = event;
    umcg_lock();
    list_push_back(&umcg.idle_workers, &worker->l);
    umcg_unlock();
    blockq_wake_one(&umcg.server_bq);
}

static void umcg_worker_event_to_server(umcg_worker worker, enum umcg_event_type event)
{
    *worker->server_event = worker->id | event;
    blockq bq = worker->server_bq;
    blockq_wake_one(bq);
    blockq_release(bq);
}

closure_func_basic(timer_handler, void, umcg_worker_timeout,
                   u64 expiry, u64 overruns)
{
    umcg_debug("worker timeout (%ld)", overruns);
    if (overruns == timer_disabled)
        return;
    umcg_worker worker = struct_from_field(closure_self(), umcg_worker, timeout_handler);
    if (compare_and_swap_32(&worker->status, UMCG_WORKER_WAITING, UMCG_WORKER_IDLE))
        umcg_worker_event_idle(worker, UMCG_WE_TIMEOUT);
    else if (!compare_and_swap_32(&worker->status, UMCG_WORKER_IDLE,
                                  UMCG_WORKER_IDLE | UMCG_WORKER_TIMEOUT))
        return;
    set_syscall_return(worker->t, -ETIMEDOUT);
}

static void umcg_syscall_pause(context ctx)
{
    thread t = ((syscall_context)ctx)->t;
    umcg_worker worker = umcg_get_worker(t);
    if ((worker != INVALID_ADDRESS) &&
        compare_and_swap_32(&worker->status, UMCG_WORKER_PAUSED, UMCG_WORKER_BLOCKED)) {
        blockq bq = worker->server_bq;
        worker->server_bq = 0;
        *worker->server_event = worker->id | UMCG_WE_BLOCK;
        blockq_wake_one(bq);
        blockq_release(bq);
    }
    ctx->pause = umcg.syscall_pause;
    ctx->pause(ctx);
}

static void umcg_worker_pause(context ctx)
{
    thread t = (thread)ctx;
    syscall_context sc = t->syscall;
    if (sc) {
        umcg_worker worker = umcg_get_worker(t);
        worker->status = UMCG_WORKER_PAUSED;
        umcg.syscall_pause = sc->uc.kc.context.pause;
        sc->uc.kc.context.pause = umcg_syscall_pause;
    }
    umcg.thread_pause(ctx);
}

static void umcg_worker_schedule_return(context ctx)
{
    umcg_worker worker = umcg_get_worker((thread)ctx);
    if (compare_and_swap_32(&worker->status, UMCG_WORKER_BLOCKED, UMCG_WORKER_IDLE)) {
        blockq server_bq = worker->server_bq;
        if (server_bq) {
            blockq_wake_one(server_bq);
            blockq_release(server_bq);
        }
        umcg_worker_event_idle(worker, UMCG_WE_WAKE);
    } else if (kern_now(CLOCK_ID_MONOTONIC_RAW) >= worker->start_time + UMCG_PREEMPT_INTERVAL) {
        worker->status = UMCG_WORKER_RUNNABLE;
        umcg_worker_event_to_server(worker, UMCG_WE_PREEMPT);
    } else {
        worker->status = UMCG_WORKER_RUNNING;
        umcg.thread_schedule_return(ctx);
    }
}

/* Called if a worker thread terminates without unregistering itself as a worker. */
static void umcg_worker_thread_free(void *__self)
{
    umcg_debug("worker thread free");
    umcg_unregister(umcg_get_worker(struct_from_closure(thread, free)));
    apply((thunk)__self);   /* invoke the real thread refcount completion */
}

static sysreturn umcg_register_worker(thread t, u64 id)
{
    umcg_debug("register worker 0x%lx", id);
    if (id & UMCG_WORKER_EVENT_MASK)
        return -EINVAL;
    umcg_worker worker = allocate(umcg.h, sizeof(*worker));
    if (worker == INVALID_ADDRESS)
        return -ENOMEM;
    worker->t = t;
    worker->id = id;
    worker->status = UMCG_WORKER_IDLE;
    init_timer(&worker->tmr);
    init_closure_func(&worker->timeout_handler, timer_handler, umcg_worker_timeout);
    umcg_lock();
    init_rbnode(&worker->node);
    if (!rbtree_insert_node(&umcg.workers, &worker->node)) {
        umcg_unlock();
        deallocate(umcg.h, worker, sizeof(*worker));
        return -EINVAL;
    }

    /* Replace thread context callbacks to be able to generate UMCG_WE_BLOCK and UMCG_WE_PRREMPT
     * events. */
    umcg.thread_pause = t->context.pause;
    t->context.pause = umcg_worker_pause;
    umcg.thread_schedule_return = t->context.schedule_return;
    t->context.schedule_return = umcg_worker_schedule_return;

    worker->event = UMCG_WE_WAKE;
    list_push_back(&umcg.idle_workers, &worker->l);
    umcg_unlock();
    blockq_wake_one(&umcg.server_bq);

    /* Replace the thread refcount completion to handle cases where a thread terminates without
     * unregistering itself as a worker. */
    umcg.thread_free = *t->context.refcount.completion;
    *t->context.refcount.completion = umcg_worker_thread_free;

    set_syscall_return(t, 0);
    return thread_maybe_sleep_uninterruptible(t);
}

static sysreturn umcg_unregister(umcg_worker worker)
{
    umcg_debug("unregister %p", worker);
    if (worker != INVALID_ADDRESS) {
        umcg_lock();
        rbtree_remove_node(&umcg.workers, &worker->node);
        umcg_unlock();
        thread t = worker->t;
        context ctx = &t->context;
        ctx->pause = umcg.thread_pause;
        ctx->schedule_return = umcg.thread_schedule_return;
        syscall_context sc = t->syscall;
        if (sc)
            sc->uc.kc.context.pause = umcg.syscall_pause;
        *t->context.refcount.completion = umcg.thread_free;
        umcg_worker_event_to_server(worker, UMCG_WE_EXIT);
        deallocate(umcg.h, worker, sizeof(*worker));
    }
    return 0;
}

static sysreturn umcg_server_get_events(u64 *events, u64 event_sz)
{
    sysreturn rv = 0;
    umcg_lock();
    while (event_sz > 1) {
        struct list *l = list_get_next(&umcg.idle_workers);
        if (!l)
            break;
        umcg_worker worker = struct_from_field(l, umcg_worker, l);
        umcg_debug("worker 0x%lx event %ld", worker->id, worker->event);
        u64 event = worker->id | worker->event;
        if (!set_user_value(events, event)) {
            if (rv == 0)
                rv = -EFAULT;
            break;
        }
        rv++;
        events++;
        event_sz--;

        /* To check for worker timeout, use compare_and_swap to protect against race with timeout
         * handler. */
        if ((worker->event == UMCG_WE_WAIT) &&
            !compare_and_swap_32(&worker->status, UMCG_WORKER_IDLE,
                                 UMCG_WORKER_IDLE | UMCG_WORKER_TIMEOUT)) {
            event = worker->id | UMCG_WE_TIMEOUT;
            if (!set_user_value(events, event)) {
                if (rv == 1)
                    rv = -EFAULT;
                break;
            }
            rv++;
            events++;
            event_sz--;
        }

        worker->status = UMCG_WORKER_RUNNABLE;
        list_delete(l);
    }
    if (event_sz > 0) {
        u64 event = 0;
        set_user_value(events, event);
    }
    umcg_unlock();
    return rv;
}

closure_function(1, 1, sysreturn, umcg_server_wait_worker_bh,
                 umcg_worker, worker,
                 u64 flags)
{
    syscall_context ctx = (syscall_context)get_current_context(current_cpu());
    sysreturn rv;
    if (flags & BLOCKQ_ACTION_NULLIFY) {
        rv = -ERESTARTSYS;
        goto out;
    }
    if (bound(worker)->status == UMCG_WORKER_BLOCKED)
        return blockq_block_required(&ctx->uc, flags);
    rv = 0;
  out:
    closure_finish();
    return syscall_return(ctx->t, rv);
}

closure_function(3, 1, sysreturn, umcg_server_wait_bh,
                 timestamp, timeout, u64 *, events, u64, event_sz,
                 u64 flags)
{
    syscall_context ctx = (syscall_context)get_current_context(current_cpu());
    sysreturn rv;
    if (flags & BLOCKQ_ACTION_TIMEDOUT) {
        rv = -ETIMEDOUT;
        goto out;
    }
    if (flags & BLOCKQ_ACTION_NULLIFY) {
        rv = bound(timeout) ? -EINTR : -ERESTARTSYS;
        goto out;
    }
    rv = umcg_server_get_events(bound(events), bound(event_sz));
    if ((rv == 0) && !compare_and_swap_32(&umcg.wake_idle_server, true, false))
        return blockq_block_required(&ctx->uc, flags);
    if (rv > 0)
        rv = 0;
  out:
    closure_finish();
    return syscall_return(ctx->t, rv);
}

closure_function(3, 1, sysreturn, umcg_server_ctx_switch_bh,
                 u64, event, u64 *, events, u64, event_sz,
                 u64 flags)
{
    syscall_context ctx = (syscall_context)get_current_context(current_cpu());
    sysreturn rv;
    if (flags & BLOCKQ_ACTION_NULLIFY) {
        rv = -ERESTARTSYS;
        goto out;
    }
    u64 event = bound(event);
    if (!event)
        return blockq_block_required(&ctx->uc, flags);
    u64 *events = bound(events);
    u64 event_sz = bound(event_sz);
    if (!set_user_value(events, event)) {
        rv = -EFAULT;
        goto out;
    }
    if (event_sz > 1) {
        rv = umcg_server_get_events(events + 1, event_sz - 1);
        if (rv > 0)
            rv = 0;
    } else {
        rv = 0;
    }
  out:
    closure_finish();
    return syscall_return(ctx->t, rv);
}

static sysreturn umcg_wait(thread t, int next_tid, u64 abs_timeout, u64 *events, u64 event_sz)
{
    umcg_debug("wait tid %d, timeout %ld", next_tid, abs_timeout);
    umcg_worker worker = umcg_get_worker(t);
    if (worker == INVALID_ADDRESS) {
        if (next_tid) {
            if (abs_timeout || events || event_sz)
                return -EINVAL;
            thread next_t = thread_from_tid(t->p, next_tid);
            if (next_t == INVALID_ADDRESS)
                return -ESRCH;
            umcg_worker next = umcg_get_worker(next_t);
            thread_release(next_t);
            if (next == INVALID_ADDRESS)
                return -EINVAL;
            blockq_action ba = contextual_closure(umcg_server_wait_worker_bh, next);
            if (ba == INVALID_ADDRESS)
                return -ENOMEM;
            blockq bq = t->thread_bq;
            next->server_bq = bq;
            blockq_reserve(bq);
            return blockq_check(bq, ba, false);
        }
        if (event_sz < 2)   /* there must be room for 2 events */
            return -EINVAL;
        if (abs_timeout == 1) {
            sysreturn  rv = umcg_server_get_events(events, event_sz);
            if (rv > 0)
                return 0;
            return (rv == 0) ? -ETIMEDOUT : rv;
        }
        timestamp ts = nanoseconds(abs_timeout);
        blockq_action ba = contextual_closure(umcg_server_wait_bh, ts, events, event_sz);
        if (ba == INVALID_ADDRESS)
            return -ENOMEM;
        return blockq_check_timeout(&umcg.server_bq, ba, false, CLOCK_ID_REALTIME, ts, true);
    } else {
        if (next_tid || events || event_sz)
            return -EINVAL;
        worker->status = UMCG_WORKER_WAITING;
        if (abs_timeout)
            register_timer(kernel_timers, &worker->tmr, CLOCK_ID_REALTIME, nanoseconds(abs_timeout),
                           true, 0, (timer_handler)&worker->timeout_handler);
        set_syscall_return(t, 0);
        umcg_worker_event_to_server(worker, UMCG_WE_WAIT);
        return thread_maybe_sleep_uninterruptible(t);
    }
}

static sysreturn umcg_ctx_switch(thread t, int next_tid, u64 abs_timeout, u64 *events, u64 event_sz)
{
    umcg_debug("ctx switch tid %d, timeout %ld", next_tid, abs_timeout);
    thread next_t = thread_from_tid(t->p, next_tid);
    if (next_t == INVALID_ADDRESS)
        return -ESRCH;
    umcg_worker next = umcg_get_worker(next_t);
    thread_release(next_t);
    if (next == INVALID_ADDRESS)
        return -EINVAL;
    blockq_action ba = 0;
    umcg_worker worker = umcg_get_worker(t);
    if (worker == INVALID_ADDRESS) {
        if (abs_timeout || (event_sz <= 0))
            return -EINVAL;
        ba = contextual_closure(umcg_server_ctx_switch_bh, 0, events, event_sz);
        if (ba == INVALID_ADDRESS)
            return -ENOMEM;
        if (!compare_and_swap_32(&next->status, UMCG_WORKER_RUNNABLE, UMCG_WORKER_RUNNING) &&
            !compare_and_swap_32(&next->status, UMCG_WORKER_WAITING, UMCG_WORKER_RUNNING)) {
            deallocate_closure(ba);
            return -EINVAL;
        }
        next->server_event = &closure_member(umcg_server_ctx_switch_bh, ba, event);
        blockq server_bq = t->thread_bq;
        next->server_bq = server_bq;
        blockq_reserve(server_bq);
    } else {
        if (!compare_and_swap_32(&next->status, UMCG_WORKER_RUNNABLE, UMCG_WORKER_RUNNING))
            return -EINVAL;
        worker->status = UMCG_WORKER_IDLE;
        umcg_worker_event_idle(worker, UMCG_WE_WAIT);
        if (abs_timeout)
            register_timer(kernel_timers, &worker->tmr, CLOCK_ID_REALTIME, nanoseconds(abs_timeout),
                           true, 0, (timer_handler)&worker->timeout_handler);
        next->server_event = worker->server_event;
        next->server_bq = worker->server_bq;
        set_syscall_return(t, 0);
    }
    remove_timer(kernel_timers, &next->tmr, 0);
    next->start_time = kern_now(CLOCK_ID_MONOTONIC_RAW);
    if (next_t->syscall)
        syscall_return(next_t, get_syscall_return(next_t));
    else
        schedule_thread(next_t);
    if (worker == INVALID_ADDRESS)
        return blockq_check(t->thread_bq, ba, false);
    else
        return thread_maybe_sleep_uninterruptible(t);
}

sysreturn umcg_ctl(u64 flags, u64 cmd, int next_tid, u64 abs_timeout, u64 *events, int event_sz)
{
    umcg_debug("cmd %d", cmd);
    thread t = current;
    switch (cmd) {
    case UMCG_REGISTER_WORKER:
        if (flags || next_tid || events || event_sz)
            return -EINVAL;
        return umcg_register_worker(t, abs_timeout);
    case UMCG_REGISTER_SERVER:
        if (flags || next_tid || abs_timeout || events || event_sz)
            return -EINVAL;
        break;
    case UMCG_UNREGISTER:
        if (flags || next_tid || abs_timeout || events || event_sz)
            return -EINVAL;
        return umcg_unregister(umcg_get_worker(t));
    case UMCG_WAKE:
        if (flags || next_tid || abs_timeout || events || event_sz)
            return -EINVAL;
        umcg.wake_idle_server = true;
        if ((blockq_wake_one(&umcg.server_bq) == INVALID_ADDRESS) &&
            compare_and_swap_32(&umcg.wake_idle_server, true, false))
            return -EAGAIN;
        break;
    case UMCG_WAIT:
        if (flags & ~UMCG_CMD_KNOWN_FLAGS)
            return -EINVAL;
        return umcg_wait(t, next_tid, abs_timeout, events, event_sz);
    case UMCG_CTX_SWITCH:
        if (flags)
            return -EINVAL;
        return umcg_ctx_switch(t, next_tid, abs_timeout, events, event_sz);
    default:
        return -EINVAL;
    }
    return 0;
}

int init(status_handler complete)
{
    umcg.h = heap_locked(get_kernel_heaps());
    init_rbtree(&umcg.workers,
                init_closure_func(&umcg.worker_compare, rb_key_compare, umcg_worker_compare), 0);
    list_init(&umcg.idle_workers);
    blockq_init(&umcg.server_bq, ss("umcg servers"));
    spin_lock_init(&umcg.lock);
    register_syscall(linux_syscalls, umcg_ctl, umcg_ctl);
    return KLIB_INIT_OK;
}
