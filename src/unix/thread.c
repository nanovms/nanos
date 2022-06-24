#include <unix_internal.h>
#include <ftrace.h>
#include <gdb.h>

BSS_RO_AFTER_INIT thread dummy_thread;

sysreturn gettid()
{
    return current->tid;
}

sysreturn set_tid_address(int *a)
{
    /* man page says this always succeeds, but... */
    if (a && !validate_user_memory(a, sizeof(int), true))
        return set_syscall_error(current, EFAULT);
    current->clear_tid = a;
    return current->tid;
}

#ifdef __x86_64__
sysreturn arch_prctl(int code, unsigned long addr)
{    
    thread_log(current, "arch_prctl: code 0x%x, addr 0x%lx", code, addr);
    if ((code == ARCH_GET_FS || code == ARCH_GET_GS) &&
        !validate_user_memory((void *)addr, sizeof(u64), true))
        return set_syscall_error(current, EFAULT);

    /* just validate the word at base */
    if ((code == ARCH_SET_FS || code == ARCH_SET_GS) &&
        !validate_user_memory((void *)addr, sizeof(u64), false))
        return set_syscall_error(current, EFAULT);

    switch (code) {
    case ARCH_SET_GS:
        thread_frame(current)[FRAME_GSBASE] = addr;
        break;
    case ARCH_SET_FS:
        thread_frame(current)[FRAME_FSBASE] = addr;
        return 0;
    case ARCH_GET_FS:
	*(u64 *) addr = thread_frame(current)[FRAME_FSBASE];
        break;
    case ARCH_GET_GS:
	*(u64 *) addr = thread_frame(current)[FRAME_GSBASE];
        break;
    default:
        return set_syscall_error(current, EINVAL);
    }
    return 0;
}
#endif

#if defined(__x86_64__)
sysreturn clone(unsigned long flags, void *child_stack, int *ptid, int *ctid, unsigned long newtls)
#elif defined(__aarch64__) || defined(__riscv)
sysreturn clone(unsigned long flags, void *child_stack, int *ptid, unsigned long newtls, int *ctid)
#endif
{
    thread_log(current, "clone: flags %lx, child_stack %p, ptid %p, ctid %p, newtls %lx",
        flags, child_stack, ptid, ctid, newtls);

    if (!(flags & CLONE_THREAD)) {
        thread_log(current, "attempted to create new process, aborting.");
        return set_syscall_error(current, ENOSYS);
    }

    /* no stack size given, just validate the top word */
    if (!validate_user_memory(child_stack, sizeof(u64), true))
        return set_syscall_error(current, EFAULT);

    if (((flags & CLONE_PARENT_SETTID) &&
         !validate_user_memory(ptid, sizeof(int), true)) ||
        ((flags & CLONE_CHILD_CLEARTID) &&
         !validate_user_memory(ctid, sizeof(int), true)))
        return set_syscall_error(current, EFAULT);

    thread t = create_thread(current->p, INVALID_PHYSICAL);
    context_frame f = thread_frame(t);
    /* clone frame processor state */
    clone_frame_pstate(f, thread_frame(current));
    thread_clone_sigmask(t, current);

    /* clone behaves like fork at the syscall level, returning 0 to the child */
    set_syscall_return(t, 0);
    f[SYSCALL_FRAME_SP] = u64_from_pointer(child_stack);
    if (flags & CLONE_SETTLS)
        set_tls(f, newtls);
    if (flags & CLONE_PARENT_SETTID)
        *ptid = t->tid;
    if (flags & CLONE_CHILD_CLEARTID)
        t->clear_tid = ctid;
    t->blocked_on = 0;
    t->syscall = 0;
    f[FRAME_FULL] = true;
    thread_reserve(t);
    schedule_thread(t);
    return t->tid;
}


void register_thread_syscalls(struct syscall *map)
{
    register_syscall(map, futex, futex, 0);
    register_syscall(map, set_robust_list, set_robust_list, 0);
    register_syscall(map, get_robust_list, get_robust_list, 0);
    register_syscall(map, clone, clone, SYSCALL_F_SET_PROC);
#ifdef __x86_64__
    register_syscall(map, arch_prctl, arch_prctl, 0);
#endif
    register_syscall(map, set_tid_address, set_tid_address, 0);
    register_syscall(map, gettid, gettid, 0);
}

void thread_log_internal(thread t, const char *desc, ...)
{
    if (t->syscall && syscall_notrace(t->p, t->syscall->call))
        return;
    vlist ap;
    vstart (ap, desc);
    buffer b = little_stack_buffer(512);
#ifndef CONFIG_TRACELOG
    bprintf(b, "%n%d ", (int) ((MAX(MIN(t->tid, 20), 1) - 1) * 4), t->tid);
#endif
    if (t->name[0] != '\0')
        bprintf(b, "[%s] ", t->name);
    buffer f = alloca_wrap_buffer(desc, runtime_strlen(desc));
    vbprintf(b, f, &ap);
    push_u8(b, '\n');
#ifdef CONFIG_TRACELOG
    tprintf(sym(thread), t->tracelog_attrs, "%b", b);
#else
    buffer_print(b);
#endif
}

static inline void check_stop_conditions(thread t)
{
    char *cause;
    u64 pending = sigstate_get_pending(&t->signals);

    /* rather abrupt to just halt...this should go do dump or recovery */
    if (pending & mask_from_sig(SIGSEGV)) {
        void * handler = sigaction_from_sig(t, SIGSEGV)->sa_handler;

        /* Terminate on uncaught SIGSEGV, or if triggered by signal handler. */
        if (handler == SIG_IGN || handler == SIG_DFL) {
            cause = "Unhandled SIGSEGV";
            goto terminate;
        }
    }

    boolean is_sigkill = (pending & mask_from_sig(SIGKILL)) != 0;
    if (is_sigkill || (pending & mask_from_sig(SIGSTOP))) {
        cause = is_sigkill ? "SIGKILL" : "SIGSTOP";
        goto terminate;
    }
    return;
  terminate:
    rprintf("\nProcess abort: %s received by thread %d\n\n", cause, t->tid);
    dump_context(&t->context);
    halt("Terminating.\n");
}

static void thread_pause(context ctx)
{
    if (shutting_down)
        return;
    thread t = (thread)ctx;
    context_frame f = thread_frame(t);
    assert(t->start_time != 0); // XXX tmp debug
    timestamp diff = now(CLOCK_ID_MONOTONIC_RAW) - t->start_time;
    t->utime += diff;
    t->start_time = 0; // XXX tmp debug
    thread_frame_save_fpsimd(f);
    thread_frame_save_tls(f);
}

static void thread_resume(context ctx)
{
    thread t = (thread)ctx;
    assert(t->start_time == 0); // XXX tmp debug
    timestamp here = now(CLOCK_ID_MONOTONIC_RAW);
    t->start_time = here == 0 ? 1 : here;
    if (do_syscall_stats && t->last_syscall == SYS_sched_yield)
        count_syscall(t, 0);
    context_frame f = thread_frame(t);
    thread_frame_restore_tls(f);
    thread_frame_restore_fpsimd(f);
    frame_enable_interrupts(f);
}

static void thread_schedule_return(context ctx)
{
    thread t = (thread)ctx;
    assert(enqueue_irqsafe(t->scheduling_queue, &t->thread_return));
}

define_closure_function(1, 0, void, thread_return,
                        thread, t)
{
    cpuinfo ci = current_cpu();
    thread t = bound(t);
    if (t->p->trap)
        runloop(); // XXX pause?

    /* temporarily install fault handler to catch faults for stack pages */
    use_fault_handler(t->context.fault_handler);
    dispatch_signals(t);
    current_cpu()->state = cpu_user;
    check_stop_conditions(t);
    // XXX fixme
    //ftrace_thread_switch(old, t);    /* ftrace needs to know about the switch event */

    thread_lock(t);
    if (t->syscall_abandoned) {
        /* TODO: This will likely leak resources allocated by the abandoned
           syscall. Such leakage could be addressed by making use of
           per-syscall transient heaps. */
        assert(t->syscall);
        context_release_refcount(&t->syscall->context); /* in lieu of syscall_finish() */
        t->syscall_abandoned = false;
    }
    /* cover wake-before-sleep situations (e.g. sched yield, fs ops that don't go to disk, etc.) */
    assert(t->blocked_on == 0);
    t->syscall = 0;

    /* If we migrated to a new CPU, remain on its thread queue. */
    t->scheduling_queue = ci->thread_queue;    
    thread_unlock(t);

    context_frame f = t->context.frame;
    assert(f[FRAME_FULL]);
    thread_log(t, "run thread, cpu %d, frame %p, pc 0x%lx, sp 0x%lx, rv 0x%lx",
               current_cpu()->id, f, f[SYSCALL_FRAME_PC], f[SYSCALL_FRAME_SP], f[SYSCALL_FRAME_RETVAL1]);
    ci->frcount++;
    clear_fault_handler();
    context_switch(&t->context);
    thread_release(t);
    frame_return(thread_frame(t));
    halt("return from frame_return!\n");
}

void thread_sleep_interruptible(void)
{
    thread_log(current, "sleep interruptible (on \"%s\")", blockq_name(current->blocked_on));
    ftrace_thread_switch(current, 0);
    count_syscall_save(current);
    syscall_yield();
}

void thread_sleep_uninterruptible(thread t)
{
    assert(!t->blocked_on);
    t->blocked_on = INVALID_ADDRESS;
    thread_log(current, "sleep uninterruptible");
    ftrace_thread_switch(t, 0);
    count_syscall_save(t);
    thread_unlock(t);
    syscall_yield();
}

void thread_yield(void)
{
    thread_log(current, "yield %d, RIP=0x%lx", current->tid, thread_frame(current)[SYSCALL_FRAME_PC]);
    assert(!current->blocked_on);
    current->syscall = 0;
    set_syscall_return(current, 0);
    syscall_finish(false);
}

/* Schedule a thread for execution, disassociating the syscall context with
   the thread. Execution stays on the syscall context into runloop(), at which
   point pause and release are called and the context is placed on a free list. */
void thread_wakeup(thread t)
{
    thread_log(current, "%s: %ld->%ld blocked_on %s, RIP=0x%lx", __func__, current->tid, t->tid,
            t->blocked_on ? (t->blocked_on != INVALID_ADDRESS ? blockq_name(t->blocked_on) : "uninterruptible") :
            "(null)", thread_frame(t)[SYSCALL_FRAME_PC]);
    cpuinfo ci = current_cpu();
    context sc = get_current_context(ci);
    assert(is_syscall_context(sc));
    assert(t->blocked_on);
    t->blocked_on = 0;
    t->syscall = 0;
    context_release_refcount(sc);
    schedule_thread(t);
}

/* hacky callback for interrupt dispatch - should be scheduler interface */
void thread_reenqueue(thread t)
{
    schedule_thread(t);
}

boolean thread_attempt_interrupt(thread t)
{
    thread_log(current, "%s: tid %d", __func__, t->tid);
    blockq bq;
    boolean success = false;
    thread_lock(t);
    if (!thread_in_interruptible_sleep(t)) {
        thread_log(current, "   uninterruptible or already running");
        bq = 0;
    } else {
        bq = t->blocked_on;
        blockq_reserve(bq);
    }
    thread_unlock(t);

    /* flush pending blockq */
    if (bq) {
        thread_log(current, "   attempting to interrupt blocked thread %d", t->tid);
        if (blockq_wake_one_for_thread(bq, t, true))
            success = true;
        blockq_release(bq);
    }
    return success;
}

define_closure_function(1, 0, void, free_thread,
                        thread, t)
{
    thread t = bound(t);
    deallocate_bitmap(t->affinity);
    deallocate_notify_set(t->signalfds);
    /* XXX only free tids from non-leader threads. Leader threads will
     * need different handling */
    if (t->p->pid != t->tid)
        deallocate_u64((heap)get_unix_heaps()->processes, t->tid, 1);
    deallocate(heap_locked(get_kernel_heaps()), t, sizeof(struct thread));
    /* TODO: Intentionally leaking tracelog_attrs; no accounting for attrs lifetime... */
}

thread create_thread(process p, u64 tid)
{
    heap h = heap_locked((kernel_heaps)p->uh);

    thread t = allocate(h, sizeof(struct thread));
    if (t == INVALID_ADDRESS)
        goto fail;
    init_context(&t->context, CONTEXT_TYPE_THREAD);
    t->context.pause = thread_pause;
    t->context.resume = thread_resume;
    t->context.schedule_return = thread_schedule_return;
    t->context.pre_suspend = 0;
    init_closure(&t->thread_return, thread_return, t);

    t->thread_bq = allocate_blockq(h, "thread");
    if (t->thread_bq == INVALID_ADDRESS)
        goto fail_bq;

    t->signalfds = allocate_notify_set(h);
    if (t->signalfds == INVALID_ADDRESS)
        goto fail_sfds;

    t->p = p;
    t->syscall = 0;
    runtime_memcpy(&t->uh, p->uh, sizeof(*p->uh));
    init_refcount(&t->context.refcount, 1, init_closure(&t->free, free_thread, t));
    t->select_epoll = 0;
    runtime_memset((void *)&t->n, 0, sizeof(struct rbnode));
    t->clear_tid = 0;
    t->name[0] = '\0';

    init_thread_fault_handler(t);
    
    t->scheduling_queue = current_cpu()->thread_queue;
    context_frame f = thread_frame(t);
#ifdef __x86_64__
    f[FRAME_CS] = 0x2b & ~1; // CS 0x28 + CPL 3 but clear bit 0 to indicate syscall
    f[FRAME_SS] = USER_DATA_SELECTOR | 0x3 /* RPL */;
#endif
#ifdef __aarch64__
    f[FRAME_EL] = 0;
#endif
#ifdef __riscv
    f[FRAME_STATUS] = FS_INITIAL<<STATUS_BIT_FS;
#endif

    t->signal_stack = 0;
    t->signal_stack_length = 0;
    t->affinity = allocate_bitmap(h, h, total_processors);
    if (t->affinity == INVALID_ADDRESS)
        goto fail_affinity;
    bitmap_range_check_and_set(t->affinity, 0, total_processors, false, true);
    t->blocked_on = 0;
    t->syscall_complete = false;
    t->syscall_abandoned = false;
    blockq_thread_init(t);
    init_sigstate(&t->signals);
    t->signal_mask = 0;
    t->saved_signal_mask = -1ull;
    t->interrupting_syscall = false;
    t->utime = t->stime = 0;
    t->start_time = 0;
    t->last_syscall = -1;

    list_init(&t->l_faultwait);
    spin_lock_init(&t->lock);

    /* install gdb fault handler if gdb is inited */
    gdb_check_fault_handler(t);
    if (tid != INVALID_PHYSICAL)
        t->tid = tid;
    else
        t->tid = allocate_u64(p->uh->processes, 1);
    assert(t->tid != INVALID_PHYSICAL);
    spin_lock(&p->threads_lock);
    rbtree_insert_node(p->threads, &t->n);
    spin_unlock(&p->threads_lock);
#ifdef CONFIG_TRACELOG
    t->tracelog_attrs = allocate_tuple();
    if (t->tracelog_attrs == INVALID_ADDRESS) {
        deallocate_bitmap(t->affinity);
        goto fail_affinity;
    }
    set(t->tracelog_attrs, sym(tid), aprintf(h, "%d", t->tid));
#endif
    return t;
  fail_affinity:
    deallocate_notify_set(t->signalfds);
  fail_sfds:
    deallocate_blockq(t->thread_bq);
  fail_bq:
    destruct_context(&t->context);
    deallocate(h, t, sizeof(struct thread));
  fail:
    msg_err("%s: failed to allocate\n", __func__);
    return INVALID_ADDRESS;
}

NOTRACE 
void exit_thread(thread t)
{
    thread_log(current, "exit_thread");

    spin_lock(&t->p->threads_lock);
    rbtree_remove_by_key(t->p->threads, &t->n);
    spin_unlock(&t->p->threads_lock);

    /* dequeue signals for thread */
    sigstate_flush_queue(&t->signals);

    /* A thread can only be terminated by itself. */
    assert(t->blocked_on == 0);

    if (t->clear_tid) {
        *t->clear_tid = 0;
        futex_wake_one_by_uaddr(t->p, t->clear_tid); /* ignore errors */
    }

    if (t->select_epoll)
        epoll_finish(t->select_epoll);

    wake_robust_list(t->p, t->robust_list);
    t->robust_list = 0;

    blockq_flush(t->thread_bq);
    deallocate_blockq(t->thread_bq);
    t->thread_bq = INVALID_ADDRESS;
    thread_release(t);
}

closure_function(0, 1, boolean, tid_print_key,
                 rbnode, n)
{
    rprintf(" %d", struct_from_field(n, thread, n)->tid);
    return true;
}

closure_function(0, 2, int, thread_tid_compare,
                 rbnode, a, rbnode, b)
{
    thread ta = struct_from_field(a, thread, n);
    thread tb = struct_from_field(b, thread, n);
    return ta->tid == tb->tid ? 0 : (ta->tid < tb->tid ? -1 : 1);
}

closure_function(1, 1, boolean, vector_from_tree_handler,
                 vector, v,
                 rbnode, n)
{
    thread t = struct_from_field(n, thread, n);
    vector_push(bound(v), t);
    return true;
}

void threads_to_vector(process p, vector v)
{
    rbtree_traverse(p->threads, RB_INORDER, stack_closure(vector_from_tree_handler, v));
}

void init_threads(process p)
{
    heap h = heap_locked((kernel_heaps)p->uh);
    p->threads = allocate_rbtree(h, closure(h, thread_tid_compare), closure(h, tid_print_key));
    spin_lock_init(&p->threads_lock);
    init_futices(p);
}
