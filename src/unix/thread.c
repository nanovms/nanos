#include <unix_internal.h>
#include <ftrace.h>
#include <gdb.h>

thread dummy_thread;

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
        current->default_frame[FRAME_GSBASE] = addr;
        break;
    case ARCH_SET_FS:
        current->default_frame[FRAME_FSBASE] = addr;
        return 0;
    case ARCH_GET_FS:
	*(u64 *) addr = current->default_frame[FRAME_FSBASE];
        break;
    case ARCH_GET_GS:
	*(u64 *) addr = current->default_frame[FRAME_GSBASE];
        break;
    default:
        return set_syscall_error(current, EINVAL);
    }
    return 0;
}
#endif

#ifdef __x86_64__
sysreturn clone(unsigned long flags, void *child_stack, int *ptid, int *ctid, unsigned long newtls)
#elif defined(__aarch64__)
sysreturn clone(unsigned long flags, void *child_stack, int *ptid, unsigned long newtls, int *ctid)
#endif
{
    thread_log(current, "clone: flags %lx, child_stack %p, ptid %p, ctid %p, newtls %lx",
        flags, child_stack, ptid, ctid, newtls);

    if (!child_stack) {   /* this is actually a fork() */
        thread_log(current, "attempted to fork by passing null child stack, aborting.");
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

    thread t = create_thread(current->p);
    /* clone frame processor state */
    clone_frame_pstate(t->default_frame, current->default_frame);
    thread_clone_sigmask(t, current);

    /* clone behaves like fork at the syscall level, returning 0 to the child */
    set_syscall_return(t, 0);
    t->default_frame[SYSCALL_FRAME_SP] = u64_from_pointer(child_stack);
    if (flags & CLONE_SETTLS)
        set_tls(t->default_frame, newtls);
    if (flags & CLONE_PARENT_SETTID)
        *ptid = t->tid;
    if (flags & CLONE_CHILD_CLEARTID)
        t->clear_tid = ctid;
    t->blocked_on = 0;
    t->syscall = -1;
    schedule_frame(t->default_frame);
    return t->tid;
}


void register_thread_syscalls(struct syscall *map)
{
    register_syscall(map, futex, futex);
    register_syscall(map, set_robust_list, set_robust_list);
    register_syscall(map, get_robust_list, get_robust_list);
    register_syscall(map, clone, clone);
#ifdef __x86_64__
    register_syscall(map, arch_prctl, arch_prctl);
#endif
    register_syscall(map, set_tid_address, set_tid_address);
    register_syscall(map, gettid, gettid);
}

void thread_log_internal(thread t, const char *desc, ...)
{
    if (syscall_notrace(t->p, t->syscall))
        return;
    vlist ap;
    vstart (ap, desc);
    buffer b = little_stack_buffer(512);
    bprintf(b, "%n%d ", (int) ((MAX(MIN(t->tid, 20), 1) - 1) * 4), t->tid);
    if (t->name[0] != '\0')
        bprintf(b, "[%s] ", t->name);
    buffer f = alloca_wrap_buffer(desc, runtime_strlen(desc));
    vbprintf(b, f, &ap);
    push_u8(b, '\n');
    buffer_print(b);
}

static inline void check_stop_conditions(thread t)
{
    char *cause;
    u64 pending = sigstate_get_pending(&t->signals);
    boolean in_sighandler = thread_frame(t) == t->sighandler_frame;
    /* rather abrupt to just halt...this should go do dump or recovery */
    if (pending & mask_from_sig(SIGSEGV)) {
        void * handler = sigaction_from_sig(t, SIGSEGV)->sa_handler;

        /* Terminate on uncaught SIGSEGV, or if triggered by signal handler. */
        if (in_sighandler || (handler == SIG_IGN || handler == SIG_DFL)) {
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
    print_frame(thread_frame(t));
    print_stack(thread_frame(t));
    halt("Terminating.\n");
}

static inline void run_thread_frame(thread t)
{
    check_stop_conditions(t);
    thread old = current;
    thread_enter_user(t);
    ftrace_thread_switch(old, t);    /* ftrace needs to know about the switch event */

    /* cover wake-before-sleep situations (e.g. sched yield, fs ops that don't go to disk, etc.) */
    thread_lock(t);
    assert(t->blocked_on == 0);
    t->syscall = -1;
    thread_unlock(t);

    if (do_syscall_stats && t->last_syscall == SYS_sched_yield)
        count_syscall(t, 0);
    context f = thread_frame(t);
    cpuinfo ci = current_cpu();
    thread_frame_restore_tls(f);
    thread_frame_restore_fpsimd(f);
    frame_enable_interrupts(f);
    f[FRAME_QUEUE] = u64_from_pointer(ci->thread_queue);

    thread_log(t, "run %s, cpu %d, frame %p, pc 0x%lx, sp 0x%lx, rv 0x%lx",
               f == t->sighandler_frame ? "sig handler" : "thread",
               current_cpu()->id, f, f[SYSCALL_FRAME_PC], f[SYSCALL_FRAME_SP], f[SYSCALL_FRAME_RETVAL1]);
    ci->frcount++;
    frame_return(f);
    halt("return from frame_return!\n");
}

define_closure_function(1, 0, void, run_thread,
                        thread, t)
{
    thread t = bound(t);
    if (t->p->trap)
        runloop();
    dispatch_signals(t);
    current_cpu()->state = cpu_user;
    run_thread_frame(t);
}

define_closure_function(1, 0, void, pause_thread,
                        thread, t)
{
    thread_pause(bound(t));
}

define_closure_function(1, 0, void, run_sighandler,
                        thread, t)
{
    current_cpu()->state = cpu_user;
    run_thread_frame(bound(t));
}

static void setup_thread_frame(heap h, context frame, thread t)
{
    frame[FRAME_FAULT_HANDLER] = u64_from_pointer(&t->fault_handler);
    frame[FRAME_QUEUE] = u64_from_pointer(current_cpu()->thread_queue);
#ifdef __x86_64__
    frame[FRAME_IS_SYSCALL] = 1;
    frame[FRAME_CS] = 0x2b; // where is this defined?
#endif
#ifdef __aarch64__
    frame[FRAME_EL] = 0;
#endif
    frame[FRAME_THREAD] = u64_from_pointer(t);
}

void thread_sleep_interruptible(void)
{
    disable_interrupts();
    thread_log(current, "sleep interruptible (on \"%s\")", blockq_name(current->blocked_on));
    ftrace_thread_switch(current, 0);
    count_syscall_save(current);
    kern_yield();
}

void thread_sleep_uninterruptible(thread t)
{
    disable_interrupts();
    assert(!t->blocked_on);
    t->blocked_on = INVALID_ADDRESS;
    thread_log(current, "sleep uninterruptible");
    ftrace_thread_switch(current, 0);
    count_syscall_save(current);
    thread_unlock();
    kern_yield();
}

void thread_yield(void)
{
    disable_interrupts();
    thread_log(current, "yield %d, RIP=0x%lx", current->tid, thread_frame(current)[SYSCALL_FRAME_PC]);
    assert(!current->blocked_on);
    current->syscall = -1;
    set_syscall_return(current, 0);
    schedule_frame(thread_frame(current));
    kern_yield();
}

void thread_wakeup(thread t)
{
    thread_log(current, "%s: %ld->%ld blocked_on %s, RIP=0x%lx", __func__, current->tid, t->tid,
            t->blocked_on ? (t->blocked_on != INVALID_ADDRESS ? blockq_name(t->blocked_on) : "uninterruptible") :
            "(null)", thread_frame(t)[SYSCALL_FRAME_PC]);
    assert(t->blocked_on);
    t->blocked_on = 0;
    t->syscall = -1;
    schedule_frame(thread_frame(t));
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
    deallocate_bitmap(bound(t)->affinity);
    deallocate_notify_set(bound(t)->signalfds);
    deallocate(heap_general(get_kernel_heaps()), bound(t), sizeof(struct thread));
}

define_closure_function(1, 0, void, resume_syscall, thread, t)
{
    thread_resume(bound(t));
    syscall_debug(thread_frame(bound(t)));
}

thread create_thread(process p)
{
    static int tidcount = 0;
    heap h = heap_general((kernel_heaps)p->uh);

    thread t = allocate(h, sizeof(struct thread));
    if (t == INVALID_ADDRESS)
        goto fail;

    t->thread_bq = allocate_blockq(h, "thread");
    if (t->thread_bq == INVALID_ADDRESS)
        goto fail_bq;

    t->signalfds = allocate_notify_set(h);
    if (t->signalfds == INVALID_ADDRESS)
        goto fail_sfds;

    t->p = p;
    t->syscall = -1;
    runtime_memcpy(&t->uh, p->uh, sizeof(*p->uh));
    init_refcount(&t->refcount, 1, init_closure(&t->free, free_thread, t));
    t->select_epoll = 0;
    runtime_memset((void *)&t->n, 0, sizeof(struct rbnode));
    t->clear_tid = 0;
    t->name[0] = '\0';

    t->default_frame = allocate_frame(h);
    init_thread_fault_handler(t);
    setup_thread_frame(h, t->default_frame, t);
    t->default_frame[FRAME_RUN] = u64_from_pointer(init_closure(&t->run_thread, run_thread, t));
    set_thread_frame(t, t->default_frame);
    
    t->sighandler_frame = allocate_frame(h);
    t->signal_stack = 0;
    setup_thread_frame(h, t->sighandler_frame, t);
    t->sighandler_frame[FRAME_RUN] = u64_from_pointer(init_closure(&t->run_sighandler, run_sighandler, t));

    t->thrd.pause = init_closure(&t->pause_thread, pause_thread, t);
    t->affinity = allocate_bitmap(h, h, total_processors);
    if (t->affinity == INVALID_ADDRESS)
        goto fail_affinity;
    bitmap_range_check_and_set(t->affinity, 0, total_processors, false, true);
    t->blocked_on = 0;
    blockq_thread_init(t);
    init_sigstate(&t->signals);
    t->dispatch_sigstate = 0;
    t->active_signo = 0;
    init_closure(&t->deferred_syscall, resume_syscall, t);
    t->sysctx = false;
    t->utime = t->stime = 0;
    t->start_time = now(CLOCK_ID_MONOTONIC_RAW);
    t->last_syscall = -1;

    list_init(&t->l_faultwait);
    spin_lock_init(&t->lock);

    /* install gdb fault handler if gdb is inited */
    gdb_check_fault_handler(t);
    // XXX sigframe
    spin_lock(&p->threads_lock);
    do {
        if (tidcount < 0)
            tidcount = 1;
        t->tid = tidcount++;
    } while (rbtree_lookup(p->threads, &t->n) != INVALID_ADDRESS);
    rbtree_insert_node(p->threads, &t->n);
    spin_unlock(&p->threads_lock);
    return t;
  fail_affinity:
    deallocate_frame(t->sighandler_frame);
    deallocate_frame(t->default_frame);
    deallocate_notify_set(t->signalfds);
  fail_sfds:
    deallocate_blockq(t->thread_bq);
  fail_bq:
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

    /* We might be exiting from the signal handler while dispatching a
       signal on behalf of the process sigstate, so reset masks as if
       we're returning from the signal handler. */
    sigstate_thread_restore(t);

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

    t->default_frame[FRAME_RUN] = INVALID_PHYSICAL;
    t->default_frame[FRAME_QUEUE] = INVALID_PHYSICAL;
    t->sighandler_frame[FRAME_RUN] = INVALID_PHYSICAL;
    t->sighandler_frame[FRAME_QUEUE] = INVALID_PHYSICAL;
    t->default_frame[FRAME_FAULT_HANDLER] = INVALID_PHYSICAL;
    deallocate_frame(t->default_frame);
    deallocate_frame(t->sighandler_frame);

    /* replace references to thread with placeholder */
    set_current_thread((nanos_thread)dummy_thread);
    set_running_frame(current_cpu(), dummy_thread->default_frame);
    refcount_release(&t->refcount);
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
    heap h = heap_general((kernel_heaps)p->uh);
    p->threads = allocate_rbtree(h, closure(h, thread_tid_compare), closure(h, tid_print_key));
    spin_lock_init(&p->threads_lock);
    init_futices(p);
}
