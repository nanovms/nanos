#include <unix_internal.h>
#include <ftrace.h>

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

sysreturn clone(unsigned long flags, void *child_stack, int *ptid, int *ctid, unsigned long newtls)
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
    /* clone thread context up to FRAME_VECTOR */
    runtime_memcpy(t->default_frame, current->default_frame, sizeof(u64) * FRAME_ERROR_CODE);
    runtime_memcpy(t->default_frame + FRAME_EXTENDED_SAVE, current->default_frame + FRAME_EXTENDED_SAVE,
                   xsave_frame_size());
    thread_clone_sigmask(t, current);

    /* clone behaves like fork at the syscall level, returning 0 to the child */
    set_syscall_return(t, 0);
    t->default_frame[FRAME_RSP] = u64_from_pointer(child_stack);
    t->default_frame[FRAME_FSBASE] = newtls;
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

static inline void check_stop_conditions(thread t)
{
    char *cause;
    u64 pending = sigstate_get_pending(&t->signals);
    boolean in_sighandler = thread_frame(t) == t->sighandler_frame;
    /* rather abrupt to just halt...this should go do dump or recovery */
    if (pending & mask_from_sig(SIGSEGV)) {
        void * handler = sigaction_from_sig(SIGSEGV)->sa_handler;

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
    kern_lock(); // xx - make thread entry a separate exclusion region for performance
    thread old = current;
    current_cpu()->current_thread = t;
    ftrace_thread_switch(old, current);    /* ftrace needs to know about the switch event */
    thread_enter_user(old, t);

    /* cover wake-before-sleep situations (e.g. sched yield, fs ops that don't go to disk, etc.) */
    t->blocked_on = 0;
    t->syscall = -1;

    context f = thread_frame(t);
    f[FRAME_FLAGS] |= U64_FROM_BIT(FLAG_INTERRUPT);

    thread_log(t, "run %s, cpu %d, frame %p, rip 0x%lx, rsp 0x%lx, rdi 0x%lx, rax 0x%lx, rflags 0x%lx, cs 0x%lx, %s",
               f == t->sighandler_frame ? "sig handler" : "thread", current_cpu()->id, f, f[FRAME_RIP], f[FRAME_RSP],
               f[FRAME_RDI], f[FRAME_RAX], f[FRAME_FLAGS], f[FRAME_CS], f[FRAME_IS_SYSCALL] ? "sysret" : "iret");
    if (current_cpu()->have_kernel_lock)
        kern_unlock();
    current_cpu()->frcount++;
    frame_return(f);
}

define_closure_function(1, 0, void, run_thread,
                        thread, t)
{
    thread t = bound(t);
    dispatch_signals(t);
    run_thread_frame(t);
}

define_closure_function(1, 0, void, run_sighandler,
                        thread, t)
{
    run_thread_frame(bound(t));
}

static void setup_thread_frame(heap h, context frame, thread t)
{
    frame[FRAME_FAULT_HANDLER] = u64_from_pointer(&t->fault_handler);
    frame[FRAME_QUEUE] = u64_from_pointer(thread_queue);
    frame[FRAME_IS_SYSCALL] = 1;
    frame[FRAME_CS] = 0x2b; // where is this defined?
    frame[FRAME_THREAD] = u64_from_pointer(t);
}

void thread_sleep_interruptible(void)
{
    disable_interrupts();
    assert(current->blocked_on);
    thread_log(current, "sleep interruptible (on \"%s\")", blockq_name(current->blocked_on));
    runloop();
}

void thread_sleep_uninterruptible(void)
{
    disable_interrupts();
    assert(!current->blocked_on);
    current->blocked_on = INVALID_ADDRESS;
    thread_log(current, "sleep uninterruptible");
    runloop();
}

void thread_yield(void)
{
    disable_interrupts();
    thread_log(current, "yield %d, RIP=0x%lx", current->tid, thread_frame(current)[FRAME_RIP]);
    assert(!current->blocked_on);
    current->syscall = -1;
    set_syscall_return(current, 0);
    schedule_frame(thread_frame(current));
    runloop();
}

void thread_wakeup(thread t)
{
    thread_log(current, "%s: %ld->%ld blocked_on %s, RIP=0x%lx", __func__, current->tid, t->tid,
               t->blocked_on ? (t->blocked_on != INVALID_ADDRESS ? blockq_name(t->blocked_on) : "uninterruptible") :
               "(null)", thread_frame(t)[FRAME_RIP]);
    assert(t->blocked_on);
    t->blocked_on = 0;
    t->syscall = -1;
    schedule_frame(thread_frame(t));
}

boolean thread_attempt_interrupt(thread t)
{
    thread_log(current, "%s: tid %d", __func__, t->tid);
    if (!thread_in_interruptible_sleep(t)) {
        thread_log(current, "uninterruptible or already running");
        return false;
    }

    /* flush pending blockq */
    thread_log(current, "... interrupting blocked thread %d", t->tid);
    assert(blockq_flush_thread(t->blocked_on, t));
    assert(thread_is_runnable(t));
    return true;
}

define_closure_function(1, 0, void, free_thread,
                        thread, t)
{
    deallocate(heap_general(get_kernel_heaps()), bound(t), sizeof(struct thread));
}

define_closure_function(1, 0, void, resume_syscall, thread, t)
{
    current_cpu()->current_thread = bound(t);
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
    t->uh = *p->uh;
    init_refcount(&t->refcount, 1, init_closure(&t->free, free_thread, t));
    t->select_epoll = 0;
    t->tid = tidcount++;
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

    // xxx another max 64
    t->affinity.mask[0] = MASK(total_processors);
    t->blocked_on = 0;
    t->file_op_is_complete = false;
    init_sigstate(&t->signals);
    t->dispatch_sigstate = 0;
    t->active_signo = 0;
    init_closure(&t->deferred_syscall, resume_syscall, t);
    if (ftrace_thread_init(t)) {
        msg_err("failed to init ftrace state for thread\n");
        deallocate_blockq(t->thread_bq);
        deallocate(h, t, sizeof(struct thread));
        return INVALID_ADDRESS;
    }
    t->sysctx = false;
    t->utime = t->stime = 0;
    t->start_time = now(CLOCK_ID_MONOTONIC);

    // XXX sigframe
    vector_set(p->threads, t->tid, t);
    return t;
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

    assert(vector_length(t->p->threads) > t->tid);
    vector_set(t->p->threads, t->tid, 0);

    /* We might be exiting from the signal handler while dispatching a
       signal on behalf of the process sigstate, so reset masks as if
       we're returning from the signal handler. */
    sigstate_thread_restore(t);

    /* dequeue signals for thread */
    sigstate_flush_queue(&t->signals);

    /* We don't yet support forcible removal while in an uninterruptible wait. */
    assert(t->blocked_on != INVALID_ADDRESS);

    /* Kill received during interruptible wait. */
    if (t->blocked_on)
        blockq_flush_thread(t->blocked_on, t);

    if (t->clear_tid) {
        *t->clear_tid = 0;
        futex_wake_one_by_uaddr(t->p, t->clear_tid); /* ignore errors */
    }

    if (t->select_epoll)
        epoll_finish(t->select_epoll);

    /* XXX futex robust list needs implementing - wake up robust futexes here */

    blockq_flush(t->thread_bq);
    deallocate_blockq(t->thread_bq);
    t->thread_bq = INVALID_ADDRESS;

    /* consider having a thread heap that we can just discard ?*/
    if (t->signal_stack) {
        deallocate((heap)t->p->virtual_page, t->signal_stack, SIGNAL_STACK_SIZE);
    }
    t->default_frame[FRAME_RUN] = INVALID_PHYSICAL;
    t->default_frame[FRAME_QUEUE] = INVALID_PHYSICAL;
    t->sighandler_frame[FRAME_RUN] = INVALID_PHYSICAL;
    t->sighandler_frame[FRAME_QUEUE] = INVALID_PHYSICAL;
    t->default_frame[FRAME_FAULT_HANDLER] = INVALID_PHYSICAL;
    deallocate_frame(t->default_frame);
    deallocate_frame(t->sighandler_frame);

    ftrace_thread_deinit(t, dummy_thread);

    /* replace references to thread with placeholder */
    current_cpu()->current_thread = dummy_thread;
    set_running_frame(dummy_thread->default_frame);
    refcount_release(&t->refcount);
}

void init_threads(process p)
{
    heap h = heap_general((kernel_heaps)p->uh);
    p->threads = allocate_vector(h, 5);
    init_futices(p);
}
