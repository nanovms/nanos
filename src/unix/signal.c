#include <unix_internal.h>
#include <ftrace.h>

//#define SIGNAL_DEBUG
#ifdef SIGNAL_DEBUG
#define sig_debug(x, ...) do {log_printf("  SIG", "%s: " x, __func__, ##__VA_ARGS__);} while(0)
#else
#define sig_debug(x, ...)
#endif

/* TODO:

   blocking calls within sig handler
   core dump
 */

typedef struct queued_signal {
    struct siginfo si;
    struct list l;
} *queued_signal;

static inline void init_siginfo(struct siginfo *si, int sig, s32 code)
{
    zero(si, sizeof(struct siginfo));
    si->si_signo = sig;
    si->si_errno = 0;
    si->si_code = code;
}

static inline int select_signal_from_masked(u64 masked)
{
    /* give priority to KILL and STOP, but otherwise the lowest signal number is served first */
    if (masked & mask_from_sig(SIGKILL))
        return SIGKILL;
    if (masked & mask_from_sig(SIGSTOP))
        return SIGSTOP;
    return lsb(masked) + 1;
}

static inline u64 get_signal_mask(thread t)
{
    return t->signal_mask;
}

static inline void set_signal_mask(thread t, u64 mask)
{
    t->signal_mask = normalize_signal_mask(mask);
}

static inline void block_signals(thread t, u64 mask)
{
    t->signal_mask |= normalize_signal_mask(mask);
}

static inline void unblock_signals(thread t, u64 mask)
{
    t->signal_mask &= ~mask;
}

static inline u64 sigstate_get_ignored(sigstate ss)
{
    return ss->ignored;
}

static inline u64 sigstate_set_ignored(sigstate ss, u64 mask)
{
    return ss->ignored = normalize_signal_mask(mask);
}

static inline u64 sigstate_get_interest(sigstate ss)
{
    return ss->interest;
}

static inline void sigstate_set_interest(sigstate ss, u64 mask)
{
    ss->interest = mask;
}

static inline u64 get_all_pending_signals(thread t)
{
    return sigstate_get_pending(&t->signals) | sigstate_get_pending(&t->p->signals);
}

static inline u64 get_effective_sigmask(thread t)
{
    return get_signal_mask(t) &
        ~(sigstate_get_interest(&t->signals) | sigstate_get_interest(&t->p->signals));
}

static inline u64 get_effective_signals(thread t)
{
    return get_all_pending_signals(t) & ~get_effective_sigmask(t);
}

static inline void sigstate_set_pending(sigstate ss, int sig)
{
    ss->pending |= mask_from_sig(sig);
}

static inline list sigstate_get_sighead(sigstate ss, int signum)
{
    assert(signum > 0 && signum <= NSIG);
    return &ss->heads[signum - 1];
}

void thread_clone_sigmask(thread dest, thread src)
{
    set_signal_mask(dest, get_signal_mask(src));
}

static queued_signal sigstate_dequeue_signal(sigstate ss, int signum)
{
    /* dequeue siginfo */
    list head = sigstate_get_sighead(ss, signum);
    list l = list_get_next(head);
    assert(l);
    queued_signal qs = struct_from_list(l, queued_signal, l);
    list_delete(l);
#ifdef SIGNAL_DEBUG
    int count = 0;
    list_foreach(head, l)
        count++;
    sig_debug("dequeued sig #%d, remain %d\n", signum, count);
#endif
    if (list_empty(head))
        ss->pending &= ~mask_from_sig(signum);
    return qs;
}

/* select and dequeue a pending signal not masked by sigmask */
static queued_signal dequeue_signal(thread t, u64 sigmask)
{
    int signum;
    sigstate ss;
    queued_signal qs;
    while (true) {
        u64 masked = get_all_pending_signals(t) & ~sigmask;
        sig_debug("tid %d, sigmask 0x%lx, masked 0x%lx\n", t->tid, sigmask, masked);
        if (masked == 0)
            return INVALID_ADDRESS;

        signum = select_signal_from_masked(masked);
        u64 mask = mask_from_sig(signum);
        ss = (sigstate_get_pending(&t->signals) & mask) ? &t->signals : &t->p->signals;
        spin_lock(&ss->ss_lock);
        qs = sigstate_dequeue_signal(ss, signum);
        spin_unlock(&ss->ss_lock);
        if (qs != INVALID_ADDRESS)
            break;
    }
    sig_debug("-> selected sig %d, dequeued from %s\n",
              signum, ss == &t->signals ? "thread" : "process");
    return qs;
}

static inline void free_queued_signal(queued_signal qs)
{
    deallocate(heap_locked(get_kernel_heaps()), qs, sizeof(struct queued_signal));
}

void sigstate_flush_queue(sigstate ss)
{
    sig_debug("sigstate %p\n", ss);
    spin_lock(&ss->ss_lock);
    for (int signum = 1; signum <= NSIG; signum++) {
        list_foreach(sigstate_get_sighead(ss, signum), l) {
            free_queued_signal(struct_from_list(l, queued_signal, l));
        }
    }
    spin_unlock(&ss->ss_lock);
}

void init_sigstate(sigstate ss)
{
    ss->pending = 0;
    ss->ignored = mask_from_sig(SIGCHLD) | mask_from_sig(SIGURG) | mask_from_sig(SIGWINCH);
    ss->interest = 0;

    spin_lock_init(&ss->ss_lock);
    for(int i = 0; i < NSIG; i++)
        list_init(&ss->heads[i]);
}

static inline boolean sig_is_ignored(process p, int sig)
{
    return (mask_from_sig(sig) & sigstate_get_ignored(&p->signals)) != 0;
}

static void deliver_signal(sigstate ss, struct siginfo *info)
{
    heap h = heap_locked(get_kernel_heaps());
    int sig = info->si_signo;

    /* Special handling for pending signals */
    spin_lock(&ss->ss_lock);    
    if (sigstate_is_pending(ss, sig)) {
        /* If this is a timer event, attempt to find a queued info for
           this timer and update the info (overrun) instead of
           queueing another entry.

           I'm kind of assuming that both 1) this won't happen at any
           high rate in real-world use, and 2) the depth of queued
           infos for a given rt signal would ever practically be more
           than one (or a few if a timer is mixed with other
           sources). But I could be wrong. If so, we could change over
           to registering a "siginfo update" closure which will update
           the overrun count after dequeueing the signal (just before
           entering the handler or other dispatch method). This would
           obviate any need to search for and update a queued info.
        */
        if (info->si_code == SI_TIMER) {
            list_foreach(sigstate_get_sighead(ss, sig), l) {
                queued_signal qs = struct_from_list(l, queued_signal, l);
                if (qs->si.si_code == SI_TIMER &&
                    qs->si.sifields.timer.tid == info->sifields.timer.tid) {
                    u64 overruns = (u64)qs->si.sifields.timer.overrun +
                        info->sifields.timer.overrun;
                    qs->si.sifields.timer.overrun = MIN((u64)S32_MAX, overruns);
                    sig_debug("timer update id %d, overrun %d\n",
                              qs->si.sifields.timer.tid,
                              qs->si.sifields.timer.overrun);
                    spin_unlock(&ss->ss_lock);
                    return;
                }
            }
        }

        if (sig < RT_SIG_START) {
            spin_unlock(&ss->ss_lock);
            /* Not queueable and no info update; ignore */
            sig_debug("already posted; ignore\n");
            return;
        }
    }

    queued_signal qs = allocate(h, sizeof(struct queued_signal));
    assert(qs != INVALID_ADDRESS);
    runtime_memcpy(&qs->si, info, sizeof(struct siginfo));
    sigstate_set_pending(ss, sig);
    list_insert_before(sigstate_get_sighead(ss, info->si_signo), &qs->l);
    spin_unlock(&ss->ss_lock);
    sig_debug("queued_signal %p, signo %d, errno %d, code %d\n",
              qs, qs->si.si_signo, qs->si.si_errno, qs->si.si_code);
    sig_debug("prev %p, next %p\n", qs->l.prev, qs->l.next);
    sig_debug("next prev %p, next %p\n", qs->l.next->prev, qs->l.next->next);
}

static inline void signalfd_dispatch(thread t, u64 pending)
{
    notify_dispatch_for_thread(t->signalfds, pending, t);
}

void deliver_pending_to_thread(thread t)
{
    u64 pending_masked = get_effective_signals(t);
    sig_debug("... effective signals 0x%lx\n", pending_masked);
    if (pending_masked == 0)
        return;

    /* First attempt to wake via signalfd notify, then attempt to interrupt a
       syscall.

       TODO: Note that spurious interruptions are possible here as a thread
       that is awoken on a signalfd read or poll wait could begin running on
       another processor and subsequently go into another blocking syscall, at
       which point the attempt interrupt below might target a syscall after
       the signal has already been delivered. A tight race, but technically
       possible.

       This could be ameliorated through the use of a gating callback passed
       to thread_attempt_interrupt() which can double-check the pending
       signals for the thread. This might require transfer from process set to
       thread set before this point, otherwise the set of pending signals
       could change before run_thread occurs... */

    signalfd_dispatch(t, pending_masked);
    thread_attempt_interrupt(t);
}

void deliver_signal_to_thread(thread t, struct siginfo *info)
{
    int sig = info->si_signo;
    sig_debug("tid %d, sig %d\n", t->tid, sig);
    if ((sig != SIGSEGV && sig != SIGKILL && sig != SIGSTOP && sig != SIGFPE) &&
        sig_is_ignored(t->p, sig)) {
        sig_debug("signal ignored; no queue\n");
        return;
    }

    /* queue to thread for delivery */
    deliver_signal(&t->signals, info);
    sig_debug("... pending now 0x%lx\n", sigstate_get_pending(&t->signals));

    deliver_pending_to_thread(t);
}

closure_function(2, 1, boolean, deliver_signal_handler,
                 thread *, can_wake, u64, sigword,
                 rbnode, n)
{
    u64 sigword = bound(sigword);
    thread *can_wake = bound(can_wake);
    thread t = struct_from_field(n, thread, n);
    if (thread_is_runnable(t)) {
        /* Note that we're only considering unmasked signals
           (handlers) here, nothing in the interest masks. The
           thread is runnable, so it can't be blocked on
           rt_sigtimedwait or a signalfd (poll wait or blocking
           read). */
        if ((sigword & get_signal_mask(t)) == 0) {
            /* thread scheduled to run or running; no explicit wakeup */
            sig_debug("thread %d running and sig unmasked; return\n",
                      t->tid);
            if (*can_wake) {
                thread_release(*can_wake);
                *can_wake = 0;
            }
            return false;
        }
    } else if (thread_in_interruptible_sleep(t) &&
                (sigword & get_effective_sigmask(t)) == 0) {
        /* Note that we check only for this signal, not
           all pending signals as with thread delivery.
           That is because our task is to wake up a thread
           on behalf of this signal delivery, not just
           wake up a thread that has any pending signals. */
        thread_reserve(t);
        *can_wake = t;
    }
    return true;
}

void deliver_signal_to_process(process p, struct siginfo *info)
{
    int sig = info->si_signo;
    u64 sigword = mask_from_sig(sig);
    sig_debug("pid %d, sig %d\n", p->pid, sig);
    if (sig_is_ignored(p, sig)) {
        sig_debug("signal ignored; no queue\n");
        return;
    }

    /* queue to process for delivery */
    deliver_signal(&p->signals, info);
    sig_debug("... pending now 0x%lx\n", sigstate_get_pending(&p->signals));

    /* Search for a runnable thread or one that can be woken up */
    thread can_wake = 0;
    spin_lock(&p->threads_lock);
    rbtree_traverse(p->threads, RB_INORDER, stack_closure(deliver_signal_handler, &can_wake, sigword));
    spin_unlock(&p->threads_lock);

    /* There's a chance a different thread could handle the pending process
       signal first, so this could cause a spurious wakeup (EINTR) ... care?

       TODO: As explained in deliver_pending_to_thread(), we may want to
       change to dequeueing the signal from the process and delivering it
       straight to the thread. */
    if (can_wake) {
        deliver_pending_to_thread(can_wake);
        thread_release(can_wake);
    }
}

sysreturn rt_sigpending(u64 *set, u64 sigsetsize)
{
    sig_debug("set %p\n", set);

    if (sigsetsize != (NSIG / 8))
        return -EINVAL;

    if (!validate_user_memory(set, sigsetsize, true))
        return -EFAULT;

    u64 pending = get_all_pending_signals(current);
    *set = pending;
    sig_debug("= 0x%lx\n", pending);
    return 0;
}

static void check_syscall_restart(thread t, sigaction sa)
{
    sysreturn rv = get_syscall_return(t);
    if (rv == -ERESTARTSYS) {
        if (sa->sa_flags & SA_RESTART) {
            sig_debug("restarting syscall\n");
            syscall_restart_arch_fixup(thread_frame(t));
        } else {
            sig_debug("interrupted syscall\n");
            syscall_return(t, -EINTR);
        }
    }
}

sysreturn rt_sigreturn(void)
{
    struct rt_sigframe *frame;
    thread t = current;

    frame = get_rt_sigframe(t);
    sig_debug("rt_sigreturn: frame:0x%lx\n", (unsigned long)frame);

    /* restore saved context and signal mask */
    restore_ucontext(&(frame->uc), t);

    /* ftrace needs to know that this call stack does not return */
    ftrace_thread_noreturn(t);
    count_syscall_noreturn(t);

    schedule_frame(thread_frame(t));
    kern_unlock();
    runloop();
}

sysreturn rt_sigaction(int signum,
                       const struct sigaction *act,
                       struct sigaction *oldact,
                       u64 sigsetsize)
{
    sig_debug("signum %d, act %p, oldact %p, sigsetsize %ld\n", signum, act, oldact, sigsetsize);

    if (signum < 1 || signum > NSIG)
        return -EINVAL;

    if (sigsetsize != (NSIG / 8))
        return -EINVAL;

    thread t = current;
    sigaction sa = sigaction_from_sig(t, signum);

    if (oldact) {
        if (validate_user_memory(oldact, sizeof(struct sigaction), true)) {
            process_lock(t->p);
            runtime_memcpy(oldact, sa, sizeof(struct sigaction));
            process_unlock(t->p);
        } else
            return -EFAULT;
    }

    if (!act)
        return 0;

    if (!validate_user_memory(act, sizeof(struct sigaction), false))
        return -EFAULT;

    if (signum == SIGKILL || signum == SIGSTOP)
        return -EINVAL;

    /* XXX we should sanitize values ... */
    if (act->sa_flags & SA_NOCLDSTOP)
        msg_warn("Warning: SA_NOCLDSTOP unsupported.\n");

    if (act->sa_flags & SA_NOCLDWAIT)
        msg_warn("Warning: SA_NOCLDWAIT unsupported.\n");

    if (act->sa_flags & SA_RESETHAND)
        msg_warn("Warning: SA_RESETHAND unsupported.\n");

#ifdef __x86_64__
    /* libc should always set this on x64 ... */
    if (!(act->sa_flags & SA_RESTORER)) {
        msg_err("sigaction without SA_RESTORER not supported.\n");
        return -EINVAL;
    }
#endif

    /* update ignored mask */
    sigstate ss = &current->p->signals;
    u64 sigword = mask_from_sig(signum);
    sigstate_set_ignored(ss, act->sa_handler == SIG_IGN ? sigstate_get_ignored(ss) | sigword :
                         sigstate_get_ignored(ss) & ~sigword);

    sig_debug("installing sigaction: handler %p, sa_mask 0x%lx, sa_flags 0x%lx\n",
              act->sa_handler, act->sa_mask.sig[0], act->sa_flags);
    process_lock(t->p);
    runtime_memcpy(sa, act, sizeof(struct sigaction));
    process_unlock(t->p);
    return 0;
}

sysreturn rt_sigprocmask(int how, const u64 *set, u64 *oldset, u64 sigsetsize)
{
    if (sigsetsize != (NSIG / 8))
        return -EINVAL;

    if (oldset) {
        if (validate_user_memory(oldset, sigsetsize, true))
            *oldset = get_signal_mask(current);
        else
            return -EFAULT;
    }

    if (set) {
        if (!validate_user_memory(set, sigsetsize, false))
            return -EFAULT;
        switch (how) {
        case SIG_BLOCK:
            block_signals(current, *set);
            break;
        case SIG_UNBLOCK:
            unblock_signals(current, *set);
            break;
        case SIG_SETMASK:
            set_signal_mask(current, *set);
            break;
        default:
            return -EINVAL;
        }
    }
    return 0;
}

closure_function(1, 1, sysreturn, rt_sigsuspend_bh,
                 thread, t,
                 u64, flags)
{
    thread t = bound(t);
    sig_debug("tid %d, blocked %d, nullify %d\n",
              t->tid, flags & BLOCKQ_ACTION_BLOCKED, flags & BLOCKQ_ACTION_NULLIFY);

    if ((flags & BLOCKQ_ACTION_NULLIFY) || get_effective_signals(t)) {
        closure_finish();
        return syscall_return(t, -EINTR);
    }

    sig_debug("-> block\n");
    return blockq_block_required(t, flags);
}

sysreturn rt_sigsuspend(const u64 * mask, u64 sigsetsize)
{
    if (sigsetsize != (NSIG / 8))
        return -EINVAL;

    if (!validate_user_memory(mask, sigsetsize, false))
        return -EFAULT;

    thread t = current;
    u64 saved_mask = get_signal_mask(t);
    sig_debug("tid %d, *mask 0x%lx, saved_mask\n", t->tid, *mask, saved_mask);
    heap h = heap_locked(get_kernel_heaps());
    blockq_action ba = closure(h, rt_sigsuspend_bh, t);
    t->saved_signal_mask = saved_mask;
    set_signal_mask(t, *mask);
    return blockq_check(t->thread_bq, t, ba, false);
}

static boolean thread_is_on_altsigstack(thread t)
{
    return t->signal_stack != 0 &&
        point_in_range(irangel(u64_from_pointer(t->signal_stack),
                               t->signal_stack_length),
                       t->frame[SYSCALL_FRAME_SP]);
}

sysreturn sigaltstack(const stack_t *ss, stack_t *oss)
{
    thread t = current;
    if (oss) {
        if (!validate_user_memory(oss, sizeof(stack_t), true))
            return -EFAULT;
        if (t->signal_stack) {
            oss->ss_sp = t->signal_stack;
            oss->ss_size = t->signal_stack_length;
            oss->ss_flags = (thread_is_on_altsigstack(t) ? SS_ONSTACK : 0);
        } else {
            oss->ss_flags = SS_DISABLE;
        }
    }
    // it doesn't seem possible to re-enable without setting
    // a new stack....so we think this is a valid interpretation
    if (ss) {
        if (!validate_user_memory(ss, sizeof(stack_t), false)) {
            return -EFAULT;
        }
        if (thread_is_on_altsigstack(t)) {
            return -EPERM;
        }
        if (ss->ss_flags & SS_DISABLE) {
            t->signal_stack = 0;
        } else if (!validate_user_memory(ss->ss_sp, ss->ss_size, true)) {
            return -EFAULT;
        } else {
            if (ss->ss_flags) { /* unknown flags */
                return -EINVAL;
            }
            if (ss->ss_size < MINSIGSTKSZ) {
                return -ENOMEM;
            }
            t->signal_stack = ss->ss_sp;
            t->signal_stack_length = ss->ss_size;
        }
    }
    return 0;
}

sysreturn tgkill(int tgid, int tid, int sig)
{
    sig_debug("tgid %d, tid %d, sig %d\n", tgid, tid, sig);

    /* tgid == pid */
    if (tgid != current->p->pid)
        return -ESRCH;

    if (tid <= 0 || sig < 0 || sig > NSIG)
        return -EINVAL;

    if (sig == 0)
        return 0;               /* always permitted */

    thread t;
    if ((t = thread_from_tid(current->p, tid)) == INVALID_ADDRESS)
        return -ESRCH;

    struct siginfo si;
    init_siginfo(&si, sig, SI_TKILL);
    si.sifields.rt.pid = tgid;
    si.sifields.rt.uid = 0;
    sig_debug("-> delivering to thread\n");
    deliver_signal_to_thread(t, &si);
    thread_release(t);
    return 0;
}

sysreturn kill(int pid, int sig)
{
    sig_debug("pid %d, sig %d\n", pid, sig);

    /* yes, we can only kill our process self */
    if (pid != current->p->pid)
        return -ESRCH;

    if (sig < 0 || sig > NSIG)
        return -EINVAL;

    if (sig == 0)
        return 0;               /* always permitted */

    struct siginfo si;
    init_siginfo(&si, sig, SI_USER);
    si.sifields.kill.pid = pid;
    si.sifields.kill.uid = 0;
    deliver_signal_to_process(current->p, &si);
    return 0;
}

static inline sysreturn sigqueueinfo_sanitize_args(int tgid, int sig, siginfo_t *uinfo)
{
    if (!validate_user_memory(uinfo, sizeof(siginfo_t), true))
        return -EFAULT;

    if (tgid != current->p->pid)
        return -ESRCH;

    if (sig < 0 || sig > NSIG)
        return -EINVAL;

    if (sig == 0)
        return 0;               /* always permitted */

    if (uinfo->si_code >= 0 || uinfo->si_code == SI_TKILL)
        return -EPERM;

    return 1;
}

sysreturn rt_sigqueueinfo(int tgid, int sig, siginfo_t *uinfo)
{
    sig_debug("tgid (pid) %d, sig %d, uinfo %p, si_code %d\n", tgid, sig, uinfo, uinfo->si_code);

    sysreturn rv = sigqueueinfo_sanitize_args(tgid, sig, uinfo);
    if (rv <= 0)
        return rv;
    uinfo->si_signo = sig;
    deliver_signal_to_process(current->p, uinfo);
    return 0;
}

sysreturn rt_tgsigqueueinfo(int tgid, int tid, int sig, siginfo_t *uinfo)
{
    sig_debug("tgid (pid) %d, sig %d, uinfo %p\n", tgid, sig, uinfo);

    sysreturn rv = sigqueueinfo_sanitize_args(tgid, sig, uinfo);
    if (rv <= 0)
        return rv;

    thread t;
    if ((t = thread_from_tid(current->p, tid)) == INVALID_ADDRESS)
        return -ESRCH;

    uinfo->si_signo = sig;
    deliver_signal_to_thread(t, uinfo);
    thread_release(t);
    return 0;
}

sysreturn tkill(int tid, int sig)
{
    return tgkill(1, tid, sig);
}

closure_function(1, 1, sysreturn, pause_bh,
                 thread, t,
                 u64, flags)
{
    thread t = bound(t);
    sig_debug("tid %d, flags 0x%lx\n", t->tid, flags);

    if ((flags & BLOCKQ_ACTION_NULLIFY) || get_effective_signals(t)) {
        closure_finish();
        return syscall_return(t, -EINTR);
    }

    sig_debug("-> block\n");
    return blockq_block_required(t, flags);
}

/* aarch64: may be invoked directly from ppoll(2) */
sysreturn pause(void)
{
    sig_debug("tid %d\n", current->tid);
    heap h = heap_locked(get_kernel_heaps());
    blockq_action ba = closure(h, pause_bh, current);
    return blockq_check(current->thread_bq, current, ba, false);
}

closure_function(4, 1, sysreturn, rt_sigtimedwait_bh,
                 thread, t, u64, interest, siginfo_t *, info, const struct timespec *, timeout,
                 u64, flags)
{
    thread t = bound(t);
    u64 interest = bound(interest);
    boolean blocked = (flags & BLOCKQ_ACTION_BLOCKED) != 0;
    boolean nullify = (flags & BLOCKQ_ACTION_NULLIFY) != 0;

    if (flags & BLOCKQ_ACTION_TIMEDOUT) {
        assert(blocked);
        closure_finish();
        return syscall_return(t, -EAGAIN);
    }

    sysreturn rv;
    queued_signal qs = dequeue_signal(t, ~interest);
    if (qs == INVALID_ADDRESS) {
        if (!blocked) {
            const struct timespec * ts = bound(timeout);
            if (ts && ts->tv_sec == 0 && ts->tv_nsec == 0) {
                closure_finish();
                return set_syscall_error(t, EAGAIN); /* poll */
            }
            sig_debug("-> block\n");
            sigstate_set_interest(&t->signals, interest);
            return BLOCKQ_BLOCK_REQUIRED;
        } else {
            /* XXX record spurious wakeups? */
            rv = nullify ? -EINTR : blockq_block_required(t, flags);
        }
    } else {
        if (bound(info))
            runtime_memcpy(bound(info), &qs->si, sizeof(struct siginfo));
        rv = qs->si.si_signo;
        free_queued_signal(qs);
    }

    closure_finish();
    return syscall_return(t, rv);
}

sysreturn rt_sigtimedwait(const u64 * set, siginfo_t * info, const struct timespec * timeout, u64 sigsetsize)
{
    if (sigsetsize != (NSIG / 8))
        return -EINVAL;
    if (!validate_user_memory(set, sigsetsize, false) ||
        (info && !validate_user_memory(info, sizeof(siginfo_t), true)) ||
        (timeout && !validate_user_memory(timeout, sizeof(struct timespec), false)))
        return -EFAULT;
    sig_debug("tid %d, interest 0x%lx, info %p, timeout %p\n", current->tid, *set, info, timeout);
    heap h = heap_locked(get_kernel_heaps());
    blockq_action ba = closure(h, rt_sigtimedwait_bh, current, *set, info, timeout);
    timestamp t = timeout ? time_from_timespec(timeout) : 0;
    return blockq_check_timeout(current->thread_bq, current, ba, false, CLOCK_ID_MONOTONIC, t, false);
}

typedef struct signal_fd {
    struct fdesc f; /* must be first */
    int fd;
    heap h;
    blockq bq;
    u64 mask;
    notify_entry n;
} *signal_fd;

static void signalfd_siginfo_fill(struct signalfd_siginfo * si, queued_signal qs)
{
    si->ssi_signo = qs->si.si_signo;
    si->ssi_errno = qs->si.si_errno;
    si->ssi_code = qs->si.si_code;

    switch(si->ssi_code) {
    case SI_USER:
        si->ssi_pid = qs->si.sifields.kill.pid;
        si->ssi_uid = qs->si.sifields.kill.uid;
        break;
    case SI_TIMER:
        si->ssi_tid = qs->si.sifields.timer.tid;
        si->ssi_overrun = qs->si.sifields.timer.overrun;
        si->ssi_ptr = (u64)qs->si.sifields.timer.sigval.sival_ptr;
        si->ssi_int = qs->si.sifields.timer.sigval.sival_int;
        break;
    case SI_SIGIO:
        si->ssi_band = qs->si.sifields.sigpoll.band;
        si->ssi_fd = qs->si.sifields.sigpoll.fd;
        break;
    case SI_MESGQ:
    case SI_ASYNCIO:
    case SI_TKILL:
    case SI_DETHREAD:
    case SI_ASYNCNL:
        si->ssi_pid = qs->si.sifields.rt.pid;
        si->ssi_uid = qs->si.sifields.rt.uid;
        si->ssi_ptr = (u64)qs->si.sifields.rt.sigval.sival_ptr;
        si->ssi_int = qs->si.sifields.rt.sigval.sival_int;
        break;
    }
}

closure_function(5, 1, sysreturn, signalfd_read_bh,
                 signal_fd, sfd, thread, t, void *, dest, u64, length, io_completion, completion,
                 u64, flags)
{
    signal_fd sfd = bound(sfd);
    int max_infos = bound(length) / sizeof(struct signalfd_siginfo);
    boolean blocked = (flags & BLOCKQ_ACTION_BLOCKED) != 0;

    thread t = bound(t);
    int ninfos = 0;
    struct signalfd_siginfo * info = (struct signalfd_siginfo *)bound(dest);
    sysreturn rv = 0;

    sig_debug("fd %d, buf %p, length %ld, tid %d, flags 0x%lx\n",
              sfd->fd, info, bound(length), t->tid, flags);

    if (flags & BLOCKQ_ACTION_NULLIFY) {
        assert(blocked);
        rv = -ERESTARTSYS;
        sig_debug("   -> EINTR\n");
        goto out;
    }

    while (ninfos < max_infos) {
        queued_signal qs = dequeue_signal(t, ~sfd->mask);
        if (qs == INVALID_ADDRESS) {
            if (ninfos == 0) {
                if (!blocked && (sfd->f.flags & SFD_NONBLOCK)) {
                    rv = -EAGAIN;
                    sig_debug("   -> EAGAIN\n");
                    goto out;
                }
                sig_debug("   -> block\n");
                return blockq_block_required(t, flags);
            }
            break;
        }
        sig_debug("   sig %d, errno %d, code %d\n", qs->si.si_signo, qs->si.si_errno, qs->si.si_code);
        signalfd_siginfo_fill(info, qs);
        free_queued_signal(qs);
        info++;
        ninfos++;
    }

    rv = ninfos * sizeof(struct signalfd_siginfo);
    sig_debug("   %d infos, %ld bytes\n", ninfos, rv);
  out:
    apply(bound(completion), t, rv);
    closure_finish();
    return rv;
}

closure_function(1, 6, sysreturn, signalfd_read,
                 signal_fd, sfd,
                 void *, buf, u64, length, u64, offset_arg, thread, t, boolean, bh, io_completion, completion)
{
    signal_fd sfd = bound(sfd);
    sig_debug("fd %d, buf %p, length %ld, tid %d, bh %d\n", sfd->fd, buf, length, t->tid, bh);
    blockq_action ba = closure(sfd->h, signalfd_read_bh, sfd, t, buf, length, completion);
    return blockq_check(sfd->bq, t, ba, bh);
}

closure_function(1, 1, u32, signalfd_events,
                 signal_fd, sfd,
                 thread, t)
{
    return (get_all_pending_signals(t) & bound(sfd)->mask) ? EPOLLIN : 0;
}

closure_function(1, 2, sysreturn, signalfd_close,
                 signal_fd, sfd,
                 thread, t, io_completion, completion)
{
    signal_fd sfd = bound(sfd);
    deallocate_blockq(sfd->bq);
    notify_remove(current->signalfds, sfd->n, true);
    deallocate_closure(sfd->f.read);
    deallocate_closure(sfd->f.events);
    deallocate_closure(sfd->f.close);
    release_fdesc(&sfd->f);
    deallocate(sfd->h, sfd, sizeof(struct signal_fd));
    return io_complete(completion, t, 0);
}

closure_function(1, 2, boolean, signalfd_notify,
                 signal_fd, sfd,
                 u64, events, void *, t)
{
    signal_fd sfd = bound(sfd);
    if (events == NOTIFY_EVENTS_RELEASE) {
        sig_debug("%d released\n", sfd->fd);
        closure_finish();
    }

    if ((events & sfd->mask) == 0) {
        sig_debug("%d spurious notify\n", sfd->fd);
        return false;
    }

    /* null thread on notify set release (thread dealloc) */
    if (t)
        blockq_wake_one_for_thread(sfd->bq, t, false);
    notify_dispatch_for_thread(sfd->f.ns, EPOLLIN, t);
    return false;
}

static void signalfd_update_siginterest(thread t)
{
    sigstate_set_interest(&t->p->signals, notify_get_eventmask_union(t->signalfds));
}

static sysreturn allocate_signalfd(const u64 *mask, int flags)
{
    heap h = heap_locked(get_kernel_heaps());

    signal_fd sfd = allocate(h, sizeof(struct signal_fd));
    if (sfd == INVALID_ADDRESS)
        goto err_mem;

    sfd->h = h;
    init_fdesc(h, &sfd->f, FDESC_TYPE_SIGNALFD);

    sfd->bq = allocate_blockq(h, "signalfd");
    if (sfd->bq == INVALID_ADDRESS)
        goto err_mem_bq;

    sfd->mask = *mask;
    sfd->n = notify_add(current->signalfds, sfd->mask, closure(h, signalfd_notify, sfd));
    if (!sfd->n)
        goto err_mem_notify;

    sfd->f.flags = flags;
    sfd->f.read = closure(h, signalfd_read, sfd);
    sfd->f.events = closure(h, signalfd_events, sfd);
    sfd->f.close = closure(h, signalfd_close, sfd);

    u64 fd = allocate_fd(current->p, sfd);
    if (fd == INVALID_PHYSICAL) {
        apply(sfd->f.close, 0, io_completion_ignore);
        return -EMFILE;
    }
    sig_debug("allocate_signalfd: %d\n", fd);
    sfd->fd = fd;
    signalfd_update_siginterest(current);
    return sfd->fd;
  err_mem_notify:
    deallocate_blockq(sfd->bq);
  err_mem_bq:
    deallocate(h, sfd, sizeof(*sfd));
  err_mem:
    msg_err("%s: failed to allocate\n", __func__);
    return set_syscall_error(current, ENOMEM);
}

sysreturn signalfd4(int fd, const u64 *mask, u64 sigsetsize, int flags)
{
    if (sigsetsize != (NSIG / 8) ||
        (flags & ~(SFD_CLOEXEC | SFD_NONBLOCK))) 
        return -EINVAL;

    if (!validate_user_memory(mask, sigsetsize, false))
        return -EFAULT;

    if (fd == -1)
        return allocate_signalfd(mask, flags);

    signal_fd sfd = resolve_fd(current->p, fd); /* macro, may return EBADF */
    if (fdesc_type(&sfd->f) != FDESC_TYPE_SIGNALFD) {
        fdesc_put(&sfd->f);
        return -EINVAL;
    }

    /* update mask */
    sfd->mask = *mask;
    notify_entry_update_eventmask(sfd->n, sfd->mask);
    signalfd_update_siginterest(current);
    fdesc_put(&sfd->f);
    return fd;
}

#ifdef __x86_64__
sysreturn signalfd(int fd, const u64 *mask, u64 sigsetsize)
{
    return signalfd4(fd, mask, sigsetsize, 0);
}
#endif

static void dump_sig_info(thread t, queued_signal qs)
{
    siginfo_t *si = &qs->si;
    rprintf("signal %d received by tid %d, errno %d, code %d\n",
            si->si_signo, t->tid, si->si_errno, si->si_code);
    if (si->si_signo == SIGSEGV || si->si_signo == SIGBUS || si->si_signo == SIGFPE)
        rprintf("   fault address 0x%lx\n", si->sifields.sigfault.addr);

    /* can add more siginfo interpretation here... */
}

static void default_signal_action(thread t, queued_signal qs)
{
    char *fate;
    int signum = qs->si.si_signo;

    switch (signum) {
    case SIGHUP:
    case SIGINT:
    case SIGKILL:
    case SIGPIPE:
    case SIGALRM:
    case SIGTERM:
    case SIGUSR1:
    case SIGUSR2:
    case SIGPROF:
    case SIGVTALRM:
    case SIGSTKFLT:
    case SIGIO:
    case SIGPWR:
        /* terminate */
        fate = "   terminate\n";
        break;

    case SIGQUIT:
    case SIGILL:
    case SIGABRT:
    case SIGFPE:
    case SIGSEGV:
    case SIGBUS:
    case SIGSYS:
    case SIGTRAP:
    case SIGXCPU:
    case SIGXFSZ:
        /* TODO add core dump action here */
        fate = "   core dump (unimplemented)\n";
        break;

    case SIGSTOP:
    case SIGTSTP:
    case SIGTTIN:
    case SIGTTOU:
        /* stop */
        fate = "   stop\n";
        break;
    default:
        /* ignore */
        return;
    }
    dump_sig_info(t, qs);
    thread_log(t, fate);
    halt(fate);
}

boolean dispatch_signals(thread t)
{
    /* dequeue (and thus reset) a pending signal */
    queued_signal qs = dequeue_signal(t, get_signal_mask(t));

    if (t->saved_signal_mask != -1ull) {
        set_signal_mask(t, t->saved_signal_mask);
        t->saved_signal_mask = -1ull;
    }

    if (qs == INVALID_ADDRESS)
        return false;

    /* act on signal disposition */
    struct siginfo *si = &qs->si;
    int signum = si->si_signo;
    sigaction sa = sigaction_from_sig(t, signum);
    void *handler = sa->sa_handler;

    sig_debug("dispatching signal %d; sigaction handler %p, sa_mask 0x%lx, sa_flags 0x%lx\n",
              signum, handler, sa->sa_mask.sig[0], sa->sa_flags);
    thread_log(t, "signal %d received, errno %d, code %d\n",
               si->si_signo, si->si_errno, si->si_code);
    if (si->si_signo == SIGSEGV || si->si_signo == SIGBUS || si->si_signo == SIGFPE)
        thread_log(t, "   fault address 0x%lx\n", si->sifields.sigfault.addr);

    if (handler == SIG_DFL) {
        const char *s = "   default action\n";
        sig_debug("%s", s);
        thread_log(t, s);
        default_signal_action(t, qs);
        /* ignore if returned */
    }

    if (handler == SIG_DFL || handler == SIG_IGN) {
        const char *s = "   ignored\n";
        sig_debug("%s", s);
        thread_log(t, s);
        return false;
    }

    /* set up and switch to the signal context */
    sig_debug("switching to sigframe: tid %d, sig %d, sigaction %p\n", t->tid, signum, sa);
    if (t->interrupting_syscall) {
        t->interrupting_syscall = false;
        check_syscall_restart(t, sa);
    }
    setup_sigframe(t, signum, si);

    /* apply signal mask for handler */
    t->signal_mask |= mask_from_sig(signum) | sa->sa_mask.sig[0];

    /* clean up and proceed to handler */
    free_queued_signal(qs);
    return true;
}

void register_signal_syscalls(struct syscall *map)
{
#ifdef __x86_64__
    register_syscall(map, pause, pause);
    register_syscall(map, signalfd, signalfd);
#endif
    register_syscall(map, kill, kill);
    register_syscall(map, rt_sigaction, rt_sigaction);
    register_syscall(map, rt_sigpending, rt_sigpending);
    register_syscall(map, rt_sigprocmask, rt_sigprocmask);
    register_syscall(map, rt_sigqueueinfo, rt_sigqueueinfo);
    register_syscall(map, rt_tgsigqueueinfo, rt_tgsigqueueinfo);
    register_syscall(map, rt_sigreturn, rt_sigreturn);
    register_syscall(map, rt_sigsuspend, rt_sigsuspend);
    register_syscall(map, rt_sigtimedwait, rt_sigtimedwait);
    register_syscall(map, sigaltstack, sigaltstack);
    register_syscall(map, signalfd4, signalfd4);
    register_syscall(map, tgkill, tgkill);
    register_syscall(map, tkill, tkill);
}
