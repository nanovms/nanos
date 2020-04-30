#include <unix_internal.h>
#include <ftrace.h>

//#define SIGNAL_DEBUG
#ifdef SIGNAL_DEBUG
#define sig_debug(x, ...) do {log_printf("  SIG", "%s: " x, __func__, ##__VA_ARGS__);} while(0)
#else
#define sig_debug(x, ...)
#endif

/* TODO:

   support for SA_RESTART
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

static inline u64 normalize_signal_mask(u64 mask)
{
    return mask & ~(mask_from_sig(SIGKILL) | mask_from_sig(SIGSTOP));
}

static inline u64 sigstate_get_mask(sigstate ss)
{
    return normalize_signal_mask(ss->mask);
}

static inline void sigstate_set_mask(sigstate ss, u64 mask)
{
    ss->mask = mask;
}

static inline void sigstate_block(sigstate ss, u64 mask)
{
    ss->mask |= normalize_signal_mask(mask);
}

static inline void sigstate_unblock(sigstate ss, u64 mask)
{
    ss->mask &= ~mask;
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
    return sigstate_get_mask(&t->signals) &
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
    sigstate_set_mask(&dest->signals, sigstate_get_mask(&src->signals));
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
static queued_signal dequeue_signal(thread t, u64 sigmask, boolean save_and_mask)
{
    u64 masked = get_all_pending_signals(t) & ~sigmask;
    sig_debug("tid %d, sigmask 0x%lx, save %d, masked 0x%lx\n", t->tid, sigmask, save_and_mask, masked);
    if (masked == 0)
        return INVALID_ADDRESS;

    int signum = select_signal_from_masked(masked);
    if (!signum)
        return INVALID_ADDRESS;

    u64 mask = mask_from_sig(signum);
    sigstate ss = (sigstate_get_pending(&t->signals) & mask) ? &t->signals : &t->p->signals;
    queued_signal qs = sigstate_dequeue_signal(ss, signum);
    assert(qs != INVALID_ADDRESS);

    sig_debug("-> selected sig %d, dequeued from %s\n",
              signum, ss == &t->signals ? "thread" : "process");

    /* for actual signal handling - bypassed if dispatching via rt_sigtimedwait */
    if (save_and_mask) {
        sigaction sa = sigaction_from_sig(signum);
        if (ss->saved == 0)      /* rt_sigsuspend may provide one */
            ss->saved = ss->mask;
        ss->mask |= mask_from_sig(signum) | sa->sa_mask.sig[0];
        sig_debug("-> saved 0x%lx, mask 0x%lx\n", ss->saved, ss->mask);
        t->dispatch_sigstate = ss;
    }
    
    return qs;
}

static inline void free_queued_signal(queued_signal qs)
{
    deallocate(heap_general(get_kernel_heaps()), qs, sizeof(struct queued_signal));
}

void sigstate_flush_queue(sigstate ss)
{
    sig_debug("sigstate %p\n", ss);
    for (int signum = 1; signum <= NSIG; signum++) {
        list_foreach(sigstate_get_sighead(ss, signum), l) {
            free_queued_signal(struct_from_list(l, queued_signal, l));
        }
    }
}

void init_sigstate(sigstate ss)
{
    ss->pending = 0;
    ss->mask = 0;
    ss->saved = 0;
    ss->ignored = mask_from_sig(SIGCHLD) | mask_from_sig(SIGURG) | mask_from_sig(SIGWINCH);
    ss->interest = 0;

    for(int i = 0; i < NSIG; i++)
        list_init(&ss->heads[i]);
}

static inline boolean sig_is_ignored(process p, int sig)
{
    return (mask_from_sig(sig) & sigstate_get_ignored(&p->signals)) != 0;
}

static void deliver_signal(sigstate ss, struct siginfo *info)
{
    heap h = heap_general(get_kernel_heaps());
    int sig = info->si_signo;

    /* Special handling for pending signals */
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
                    return;
                }
            }
        }

        if (sig < RT_SIG_START) {
            /* Not queueable and no info update; ignore */
            sig_debug("already posted; ignore\n");
            return;
        }
    }

    sigstate_set_pending(ss, sig);
    queued_signal qs = allocate(h, sizeof(struct queued_signal));
    assert(qs != INVALID_ADDRESS);
    runtime_memcpy(&qs->si, info, sizeof(struct siginfo));
    list_insert_before(sigstate_get_sighead(ss, info->si_signo), &qs->l);
    sig_debug("queued_signal %p, signo %d, errno %d, code %d\n",
              qs, qs->si.si_signo, qs->si.si_errno, qs->si.si_code);
    sig_debug("prev %p, next %p\n", qs->l.prev, qs->l.next);
    sig_debug("next prev %p, next %p\n", qs->l.next->prev, qs->l.next->next);
}

static inline void signalfd_dispatch(thread t, u64 pending)
{
    notify_dispatch_for_thread(t->signalfds, pending, t);
}

void deliver_signal_to_thread(thread t, struct siginfo *info)
{
    int sig = info->si_signo;
    sig_debug("tid %d, sig %d\n", t->tid, sig);
    if ((sig != SIGSEGV && sig != SIGKILL && sig != SIGSTOP) &&
        sig_is_ignored(t->p, sig)) {
        sig_debug("signal ignored; no queue\n");
        return;
    }

    /* queue to thread for delivery */
    deliver_signal(&t->signals, info);
    sig_debug("... pending now 0x%lx\n", sigstate_get_pending(&t->signals));

    u64 pending_masked = get_effective_signals(t);
    sig_debug("... effective signals 0x%lx\n", pending_masked);
    if (pending_masked == 0)
        return;

    /* attempt to wake via signalfd notify */
    if (thread_in_interruptible_sleep(t))
        signalfd_dispatch(t, pending_masked);

    if (thread_is_runnable(t)) {
        sig_debug("... thread runnable, no interrupt\n");
        return;
    }

    sig_debug("attempting to interrupt thread\n");
    if (!thread_attempt_interrupt(t))
        sig_debug("failed to interrupt\n");
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

    /* If a thread is set as runnable and can handle this signal, just return. */
    thread t, can_wake = 0;
    vector_foreach(current->p->threads, t) {
        if (!t)
            continue;
        if (thread_is_runnable(t)) {
            /* Note that we're only considering unmasked signals
               (handlers) here, nothing in the interest masks. The
               thread is runnable, so it can't be blocked on
               rt_sigtimedwait or a signalfd (poll wait or blocking
               read). */
            if ((sigword & sigstate_get_mask(&t->signals)) == 0) {
                /* thread scheduled to run or running; no explicit wakeup */
                sig_debug("thread %d running and sig %d unmasked; return\n",
                          t->tid, sig);
                return;
            }
        } else if (thread_in_interruptible_sleep(t) &&
                   (sigword & get_effective_sigmask(t)) == 0) {
            /* First attempt to deliver via signalfd notify. If the
               thread becomes runnable, we're done. Note that we check
               only for this signal, not all pending signals as with
               thread delivery. That is because our task is to wake up
               a thread on behalf of this signal delivery, not just
               wake up a thread that has any pending signals. */
            signalfd_dispatch(t, sigword);
            if (thread_is_runnable(t))
                return;

            /* Otherwise, it's a candidate for interrupting. */
            can_wake = t;
        }
    }

    /* There's a chance a different thread could handle the pending process
       signal first, so this could cause a spurious wakeup (EINTR) ... care? */
    if (can_wake) {
        sig_debug("attempting to interrupt thread %d\n", can_wake->tid);
        if (!thread_attempt_interrupt(can_wake))
            sig_debug("failed to interrupt\n");
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

/*
 * Copy the context in frame 'f' to the ucontext *uctx
 */
static void setup_ucontext(struct ucontext * uctx, struct sigaction * sa, 
            struct siginfo * si, context f)
{
    struct sigcontext * mcontext = &(uctx->uc_mcontext);

    /* XXX for now we ignore everything but mcontext, incluing FP state ... */

    runtime_memset((void *)uctx, 0, sizeof(struct ucontext));
    mcontext->r8 = f[FRAME_R8];
    mcontext->r9 = f[FRAME_R9];
    mcontext->r10 = f[FRAME_R10];
    mcontext->r11 = f[FRAME_R11];
    mcontext->r12 = f[FRAME_R12];
    mcontext->r13 = f[FRAME_R13];
    mcontext->r14 = f[FRAME_R14];
    mcontext->r15 = f[FRAME_R15];
    mcontext->rdi = f[FRAME_RDI];
    mcontext->rsi = f[FRAME_RSI];
    mcontext->rbp = f[FRAME_RBP];
    mcontext->rbx = f[FRAME_RBX];
    mcontext->rdx = f[FRAME_RDX];
    mcontext->rax = f[FRAME_RAX];
    mcontext->rcx = f[FRAME_RCX];
    mcontext->rsp = f[FRAME_RSP];
    mcontext->rip = f[FRAME_RIP];
    mcontext->eflags = f[FRAME_FLAGS];
    mcontext->cs = f[FRAME_CS];
    mcontext->fs = 0;
    mcontext->gs = 0;
    mcontext->ss = 0; /* FRAME[SS] if UC_SIGCONTEXT SS */
    mcontext->err = f[FRAME_ERROR_CODE];
    mcontext->trapno = f[FRAME_VECTOR];
    mcontext->oldmask = sa->sa_mask.sig[0];
    mcontext->cr2 = f[FRAME_CR2];
}

/*
 * Copy the context from *uctx to the context in frame f
 */
static void restore_ucontext(struct ucontext * uctx, context f)
{
    struct sigcontext * mcontext = &(uctx->uc_mcontext);

    f[FRAME_R8] = mcontext->r8;
    f[FRAME_R9] = mcontext->r9;
    f[FRAME_R10] = mcontext->r10;
    f[FRAME_R11] = mcontext->r11;
    f[FRAME_R12] = mcontext->r12;
    f[FRAME_R13] = mcontext->r13;
    f[FRAME_R14] = mcontext->r14;
    f[FRAME_R15] = mcontext->r15;
    f[FRAME_RDI] = mcontext->rdi;
    f[FRAME_RSI] = mcontext->rsi;
    f[FRAME_RBP] = mcontext->rbp;
    f[FRAME_RBX] = mcontext->rbx;
    f[FRAME_RDX] = mcontext->rdx;
    f[FRAME_RAX] = mcontext->rax;
    f[FRAME_RCX] = mcontext->rcx;
    f[FRAME_RSP] = mcontext->rsp;
    f[FRAME_RIP] = mcontext->rip;
    f[FRAME_FLAGS] = mcontext->eflags;
    f[FRAME_CS] = mcontext->cs;
}

sysreturn rt_sigreturn(void)
{
    struct rt_sigframe *frame;
    sigaction sa;
    thread t = current;

    assert(t->dispatch_sigstate);

    /* sigframe sits at %rsp minus the return address word (pretcode) */
    frame = (struct rt_sigframe *)(t->sighandler_frame[FRAME_RSP] - sizeof(u64));
    sig_debug("rt_sigreturn: frame:0x%lx\n", (unsigned long)frame);

    /* safer to query via thread variable */
    sa = sigaction_from_sig(t->active_signo);
    t->active_signo = 0;

    /* restore signal mask and saved context, if applicable */
    sigstate_thread_restore(t);
    if (sa->sa_flags & SA_SIGINFO) {
        sig_debug("-> restore ucontext\n");
        restore_ucontext(&(frame->uc), t->default_frame);
    }

    /* ftrace needs to know that this call stack does not return */
    ftrace_thread_noreturn(t);

    /* see if we have more handlers to invoke */
    if (!dispatch_signals(t))
        set_thread_frame(t, t->default_frame);

    context f = thread_frame(t);
    sig_debug("switching to thread frame %p, rip 0x%lx, rax 0x%lx\n",
              f, f[FRAME_RIP], f[FRAME_RAX]);

    schedule_frame(f);
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

    sigaction sa = sigaction_from_sig(signum);

    if (oldact) {
        if (validate_user_memory(oldact, sizeof(struct sigaction), true))
            runtime_memcpy(oldact, sa, sizeof(struct sigaction));
        else
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

    if (act->sa_flags & SA_RESTART)
        msg_warn("Warning: SA_RESTART unsupported.\n");

    if (act->sa_flags & SA_RESETHAND)
        msg_warn("Warning: SA_RESETHAND unsupported.\n");

    /* libc should always set this on x64 ... */
    if (!(act->sa_flags & SA_RESTORER)) {
        msg_err("sigaction without SA_RESTORER not supported.\n");
        return -EINVAL;
    }

    /* update ignored mask */
    sigstate ss = &current->p->signals;
    u64 sigword = mask_from_sig(signum);
    sigstate_set_ignored(ss, act->sa_handler == SIG_IGN ? sigstate_get_ignored(ss) | sigword :
                         sigstate_get_ignored(ss) & ~sigword);

    sig_debug("installing sigaction: handler %p, sa_mask 0x%lx, sa_flags 0x%lx\n",
              act->sa_handler, act->sa_mask.sig[0], act->sa_flags);
    runtime_memcpy(sa, act, sizeof(struct sigaction));
    return 0;
}

sysreturn rt_sigprocmask(int how, const u64 *set, u64 *oldset, u64 sigsetsize)
{
    if (sigsetsize != (NSIG / 8))
        return -EINVAL;

    if (oldset) {
        if (validate_user_memory(oldset, sigsetsize, true))
            *oldset = sigstate_get_mask(&current->signals);
        else
            return -EFAULT;
    }

    if (set) {
        if (!validate_user_memory(set, sigsetsize, false))
            return -EFAULT;
        switch (how) {
        case SIG_BLOCK:
            sigstate_block(&current->signals, *set);
            break;
        case SIG_UNBLOCK:
            sigstate_unblock(&current->signals, *set);
            break;
        case SIG_SETMASK:
            sigstate_set_mask(&current->signals, *set);
            break;
        default:
            return -EINVAL;
        }
    }
    return 0;
}

closure_function(2, 1, sysreturn, rt_sigsuspend_bh,
                 thread, t, u64, saved_mask,
                 u64, flags)
{
    thread t = bound(t);
    sig_debug("tid %d, saved_mask 0x%lx blocked %d, nullify %d\n",
              t->tid, bound(saved_mask), flags & BLOCKQ_ACTION_BLOCKED, flags & BLOCKQ_ACTION_NULLIFY);

    if ((flags & BLOCKQ_ACTION_NULLIFY) || get_effective_signals(t)) {
        if (flags & BLOCKQ_ACTION_BLOCKED)
            thread_wakeup(t);
        closure_finish();
        return set_syscall_error(t, EINTR);
    }

    sig_debug("-> block\n");
    return BLOCKQ_BLOCK_REQUIRED;
}

sysreturn rt_sigsuspend(const u64 * mask, u64 sigsetsize)
{
    if (sigsetsize != (NSIG / 8))
        return -EINVAL;

    if (!validate_user_memory(mask, sigsetsize, false))
        return -EFAULT;

    thread t = current;
    sig_debug("tid %d, *mask 0x%lx\n", t->tid, *mask);
    heap h = heap_general(get_kernel_heaps());
    u64 orig_mask = sigstate_get_mask(&t->signals);
    blockq_action ba = closure(h, rt_sigsuspend_bh, t, orig_mask);
    t->signals.saved = orig_mask;
    sigstate_set_mask(&t->signals, *mask);
    return blockq_check(t->thread_bq, t, ba, false);
}

static boolean thread_is_on_altsigstack(thread t)
{
    return (t->active_signo &&
            point_in_range(irange(u64_from_pointer(t->signal_stack),
            u64_from_pointer(t->signal_stack + t->signal_stack_length)),
            t->sighandler_frame[FRAME_RSP]));
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
        if (!validate_user_memory(ss, sizeof(stack_t), false) ||
            !validate_user_memory(ss->ss_sp, ss->ss_size, true))
            return -EFAULT;
        if (thread_is_on_altsigstack(t)) {
            return -EPERM;
        }
        if (ss->ss_flags & SS_DISABLE) {
            t->signal_stack = 0;
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
        if (flags & BLOCKQ_ACTION_BLOCKED) {
            sig_debug("-> wakeup\n");
            thread_wakeup(t);
        }
        closure_finish();
        return set_syscall_error(t, EINTR);
    }

    sig_debug("-> block\n");
    return BLOCKQ_BLOCK_REQUIRED;
}

sysreturn pause(void)
{
    sig_debug("tid %d\n", current->tid);
    heap h = heap_general(get_kernel_heaps());
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
        thread_wakeup(t);
        closure_finish();
        return set_syscall_error(t, EAGAIN);
    }

    sysreturn rv;
    queued_signal qs = dequeue_signal(t, ~interest, false);
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
            rv = nullify ? -EINTR : BLOCKQ_BLOCK_REQUIRED;
        }
    } else {
        if (bound(info))
            runtime_memcpy(bound(info), &qs->si, sizeof(struct siginfo));
        rv = qs->si.si_signo;
        free_queued_signal(qs);
    }

    if (blocked)
        thread_wakeup(t);
    closure_finish();
    return set_syscall_return(t, rv);
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
    heap h = heap_general(get_kernel_heaps());
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
        rv = -EINTR;
        sig_debug("   -> EINTR\n");
        goto out;
    }

    while (ninfos < max_infos) {
        queued_signal qs = dequeue_signal(t, ~sfd->mask, false);
        if (qs == INVALID_ADDRESS) {
            if (ninfos == 0) {
                if (!blocked && (sfd->f.flags & SFD_NONBLOCK)) {
                    rv = -EAGAIN;
                    sig_debug("   -> EAGAIN\n");
                    goto out;
                }
                sig_debug("   -> block\n");
                return BLOCKQ_BLOCK_REQUIRED;
            }
            break;
        }
        sig_debug("   sig %d, errno %d, code %d\n", qs->si.si_signo, qs->si.si_errno, qs->si.si_code);
        signalfd_siginfo_fill(info, qs);
        info++;
        ninfos++;
    }

    rv = ninfos * sizeof(struct signalfd_siginfo);
    sig_debug("   %d infos, %ld bytes\n", ninfos, rv);
  out:
    blockq_handle_completion(sfd->bq, flags, bound(completion), t, rv);
    closure_finish();
    return rv;
}

closure_function(1, 6, sysreturn, signalfd_read,
                 signal_fd, sfd,
                 void *, buf, u64, length, u64, offset_arg, thread, t, boolean, bh, io_completion, completion)
{
    if (length < sizeof(struct signalfd_siginfo))
        return 0;
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

closure_function(1, 0, sysreturn, signalfd_close,
                 signal_fd, sfd)
{
    signal_fd sfd = bound(sfd);
    deallocate_blockq(sfd->bq);
    notify_remove(current->signalfds, sfd->n, true);
    deallocate_closure(sfd->f.read);
    deallocate_closure(sfd->f.events);
    deallocate_closure(sfd->f.close);
    release_fdesc(&sfd->f);
    deallocate(sfd->h, sfd, sizeof(struct signal_fd));
    return 0;
}

closure_function(1, 2, void, signalfd_notify,
                 signal_fd, sfd,
                 u64, events,
                 thread, t)
{
    signal_fd sfd = bound(sfd);
    if (events == NOTIFY_EVENTS_RELEASE) {
        sig_debug("%d released\n", sfd->fd);
        closure_finish();
    }

    if ((events & sfd->mask) == 0) {
        sig_debug("%d spurious notify\n", sfd->fd);
        return;
    }
    blockq_wake_one_for_thread(sfd->bq, t);
    notify_dispatch_for_thread(sfd->f.ns, EPOLLIN, t);
}

static void signalfd_update_siginterest(thread t)
{
    sigstate_set_interest(&t->p->signals, notify_get_eventmask_union(t->signalfds));
}

static sysreturn allocate_signalfd(const u64 *mask, int flags)
{
    heap h = heap_general(get_kernel_heaps());

    signal_fd sfd = allocate(h, sizeof(struct signal_fd));
    if (sfd == INVALID_ADDRESS)
        goto err_mem;

    u64 fd = allocate_fd(current->p, sfd);
    if (fd == INVALID_PHYSICAL) {
        deallocate(h, sfd, sizeof(struct signal_fd));
        return -EMFILE;
    }
    sig_debug("allocate_signalfd: %d\n", fd);

    sfd->fd = fd;
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
    signalfd_update_siginterest(current);
    return sfd->fd;
  err_mem_notify:
    deallocate_blockq(sfd->bq);
  err_mem_bq:
    deallocate_fd(current->p, sfd->fd);
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
    if (fdesc_type(&sfd->f) != FDESC_TYPE_SIGNALFD)
        return -EINVAL;

    /* update mask */
    sfd->mask = *mask;
    notify_entry_update_eventmask(sfd->n, sfd->mask);
    signalfd_update_siginterest(current);
    return fd;
}

sysreturn signalfd(int fd, const u64 *mask, u64 sigsetsize)
{
    return signalfd4(fd, mask, sigsetsize, 0);
}

static void setup_sigframe(thread t, int signum, struct siginfo *si)
{
    sigaction sa = sigaction_from_sig(signum);

    assert(sizeof(struct siginfo) == 128);

    sig_debug("sa->sa_flags 0x%lx\n", sa->sa_flags);

    /* copy only what we really need */
    t->sighandler_frame[FRAME_FSBASE] = t->default_frame[FRAME_FSBASE];
    t->sighandler_frame[FRAME_GSBASE] = t->default_frame[FRAME_GSBASE];

    if (sa->sa_flags & SA_ONSTACK && t->signal_stack) {
        t->sighandler_frame[FRAME_RSP] = u64_from_pointer(t->signal_stack + t->signal_stack_length);
    } else {
        t->sighandler_frame[FRAME_RSP] = t->default_frame[FRAME_RSP];
    }

    /* avoid redzone and align rsp

       Note: We are actually aligning to 8 but not 16 bytes; the ABI
       requires that stacks are aligned to 16 before a call, but the
       sigframe return into the function takes the place of a call,
       which would have pushed a return address. The function prologue
       typically pushes the frame pointer on the stack, thus
       re-aligning to 16 before executing the function body.
    */
    t->sighandler_frame[FRAME_RSP] = ((t->sighandler_frame[FRAME_RSP] & ~15)
                                      - 128 /* redzone */
                                      - 8 /* same effect as call pushing ra */);

    /* create space for rt_sigframe */
    t->sighandler_frame[FRAME_RSP] -= pad(sizeof(struct rt_sigframe), 16);

    /* setup sigframe for user sig trampoline */
    struct rt_sigframe *frame = (struct rt_sigframe *)t->sighandler_frame[FRAME_RSP];
    frame->pretcode = sa->sa_restorer;

    if (sa->sa_flags & SA_SIGINFO) {
        runtime_memcpy(&frame->info, si, sizeof(struct siginfo));
        setup_ucontext(&frame->uc, sa, si, t->default_frame);
        t->sighandler_frame[FRAME_RSI] = u64_from_pointer(&frame->info);
        t->sighandler_frame[FRAME_RDX] = u64_from_pointer(&frame->uc);
    } else {
        t->sighandler_frame[FRAME_RSI] = 0;
        t->sighandler_frame[FRAME_RDX] = 0;
    }

    /* setup regs for signal handler */
    t->sighandler_frame[FRAME_RIP] = u64_from_pointer(sa->sa_handler);
    t->sighandler_frame[FRAME_RDI] = signum;
    t->sighandler_frame[FRAME_IS_SYSCALL] = 1;

    /* save signo for safer sigreturn */
    t->active_signo = signum;

    sig_debug("sigframe tid %d, sig %d, rip 0x%lx, rsp 0x%lx, "
              "rdi 0x%lx, rsi 0x%lx, rdx 0x%lx, r8 0x%lx\n", t->tid, signum,
              t->sighandler_frame[FRAME_RIP], t->sighandler_frame[FRAME_RSP],
              t->sighandler_frame[FRAME_RDI], t->sighandler_frame[FRAME_RSI],
              t->sighandler_frame[FRAME_RDX], t->sighandler_frame[FRAME_R8]);
}

/* return true if t->sighandler_frame should be scheduled to run */
boolean dispatch_signals(thread t)
{
    if (t->dispatch_sigstate)
        goto no_sig; /* sorry, no nested handling */

    /* dequeue (and thus reset) a pending signal, masking temporarily */
    queued_signal qs = dequeue_signal(t, sigstate_get_mask(&t->signals), true);
    if (qs == INVALID_ADDRESS)
        goto no_sig;

    /* act on signal disposition */
    int signum = qs->si.si_signo;
    sigaction sa = sigaction_from_sig(signum);
    void * handler = sa->sa_handler;

    sig_debug("dispatching signal %d; sigaction handler %p, sa_mask 0x%lx, sa_flags 0x%lx\n",
              signum, handler, sa->sa_mask.sig[0], sa->sa_flags);

    if (handler == SIG_IGN) {
        sig_debug("sigact == SIG_IGN\n");
        goto ignore;
    } else if (handler == SIG_DFL) {
        switch (signum) {
        /* terminate */
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
            msg_err("signal %d resulting in thread termination\n", signum);
            halt("unimplemented signal\n");
            // exit_thread(t);
            break;

        /* core dump */
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
            msg_err("signal %d resulting in core dump\n", signum);
            halt("unimplemented signal\n");
            // core_dump(t);
            break;

        /* stop */
        case SIGSTOP:
        case SIGTSTP:
        case SIGTTIN:
        case SIGTTOU:
            msg_err("signal %d resulting in thread stop\n", signum);
            halt("unimplemented signal\n");
            // thread_stop(t);
            break;

        /* ignore the rest */
        default:
            goto ignore;
        }
    }

    /* set up and switch to the signal context */
    sig_debug("switching to sigframe: tid %d, sig %d, sigaction %p\n", t->tid, signum, sa);
    setup_sigframe(t, signum, &qs->si);

    /* clean up and proceed to handler */
    free_queued_signal(qs);
    set_thread_frame(t, t->sighandler_frame);
    return true;
  ignore:
    sig_debug("ignoring signal %d\n", signum);
    sigstate_thread_restore(t);
  no_sig:
    return false;
}

void register_signal_syscalls(struct syscall *map)
{
    register_syscall(map, kill, kill);
    register_syscall(map, pause, pause);
    register_syscall(map, rt_sigaction, rt_sigaction);
    register_syscall(map, rt_sigpending, rt_sigpending);
    register_syscall(map, rt_sigprocmask, rt_sigprocmask);
    register_syscall(map, rt_sigqueueinfo, rt_sigqueueinfo);
    register_syscall(map, rt_tgsigqueueinfo, rt_tgsigqueueinfo);
    register_syscall(map, rt_sigreturn, rt_sigreturn);
    register_syscall(map, rt_sigsuspend, rt_sigsuspend);
    register_syscall(map, rt_sigtimedwait, rt_sigtimedwait);
    register_syscall(map, sigaltstack, sigaltstack);
    register_syscall(map, signalfd, signalfd);
    register_syscall(map, signalfd4, signalfd4);
    register_syscall(map, tgkill, tgkill);
    register_syscall(map, tkill, tkill);
}
