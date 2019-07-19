#include <unix_internal.h>

//#define SIGNAL_DEBUG
#ifdef SIGNAL_DEBUG
#define sig_debug(x, ...) do {log_printf(" SIG", "%s: " x, __func__, ##__VA_ARGS__);} while(0)
#else
#define sig_debug(x, ...)
#endif

/* TODO:

   support for SA_RESTART
   support for signalfd
   blocking calls within sig handler
   nested signal handlers

   kill
   sigqueue
   sigaltstack *
   signal *
   sigpending *
   rt_sigprocmask
   sigsuspend
   sigtimedwait / sigwaitinfo
   rt_sigqueueinfo

   add additional blockqs for:
   - epoll_wait
   - select_internal
   - poll_internal
   - futex
   - nanosleep

   core dump

   signal mask
   queueable / level?

   sig actions / defaults
 */

typedef struct queued_signal {
    struct siginfo si;
    struct list l;
} *queued_signal;

static inline u64 mask_from_sig(int sig)
{
    assert(sig > 0);
    return U64_FROM_BIT(sig - 1);
}

static inline sigaction get_sigaction(int signum)
{
    return &current->p->sigactions[signum - 1];
}

static inline void init_siginfo(struct siginfo *si, int sig, s32 code)
{
    zero(si, sizeof(struct siginfo));
    si->si_signo = sig;
    si->si_code = code;
}

static inline int select_signal_from_masked(u64 masked)
{
    /* give priority to KILL and STOP, but otherwise the lowest signal number is served first */
    if (masked & mask_from_sig(SIGKILL))
        return SIGKILL;
    if (masked & mask_from_sig(SIGSTOP))
        return SIGKILL;
    return lsb(masked) + 1;
}

static inline u64 sigstate_get_mask(sigstate ss)
{
    return ss->sigmask & ~(mask_from_sig(SIGKILL) | mask_from_sig(SIGSTOP));
}

static inline u64 sigstate_get_pending(sigstate ss)
{
    return ss->sigpending;
}

static inline u64 sigstate_get_pending_masked(sigstate ss)
{
    return ss->sigpending & ~sigstate_get_mask(ss);
}

static inline void sigstate_set_pending(sigstate ss, int sig)
{
    ss->sigpending |= mask_from_sig(sig);
}

static inline boolean sigstate_is_pending(sigstate ss, int sig)
{
    return (ss->sigpending & mask_from_sig(sig)) != 0;
}

static inline list sigstate_get_sighead(sigstate ss, int signum)
{
    assert(signum > 0 && signum <= 64);
    return &ss->sigheads[signum - 1];
}

static inline void sigstate_restore(sigstate ss)
{
    ss->sigmask = ss->sigsaved;
    ss->sigsaved = 0;
}

static queued_signal sigstate_get_signal(sigstate ss)
{
    sig_debug("sigstate %p\n", ss);
    u64 masked = sigstate_get_pending_masked(ss);
    if (masked == 0)
        return INVALID_ADDRESS;

    int signum = select_signal_from_masked(masked);
    if (!signum)
        return INVALID_ADDRESS;
    sigaction sa = get_sigaction(signum);
    u64 sigword = mask_from_sig(signum);
    ss->sigsaved = ss->sigmask;
    ss->sigmask |= sigword | sa->sa_mask.sig[0];
    sig_debug("sig %d, now sigsaved 0x%lx, sigmask 0x%lx\n",
              signum, ss->sigsaved, ss->sigmask);

    /* dequeue siginfo */
    list head = sigstate_get_sighead(ss, signum);
    list l = list_get_next(head);
    assert(l);
    queued_signal qs = struct_from_list(l, queued_signal, l);
    list_delete(l);
    if (list_empty(head))
        ss->sigpending &= ~sigword;
    return qs;
}

static inline void free_queued_signal(queued_signal qs)
{
    deallocate(heap_general(get_kernel_heaps()), qs, sizeof(struct queued_signal));
}

static void deliver_signal(sigstate ss, struct siginfo *info)
{
    heap h = heap_general(get_kernel_heaps());
    int sig = info->si_signo;

    /* check if we can post */
    if (info->si_signo < RT_SIG_START && sigstate_is_pending(ss, sig)) {
        /* Standard signal already posted. Unless a particular signal
           would allow the updating of posted siginfo, just return here. */
        sig_debug("already posted; ignore\n");
        return;
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

void deliver_signal_to_thread(thread t, struct siginfo *info)
{
    sig_debug("tid %d, sig %d\n", t->tid, info->si_signo);
    deliver_signal(&t->signals, info);
    sig_debug("... pending now 0x%lx\n", sigstate_get_pending(&t->signals));

    /* queue for delivery */
    u64 pending_masked = sigstate_get_pending_masked(&t->signals);
    if (pending_masked) {
        sig_debug("masked = 0x%lx; attempting to interrupt thread\n", pending_masked);
        if (!thread_attempt_interrupt(t))
            sig_debug("failed to interrupt\n");
    }
}

void deliver_signal_to_process(process p, struct siginfo *info)
{
    int sig = info->si_signo;
    sig_debug("pid %d, sig %d\n", p->pid, sig);
    deliver_signal(&p->signals, info);
    sig_debug("... pending now 0x%lx\n", sigstate_get_pending(&p->signals));

    /* if there isn't a thread awake that can handle this signal, try to wake one */
    thread t, can_wake = 0;
    vector_foreach(current->p->threads, t) {
        if ((sigstate_get_mask(&t->signals) & mask_from_sig(sig)) == 0) {
            if (thread_is_runnable(t)) {
                sig_debug("thread %d running and able to handle sig %d; return\n", t->tid, sig);
                /* nothing to do; let it run */
                return;
            }
            if (thread_in_interruptible_sleep(t))
                can_wake = t;   /* could attempt to randomize selection if we cared */
        }
    }

    if (can_wake) {
        sig_debug("attempting to interrupt thread %d\n", can_wake->tid);
        if (!thread_attempt_interrupt(t))
            sig_debug("failed to interrupt\n");
    }
}

sysreturn rt_sigpending(sigset_t *set)
{
    sig_debug("set %p\n");
    if (!set)
        return -EFAULT;

    u64 pending = sigstate_get_pending(&current->signals) |
        sigstate_get_pending(&current->p->signals);

    *((u64 *)set) = pending;
    sig_debug("= 0x%lx\n", pending);
    return 0;
}

sysreturn rt_sigreturn()
{
    thread t = current;
    sig_debug("tid %d\n", t->tid);

    assert(t->dispatch_sigstate);

    /* reset signal mask */
    sigstate_restore(t->dispatch_sigstate);
    t->dispatch_sigstate = 0;

    /* restore saved context */
    t->frame[FRAME_RAX] = t->rax_saved;
    running_frame = t->frame;

    sig_debug("switching to thread frame %p\n", running_frame);
    /* return - XXX or reschedule? */
    IRETURN(running_frame);
    return 0;
}

sysreturn rt_sigaction(int signum,
                       const struct sigaction *act,
                       struct sigaction *oldact,
                       u64 sigsetsize)
{
    sig_debug("signum %d, act %p, oldact %p, sigsetsize %ld\n", signum, act, oldact, sigsetsize);

    if (signum < 1 || signum > NSIG)
        return -EINVAL;

    if (sigsetsize != (NSIG / 8)) {
        msg_err("sigsetsize (%ld) != NSIG (%ld)\n", sigsetsize, NSIG);
        return -EINVAL;
    }

    if (signum > NSIG) {
        msg_err("signum %d greater than NSIG\n", signum);
        return -EINVAL;
    }

    sigaction sa = get_sigaction(signum);

    if (oldact)
        runtime_memcpy(oldact, sa, sizeof(struct sigaction));

    if (!act)
        return 0;

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

    sig_debug("installing sigaction: handler %p, sa_mask 0x%lx, sa_flags 0x%lx\n",
              act->sa_handler, act->sa_mask.sig[0], act->sa_flags);
    runtime_memcpy(sa, act, sizeof(struct sigaction));
    return 0;
}

sysreturn rt_sigprocmask(int how, const sigset_t *set, sigset_t *oldset, u64 sigsetsize)
{
    if (oldset)
        runtime_memset((void *) oldset, 0, sigsetsize);

    return 0;
}

sysreturn sigaltstack(const stack_t *ss, stack_t *oss)
{

    return 0;
}

sysreturn tgkill(int tgid, int tid, int sig)
{
    sig_debug("tgid %d, tid %d, sig %d\n", tgid, tid, sig);
    /* XXX validate that tgid is the one valid value... */
    if (tgid <= 0 || tid <= 0)
        return -EINVAL;

    thread t;
    sig_debug("%d, %p\n", vector_length(current->p->threads),
              vector_get(current->p->threads, tid - 1));
    if (tid > vector_length(current->p->threads) ||
        !(t = vector_get(current->p->threads, tid - 1)))
        return -ESRCH;

    struct siginfo si;
    init_siginfo(&si, sig, SI_TKILL);
    deliver_signal_to_thread(t, &si);
    return 0;
}

sysreturn tkill(int tid, int sig)
{
    return tgkill(0, tid, sig);
}

sysreturn kill(int pid, int sig)
{
    sig_debug("pid %d, sig %d\n", pid, sig);

    /* yes, we can only kill our process self */
    if (pid != current->p->pid)
        return -ESRCH;

    struct siginfo si;
    init_siginfo(&si, sig, SI_USER);
    deliver_signal_to_process(current->p, &si);
    return 0;
}

static CLOSURE_1_2(pause_bh, sysreturn,
                   thread,
                   boolean, boolean);
static sysreturn pause_bh(thread t, boolean blocked, boolean nullify)
{
    sig_debug("tid %d, blocked %d, nullify %d\n", t->tid, blocked, nullify);

    if (nullify ||
        sigstate_get_pending_masked(&t->signals) ||
        sigstate_get_pending_masked(&t->p->signals)) {
        if (blocked)
            thread_wakeup(t);
        return set_syscall_return(t, -EINTR);
    }

    sig_debug("-> block\n");
    return infinity;
}

sysreturn pause(void)
{
    sig_debug("tid %d, blocking...\n", current->tid);
    heap h = heap_general(get_kernel_heaps());
    blockq_action ba = closure(h, pause_bh, current);
    return blockq_check(current->dummy_blockq, current, ba, false);
}

void register_signal_syscalls(struct syscall *map)
{
    register_syscall(map, kill, kill);
    register_syscall(map, pause, pause);
    register_syscall(map, rt_sigaction, rt_sigaction);
    register_syscall(map, rt_sigpending, rt_sigpending);
    register_syscall(map, rt_sigprocmask, rt_sigprocmask);
    register_syscall(map, rt_sigreturn, rt_sigreturn);
    register_syscall(map, sigaltstack, syscall_ignore);
    register_syscall(map, tgkill, tgkill);
    register_syscall(map, tkill, tkill);
}

/* guts of signal dispatch */

static void __attribute__((section (".vdso"))) signal_trampoline(u32 signum,
                                                                 void *handler,
                                                                 siginfo_t *siginfo,
                                                                 void *ucontext)
{
    if (siginfo) {
        ((__sigaction_t)handler)(signum, siginfo, ucontext);
    } else {
        ((__sighandler_t)handler)(signum);
    }

    sysreturn rv;
    asm volatile("syscall" : "=a" (rv) : "0" (SYS_rt_sigreturn) : "memory");

    /* shouldn't return */
    assert(0);
}

static void setup_sigframe(thread t, int signum, struct siginfo *si, void * ucontext)
{
    sigaction sa = get_sigaction(signum);

    assert(sizeof(struct siginfo) == 128);

    /* XXX prob should zero most of this, but not sure yet what needs
     * to be carried over */
    runtime_memcpy(t->sigframe, t->frame, sizeof(u64) * FRAME_MAX);

    /* XXX hack: stash %RAX which will get clobbered in a sig handler */
    t->rax_saved = t->frame[FRAME_RAX];

    /* return to signal trampoline */
    t->sigframe[FRAME_RIP] = u64_from_pointer(signal_trampoline);

    /* arguments to trampoline */
    t->sigframe[FRAME_RDI] = signum;
    t->sigframe[FRAME_RSI] = u64_from_pointer(sa->sa_handler);

    sig_debug("sa->sa_flags 0x%lx\n", sa->sa_flags);

    /* check for altstack */
    if (sa->sa_flags & SA_ONSTACK) {
        t->sigframe[FRAME_RSP] = 0; /* TODO */
    } else {
        /* must avoid redzone */
        t->sigframe[FRAME_RSP] -= 128;
    }

    if (sa->sa_flags & SA_SIGINFO) {
        /* place a siginfo on the stack */
        t->sigframe[FRAME_RSP] -= pad(sizeof(struct siginfo), 16);
        siginfo_t * dest_si = pointer_from_u64(t->sigframe[FRAME_RSP]);
        sig_debug("copying siginfo to [%p, %p)\n", dest_si, ((void *)dest_si) + sizeof(struct siginfo));
        runtime_memcpy(dest_si, si, sizeof(struct siginfo));
        t->sigframe[FRAME_RDX] = t->sigframe[FRAME_RSP];
    } else {
        t->sigframe[FRAME_RDX] = 0;
    }

    /* XXX ucontext, revisit later */
    t->sigframe[FRAME_RCX] = 0;

    sig_debug("sigframe tid %d, sig %d, rip 0x%lx, rsp 0x%lx, "
              "rdi 0x%lx, rsi 0x%lx, rdx 0x%lx, rcx 0x%lx\n", t->tid, signum,
              t->sigframe[FRAME_RIP], t->sigframe[FRAME_RSP],
              t->sigframe[FRAME_RDI], t->sigframe[FRAME_RSI],
              t->sigframe[FRAME_RDX], t->sigframe[FRAME_RCX]);
}

/* XXX lock down / use access fns */
void dispatch_signals(thread t)
{
    sig_debug("tid %d\n", t->tid);

    if (t->dispatch_sigstate) {
        /* sorry, no nested handling */
        return;
    }

    /* procure a pending signal from the thread or, failing that, the process */
    sigstate ss = &t->signals;
    queued_signal qs = sigstate_get_signal(ss);
    if (qs == INVALID_ADDRESS) {
        ss = &t->p->signals;
        qs = sigstate_get_signal(ss);
        if (qs == INVALID_ADDRESS) {
            sig_debug("tid %d: nothing to process\n", t->tid);
            return;
        }
    }
    t->dispatch_sigstate = ss;

    /* act on signal disposition */
    int signum = qs->si.si_signo;
    sigaction sa = get_sigaction(signum);
    void * handler = sa->sa_handler;

    sig_debug("dispatching signal %d; sigaction handler %p, sa_mask 0x%lx, sa_flags 0x%lx\n",
              signum, handler, sa->sa_mask.sig[0], sa->sa_flags);

    if (handler == SIG_IGN) {
        sig_debug("sigact == SIG_IGN\n");
        return;
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
            halt("unimplemented");
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
            halt("unimplemented");
            // core_dump(t);
            break;

        /* stop */
        case SIGSTOP:
        case SIGTSTP:
        case SIGTTIN:
        case SIGTTOU:
            msg_err("signal %d resulting in thread stop\n", signum);
            halt("unimplemented");
            // thread_stop(t);
            break;
            /* ignore */
        }

        /* ignore the rest */
        sig_debug("ignoring signal %d\n", signum);
        return;
    }

#if 0
    // XXX convince me
    /* thread may have blocked while signals are still pending; flush in case */
    if (t->blocked_on)
        blockq_flush_thread(t->blocked_on, t);
#endif

    /* set up and switch to the signal context */
    sig_debug("switching to sigframe: tid %d, sig %d, sigaction %p\n", t->tid, signum, sa);
    setup_sigframe(t, signum, &qs->si, 0);

    /* clean up and proceed to trampoline */
    free_queued_signal(qs);
    running_frame = t->sigframe;
}
