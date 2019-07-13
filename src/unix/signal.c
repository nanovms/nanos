#include <unix_internal.h>

//#define SIGNAL_DEBUG
#ifdef SIGNAL_DEBUG
#define sig_debug(x, ...) do {log_printf(" SIG", "%s: " x, __func__, ##__VA_ARGS__);} while(0)
#else
#define sig_debug(x, ...)
#endif

/* TODO

   restart_syscall ?
   seccomp ?
   
   sigaltstack *
   signal *
   signalfd
   sigpending *
   rt_sigprocmask *
   sigqueue ?
   rt_sigreturn *
   sigsuspend

   signal mask
   queueable / level?

   sig actions / defaults
 */

static inline u64 mask_from_sig(int sig)
{
    assert(sig > 0);
    return U64_FROM_BIT(sig - 1);
}

static inline u64 get_masked(thread t)
{
    return t->sigpending &
        (~t->sigmask | mask_from_sig(SIGKILL) | mask_from_sig(SIGSTOP));
}

typedef void * signal_handler;

static void __attribute__((section (".vdso"))) signal_trampoline(u32 signum,
                                                                 u64 sa_flags,
                                                                 signal_handler handler)
{
    /* XXX need to add mux for sigaction */
    if (handler) {
#if 0
        // XXX siginfo
        if ((sa_flags & SA_SIGINFO)) {

        }
#endif
        ((__sighandler_t)handler)(signum);
    }

    sysreturn rv;
    asm volatile("syscall" : "=a" (rv) : "0" (SYS_rt_sigreturn) : "memory");

    /* shouldn't return, handle error otherwise */
    assert(0);
}

void setup_sigframe(thread t, int signum, signal_handler handler)
{
    /* XXX prob should zero most of this, but not sure yet what needs
     * to be carried over */
    runtime_memcpy(t->sigframe, t->frame, sizeof(u64) * FRAME_MAX);

    /* XXX hack: stash %RAX which will get clobbered in a sig handler */
    t->rax_saved = t->frame[FRAME_RAX];

    /* XXX check for altstack */
    t->sigframe[FRAME_RIP] = u64_from_pointer(signal_trampoline);
    t->sigframe[FRAME_RDI] = signum;
    t->sigframe[FRAME_RSI] = 0; // XXX sa_mask
    t->sigframe[FRAME_RDX] = u64_from_pointer(handler);
}

/* XXX lock down / use access fns */
void dispatch_signals(thread t)
{
    /* propagate process pending and mask into thread */
    t->sigpending |= t->p->sigpending;
    t->sigmask |= t->p->sigmask;
    
    /* get masked pending signals */
    u64 masked = get_masked(t);
    if (masked == 0)
        return;

    sig_debug("tid %d, pending 0x%lx, mask 0x%lx, masked 0x%lx\n",
              t->tid, t->sigpending, t->sigmask, masked);

    /* select signal to dispatch and get disposition */
    int signum = msb(masked) + 1;  /* XXX TMP */
    signal_handler sigact = t->p->sigacts[signum - 1];
    sig_debug("selected signum %d, sigact %p\n", signum, sigact);

    /* XXX core dump */
    if (sigact == SIG_ERR) {
        msg_err("thread %d: core dump unimpl\n", t->tid);
        return;
    } else if (sigact == SIG_IGN) {
        sig_debug("sigact == SIG_IGN\n");
        return;
    } else if (sigact == SIG_DFL) {
        // XXX lookup if SIG_DFL
        return;
    }

    /* save current sigmask, mask sig */
    /* XXX wrap these up in static inlines */
    u64 mask = mask_from_sig(signum);
    t->sigsaved = t->sigmask;
    t->sigmask |= mask;
    t->sigpending &= ~mask;

    /* XXX process too */

    /* set up and switch to the signal context */
    sig_debug("switching to sigframe: tid %d, sig %d, sigact %p\n", t->tid, signum, sigact);
    setup_sigframe(t, signum, sigact);
    running_frame = t->sigframe;
}

sysreturn rt_sigreturn()
{
    thread t = current;
    sig_debug("tid %d\n", t->tid);

    /* reset signal mask */
    t->sigmask = t->sigsaved;
    t->sigsaved = infinity;

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

    if (oldact)
        oldact->_u._sa_handler = SIG_DFL;

    if (sigsetsize != (NSIG / 8)) {
        msg_err("sigsetsize (%ld) != NSIG (%ld)\n", sigsetsize, NSIG);
        return -EINVAL;
    }

    if (signum > NSIG) {
        msg_err("signum %d greater than NSIG\n", signum);
        return -EINVAL;
    }

    if (!act)
        return 0;

#if 0
    if ((act->sa_flags & SA_SIGINFO)) {

    }
#endif

    /* XXX some sanitizing of enum vals in order */
    void * handler = (signal_handler)act->_u._sa_handler;
    current->p->sigacts[signum - 1] = handler;
    sig_debug("installed handler %p\n", handler);
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

/* XXX add info */
void deliver_signal_thread(thread t, int signum)
{
    sig_debug("tid %d, sig %d\n", t->tid, signum);

    /* set pending */
    t->sigpending |= mask_from_sig(signum);
    u64 masked = get_masked(t);
    sig_debug("pending 0x%lx, masked 0x%lx\n", t->sigpending, masked);

    if (masked) {
        /* no stored blockq means we're not in an interruptible wait */
        if (!t->blocked_on)
            return;

        /* flush pending blockq */
        blockq_flush_thread(t->blocked_on, t);

        /* make runnable */
        thread_wakeup(t);
    }
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

    deliver_signal_thread(t, sig);
    return 0;
}

sysreturn tkill(int tid, int sig)
{
    return tgkill(0, tid, sig);
}

sysreturn kill(int pid, int sig)
{
    if (pid != current->p->pid)
        return -ESRCH;

    thread t;
    u64 mask = mask_from_sig(sig);

    // XXX fucked

    current->p->sigpending |= mask;
    vector_foreach(current->p->threads, t) {
        if (t && (~t->sigmask & mask) != 0) {
            deliver_signal_thread(t, sig);
            return 0;
        }
    }

    /* couldn't deliver directly, but marked as pending */
    return 0;
}

static CLOSURE_1_2(pause_bh, sysreturn,
                   thread,
                   boolean, boolean);
static sysreturn pause_bh(thread t, boolean blocked, boolean nullify)
{
    sig_debug("tid %d, blocked %d, nullify %d\n", t->tid, blocked, nullify);
    return nullify ? set_syscall_return(t, -EINTR) : infinity;
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
    register_syscall(map, rt_sigprocmask, rt_sigprocmask);
    register_syscall(map, rt_sigaction, rt_sigaction);
    register_syscall(map, rt_sigreturn, rt_sigreturn);
    register_syscall(map, sigaltstack, syscall_ignore);
    register_syscall(map, tgkill, tgkill);
    register_syscall(map, tkill, tkill);
    register_syscall(map, kill, kill);
    register_syscall(map, pause, pause);
}
