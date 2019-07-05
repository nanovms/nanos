#include <unix_internal.h>

#define SIGNAL_DEBUG
#ifdef SIGNAL_DEBUG
#define sig_debug(x, ...) do {log_printf(" SIG", "%s: " x, __func__, ##__VA_ARGS__);} while(0)
#else
#define sig_debug(x, ...)
#endif

/* 

   syscalls:

      kill *
      pause
      restart_syscall ?
      seccomp ?
   
      rt_sigaction *
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
    asm("syscall" : "=a" (rv) : "0" (SYS_rt_sigreturn) : "memory");
    /* shouldn't return, handle error otherwise */
}

void setup_sigframe(thread t, int signum, signal_handler handler)
{
    /* XXX prob should zero most of this, but not sure yet what needs
     * to be carried over */
    runtime_memcpy(t->sigframe, t->frame, sizeof(u64) * FRAME_MAX);

    /* XXX check for altstack */
    t->sigframe[FRAME_RIP] = u64_from_pointer(signal_trampoline);
    t->sigframe[FRAME_RDI] = signum;
    t->sigframe[FRAME_RSI] = 0; // XXX sa_mask
    t->sigframe[FRAME_RDX] = u64_from_pointer(handler);
}

/* XXX lock down / use access fns */
void dispatch_signals(thread t)
{
    /* propagate process pending into thread pending */
    t->sigpending = t->p->sigpending;
    
    /* get masked pending signals */
    u64 masked = t->sigpending & t->sigmask;
    if (masked == 0)
        return;

    /* select signal to dispatch and get disposition */
    int signum = msb(masked) + 1;  /* XXX TMP */
    signal_handler sigact = t->p->sigacts[signum];

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
    u64 sigword = U64_FROM_BIT(signum - 1);
    t->sigsaved = t->sigmask;
    t->sigmask |= sigword;
    t->sigpending &= ~sigword;
    
    /* set up and switch to the signal context */
    setup_sigframe(t, signum, sigact);
    running_frame = t->sigframe;
}

sysreturn rt_sigreturn()
{
    thread t = current;

    if (running_frame != t->sigframe) {
        msg_err("foooooo\n");
    }

    /* reset signal mask */
    t->sigmask = t->sigsaved;
    t->sigsaved = infinity;

    /* restore saved context */
    running_frame = t->frame;

    /* return - XXX or reschedule? */
    IRETURN(running_frame);
    return 0;
}

sysreturn rt_sigaction(int signum,
                       const struct sigaction *act,
                       struct sigaction *oldact,
                       u64 sigsetsize)
{
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
    current->p->sigacts[signum] = (signal_handler)act->_u._sa_handler;

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

void register_signal_syscalls(struct syscall *map)
{
    register_syscall(map, rt_sigprocmask, rt_sigprocmask);
    register_syscall(map, rt_sigaction, rt_sigaction);
    register_syscall(map, rt_sigreturn, rt_sigreturn);
    register_syscall(map, sigaltstack, syscall_ignore);
}
