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
    /* Propagate process-level pending and mask before evaluating our own
       XXX p spinlock */
    t->sigpending |= t->p->sigpending;
    t->sigmask |= t->p->sigmask;

    return t->sigpending &
        (~t->sigmask | mask_from_sig(SIGKILL) | mask_from_sig(SIGSTOP));
}

static inline sigaction get_sigaction(int signum)
{
    return &current->p->sigactions[signum - 1];
}

static inline list get_sighead(thread t, int signum)
{
    assert(signum > 0 && signum <= 64);
    return &t->sigheads[signum - 1];
}

static void __attribute__((section (".vdso"))) signal_trampoline(u32 signum,
                                                                 void *handler,
                                                                 siginfo_t *siginfo,
                                                                 void *ucontext)
{
    /* XXX need to add mux for sigaction */
    if (siginfo) {
        ((__sigaction_t)handler)(signum, siginfo, ucontext);
    } else {
        ((__sighandler_t)handler)(signum);
    }

    sysreturn rv;
    asm volatile("syscall" : "=a" (rv) : "0" (SYS_rt_sigreturn) : "memory");

    /* shouldn't return, handle error otherwise */
    assert(0);
}

typedef struct queued_signal {
    struct siginfo si;
    struct list l;
} *queued_signal;

void setup_sigframe(thread t, int signum, struct siginfo *si, void * ucontext)
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
    heap h = heap_general((kernel_heaps)&t->uh);

    /* get masked pending signals */
    u64 masked = get_masked(t);
    if (masked == 0)
        return;

    sig_debug("tid %d, t->sigpending 0x%lx, mask 0x%lx, masked 0x%lx\n",
              t->tid, t->sigpending, t->sigmask, masked);

    /* select signal to dispatch */
    int signum = msb(masked) + 1;  /* XXX TMP */

    /* act on signal disposition */
    sigaction sa = get_sigaction(signum);
    void * handler = sa->sa_handler;

    sig_debug("dispatching signal %d; sigaction handler %p, sa_mask 0x%lx, sa_flags 0x%lx\n",
              signum, handler, sa->sa_mask.sig[0], sa->sa_flags);

    //
    //
    //

    /* XXX core dump */
    if (handler == SIG_ERR) {
        msg_err("thread %d: core dump unimpl\n", t->tid);
        return;
    } else if (handler == SIG_IGN) {
        sig_debug("sigact == SIG_IGN\n");
        return;
    } else if (handler == SIG_DFL) {
        // XXX lookup if SIG_DFL
        return;
    }

    // XXX convince me
    /* thread may have blocked while signals are still pending; flush in case */
    blockq_flush_thread(t->blocked_on, t);

    /* dequeue siginfo */
    list l = list_get_next(get_sighead(t, signum));
    assert(l);
    queued_signal q = struct_from_list(l, queued_signal, l);

    sig_debug("queued_signal %p, prev addr %p, prev %p, next %p\n",
              q, &l->prev, l->prev, l->next);
    list_delete(l);

    /* stash sigmask, or in mask for handler */
    u64 mask = mask_from_sig(signum);
    t->sigsaved = t->sigmask;
    t->sigmask |= mask | sa->sa_mask.sig[0];

    /* XXX need lock here */
    if (list_empty(get_sighead(t, signum)))
        t->sigpending &= ~mask;

    /* XXX process too */

    /* set up and switch to the signal context */
    sig_debug("switching to sigframe: tid %d, sig %d, sigaction %p\n", t->tid, signum, sa);
    setup_sigframe(t, signum, &q->si, 0);
    deallocate(h, q, sizeof(struct queued_signal));
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
        *oldact = *sa;

    if (!act)
        return 0;

    /* we should sanitize values ... */
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

void deliver_signal_to_thread(thread t, struct siginfo *info)
{
    sig_debug("tid %d, sig %d\n", t->tid, info->si_signo);

    /* check if we can post */
    u64 sigmask = mask_from_sig(info->si_signo);
    if (t->sigpending & sigmask) {
        if (info->si_signo < RT_SIG_START) {
            /* Standard signal already posted. Unless a particular
               signal would allow the updating of posted siginfo, just
               return here. */
            sig_debug("already posted; ignore\n");
            return;
        }
    }

    /* set pending and enqueue */
//    p->sigpending |= sigmask;   /* XXX tricky part - separate saved mask for process? */
    t->sigpending |= sigmask;
    heap h = heap_general((kernel_heaps)&t->uh);
    queued_signal qs = allocate(h, sizeof(struct queued_signal));
    assert(qs != INVALID_ADDRESS);
    runtime_memcpy(&qs->si, info, sizeof(struct siginfo));
    list_insert_before(get_sighead(t, info->si_signo), &qs->l);
    sig_debug("queued_signal %p, signo %d, errno %d, code %d\n",
              qs, qs->si.si_signo, qs->si.si_errno, qs->si.si_code);
    sig_debug("prev %p, next %p\n", qs->l.prev, qs->l.next);
    sig_debug("next prev %p, next %p\n", qs->l.next->prev, qs->l.next->next);

    /* queue for delivery */
    u64 masked = get_masked(t);
    sig_debug("pending 0x%lx, masked 0x%lx\n", t->sigpending, masked);
    if (masked) {
        /* no stored blockq means we're not in an interruptible wait */
        if (!t->blocked_on)
            return;

        /* flush pending blockq */
        if (blockq_flush_thread(t->blocked_on, t)) {
            /* make runnable */
            thread_wakeup(t);
        }
    }
}

void init_siginfo(struct siginfo *si, int sig, s32 code)
{
    zero(si, sizeof(struct siginfo));
    si->si_signo = sig;
    si->si_code = code;
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
    if (pid != current->p->pid)
        return -ESRCH;

    thread t;
    u64 mask = mask_from_sig(sig);

    // XXX fucked

    current->p->sigpending |= mask;
    vector_foreach(current->p->threads, t) {
        if (t && (~t->sigmask & mask) != 0) {
            struct siginfo si;
            init_siginfo(&si, sig, SI_USER);
            deliver_signal_to_thread(t, &si);
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

    if (nullify || get_masked(t))
        return set_syscall_return(t, -EINTR);

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
    register_syscall(map, rt_sigprocmask, rt_sigprocmask);
    register_syscall(map, rt_sigaction, rt_sigaction);
    register_syscall(map, rt_sigreturn, rt_sigreturn);
    register_syscall(map, sigaltstack, syscall_ignore);
    register_syscall(map, tgkill, tgkill);
    register_syscall(map, tkill, tkill);
    register_syscall(map, kill, kill);
    register_syscall(map, pause, pause);
}
