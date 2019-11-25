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
    ss->mask = normalize_signal_mask(mask);
}

static inline void sigstate_block(sigstate ss, u64 mask)
{
    ss->mask |= normalize_signal_mask(mask);
}

static inline void sigstate_unblock(sigstate ss, u64 mask)
{
    ss->mask &= ~mask;
}

static inline u64 sigstate_get_pending(sigstate ss)
{
    return ss->pending;
}

static inline u64 sigstate_get_ignored(sigstate ss)
{
    return ss->ignored;
}

static inline u64 sigstate_set_ignored(sigstate ss, u64 mask)
{
    return ss->ignored = normalize_signal_mask(mask);
}

static inline u64 get_all_pending_signals(thread t)
{
    // XXX ignored?
    return sigstate_get_pending(&t->signals) | sigstate_get_pending(&t->p->signals);
}

static inline u64 get_effective_sigmask(thread t)
{
    /* parent sigmask affects initial thread - otherwise ignored? */
    return sigstate_get_mask(&t->signals) & ~t->siginterest;
}

static inline u64 get_effective_signals(thread t)
{
    return get_all_pending_signals(t) & ~get_effective_sigmask(t);
}

static inline void sigstate_set_pending(sigstate ss, int sig)
{
    ss->pending |= mask_from_sig(sig);
}

static inline boolean sigstate_is_pending(sigstate ss, int sig)
{
    return (ss->pending & mask_from_sig(sig)) != 0;
}

static inline list sigstate_get_sighead(sigstate ss, int signum)
{
    assert(signum > 0 && signum <= NSIG);
    return &ss->heads[signum - 1];
}
