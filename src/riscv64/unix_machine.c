#include <unix_internal.h>
#include <vdso-offset.h>

struct rt_sigframe *get_rt_sigframe(thread t)
{
    return pointer_from_u64(thread_frame(t)[FRAME_SP]);
}

static void setup_ucontext(struct ucontext *uctx, thread t)
{
    context_frame f = thread_frame(t);
    struct sigcontext *mcontext = &uctx->uc_mcontext;

    runtime_memcpy(&mcontext->sc_regs, f, sizeof(u64) * 32);
    uctx->uc_sigmask.sig[0] = t->signal_mask;
}

static void copy_fpsimd(void *b, thread t)
{
    context_frame f = thread_frame(t);
    struct __riscv_d_ext_state *fpctx = b;

    fpctx->fcsr = f[FRAME_FCSR];
    runtime_memcpy(fpctx->f, &f[FRAME_F0], sizeof(u64) * 32);
}

static void setup_ucontext_fpsimd(struct ucontext *uctx, thread t)
{
    copy_fpsimd(&uctx->uc_mcontext.sc_fpregs.d, t);
}

boolean setup_sigframe(thread t, int signum, struct siginfo *si)
{
    sigaction sa = sigaction_from_sig(t, signum);

    assert(sizeof(struct siginfo) == 128);

    context_frame f = thread_frame(t);
    u64 sp;

    if ((sa->sa_flags & SA_ONSTACK) && t->signal_stack)
        sp = u64_from_pointer(t->signal_stack + t->signal_stack_length);
    else
        sp = f[FRAME_SP];

    /* align sp */
    sp = sp & ~15;

    /* create space for rt_sigframe */
    sp -= pad(sizeof(struct rt_sigframe), 16);

    /* setup sigframe for user sig trampoline */
    struct rt_sigframe *frame = (struct rt_sigframe *)sp;

    context ctx = get_current_context(current_cpu());
    if (context_set_err(ctx))
        return false;
    setup_ucontext(&frame->uc, t);
    setup_ucontext_fpsimd(&frame->uc, t);   // XXX should only be sometimes

    if (sa->sa_flags & SA_SIGINFO) {
        runtime_memcpy(&frame->info, si, sizeof(struct siginfo));
        f[FRAME_A1] = u64_from_pointer(&frame->info);
        f[FRAME_A2] = u64_from_pointer(&frame->uc);
    } else {
        f[FRAME_A1] = 0;
        f[FRAME_A2] = 0;
    }
    context_clear_err(ctx);
    f[FRAME_SP] = sp;

    /* setup regs for signal handler */
    f[FRAME_PC] = u64_from_pointer(sa->sa_handler);
    f[FRAME_A0] = signum;
    f[FRAME_RA] = (sa->sa_flags & SA_RESTORER) ?
        u64_from_pointer(sa->sa_restorer) : t->p->vdso_base + VDSO_OFFSET_RT_SIGRETURN;
    return true;
}

void restore_ucontext_fpsimd(struct __riscv_d_ext_state *d, thread t)
{
    context_frame f = thread_frame(t);
    f[FRAME_FCSR] = d->fcsr;
    runtime_memcpy(&f[FRAME_F0], d, sizeof(u64) * 32);
}

void restore_ucontext(struct ucontext *uctx, thread t)
{
    context_frame f = thread_frame(t);
    struct sigcontext *mcontext = &uctx->uc_mcontext;
    runtime_memcpy(f, &mcontext->sc_regs, sizeof(u64) * 32);
    t->signal_mask = normalize_signal_mask(uctx->uc_sigmask.sig[0]);
    restore_ucontext_fpsimd(&mcontext->sc_fpregs.d, t);
}

void reg_copy_out(struct core_regs *r, thread t)
{
    context_frame f = thread_frame(t);
    runtime_memcpy((void *)r, f, sizeof(*r));
}

u64 fpreg_size(void)
{
    return sizeof(struct __riscv_d_ext_state);
}

void fpreg_copy_out(void *b, thread t)
{
    copy_fpsimd(b, t);
}

void register_other_syscalls(struct syscall *map)
{
    register_syscall(map, wait4, syscall_ignore);
    register_syscall(map, flock, syscall_ignore);
    register_syscall(map, fchmod, syscall_ignore);
    register_syscall(map, fchown, syscall_ignore);
    register_syscall(map, getgid, syscall_ignore);
    register_syscall(map, getegid, syscall_ignore);
    register_syscall(map, mlock, syscall_ignore);
    register_syscall(map, munlock, syscall_ignore);
    register_syscall(map, mlockall, syscall_ignore);
    register_syscall(map, munlockall, syscall_ignore);
    register_syscall(map, fchownat, syscall_ignore);
    register_syscall(map, fchmodat, syscall_ignore);
    register_syscall(map, mlock2, syscall_ignore);
}

