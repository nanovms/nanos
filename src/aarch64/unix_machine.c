#include <unix_internal.h>
#include <vdso-offset.h>

struct rt_sigframe *get_rt_sigframe(thread t)
{
    return pointer_from_u64(thread_frame(t)[SYSCALL_FRAME_SP]);
}

struct frame_record {
    u64 fp;
    u64 lr;
};

/*
 * Copy the context in frame 'f' to the ucontext *uctx
 */
static void setup_ucontext(struct ucontext *uctx, thread t)
{
    context_frame f = thread_frame(t);
    struct sigcontext * mcontext = &(uctx->uc_mcontext);

    mcontext->fault_address = f[FRAME_FAULT_ADDRESS];
    runtime_memcpy(mcontext->regs, f, sizeof(u64) * 31);
    mcontext->sp = f[FRAME_SP];
    mcontext->pc = f[FRAME_ELR];
    mcontext->pstate = f[FRAME_ESR_SPSR] & MASK(32);
    uctx->uc_sigmask.sig[0] = t->signal_mask;
}

static void setup_ucontext_fpsimd(struct ucontext *uctx, thread t)
{
    /* We're not building frames like Linux yet; just a fixed fpsimd_context for now... */
    context_frame f = thread_frame(t);
    u64 *fp = frame_extended(f);
    if (!fp)
        return;
    struct fpsimd_context *fpctx = (struct fpsimd_context *)uctx->uc_mcontext.reserved;
    fpctx->head.magic = FPSIMD_MAGIC;
    fpctx->head.size = sizeof(struct fpsimd_context);
    fpctx->fpsr = fp[FRAME_FPSR];
    fpctx->fpcr = fp[FRAME_FPCR];
    runtime_memcpy(fpctx->vregs, &fp[FRAME_Q0], sizeof(fpctx->vregs));
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
    sp = (sp - sizeof(struct frame_record)) & ~15;
    struct frame_record *rec = pointer_from_u64(sp);

    /* create space for rt_sigframe */
    sp -= pad(sizeof(struct rt_sigframe), 16);

    /* setup sigframe for user sig trampoline */
    struct rt_sigframe *frame = (struct rt_sigframe *)sp;

    context ctx = get_current_context(current_cpu());
    if (context_set_err(ctx))
        return false;
    setup_ucontext(&frame->uc, t);
    if (f[FRAME_TXCTX_FLAGS] & FRAME_TXCTX_FPSIMD_SAVED)
        setup_ucontext_fpsimd(&frame->uc, t);
    else
        *(u64*)(frame->uc.uc_mcontext.reserved) = 0; /* magic terminate */

    if (sa->sa_flags & SA_SIGINFO) {
        runtime_memcpy(&frame->info, si, sizeof(struct siginfo));
        f[FRAME_X1] = u64_from_pointer(&frame->info);
        f[FRAME_X2] = u64_from_pointer(&frame->uc);
    } else {
        f[FRAME_X1] = 0;
        f[FRAME_X2] = 0;
    }
    context_clear_err(ctx);
    f[FRAME_SP] = sp;

    /* setup regs for signal handler */
    f[FRAME_EL] = 0;
    f[FRAME_ELR] = u64_from_pointer(sa->sa_handler);
    f[FRAME_X0] = signum;
    f[FRAME_ESR_SPSR] &= ~SPSR_TCO;
    f[FRAME_X29] = u64_from_pointer(&rec->fp);
    f[FRAME_X30] = (sa->sa_flags & SA_RESTORER) ?
        u64_from_pointer(sa->sa_restorer) : t->p->vdso_base + VDSO_OFFSET_RT_SIGRETURN;

    /* TODO address BTI if supported */
    return true;
}

static void restore_ucontext_fpsimd(struct fpsimd_context *fpctx, thread t)
{
    /* We're not building frames like Linux yet; just a fixed fpsimd_context for now... */
    context_frame f = thread_frame(t);
    u64 *fp = frame_extended(f);
    if (!fp)
        return;
    fp[FRAME_FPSR] = fpctx->fpsr;
    fp[FRAME_FPCR] = fpctx->fpcr;
    runtime_memcpy(&fp[FRAME_Q0], fpctx->vregs, sizeof(fpctx->vregs));
}

/*
 * Copy the context from *uctx to the context in frame f
 */
void restore_ucontext(struct ucontext *uctx, thread t)
{
    context_frame f = thread_frame(t);
    struct sigcontext * mcontext = &(uctx->uc_mcontext);
    runtime_memcpy(f, mcontext->regs, sizeof(u64) * 31);
    f[FRAME_SP] = mcontext->sp;
    f[FRAME_ELR] = mcontext->pc;

    f[FRAME_ESR_SPSR] = (f[FRAME_ESR_SPSR] & ~MASK(32)) | (mcontext->pstate & MASK(32));
    t->signal_mask = normalize_signal_mask(uctx->uc_sigmask.sig[0]);

    struct _aarch64_ctx *actx = (struct _aarch64_ctx *)uctx->uc_mcontext.reserved;
    if (actx->magic == FPSIMD_MAGIC && actx->size == sizeof(struct fpsimd_context))
        restore_ucontext_fpsimd((struct fpsimd_context *)uctx->uc_mcontext.reserved, t);
}

void reg_copy_out(struct core_regs *r, thread t)
{
    context_frame f = thread_frame(t);
    runtime_memcpy(r, f, sizeof(u64) * 31);
    r->sp = f[FRAME_SP];
    r->pc = f[FRAME_ELR];
    r->pstate = f[FRAME_ESR_SPSR] & MASK(32);
}

struct fpsimd_state {
    u128 vregs[32];
    u32 fpsr;
    u32 fpcr;
    u32 reserved[2];
};

u64 fpreg_size(void)
{
    return sizeof(struct fpsimd_state);
}

void fpreg_copy_out(void *b, thread t)
{
    struct fpsimd_state *s = b;
    runtime_memset((void *)s, 0, sizeof(*s));
    context_frame f = thread_frame(t);
    u64 *fp = frame_extended(f);
    if (!fp)
        return;
    s->fpsr = fp[FRAME_FPSR];
    s->fpcr = fp[FRAME_FPCR];
    runtime_memcpy(s->vregs, &fp[FRAME_Q0], sizeof(s->vregs));
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
