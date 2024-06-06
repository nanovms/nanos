#include <unix_internal.h>
#include <synth.h>

#define VSYSCALL_OFFSET_VGETTIMEOFDAY   0x000
#define VSYSCALL_OFFSET_VTIME           0x400
#define VSYSCALL_OFFSET_VGETCPU         0x800

extern void * vsyscall_start;
extern void * vsyscall_end;

/* vsyscalls are deprecated -- just provide a simple emulation layer */
VSYSCALL sysreturn
vsyscall_gettimeofday(struct timeval * tv, void * tz)
{
    return do_syscall(SYS_gettimeofday, tv, tz);
}

VSYSCALL sysreturn
vsyscall_time(time_t * t)
{
    return do_syscall(SYS_time, t, 0);
}

VSYSCALL sysreturn
vsyscall_getcpu(unsigned * cpu, unsigned * node, void * tcache)
{
    if (cpu)
        *cpu = 0;
    if (node)
        *node = 0;
    return 0;
}

/*
 * Init legacy vsyscall support
 */
void init_vsyscall(heap phys)
{
    /* build vsyscall vectors */
    u64 p = allocate_u64(phys, PAGESIZE);
    assert(p != INVALID_PHYSICAL);
    pageflags flags = pageflags_exec(pageflags_default_user());
    map(VSYSCALL_BASE, p, PAGESIZE, pageflags_writable(flags));

    buffer b = alloca_wrap_buffer(pointer_from_u64(VSYSCALL_BASE), PAGESIZE);
    b->end = VSYSCALL_OFFSET_VGETTIMEOFDAY;
    mov_64_imm(b, 0, u64_from_pointer(vsyscall_gettimeofday));
    jump_indirect(b, 0);

    b->end = VSYSCALL_OFFSET_VTIME;
    mov_64_imm(b, 0, u64_from_pointer(vsyscall_time));
    jump_indirect(b, 0);

    b->end = VSYSCALL_OFFSET_VGETCPU;
    mov_64_imm(b, 0, u64_from_pointer(vsyscall_getcpu));
    jump_indirect(b, 0);
    update_map_flags(VSYSCALL_BASE, PAGESIZE, flags);

    /* allow user execution for vsyscall pages */
    u64 vs = u64_from_pointer(&vsyscall_start);
    u64 ve = u64_from_pointer(&vsyscall_end);
    u64 len = pad(ve - vs, PAGESIZE);
    update_map_flags(vs, len, flags);
}

struct rt_sigframe *get_rt_sigframe(thread t)
{
    /* sigframe sits at %rsp minus the return address word (pretcode) */
    return (struct rt_sigframe *)(thread_frame(t)[FRAME_RSP] - sizeof(u64));
}

/*
 * Copy the context in frame 'f' to the ucontext *uctx
 */
static void setup_ucontext(struct ucontext *uctx, thread t, void *fpstate)
{
    context_frame f = thread_frame(t);
    struct sigcontext * mcontext = &(uctx->uc_mcontext);

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
    mcontext->eflags = f[FRAME_EFLAGS];
    mcontext->cs = f[FRAME_CS];
    mcontext->ss = f[FRAME_SS];
    mcontext->fs = 0;
    mcontext->gs = 0;
    mcontext->err = f[FRAME_ERROR_CODE];
    mcontext->trapno = f[FRAME_VECTOR];
    mcontext->oldmask = t->signal_mask;
    mcontext->cr2 = f[FRAME_CR2];
    mcontext->fpstate = fpstate;
}

static u64 setup_ucontext_fpstate(void **fpstate, thread t, u64 rsp)
{
    rsp -= pad(extended_frame_size, 16);
    *fpstate = pointer_from_u64(rsp);
    runtime_memcpy(*fpstate, frame_extended(t->context.frame), extended_frame_size);
    return rsp;
}

boolean setup_sigframe(thread t, int signum, struct siginfo *si)
{
    sigaction sa = sigaction_from_sig(t, signum);

    assert(sizeof(struct siginfo) == 128);

    context_frame f = thread_frame(t);
    u64 rsp;

    if ((sa->sa_flags & SA_ONSTACK) && t->signal_stack)
        rsp = u64_from_pointer(t->signal_stack + t->signal_stack_length);
    else
        rsp = f[FRAME_RSP];

    /* avoid redzone */
    rsp = (rsp & ~15) - 128;

    context ctx = get_current_context(current_cpu());
    if (context_set_err(ctx))
        return false;
    void *fpstate;
    rsp = setup_ucontext_fpstate(&fpstate, t, rsp);

    /* Create space for rt_sigframe. Note that we are actually aligning to 8
       but not 16 bytes; the ABI requires that stacks are aligned to 16 before
       a call, but the sigframe return into the function takes the place of a
       call, which would have pushed a return address. The function prologue
       typically pushes the frame pointer on the stack, thus re-aligning to 16
       before executing the function body. */
    rsp -= pad(sizeof(struct rt_sigframe), 16) + 8; /* ra offset */

    /* setup sigframe for user sig trampoline */
    struct rt_sigframe *frame = (struct rt_sigframe *)rsp;
    frame->pretcode = sa->sa_restorer;

    if (sa->sa_flags & SA_SIGINFO)
        runtime_memcpy(&frame->info, si, sizeof(struct siginfo));
    setup_ucontext(&frame->uc, t, fpstate);
    f[FRAME_RSP] = rsp;
    f[FRAME_RSI] = u64_from_pointer(&frame->info);
    f[FRAME_RDX] = u64_from_pointer(&frame->uc);

    /* setup regs for signal handler */
    f[FRAME_RIP] = u64_from_pointer(sa->sa_handler);
    f[FRAME_RDI] = signum;
    context_clear_err(ctx);
    return true;
}

/*
 * Copy the context from *uctx to the context in frame f
 */
void restore_ucontext(struct ucontext * uctx, thread t)
{
    context_frame f = thread_frame(t);
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
    f[FRAME_EFLAGS] = (f[FRAME_EFLAGS] & ~SAFE_EFLAGS) | (mcontext->eflags & SAFE_EFLAGS);
    /* Don't trust segment selector values (CS and SS) that may have been modified by the process,
     * because invalid values can cause a general protection fault (in kernel mode) when trying to
     * resume this thread. Only copy the low bit of the CS field, which indicates whether the sysret
     * or iret path should be taken to resume the thread. */
    if (mcontext->cs & 1)
        f[FRAME_CS] |= 1;
    else
        f[FRAME_CS] &= ~1;
    t->signal_mask = normalize_signal_mask(mcontext->oldmask);
    if (mcontext->fpstate)
        runtime_memcpy(frame_extended(t->context.frame), mcontext->fpstate, extended_frame_size);
}

void reg_copy_out(struct core_regs *r, thread t)
{
    r->r15 = t->context.frame[FRAME_R15];
    r->r14 = t->context.frame[FRAME_R14];
    r->r13 = t->context.frame[FRAME_R13];
    r->r12 = t->context.frame[FRAME_R12];
    r->bp = t->context.frame[FRAME_RBP];
    r->bx = t->context.frame[FRAME_RBX];
    r->r11 = t->context.frame[FRAME_R11];
    r->r10 = t->context.frame[FRAME_R10];
    r->r9 = t->context.frame[FRAME_R9];
    r->r8 = t->context.frame[FRAME_R8];
    r->ax = t->context.frame[FRAME_RAX];
    r->cx = t->context.frame[FRAME_RCX];
    r->dx = t->context.frame[FRAME_RDX];
    r->si = t->context.frame[FRAME_RSI];
    r->di = t->context.frame[FRAME_RDI];
    r->orig_ax = t->context.frame[FRAME_SAVED_RAX];
    r->ip = t->context.frame[FRAME_RIP];
    r->cs = t->context.frame[FRAME_CS];
    r->flags = t->context.frame[FRAME_EFLAGS];
    r->sp = t->context.frame[FRAME_RSP];
    r->ss = t->context.frame[FRAME_SS];
    r->fs_base = t->context.frame[FRAME_FSBASE];
    r->gs_base = t->context.frame[FRAME_GSBASE];
    r->ds = t->context.frame[FRAME_DS];
    r->es = t->context.frame[FRAME_ES];
    r->fs = 0; // XXX ?
    r->gs = 0; // XXX ?
}

#define FPREG_SIZE 0x200 /* this is the size in a Linux core, defined anywhere else? */

u64 fpreg_size(void)
{
    return MIN(FPREG_SIZE, extended_frame_size);
}

void fpreg_copy_out(void *b, thread t)
{
    runtime_memcpy(b, pointer_from_u64(t->context.frame[FRAME_EXTENDED]),
        fpreg_size());
}

void register_other_syscalls(struct syscall *map)
{
    register_syscall(map, wait4, syscall_ignore);
    register_syscall(map, flock, syscall_ignore);
    register_syscall(map, chmod, syscall_ignore);
    register_syscall(map, fchmod, syscall_ignore);
    register_syscall(map, fchown, syscall_ignore);
    register_syscall(map, lchown, syscall_ignore);
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

