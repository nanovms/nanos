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
    u64 *fp = pointer_from_u64(f[FRAME_EXTENDED]);
    if (!fp)
        return;
    struct fpsimd_context *fpctx = (struct fpsimd_context *)uctx->uc_mcontext.reserved;
    fpctx->head.magic = FPSIMD_MAGIC;
    fpctx->head.size = sizeof(struct fpsimd_context);
    fpctx->fpsr = fp[FRAME_FPSR];
    fpctx->fpcr = fp[FRAME_FPCR];
    runtime_memcpy(fpctx->vregs, &fp[FRAME_Q0], sizeof(fpctx->vregs));
}

void setup_sigframe(thread t, int signum, struct siginfo *si)
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
}

static void restore_ucontext_fpsimd(struct fpsimd_context *fpctx, thread t)
{
    /* We're not building frames like Linux yet; just a fixed fpsimd_context for now... */
    context_frame f = thread_frame(t);
    u64 *fp = pointer_from_u64(f[FRAME_EXTENDED]);
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

void register_other_syscalls(struct syscall *map)
{
    register_syscall(map, shmget, 0);
    register_syscall(map, shmat, 0);
    register_syscall(map, shmctl, 0);
    register_syscall(map, execve, 0);
    register_syscall(map, wait4, syscall_ignore);
    register_syscall(map, semget, 0);
    register_syscall(map, semop, 0);
    register_syscall(map, semctl, 0);
    register_syscall(map, shmdt, 0);
    register_syscall(map, msgget, 0);
    register_syscall(map, msgsnd, 0);
    register_syscall(map, msgrcv, 0);
    register_syscall(map, msgctl, 0);
    register_syscall(map, flock, syscall_ignore);
    register_syscall(map, fchmod, syscall_ignore);
    register_syscall(map, fchown, syscall_ignore);
    register_syscall(map, ptrace, 0);
    register_syscall(map, syslog, 0);
    register_syscall(map, getgid, syscall_ignore);
    register_syscall(map, getegid, syscall_ignore);
    register_syscall(map, setpgid, 0);
    register_syscall(map, getppid, 0);
    register_syscall(map, setsid, 0);
    register_syscall(map, setreuid, 0);
    register_syscall(map, setregid, 0);
    register_syscall(map, getgroups, 0);
    register_syscall(map, setresuid, 0);
    register_syscall(map, getresuid, 0);
    register_syscall(map, setresgid, 0);
    register_syscall(map, getresgid, 0);
    register_syscall(map, getpgid, 0);
    register_syscall(map, setfsuid, 0);
    register_syscall(map, setfsgid, 0);
    register_syscall(map, getsid, 0);
    register_syscall(map, personality, 0);
    register_syscall(map, getpriority, 0);
    register_syscall(map, setpriority, 0);
    register_syscall(map, sched_setparam, 0);
    register_syscall(map, sched_getparam, 0);
    register_syscall(map, sched_setscheduler, 0);
    register_syscall(map, sched_getscheduler, 0);
    register_syscall(map, sched_get_priority_max, 0);
    register_syscall(map, sched_get_priority_min, 0);
    register_syscall(map, sched_rr_get_interval, 0);
    register_syscall(map, mlock, syscall_ignore);
    register_syscall(map, munlock, syscall_ignore);
    register_syscall(map, mlockall, syscall_ignore);
    register_syscall(map, munlockall, syscall_ignore);
    register_syscall(map, vhangup, 0);
    register_syscall(map, pivot_root, 0);
    register_syscall(map, adjtimex, 0);
    register_syscall(map, chroot, 0);
    register_syscall(map, acct, 0);
    register_syscall(map, settimeofday, 0);
    register_syscall(map, mount, 0);
    register_syscall(map, umount2, 0);
    register_syscall(map, swapon, 0);
    register_syscall(map, swapoff, 0);
    register_syscall(map, reboot, 0);
    register_syscall(map, sethostname, 0);
    register_syscall(map, setdomainname, 0);
    register_syscall(map, init_module, 0);
    register_syscall(map, delete_module, 0);
    register_syscall(map, quotactl, 0);
    register_syscall(map, nfsservctl, 0);
    register_syscall(map, readahead, 0);
    register_syscall(map, setxattr, 0);
    register_syscall(map, lsetxattr, 0);
    register_syscall(map, fsetxattr, 0);
    register_syscall(map, getxattr, 0);
    register_syscall(map, lgetxattr, 0);
    register_syscall(map, fgetxattr, 0);
    register_syscall(map, listxattr, 0);
    register_syscall(map, llistxattr, 0);
    register_syscall(map, flistxattr, 0);
    register_syscall(map, removexattr, 0);
    register_syscall(map, lremovexattr, 0);
    register_syscall(map, fremovexattr, 0);
    register_syscall(map, io_cancel, 0);
    register_syscall(map, lookup_dcookie, 0);
    register_syscall(map, remap_file_pages, 0);
    register_syscall(map, restart_syscall, 0);
    register_syscall(map, semtimedop, 0);
    register_syscall(map, clock_settime, 0);
    register_syscall(map, mbind, 0);
    register_syscall(map, set_mempolicy, 0);
    register_syscall(map, get_mempolicy, 0);
    register_syscall(map, mq_open, 0);
    register_syscall(map, mq_unlink, 0);
    register_syscall(map, mq_timedsend, 0);
    register_syscall(map, mq_timedreceive, 0);
    register_syscall(map, mq_notify, 0);
    register_syscall(map, mq_getsetattr, 0);
    register_syscall(map, kexec_load, 0);
    register_syscall(map, waitid, 0);
    register_syscall(map, add_key, 0);
    register_syscall(map, request_key, 0);
    register_syscall(map, keyctl, 0);
    register_syscall(map, ioprio_set, 0);
    register_syscall(map, ioprio_get, 0);
    register_syscall(map, migrate_pages, 0);
    register_syscall(map, mknodat, 0);
    register_syscall(map, fchownat, syscall_ignore);
    register_syscall(map, linkat, 0);
    register_syscall(map, fchmodat, syscall_ignore);
    register_syscall(map, unshare, 0);
    register_syscall(map, splice, 0);
    register_syscall(map, tee, 0);
    register_syscall(map, sync_file_range, 0);
    register_syscall(map, vmsplice, 0);
    register_syscall(map, move_pages, 0);
    register_syscall(map, utimensat, 0);
    register_syscall(map, preadv, 0);
    register_syscall(map, pwritev, 0);
    register_syscall(map, perf_event_open, 0);
    register_syscall(map, recvmmsg, 0);
    register_syscall(map, fanotify_init, 0);
    register_syscall(map, fanotify_mark, 0);
    register_syscall(map, name_to_handle_at, 0);
    register_syscall(map, open_by_handle_at, 0);
    register_syscall(map, clock_adjtime, 0);
    register_syscall(map, setns, 0);
    register_syscall(map, process_vm_readv, 0);
    register_syscall(map, process_vm_writev, 0);
    register_syscall(map, kcmp, 0);
    register_syscall(map, finit_module, 0);
    register_syscall(map, sched_setattr, 0);
    register_syscall(map, sched_getattr, 0);
    register_syscall(map, seccomp, 0);
    register_syscall(map, memfd_create, 0);
    register_syscall(map, kexec_file_load, 0);
    register_syscall(map, bpf, 0);
    register_syscall(map, execveat, 0);
    register_syscall(map, userfaultfd, 0);
    register_syscall(map, membarrier, 0);
    register_syscall(map, mlock2, syscall_ignore);
    register_syscall(map, copy_file_range, 0);
    register_syscall(map, preadv2, 0);
    register_syscall(map, pwritev2, 0);
    register_syscall(map, pkey_mprotect, 0);
    register_syscall(map, pkey_alloc, 0);
    register_syscall(map, pkey_free, 0);
}
