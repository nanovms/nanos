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
    register_syscall(map, shmget, 0, 0);
    register_syscall(map, shmat, 0, 0);
    register_syscall(map, shmctl, 0, 0);
    register_syscall(map, execve, 0, 0);
    register_syscall(map, wait4, syscall_ignore, 0);
    register_syscall(map, semget, 0, 0);
    register_syscall(map, semop, 0, 0);
    register_syscall(map, semctl, 0, 0);
    register_syscall(map, shmdt, 0, 0);
    register_syscall(map, msgget, 0, 0);
    register_syscall(map, msgsnd, 0, 0);
    register_syscall(map, msgrcv, 0, 0);
    register_syscall(map, msgctl, 0, 0);
    register_syscall(map, flock, syscall_ignore, 0);
    register_syscall(map, fchmod, syscall_ignore, 0);
    register_syscall(map, fchown, syscall_ignore, 0);
    register_syscall(map, ptrace, 0, 0);
    register_syscall(map, syslog, 0, 0);
    register_syscall(map, getgid, syscall_ignore, 0);
    register_syscall(map, getegid, syscall_ignore, 0);
    register_syscall(map, setpgid, 0, 0);
    register_syscall(map, getppid, 0, 0);
    register_syscall(map, setsid, 0, 0);
    register_syscall(map, setreuid, 0, 0);
    register_syscall(map, setregid, 0, 0);
    register_syscall(map, getgroups, 0, 0);
    register_syscall(map, setresuid, 0, 0);
    register_syscall(map, getresuid, 0, 0);
    register_syscall(map, setresgid, 0, 0);
    register_syscall(map, getresgid, 0, 0);
    register_syscall(map, getpgid, 0, 0);
    register_syscall(map, setfsuid, 0, 0);
    register_syscall(map, setfsgid, 0, 0);
    register_syscall(map, getsid, 0, 0);
    register_syscall(map, personality, 0, 0);
    register_syscall(map, getpriority, 0, 0);
    register_syscall(map, setpriority, 0, 0);
    register_syscall(map, sched_setparam, 0, 0);
    register_syscall(map, sched_getparam, 0, 0);
    register_syscall(map, sched_setscheduler, 0, 0);
    register_syscall(map, sched_getscheduler, 0, 0);
    register_syscall(map, sched_get_priority_max, 0, 0);
    register_syscall(map, sched_get_priority_min, 0, 0);
    register_syscall(map, sched_rr_get_interval, 0, 0);
    register_syscall(map, mlock, syscall_ignore, 0);
    register_syscall(map, munlock, syscall_ignore, 0);
    register_syscall(map, mlockall, syscall_ignore, 0);
    register_syscall(map, munlockall, syscall_ignore, 0);
    register_syscall(map, vhangup, 0, 0);
    register_syscall(map, pivot_root, 0, 0);
    register_syscall(map, adjtimex, 0, 0);
    register_syscall(map, chroot, 0, 0);
    register_syscall(map, acct, 0, 0);
    register_syscall(map, mount, 0, 0);
    register_syscall(map, umount2, 0, 0);
    register_syscall(map, swapon, 0, 0);
    register_syscall(map, swapoff, 0, 0);
    register_syscall(map, reboot, 0, 0);
    register_syscall(map, sethostname, 0, 0);
    register_syscall(map, setdomainname, 0, 0);
    register_syscall(map, init_module, 0, 0);
    register_syscall(map, delete_module, 0, 0);
    register_syscall(map, quotactl, 0, 0);
    register_syscall(map, nfsservctl, 0, 0);
    register_syscall(map, readahead, 0, 0);
    register_syscall(map, setxattr, 0, 0);
    register_syscall(map, lsetxattr, 0, 0);
    register_syscall(map, fsetxattr, 0, 0);
    register_syscall(map, getxattr, 0, 0);
    register_syscall(map, lgetxattr, 0, 0);
    register_syscall(map, fgetxattr, 0, 0);
    register_syscall(map, listxattr, 0, 0);
    register_syscall(map, llistxattr, 0, 0);
    register_syscall(map, flistxattr, 0, 0);
    register_syscall(map, removexattr, 0, 0);
    register_syscall(map, lremovexattr, 0, 0);
    register_syscall(map, fremovexattr, 0, 0);
    register_syscall(map, io_cancel, 0, 0);
    register_syscall(map, lookup_dcookie, 0, 0);
    register_syscall(map, remap_file_pages, 0, 0);
    register_syscall(map, restart_syscall, 0, 0);
    register_syscall(map, semtimedop, 0, 0);
    register_syscall(map, mbind, 0, 0);
    register_syscall(map, set_mempolicy, 0, 0);
    register_syscall(map, get_mempolicy, 0, 0);
    register_syscall(map, mq_open, 0, 0);
    register_syscall(map, mq_unlink, 0, 0);
    register_syscall(map, mq_timedsend, 0, 0);
    register_syscall(map, mq_timedreceive, 0, 0);
    register_syscall(map, mq_notify, 0, 0);
    register_syscall(map, mq_getsetattr, 0, 0);
    register_syscall(map, kexec_load, 0, 0);
    register_syscall(map, waitid, 0, 0);
    register_syscall(map, add_key, 0, 0);
    register_syscall(map, request_key, 0, 0);
    register_syscall(map, keyctl, 0, 0);
    register_syscall(map, ioprio_set, 0, 0);
    register_syscall(map, ioprio_get, 0, 0);
    register_syscall(map, migrate_pages, 0, 0);
    register_syscall(map, mknodat, 0, 0);
    register_syscall(map, fchownat, syscall_ignore, 0);
    register_syscall(map, linkat, 0, 0);
    register_syscall(map, fchmodat, syscall_ignore, 0);
    register_syscall(map, unshare, 0, 0);
    register_syscall(map, splice, 0, 0);
    register_syscall(map, tee, 0, 0);
    register_syscall(map, sync_file_range, 0, 0);
    register_syscall(map, vmsplice, 0, 0);
    register_syscall(map, move_pages, 0, 0);
    register_syscall(map, perf_event_open, 0, 0);
    register_syscall(map, fanotify_init, 0, 0);
    register_syscall(map, fanotify_mark, 0, 0);
    register_syscall(map, name_to_handle_at, 0, 0);
    register_syscall(map, open_by_handle_at, 0, 0);
    register_syscall(map, clock_adjtime, 0, 0);
    register_syscall(map, setns, 0, 0);
    register_syscall(map, process_vm_readv, 0, 0);
    register_syscall(map, process_vm_writev, 0, 0);
    register_syscall(map, kcmp, 0, 0);
    register_syscall(map, finit_module, 0, 0);
    register_syscall(map, sched_setattr, 0, 0);
    register_syscall(map, sched_getattr, 0, 0);
    register_syscall(map, seccomp, 0, 0);
    register_syscall(map, memfd_create, 0, 0);
    register_syscall(map, kexec_file_load, 0, 0);
    register_syscall(map, bpf, 0, 0);
    register_syscall(map, execveat, 0, 0);
    register_syscall(map, userfaultfd, 0, 0);
    register_syscall(map, membarrier, 0, 0);
    register_syscall(map, mlock2, syscall_ignore, 0);
    register_syscall(map, copy_file_range, 0, 0);
    register_syscall(map, preadv2, 0, 0);
    register_syscall(map, pwritev2, 0, 0);
    register_syscall(map, pkey_mprotect, 0, 0);
    register_syscall(map, pkey_alloc, 0, 0);
    register_syscall(map, pkey_free, 0, 0);
}

