#include <unix_internal.h>

/*
 * Copy the context in frame 'f' to the ucontext *uctx
 */
void setup_ucontext(struct ucontext * uctx, struct sigaction * sa,
                    struct siginfo * si, context f)
{
    struct sigcontext * mcontext = &(uctx->uc_mcontext);

    /* XXX for now we ignore everything but mcontext, incluing FP state ... */

    runtime_memset((void *)uctx, 0, sizeof(struct ucontext));
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
    mcontext->eflags = f[FRAME_FLAGS];
    mcontext->cs = f[FRAME_CS];
    mcontext->fs = 0;
    mcontext->gs = 0;
    mcontext->ss = 0; /* FRAME[SS] if UC_SIGCONTEXT SS */
    mcontext->err = f[FRAME_ERROR_CODE];
    mcontext->trapno = f[FRAME_VECTOR];
    mcontext->oldmask = sa->sa_mask.sig[0];
    mcontext->cr2 = f[FRAME_CR2];
}

/*
 * Copy the context from *uctx to the context in frame f
 */
void restore_ucontext(struct ucontext * uctx, context f)
{
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
    f[FRAME_FLAGS] = mcontext->eflags;
    f[FRAME_CS] = mcontext->cs;
}

void register_other_syscalls(struct syscall *map)
{
    register_syscall(map, shmget, 0);
    register_syscall(map, shmat, 0);
    register_syscall(map, shmctl, 0);
    register_syscall(map, fork, 0);
    register_syscall(map, vfork, 0);
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
    register_syscall(map, link, 0);
    register_syscall(map, chmod, syscall_ignore);
    register_syscall(map, fchmod, syscall_ignore);
    register_syscall(map, fchown, syscall_ignore);
    register_syscall(map, lchown, syscall_ignore);
    register_syscall(map, ptrace, 0);
    register_syscall(map, syslog, 0);
    register_syscall(map, getgid, syscall_ignore);
    register_syscall(map, getegid, syscall_ignore);
    register_syscall(map, setpgid, 0);
    register_syscall(map, getppid, 0);
    register_syscall(map, getpgrp, 0);
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
    register_syscall(map, mknod, 0);
    register_syscall(map, uselib, 0);
    register_syscall(map, personality, 0);
    register_syscall(map, ustat, 0);
    register_syscall(map, sysfs, 0);
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
    register_syscall(map, modify_ldt, 0);
    register_syscall(map, pivot_root, 0);
    register_syscall(map, _sysctl, 0);
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
    register_syscall(map, iopl, 0);
    register_syscall(map, ioperm, 0);
    register_syscall(map, create_module, 0);
    register_syscall(map, init_module, 0);
    register_syscall(map, delete_module, 0);
    register_syscall(map, get_kernel_syms, 0);
    register_syscall(map, query_module, 0);
    register_syscall(map, quotactl, 0);
    register_syscall(map, nfsservctl, 0);
    register_syscall(map, getpmsg, 0);
    register_syscall(map, putpmsg, 0);
    register_syscall(map, afs_syscall, 0);
    register_syscall(map, tuxcall, 0);
    register_syscall(map, security, 0);
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
    register_syscall(map, set_thread_area, 0);
    register_syscall(map, io_cancel, 0);
    register_syscall(map, get_thread_area, 0);
    register_syscall(map, lookup_dcookie, 0);
    register_syscall(map, epoll_ctl_old, 0);
    register_syscall(map, epoll_wait_old, 0);
    register_syscall(map, remap_file_pages, 0);
    register_syscall(map, restart_syscall, 0);
    register_syscall(map, semtimedop, 0);
    register_syscall(map, clock_settime, 0);
    register_syscall(map, vserver, 0);
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
    register_syscall(map, inotify_init, 0);
    register_syscall(map, inotify_add_watch, 0);
    register_syscall(map, inotify_rm_watch, 0);
    register_syscall(map, migrate_pages, 0);
    register_syscall(map, mknodat, 0);
    register_syscall(map, fchownat, syscall_ignore);
    register_syscall(map, futimesat, 0);
    register_syscall(map, linkat, 0);
    register_syscall(map, fchmodat, syscall_ignore);
    register_syscall(map, faccessat, 0);
    register_syscall(map, unshare, 0);
    register_syscall(map, splice, 0);
    register_syscall(map, tee, 0);
    register_syscall(map, sync_file_range, 0);
    register_syscall(map, vmsplice, 0);
    register_syscall(map, move_pages, 0);
    register_syscall(map, utimensat, 0);
    register_syscall(map, inotify_init1, 0);
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

