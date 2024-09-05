#include "strace.h"

#define STRACE_SC_F_NOTRACE     (1 << 0)

#define STRACE_SC_F_SET_FILE    (1 << 8)
#define STRACE_SC_F_SET_DESC    (1 << 9)
#define STRACE_SC_F_SET_MEM     (1 << 10)
#define STRACE_SC_F_SET_PROC    (1 << 11)
#define STRACE_SC_F_SET_SIG     (1 << 12)
#define STRACE_SC_F_SET_NET     (1 << 13)

#define strace_syscall_init(sc_name, sc_flags)  [SYS_##sc_name] = { \
    .name = ss_static_init(#sc_name),                               \
    .flags = sc_flags,                                              \
}

#define strace_sc_name(call)    ({                                                      \
    sstring sc_name = (call < SYS_MAX) ? strace_syscalls[call].name : sstring_null();   \
    if (sstring_is_null(sc_name)) {                                                     \
        buffer name_b = little_stack_buffer(32);                                        \
        bprintf(name_b, "syscall_%u", call);                                            \
        sc_name = buffer_to_sstring(name_b);                                            \
    }                                                                                   \
    sc_name;                                                                            \
    })

extern void syscall_handler(thread t);

static struct {
    sstring name;
    u16 flags;
} strace_syscalls[SYS_MAX] = {
        strace_syscall_init(futex, 0),
        strace_syscall_init(socket, STRACE_SC_F_SET_NET),
        strace_syscall_init(bind, STRACE_SC_F_SET_NET),
        strace_syscall_init(listen, STRACE_SC_F_SET_NET),
        strace_syscall_init(accept, STRACE_SC_F_SET_NET),
        strace_syscall_init(accept4, STRACE_SC_F_SET_NET),
        strace_syscall_init(connect, STRACE_SC_F_SET_NET),
        strace_syscall_init(sendto, STRACE_SC_F_SET_NET),
        strace_syscall_init(sendmsg, STRACE_SC_F_SET_NET),
        strace_syscall_init(sendmmsg, STRACE_SC_F_SET_NET),
        strace_syscall_init(recvfrom, STRACE_SC_F_SET_NET),
        strace_syscall_init(recvmsg, STRACE_SC_F_SET_NET),
        strace_syscall_init(recvmmsg, STRACE_SC_F_SET_NET),
        strace_syscall_init(setsockopt, STRACE_SC_F_SET_NET),
        strace_syscall_init(getsockopt, STRACE_SC_F_SET_NET),
        strace_syscall_init(getsockname, STRACE_SC_F_SET_NET),
        strace_syscall_init(getpeername, STRACE_SC_F_SET_NET),
        strace_syscall_init(shutdown, STRACE_SC_F_SET_NET),
        strace_syscall_init(mmap, STRACE_SC_F_SET_DESC | STRACE_SC_F_SET_MEM),
        strace_syscall_init(munmap, STRACE_SC_F_SET_MEM),
        strace_syscall_init(mremap, STRACE_SC_F_SET_MEM),
        strace_syscall_init(msync, STRACE_SC_F_SET_MEM),
        strace_syscall_init(mprotect, STRACE_SC_F_SET_MEM),
        strace_syscall_init(mincore, STRACE_SC_F_SET_MEM),
        strace_syscall_init(madvise, STRACE_SC_F_SET_MEM),
        strace_syscall_init(epoll_create1, STRACE_SC_F_SET_DESC),
        strace_syscall_init(epoll_ctl, STRACE_SC_F_SET_DESC),
        strace_syscall_init(ppoll, STRACE_SC_F_SET_DESC),
        strace_syscall_init(pselect6, STRACE_SC_F_SET_DESC),
        strace_syscall_init(epoll_pwait, STRACE_SC_F_SET_DESC),
        strace_syscall_init(kill, STRACE_SC_F_SET_PROC | STRACE_SC_F_SET_SIG),
        strace_syscall_init(rt_sigaction, STRACE_SC_F_SET_SIG),
        strace_syscall_init(rt_sigpending, STRACE_SC_F_SET_SIG),
        strace_syscall_init(rt_sigprocmask, STRACE_SC_F_SET_SIG),
        strace_syscall_init(rt_sigqueueinfo, STRACE_SC_F_SET_SIG),
        strace_syscall_init(rt_tgsigqueueinfo, STRACE_SC_F_SET_PROC | STRACE_SC_F_SET_SIG),
        strace_syscall_init(rt_sigreturn, STRACE_SC_F_SET_SIG),
        strace_syscall_init(rt_sigsuspend, STRACE_SC_F_SET_SIG),
        strace_syscall_init(rt_sigtimedwait, STRACE_SC_F_SET_SIG),
        strace_syscall_init(sigaltstack, STRACE_SC_F_SET_SIG),
        strace_syscall_init(signalfd4, STRACE_SC_F_SET_SIG),
        strace_syscall_init(tgkill, STRACE_SC_F_SET_PROC | STRACE_SC_F_SET_SIG),
        strace_syscall_init(tkill, STRACE_SC_F_SET_PROC | STRACE_SC_F_SET_SIG),
        strace_syscall_init(read, STRACE_SC_F_SET_DESC),
        strace_syscall_init(pread64, STRACE_SC_F_SET_DESC),
        strace_syscall_init(write, STRACE_SC_F_SET_DESC),
        strace_syscall_init(pwrite64, STRACE_SC_F_SET_DESC),
        strace_syscall_init(inotify_init1, STRACE_SC_F_SET_DESC),
        strace_syscall_init(inotify_add_watch, STRACE_SC_F_SET_FILE | STRACE_SC_F_SET_DESC),
        strace_syscall_init(inotify_rm_watch, STRACE_SC_F_SET_DESC),
        strace_syscall_init(openat, STRACE_SC_F_SET_FILE | STRACE_SC_F_SET_DESC),
        strace_syscall_init(dup, STRACE_SC_F_SET_DESC),
        strace_syscall_init(dup3, STRACE_SC_F_SET_DESC),
        strace_syscall_init(fallocate, STRACE_SC_F_SET_DESC),
        strace_syscall_init(faccessat, STRACE_SC_F_SET_FILE | STRACE_SC_F_SET_DESC),
        strace_syscall_init(fadvise64, STRACE_SC_F_SET_DESC),
        strace_syscall_init(fstat, STRACE_SC_F_SET_DESC),
        strace_syscall_init(newfstatat, STRACE_SC_F_SET_FILE | STRACE_SC_F_SET_DESC),
        strace_syscall_init(statx, STRACE_SC_F_SET_FILE | STRACE_SC_F_SET_DESC),
        strace_syscall_init(readv, STRACE_SC_F_SET_DESC),
        strace_syscall_init(writev, STRACE_SC_F_SET_DESC),
        strace_syscall_init(preadv, STRACE_SC_F_SET_DESC),
        strace_syscall_init(pwritev, STRACE_SC_F_SET_DESC),
        strace_syscall_init(sendfile, STRACE_SC_F_SET_DESC | STRACE_SC_F_SET_NET),
        strace_syscall_init(truncate, STRACE_SC_F_SET_FILE),
        strace_syscall_init(ftruncate, STRACE_SC_F_SET_DESC),
        strace_syscall_init(fdatasync, STRACE_SC_F_SET_DESC),
        strace_syscall_init(fsync, STRACE_SC_F_SET_DESC),
        strace_syscall_init(sync, 0),
        strace_syscall_init(syncfs, STRACE_SC_F_SET_DESC),
        strace_syscall_init(io_setup, STRACE_SC_F_SET_MEM),
        strace_syscall_init(io_submit, 0),
        strace_syscall_init(io_getevents, 0),
        strace_syscall_init(io_destroy, STRACE_SC_F_SET_MEM),
        strace_syscall_init(lseek, STRACE_SC_F_SET_DESC),
        strace_syscall_init(fcntl, STRACE_SC_F_SET_DESC),
        strace_syscall_init(ioctl, STRACE_SC_F_SET_DESC),
        strace_syscall_init(getcwd, STRACE_SC_F_SET_FILE),
        strace_syscall_init(symlinkat, STRACE_SC_F_SET_FILE | STRACE_SC_F_SET_DESC),
        strace_syscall_init(readlinkat, STRACE_SC_F_SET_FILE | STRACE_SC_F_SET_DESC),
        strace_syscall_init(unlinkat, STRACE_SC_F_SET_FILE | STRACE_SC_F_SET_DESC),
        strace_syscall_init(renameat, STRACE_SC_F_SET_FILE | STRACE_SC_F_SET_DESC),
        strace_syscall_init(renameat2, STRACE_SC_F_SET_FILE | STRACE_SC_F_SET_DESC),
        strace_syscall_init(utimensat, STRACE_SC_F_SET_FILE | STRACE_SC_F_SET_DESC),
        strace_syscall_init(close, STRACE_SC_F_SET_DESC),
        strace_syscall_init(sched_yield, 0),
        strace_syscall_init(brk, STRACE_SC_F_SET_MEM),
        strace_syscall_init(uname, 0),
        strace_syscall_init(getrlimit, 0),
        strace_syscall_init(setrlimit, 0),
        strace_syscall_init(prlimit64, 0),
        strace_syscall_init(getrusage, 0),
        strace_syscall_init(getpid, 0),
        strace_syscall_init(exit_group, STRACE_SC_F_SET_PROC),
        strace_syscall_init(exit, STRACE_SC_F_SET_PROC),
        strace_syscall_init(getdents64, STRACE_SC_F_SET_DESC),
        strace_syscall_init(mkdirat, STRACE_SC_F_SET_FILE | STRACE_SC_F_SET_DESC),
        strace_syscall_init(getrandom, 0),
        strace_syscall_init(pipe2, STRACE_SC_F_SET_DESC),
        strace_syscall_init(socketpair, STRACE_SC_F_SET_NET),
        strace_syscall_init(eventfd2, STRACE_SC_F_SET_DESC),
        strace_syscall_init(chdir, STRACE_SC_F_SET_FILE),
        strace_syscall_init(fchdir, STRACE_SC_F_SET_DESC),
        strace_syscall_init(sched_getaffinity, 0),
        strace_syscall_init(sched_setaffinity, 0),
        strace_syscall_init(getuid, 0),
        strace_syscall_init(geteuid, 0),
        strace_syscall_init(setgroups, 0),
        strace_syscall_init(setuid, 0),
        strace_syscall_init(setgid, 0),
        strace_syscall_init(capget, 0),
        strace_syscall_init(capset, 0),
        strace_syscall_init(prctl, 0),
        strace_syscall_init(sysinfo, 0),
        strace_syscall_init(umask, 0),
        strace_syscall_init(statfs, STRACE_SC_F_SET_FILE),
        strace_syscall_init(fstatfs, STRACE_SC_F_SET_DESC),
        strace_syscall_init(io_uring_setup, STRACE_SC_F_SET_DESC),
        strace_syscall_init(io_uring_enter, STRACE_SC_F_SET_DESC),
        strace_syscall_init(io_uring_register, STRACE_SC_F_SET_DESC),
        strace_syscall_init(getcpu, 0),
        strace_syscall_init(set_robust_list, 0),
        strace_syscall_init(get_robust_list, 0),
        strace_syscall_init(clone, STRACE_SC_F_SET_PROC),
        strace_syscall_init(clone3, STRACE_SC_F_SET_PROC),
        strace_syscall_init(set_tid_address, 0),
        strace_syscall_init(gettid, 0),
        strace_syscall_init(timerfd_create, STRACE_SC_F_SET_DESC),
        strace_syscall_init(timerfd_gettime, STRACE_SC_F_SET_DESC),
        strace_syscall_init(timerfd_settime, STRACE_SC_F_SET_DESC),
        strace_syscall_init(timer_create, 0),
        strace_syscall_init(timer_gettime, 0),
        strace_syscall_init(timer_settime, 0),
        strace_syscall_init(timer_getoverrun, 0),
        strace_syscall_init(timer_delete, 0),
        strace_syscall_init(getitimer, 0),
        strace_syscall_init(setitimer, 0),
        strace_syscall_init(clock_gettime, 0),
        strace_syscall_init(clock_settime, 0),
        strace_syscall_init(clock_getres, 0),
        strace_syscall_init(clock_nanosleep, 0),
        strace_syscall_init(gettimeofday, 0),
        strace_syscall_init(settimeofday, 0),
        strace_syscall_init(nanosleep, 0),
        strace_syscall_init(times, 0),
        strace_syscall_init(shmget, 0),
        strace_syscall_init(shmat, 0),
        strace_syscall_init(shmctl, 0),
        strace_syscall_init(execve, 0),
        strace_syscall_init(wait4, 0),
        strace_syscall_init(semget, 0),
        strace_syscall_init(semop, 0),
        strace_syscall_init(semctl, 0),
        strace_syscall_init(shmdt, 0),
        strace_syscall_init(msgget, 0),
        strace_syscall_init(msgsnd, 0),
        strace_syscall_init(msgrcv, 0),
        strace_syscall_init(msgctl, 0),
        strace_syscall_init(flock, 0),
        strace_syscall_init(fchmod, 0),
        strace_syscall_init(fchown, 0),
        strace_syscall_init(ptrace, 0),
        strace_syscall_init(syslog, 0),
        strace_syscall_init(getgid, 0),
        strace_syscall_init(getegid, 0),
        strace_syscall_init(setpgid, 0),
        strace_syscall_init(getppid, 0),
        strace_syscall_init(setsid, 0),
        strace_syscall_init(setreuid, 0),
        strace_syscall_init(setregid, 0),
        strace_syscall_init(getgroups, 0),
        strace_syscall_init(setresuid, 0),
        strace_syscall_init(getresuid, 0),
        strace_syscall_init(setresgid, 0),
        strace_syscall_init(getresgid, 0),
        strace_syscall_init(getpgid, 0),
        strace_syscall_init(setfsuid, 0),
        strace_syscall_init(setfsgid, 0),
        strace_syscall_init(getsid, 0),
        strace_syscall_init(personality, 0),
        strace_syscall_init(getpriority, 0),
        strace_syscall_init(setpriority, 0),
        strace_syscall_init(sched_setparam, 0),
        strace_syscall_init(sched_getparam, 0),
        strace_syscall_init(sched_setscheduler, 0),
        strace_syscall_init(sched_getscheduler, 0),
        strace_syscall_init(sched_get_priority_max, 0),
        strace_syscall_init(sched_get_priority_min, 0),
        strace_syscall_init(sched_rr_get_interval, 0),
        strace_syscall_init(mlock, 0),
        strace_syscall_init(munlock, 0),
        strace_syscall_init(mlockall, 0),
        strace_syscall_init(munlockall, 0),
        strace_syscall_init(vhangup, 0),
        strace_syscall_init(pivot_root, 0),
        strace_syscall_init(adjtimex, 0),
        strace_syscall_init(chroot, 0),
        strace_syscall_init(acct, 0),
        strace_syscall_init(mount, 0),
        strace_syscall_init(umount2, 0),
        strace_syscall_init(swapon, 0),
        strace_syscall_init(swapoff, 0),
        strace_syscall_init(reboot, 0),
        strace_syscall_init(sethostname, 0),
        strace_syscall_init(setdomainname, 0),
        strace_syscall_init(init_module, 0),
        strace_syscall_init(delete_module, 0),
        strace_syscall_init(quotactl, 0),
        strace_syscall_init(nfsservctl, 0),
        strace_syscall_init(readahead, 0),
        strace_syscall_init(setxattr, 0),
        strace_syscall_init(lsetxattr, 0),
        strace_syscall_init(fsetxattr, 0),
        strace_syscall_init(getxattr, 0),
        strace_syscall_init(lgetxattr, 0),
        strace_syscall_init(fgetxattr, 0),
        strace_syscall_init(listxattr, 0),
        strace_syscall_init(llistxattr, 0),
        strace_syscall_init(flistxattr, 0),
        strace_syscall_init(removexattr, 0),
        strace_syscall_init(lremovexattr, 0),
        strace_syscall_init(fremovexattr, 0),
        strace_syscall_init(io_cancel, 0),
        strace_syscall_init(lookup_dcookie, 0),
        strace_syscall_init(remap_file_pages, 0),
        strace_syscall_init(restart_syscall, 0),
        strace_syscall_init(semtimedop, 0),
        strace_syscall_init(mbind, 0),
        strace_syscall_init(set_mempolicy, 0),
        strace_syscall_init(get_mempolicy, 0),
        strace_syscall_init(mq_open, 0),
        strace_syscall_init(mq_unlink, 0),
        strace_syscall_init(mq_timedsend, 0),
        strace_syscall_init(mq_timedreceive, 0),
        strace_syscall_init(mq_notify, 0),
        strace_syscall_init(mq_getsetattr, 0),
        strace_syscall_init(kexec_load, 0),
        strace_syscall_init(waitid, 0),
        strace_syscall_init(add_key, 0),
        strace_syscall_init(request_key, 0),
        strace_syscall_init(keyctl, 0),
        strace_syscall_init(ioprio_set, 0),
        strace_syscall_init(ioprio_get, 0),
        strace_syscall_init(migrate_pages, 0),
        strace_syscall_init(mknodat, 0),
        strace_syscall_init(fchownat, 0),
        strace_syscall_init(linkat, 0),
        strace_syscall_init(fchmodat, 0),
        strace_syscall_init(unshare, 0),
        strace_syscall_init(splice, 0),
        strace_syscall_init(tee, 0),
        strace_syscall_init(sync_file_range, 0),
        strace_syscall_init(vmsplice, 0),
        strace_syscall_init(move_pages, 0),
        strace_syscall_init(perf_event_open, 0),
        strace_syscall_init(fanotify_init, 0),
        strace_syscall_init(fanotify_mark, 0),
        strace_syscall_init(name_to_handle_at, 0),
        strace_syscall_init(open_by_handle_at, 0),
        strace_syscall_init(clock_adjtime, 0),
        strace_syscall_init(setns, 0),
        strace_syscall_init(process_vm_readv, 0),
        strace_syscall_init(process_vm_writev, 0),
        strace_syscall_init(kcmp, 0),
        strace_syscall_init(finit_module, 0),
        strace_syscall_init(sched_setattr, 0),
        strace_syscall_init(sched_getattr, 0),
        strace_syscall_init(seccomp, 0),
        strace_syscall_init(memfd_create, 0),
        strace_syscall_init(kexec_file_load, 0),
        strace_syscall_init(bpf, 0),
        strace_syscall_init(execveat, 0),
        strace_syscall_init(userfaultfd, 0),
        strace_syscall_init(membarrier, 0),
        strace_syscall_init(mlock2, 0),
        strace_syscall_init(copy_file_range, 0),
        strace_syscall_init(preadv2, 0),
        strace_syscall_init(pwritev2, 0),
        strace_syscall_init(pkey_mprotect, 0),
        strace_syscall_init(pkey_alloc, 0),
        strace_syscall_init(pkey_free, 0),
#if defined(__x86_64__)
        strace_syscall_init(epoll_create, STRACE_SC_F_SET_DESC),
        strace_syscall_init(epoll_wait, STRACE_SC_F_SET_DESC),
        strace_syscall_init(poll, STRACE_SC_F_SET_DESC),
        strace_syscall_init(select, STRACE_SC_F_SET_DESC),
        strace_syscall_init(pause, STRACE_SC_F_SET_SIG),
        strace_syscall_init(signalfd, STRACE_SC_F_SET_DESC | STRACE_SC_F_SET_SIG),
        strace_syscall_init(open, STRACE_SC_F_SET_FILE | STRACE_SC_F_SET_DESC),
        strace_syscall_init(dup2, STRACE_SC_F_SET_DESC),
        strace_syscall_init(stat, STRACE_SC_F_SET_FILE),
        strace_syscall_init(lstat, STRACE_SC_F_SET_FILE),
        strace_syscall_init(access, STRACE_SC_F_SET_FILE),
        strace_syscall_init(readlink, STRACE_SC_F_SET_FILE),
        strace_syscall_init(unlink, STRACE_SC_F_SET_FILE),
        strace_syscall_init(rmdir, STRACE_SC_F_SET_FILE),
        strace_syscall_init(rename, STRACE_SC_F_SET_FILE),
        strace_syscall_init(getdents, STRACE_SC_F_SET_DESC),
        strace_syscall_init(mkdir, STRACE_SC_F_SET_FILE),
        strace_syscall_init(pipe, STRACE_SC_F_SET_DESC),
        strace_syscall_init(eventfd, STRACE_SC_F_SET_DESC),
        strace_syscall_init(creat, STRACE_SC_F_SET_FILE | STRACE_SC_F_SET_DESC),
        strace_syscall_init(utime, STRACE_SC_F_SET_FILE),
        strace_syscall_init(utimes, STRACE_SC_F_SET_FILE),
        strace_syscall_init(chown, STRACE_SC_F_SET_FILE),
        strace_syscall_init(symlink, STRACE_SC_F_SET_FILE),
        strace_syscall_init(inotify_init, STRACE_SC_F_SET_DESC),
        strace_syscall_init(arch_prctl, 0),
        strace_syscall_init(alarm, 0),
        strace_syscall_init(time, 0),
        strace_syscall_init(fork, 0),
        strace_syscall_init(vfork, 0),
        strace_syscall_init(link, 0),
        strace_syscall_init(chmod, 0),
        strace_syscall_init(lchown, 0),
        strace_syscall_init(getpgrp, 0),
        strace_syscall_init(mknod, 0),
        strace_syscall_init(uselib, 0),
        strace_syscall_init(ustat, 0),
        strace_syscall_init(sysfs, 0),
        strace_syscall_init(modify_ldt, 0),
        strace_syscall_init(_sysctl, 0),
        strace_syscall_init(iopl, 0),
        strace_syscall_init(ioperm, 0),
        strace_syscall_init(create_module, 0),
        strace_syscall_init(get_kernel_syms, 0),
        strace_syscall_init(query_module, 0),
        strace_syscall_init(getpmsg, 0),
        strace_syscall_init(putpmsg, 0),
        strace_syscall_init(afs_syscall, 0),
        strace_syscall_init(tuxcall, 0),
        strace_syscall_init(security, 0),
        strace_syscall_init(set_thread_area, 0),
        strace_syscall_init(get_thread_area, 0),
        strace_syscall_init(epoll_ctl_old, 0),
        strace_syscall_init(epoll_wait_old, 0),
        strace_syscall_init(vserver, 0),
        strace_syscall_init(futimesat, 0),
#endif
};

static const struct strace_set {
    sstring name;
    u64 flag;
} strace_sets[] = {
    { ss_static_init("%file"), STRACE_SC_F_SET_FILE },
    { ss_static_init("%desc"), STRACE_SC_F_SET_DESC },
    { ss_static_init("%memory"), STRACE_SC_F_SET_MEM },
    { ss_static_init("%process"), STRACE_SC_F_SET_PROC },
    { ss_static_init("%signal"), STRACE_SC_F_SET_SIG },
    { ss_static_init("%net"), STRACE_SC_F_SET_NET },
    { ss_static_init("%network"), STRACE_SC_F_SET_NET },
};

typedef struct strace_sc_stat {
    u64 calls;
    u64 errors;
    u64 usecs;
} *strace_sc_stat;

static struct {
    struct {
        strace_sc_enter enter;
        strace_sc_exit exit;
    } sc_handlers[SYS_MAX];
    heap h;
    table sc_contexts;
    struct spinlock lock;
    struct strace_sc_stat sc_stats[SYS_MAX];
    boolean do_sc_trace;
    boolean do_sc_stats;
} strace;

static void strace_print_header(buffer dest, thread t)
{
    const char *t_name = t->name;
    if (t_name[0] != '\0')
        bprintf(dest, "[%s] ", sstring_from_cstring(t_name, sizeof(t->name)));
    else
        bprintf(dest, "[%d] ", t->tid);
}

static void strace_print_errno(buffer dest, sysreturn rv)
{
    sstring errno;
    switch (rv) {
    SWITCH_NUM_TO_STRING(-EPERM, errno);
    SWITCH_NUM_TO_STRING(-ENOENT, errno);
    SWITCH_NUM_TO_STRING(-ESRCH, errno);
    SWITCH_NUM_TO_STRING(-EINTR, errno);
    SWITCH_NUM_TO_STRING(-EIO, errno);
    SWITCH_NUM_TO_STRING(-ENXIO, errno);
    SWITCH_NUM_TO_STRING(-E2BIG, errno);
    SWITCH_NUM_TO_STRING(-ENOEXEC, errno);
    SWITCH_NUM_TO_STRING(-EBADF, errno);
    SWITCH_NUM_TO_STRING(-ECHILD, errno);
    SWITCH_NUM_TO_STRING(-EAGAIN, errno);
    SWITCH_NUM_TO_STRING(-ENOMEM, errno);
    SWITCH_NUM_TO_STRING(-EACCES, errno);
    SWITCH_NUM_TO_STRING(-EFAULT, errno);
    SWITCH_NUM_TO_STRING(-EBUSY, errno);
    SWITCH_NUM_TO_STRING(-EEXIST, errno);
    SWITCH_NUM_TO_STRING(-EXDEV, errno);
    SWITCH_NUM_TO_STRING(-ENODEV, errno);
    SWITCH_NUM_TO_STRING(-ENOTDIR, errno);
    SWITCH_NUM_TO_STRING(-EISDIR, errno);
    SWITCH_NUM_TO_STRING(-EINVAL, errno);
    SWITCH_NUM_TO_STRING(-ENFILE, errno);
    SWITCH_NUM_TO_STRING(-EMFILE, errno);
    SWITCH_NUM_TO_STRING(-ENOTTY, errno);
    SWITCH_NUM_TO_STRING(-EFBIG, errno);
    SWITCH_NUM_TO_STRING(-ENOSPC, errno);
    SWITCH_NUM_TO_STRING(-ESPIPE, errno);
    SWITCH_NUM_TO_STRING(-EROFS, errno);
    SWITCH_NUM_TO_STRING(-EMLINK, errno);
    SWITCH_NUM_TO_STRING(-EPIPE, errno);
    SWITCH_NUM_TO_STRING(-ERANGE, errno);
    SWITCH_NUM_TO_STRING(-ENAMETOOLONG, errno);
    SWITCH_NUM_TO_STRING(-ENOSYS, errno);
    SWITCH_NUM_TO_STRING(-ENOTEMPTY, errno);
    SWITCH_NUM_TO_STRING(-ELOOP, errno);
    SWITCH_NUM_TO_STRING(-ENOPROTOOPT, errno);
    SWITCH_NUM_TO_STRING(-ENODATA, errno);
    SWITCH_NUM_TO_STRING(-ETIME, errno);
    SWITCH_NUM_TO_STRING(-EOVERFLOW, errno);
    SWITCH_NUM_TO_STRING(-EBADFD, errno);
    SWITCH_NUM_TO_STRING(-EDESTADDRREQ, errno);
    SWITCH_NUM_TO_STRING(-EMSGSIZE, errno);
    SWITCH_NUM_TO_STRING(-EPROTOTYPE, errno);
    SWITCH_NUM_TO_STRING(-EOPNOTSUPP, errno);
    SWITCH_NUM_TO_STRING(-ECONNABORTED, errno);
    SWITCH_NUM_TO_STRING(-EISCONN, errno);
    SWITCH_NUM_TO_STRING(-ENOTCONN, errno);
    SWITCH_NUM_TO_STRING(-ETIMEDOUT, errno);
    SWITCH_NUM_TO_STRING(-EALREADY, errno);
    SWITCH_NUM_TO_STRING(-EINPROGRESS, errno);
    SWITCH_NUM_TO_STRING(-ECANCELED, errno);
    SWITCH_NUM_TO_STRING(-ERESTARTSYS, errno);
    SWITCH_NUM_TO_STRING(-ERESTARTNOHAND, errno);
    default:    /* unknown errno */
        bprintf(dest, "%ld", rv);
        return;
    }
    bprintf(dest, "%s", errno);
}

static void strace_print_rv(buffer dest, sysreturn rv, enum strace_rv_fmt rv_fmt)
{
    buffer_write_cstring(dest, ") = ");
    switch (rv_fmt) {
    case STRACE_RV_DE:
        if (rv >= 0)
            bprintf(dest, "%ld", rv);
        else
            strace_print_errno(dest, rv);
        break;
    case STRACE_RV_XE:
        if (rv >= 0)
            bprintf(dest, "0x%lx", rv);
        else
            strace_print_errno(dest, rv);
        break;
    }
    push_u8(dest, '\n');
}

static void strace_sc_count(strace_sc_ctx ctx, sysreturn rv)
{
    u64 call = ctx->call;
    if (call >= SYS_MAX)
        return;
    strace_sc_stat ss = &strace.sc_stats[call];
    fetch_and_add(&ss->calls, 1);
    if (rv < 0 && rv >= -255)
        fetch_and_add(&ss->errors, 1);
    timestamp cpu_time = ctx->cpu_time;
    timestamp enter_ts = ctx->enter_ts;
    if (enter_ts)
        cpu_time += kern_now(CLOCK_ID_MONOTONIC_RAW) - enter_ts;
    fetch_and_add(&ss->usecs, usec_from_timestamp(cpu_time));
}

static void strace_sc_done(strace_sc_ctx sc_ctx, context ctx)
{
    thread t = ((syscall_context)ctx)->t;
    if (strace.do_sc_stats)
        strace_sc_count(sc_ctx, t ? sc_retval(t) : 0);
    buffer trace_buf = sc_ctx->trace_buf;
    if (trace_buf) {
        if (t) {
            u64 call = sc_ctx->call;
            if (buffer_length(trace_buf) == 0) {
                strace_print_header(trace_buf, t);
                sstring sc_name = strace_sc_name(call);
                bprintf(trace_buf, "<... %s resumed>", sc_name);
            }
            if ((call < SYS_MAX) && strace.sc_handlers[call].exit)
                strace.sc_handlers[call].exit(t, sc_ctx);
            strace_print_rv(trace_buf, sc_retval(t), sc_ctx->rv_fmt);
        } else {
            buffer_write_cstring(trace_buf, ") = ?\n");
        }
        buffer_print(trace_buf);
        deallocate_buffer(trace_buf);
    }
    ctx->pause = sc_ctx->pause;
    ctx->resume = sc_ctx->resume;
    deallocate(strace.h, sc_ctx, sizeof(*sc_ctx));
}

static void strace_sc_pause(context ctx)
{
    thread t = ((syscall_context)ctx)->t;
    boolean done = !t || !t->syscall;
    strace_sc_ctx sc_ctx;
    spin_lock(&strace.lock);
    if (done)
        sc_ctx = table_remove(strace.sc_contexts, ctx);
    else
        sc_ctx = table_find(strace.sc_contexts, ctx);
    spin_unlock(&strace.lock);
    void (*pause)(context) = sc_ctx->pause;
    if (done) {
        strace_sc_done(sc_ctx, ctx);
    } else {
        if (strace.do_sc_stats && sc_ctx->enter_ts) {
            sc_ctx->cpu_time += kern_now(CLOCK_ID_MONOTONIC_RAW) - sc_ctx->enter_ts;
            sc_ctx->enter_ts = 0;
        }
        buffer trace_buf = sc_ctx->trace_buf;
        if (trace_buf && (buffer_length(trace_buf) != 0)) {
            buffer_write_cstring(trace_buf, " <unfinished ...>\n");
            buffer_print(trace_buf);
            buffer_clear(trace_buf);
        }
    }
    pause(ctx);
}

static void strace_sc_resume(context ctx)
{
    spin_lock(&strace.lock);
    strace_sc_ctx sc_ctx = table_find(strace.sc_contexts, ctx);
    spin_unlock(&strace.lock);
    if (strace.do_sc_stats)
        sc_ctx->enter_ts = kern_now(CLOCK_ID_MONOTONIC_RAW);
    sc_ctx->resume(ctx);
}

/* Set up CPU state and (thread and syscall contexts) so that any access to non-resident userspace
 * memory addresses is handled correctly (i.e. any page fault is handled the Unix fault handler)
 * regardless of whether the fault happens in strace handlers or during normal syscall processing.
 */
static boolean strace_sc_prepare(thread t)
{
    context_frame f = thread_frame(t);
    f[FRAME_FULL] = true;
    thread_reserve(t);
    syscall_restart_arch_setup(f);
    cpuinfo ci = current_cpu();
    ci->state = cpu_kernel;
    context ctx = get_current_context(ci);
    syscall_context sc = (syscall_context)ctx;
    sc->t = t;
    ctx->fault_handler = t->context.fault_handler;
    sc->start_time = 0;
    sc->call = f[FRAME_VECTOR];
    t->syscall = sc;
    context_pause(&t->context);
    context_release(&t->context);
    context_resume(ctx);
    return !(shutting_down & SHUTDOWN_ONGOING);
}

static void strace_syscall(thread t)
{
    if (!strace_sc_prepare(t))
        goto out;
    context_frame f = thread_frame(t);
    u64 call = f[FRAME_VECTOR];
    cpuinfo ci = current_cpu();
    context ctx = get_current_context(ci);
    boolean trace = strace.do_sc_trace &&
                    ((call >= SYS_MAX) || !(strace_syscalls[call].flags & STRACE_SC_F_NOTRACE));
    sysreturn rv;
    if (!strace.do_sc_stats && !trace)
        goto call_handler;
    strace_sc_ctx sc_ctx = allocate(strace.h, sizeof(*sc_ctx));
    if (sc_ctx == INVALID_ADDRESS)
        goto call_handler;
    sc_ctx->call = call;
    if (trace) {
        buffer trace_buf = sc_ctx->trace_buf = allocate_buffer(strace.h, 32);
        if (trace_buf == INVALID_ADDRESS) {
            deallocate(strace.h, sc_ctx, sizeof(*sc_ctx));
            goto call_handler;
        }
        strace_print_header(trace_buf, t);
        sstring sc_name = strace_sc_name(call);
        bprintf(trace_buf, "%s(", sc_name);
        if ((call < SYS_MAX) && strace.sc_handlers[call].enter)
            strace.sc_handlers[call].enter(t, sc_ctx);
        else
            sc_ctx->rv_fmt = STRACE_RV_DE;
    } else {
        sc_ctx->trace_buf = 0;
    }
    if (strace.do_sc_stats) {
        sc_ctx->enter_ts = kern_now(CLOCK_ID_MONOTONIC_RAW);
        sc_ctx->cpu_time = 0;
    }
    spin_lock(&strace.lock);

    /* Check if this syscall context is associated to another strace context (it happens when a
     * blocked thread is scheduled from outside its syscall context, such as during UMCG context
     * switching, in which case strace fails to capture the syscall exit event). */
    strace_sc_ctx old_sc_ctx = table_find(strace.sc_contexts, ctx);
    if (old_sc_ctx) {
        /* Set the thread field to NULL so that the thread structure is not accessed (the thread may
         * not even exist anymore), and clean up the trace buffer if there is any (we already missed
         * the syscall exit event, no much point in outputting a bogus strace record now). */
        ((syscall_context)ctx)->t = 0;
        buffer trace_buf = old_sc_ctx->trace_buf;
        if (trace_buf) {
            deallocate_buffer(trace_buf);
            old_sc_ctx->trace_buf = 0;
        }
        strace_sc_done(old_sc_ctx, ctx);
    }

    sc_ctx->pause = ctx->pause;
    ctx->pause = strace_sc_pause;
    sc_ctx->resume = ctx->resume;
    ctx->resume = strace_sc_resume;
    table_set(strace.sc_contexts, ctx, sc_ctx);
    spin_unlock(&strace.lock);
  call_handler:
    rv = -ENOSYS;
    if (call < SYS_MAX) {
        u64 *h_addr = (u64 *)(t->p->syscalls) + call;
        sysreturn (*h)(u64, u64, u64, u64, u64, u64) = pointer_from_u64(*h_addr);
        if (h) {
            t->syscall_complete = false;
            context_reserve_refcount(ctx);
            rv = h(sc_arg0(t), sc_arg1(t), sc_arg2(t), sc_arg3(t), sc_arg4(t), sc_arg5(t));
            context_release_refcount(ctx);
        }
    }
    set_syscall_return(t, rv);
    t->syscall = 0;
    schedule_thread(t);
  out:
    kern_yield();
}

void strace_register_sc_handlers(int sc, strace_sc_enter enter, strace_sc_exit exit)
{
    strace.sc_handlers[sc].enter = enter;
    strace.sc_handlers[sc].exit = exit;
}

void strace_print_user_long(strace_sc_ctx ctx, const long *data, boolean hex)
{
    buffer trace_buf = ctx->trace_buf;
    long value;
    if (!data) {
        buffer_write_cstring(trace_buf, "NULL");
    } else if (get_user_value(data, &value)) {
        if (hex)
            bprintf(trace_buf, "[0x%lx]", value);
        else
            bprintf(trace_buf, "[%ld]", value);
    } else {
        bprintf(trace_buf, "%p", data);
    }
}

void strace_print_user_string(strace_sc_ctx ctx, const char *str)
{
    buffer trace_buf = ctx->trace_buf;
    sstring sstr;
    if (!str)
        buffer_write_cstring(trace_buf, "NULL");
    else if (fault_in_user_string(str, &sstr))
        bprintf(trace_buf, "\"%s\"", sstr);
    else
        bprintf(trace_buf, "%p", str);
}

void strace_print_user_data(strace_sc_ctx ctx, const void *data,
                            void handler(strace_sc_ctx, const void *))
{
    buffer trace_buf = ctx->trace_buf;
    context c = get_current_context(current_cpu());
    if (!context_set_err(c)) {
        handler(ctx, data);
        context_clear_err(c);
    } else if (data) {
        bprintf(trace_buf, "%p", data);
    } else {
        buffer_write_cstring(trace_buf, "NULL");
    }
}

static void strace_set_sc_handler(void)
{
    extern void (*syscall)(thread t);
    if (strace.do_sc_trace || strace.do_sc_stats)
        syscall = strace_syscall;
    else
        syscall = syscall_handler;
}

closure_func_basic(set_value_notify, boolean, strace_debugsyscalls_notify,
                   value v)
{
    strace.do_sc_trace = !!v;
    strace_set_sc_handler();
    return true;
}

static void strace_notrace_cfg(boolean set)
{
    for (int i = 0; i < SYS_MAX; i++) {
        if (set)
            strace_syscalls[i].flags |= STRACE_SC_F_NOTRACE;
        else
            strace_syscalls[i].flags &= ~STRACE_SC_F_NOTRACE;
    }
}

closure_function(1, 2, boolean, strace_notrace_each,
                 boolean, set,
                 value k, value v)
{
    if (peek_char(v) == '%') {
        for (int j = 0; j < sizeof(strace_sets) / sizeof(strace_sets[0]); j++) {
            const struct strace_set *ts = strace_sets + j;
            if (buffer_compare_with_sstring(v, ts->name))
                continue;

            for (int i = 0; i < SYS_MAX; i++) {
                if (sstring_is_null(strace_syscalls[i].name) ||
                    !(strace_syscalls[i].flags & ts->flag))
                    continue;

                if (bound(set))
                    strace_syscalls[i].flags |= STRACE_SC_F_NOTRACE;
                else
                    strace_syscalls[i].flags &= ~STRACE_SC_F_NOTRACE;
            }
            break;
        }
    } else {
        for (int i = 0; i < SYS_MAX; i++) {
            if (sstring_is_null(strace_syscalls[i].name) ||
                buffer_compare_with_sstring(v, strace_syscalls[i].name))
                continue;

            if (bound(set))
                strace_syscalls[i].flags |= STRACE_SC_F_NOTRACE;
            else
                strace_syscalls[i].flags &= ~STRACE_SC_F_NOTRACE;
            break;
        }
    }
    return true;
}

closure_func_basic(set_value_notify, boolean, strace_notrace_notify,
                   value v)
{
    strace_notrace_cfg(false);
    if (is_composite(v))
        iterate(v, stack_closure(strace_notrace_each, true));
    return true;
}

closure_func_basic(set_value_notify, boolean, strace_tracelist_notify,
                   value v)
{
    strace_notrace_cfg(true);
    if (is_composite(v))
        iterate(v, stack_closure(strace_notrace_each, false));
    return true;
}

static boolean strace_stat_compare(void *za, void *zb)
{
    strace_sc_stat sa = za;
    strace_sc_stat sb = zb;
    return sb->usecs > sa->usecs;
}

static inline sstring print_usecs(buffer b, u64 x)
{
    buffer_clear(b);
    bprintf(b, "%d.%06d", x / MILLION, x % MILLION);
    return buffer_to_sstring(b);
}

static inline sstring print_pct(buffer b, u64 x, u64 y)
{
    buffer_clear(b);
    x *= 100;
    bprintf(b, "%d.%02d", x / y, (x * 100 / y) % 100);
    return buffer_to_sstring(b);
}

#define LINE "------"
#define LINE2 LINE LINE
#define LINE3 LINE LINE LINE
#define SEPARATOR LINE " " LINE2 " " LINE2 " " LINE2 " " LINE2 " " LINE3 "\n"
#define HDR_FMT "%6s %12s %12s %12s %12s %-18s\n"
#define DATA_FMT "%6s %12s %12d %12d %12.0d %-18s\n"
#define SUM_FMT "%6s %12s %12.0d %12d %12.0d %-18s\n"

#define ROUNDED_IDIV(x, y) (((x)* 10 / (y) + 5) / 10)

closure_func_basic(shutdown_handler, void, strace_print_stats_cfn,
                   int status, merge m)
{
    u64 tot_usecs = 0;
    u64 tot_calls = 0;
    u64 tot_errs = 0;
    buffer tbuf = little_stack_buffer(24);
    buffer pbuf = little_stack_buffer(24);
    pqueue pq = allocate_pqueue(strace.h, strace_stat_compare);
    strace_sc_stat ss;

    rprintf("\n" HDR_FMT SEPARATOR, ss("% time"), ss("seconds"), ss("usecs/call"), ss("calls"),
            ss("errors"), ss("syscall"));
    for (int i = 0; i < SYS_MAX; i++) {
        ss = &strace.sc_stats[i];
        if (ss->calls == 0)
            continue;
        tot_usecs += ss->usecs;
        pqueue_insert(pq, ss);
    }
    while ((ss = pqueue_pop(pq)) != INVALID_ADDRESS) {
        tot_calls += ss->calls;
        tot_errs += ss->errors;
        sstring sc_name = strace_sc_name(ss - strace.sc_stats);
        rprintf(DATA_FMT, print_pct(pbuf, ss->usecs, tot_usecs), print_usecs(tbuf, ss->usecs),
                ROUNDED_IDIV(ss->usecs, ss->calls), ss->calls, ss->errors, sc_name);
    }
    rprintf(SEPARATOR SUM_FMT, ss("100.00"), print_usecs(tbuf, tot_usecs), 0, tot_calls, tot_errs,
            ss("total"));
    deallocate_pqueue(pq);
}

int init(status_handler complete)
{
    strace.h = heap_locked(get_kernel_heaps());
    strace.sc_contexts = allocate_table(strace.h, identity_key, pointer_equal);
    if (strace.sc_contexts == INVALID_ADDRESS)
        goto oom;
    spin_lock_init(&strace.lock);
    set_value_notify n = closure_func(strace.h, set_value_notify, strace_debugsyscalls_notify);
    if (n == INVALID_ADDRESS)
        goto oom;
    register_root_notify(sym(debugsyscalls), n);
    n = closure_func(strace.h, set_value_notify, strace_notrace_notify);
    if (n == INVALID_ADDRESS)
        goto oom;
    register_root_notify(sym(notrace), n);
    n = closure_func(strace.h, set_value_notify, strace_tracelist_notify);
    if (n == INVALID_ADDRESS)
        goto oom;
    register_root_notify(sym(tracelist), n);
    tuple root = get_root_tuple();
    strace.do_sc_stats = get(root, sym(syscall_summary)) != 0;
    if (strace.do_sc_stats) {
        strace_set_sc_handler();
        shutdown_handler print_syscall_stats = closure_func(strace.h, shutdown_handler,
                                                            strace_print_stats_cfn);
        if (print_syscall_stats == INVALID_ADDRESS)
            goto oom;
        add_shutdown_completion(print_syscall_stats);
    }
    strace_file_init();
    strace_mem_init();
    strace_misc_init();
    return KLIB_INIT_OK;
  oom:
    msg_err("out of memory\n");
    return KLIB_INIT_FAILED;
}
