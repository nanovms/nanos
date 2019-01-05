#include <unix_internal.h>
#include <metadata.h>
#include <path.h>

// lifted from linux UAPI
#define DT_UNKNOWN	0
#define DT_FIFO		1
#define DT_CHR		2
#define DT_DIR		4
#define DT_BLK		6
#define DT_REG		8
#define DT_LNK		10
#define DT_SOCK		12
#define DT_WHT		14

typedef struct code {
    int c;
    char *n;
} *code;

// xxx - put in tuple space
struct code syscall_codes[]= {
    {SYS_read, "read"},
    {SYS_write, "write"},
    {SYS_open, "open"},
    {SYS_close, "close"},
    {SYS_stat, "stat"},
    {SYS_fstat, "fstat"},
    {SYS_lstat, "lstat"},
    {SYS_poll, "poll"},
    {SYS_lseek, "lseek"},
    {SYS_mmap, "mmap"},
    {SYS_mprotect, "mprotect"},
    {SYS_munmap, "munmap"},
    {SYS_brk, "brk"},
    {SYS_rt_sigaction, "rt_sigaction"},
    {SYS_rt_sigprocmask, "rt_sigprocmask"},
    {SYS_rt_sigreturn, "rt_sigreturn"},
    {SYS_ioctl, "ioctl"},
    {SYS_pread64, "pread64"},
    {SYS_pwrite64, "pwrite64"},
    {SYS_readv, "readv"},
    {SYS_writev, "writev"},
    {SYS_access, "access"},
    {SYS_pipe, "pipe"},
    {SYS_select, "select"},
    {SYS_sched_yield, "sched_yield"},
    {SYS_mremap, "mremap"},
    {SYS_msync, "msync"},
    {SYS_mincore, "mincore"},
    {SYS_madvise, "madvise"},
    {SYS_shmget, "shmget"},
    {SYS_shmat, "shmat"},
    {SYS_shmctl, "shmctl"},
    {SYS_dup, "dup"},
    {SYS_dup2, "dup2"},
    {SYS_pause, "pause"},
    {SYS_nanosleep, "nanosleep"},
    {SYS_getitimer, "getitimer"},
    {SYS_alarm, "alarm"},
    {SYS_setitimer, "setitimer"},
    {SYS_getpid, "getpid"},
    {SYS_sendfile, "sendfile"},
    {SYS_socket, "socket"},
    {SYS_connect, "connect"},
    {SYS_accept, "accept"},
    {SYS_sendto, "sendto"},
    {SYS_recvfrom, "recvfrom"},
    {SYS_sendmsg, "sendmsg"},
    {SYS_recvmsg, "recvmsg"},
    {SYS_shutdown, "shutdown"},
    {SYS_bind, "bind"},
    {SYS_listen, "listen"},
    {SYS_getsockname, "getsockname"},
    {SYS_getpeername, "getpeername"},
    {SYS_socketpair, "socketpair"},
    {SYS_setsockopt, "setsockopt"},
    {SYS_getsockopt, "getsockopt"},
    {SYS_clone, "clone"},
    {SYS_fork, "fork"},
    {SYS_vfork, "vfork"},
    {SYS_execve, "execve"},
    {SYS_exit, "exit"},
    {SYS_wait4, "wait4"},
    {SYS_kill, "kill"},
    {SYS_uname, "uname"},
    {SYS_semget, "semget"},
    {SYS_semop, "semop"},
    {SYS_semctl, "semctl"},
    {SYS_shmdt, "shmdt"},
    {SYS_msgget, "msgget"},
    {SYS_msgsnd, "msgsnd"},
    {SYS_msgrcv, "msgrcv"},
    {SYS_msgctl, "msgctl"},
    {SYS_fcntl, "fcntl"},
    {SYS_flock, "flock"},
    {SYS_fsync, "fsync"},
    {SYS_fdatasync, "fdatasync"},
    {SYS_truncate, "truncate"},
    {SYS_ftruncate, "ftruncate"},
    {SYS_getdents, "getdents"},
    {SYS_getcwd, "getcwd"},
    {SYS_chdir, "chdir"},
    {SYS_fchdir, "fchdir"},
    {SYS_rename, "rename"},
    {SYS_mkdir, "mkdir"},
    {SYS_rmdir, "rmdir"},
    {SYS_creat, "creat"},
    {SYS_link, "link"},
    {SYS_unlink, "unlink"},
    {SYS_symlink, "symlink"},
    {SYS_readlink, "readlink"},
    {SYS_chmod, "chmod"},
    {SYS_fchmod, "fchmod"},
    {SYS_chown, "chown"},
    {SYS_fchown, "fchown"},
    {SYS_lchown, "lchown"},
    {SYS_umask, "umask"},
    {SYS_gettimeofday, "gettimeofday"},
    {SYS_getrlimit, "getrlimit"},
    {SYS_getrusage, "getrusage"},
    {SYS_sysinfo, "sysinfo"},
    {SYS_times, "times"},
    {SYS_ptrace, "ptrace"},
    {SYS_getuid, "getuid"},
    {SYS_syslog, "syslog"},
    {SYS_getgid, "getgid"},
    {SYS_setuid, "setuid"},
    {SYS_setgid, "setgid"},
    {SYS_geteuid, "geteuid"},
    {SYS_getegid, "getegid"},
    {SYS_setpgid, "setpgid"},
    {SYS_getppid, "getppid"},
    {SYS_getpgrp, "getpgrp"},
    {SYS_setsid, "setsid"},
    {SYS_setreuid, "setreuid"},
    {SYS_setregid, "setregid"},
    {SYS_getgroups, "getgroups"},
    {SYS_setgroups, "setgroups"},
    {SYS_setresuid, "setresuid"},
    {SYS_getresuid, "getresuid"},
    {SYS_setresgid, "setresgid"},
    {SYS_getresgid, "getresgid"},
    {SYS_getpgid, "getpgid"},
    {SYS_setfsuid, "setfsuid"},
    {SYS_setfsgid, "setfsgid"},
    {SYS_getsid, "getsid"},
    {SYS_capget, "capget"},
    {SYS_capset, "capset"},
    {SYS_rt_sigpending, "rt_sigpending"},
    {SYS_rt_sigtimedwait, "rt_sigtimedwait"},
    {SYS_rt_sigqueueinfo, "rt_sigqueueinfo"},
    {SYS_rt_sigsuspend, "rt_sigsuspend"},
    {SYS_sigaltstack, "sigaltstack"},
    {SYS_utime, "utime"},
    {SYS_mknod, "mknod"},
    {SYS_uselib, "uselib"},
    {SYS_personality, "personality"},
    {SYS_ustat, "ustat"},
    {SYS_statfs, "statfs"},
    {SYS_fstatfs, "fstatfs"},
    {SYS_sysfs, "sysfs"},
    {SYS_getpriority, "getpriority"},
    {SYS_setpriority, "setpriority"},
    {SYS_sched_setparam, "sched_setparam"},
    {SYS_sched_getparam, "sched_getparam"},
    {SYS_sched_setscheduler, "sched_setscheduler"},
    {SYS_sched_getscheduler, "sched_getscheduler"},
    {SYS_sched_get_priority_max, "sched_get_priority_max"},
    {SYS_sched_get_priority_min, "sched_get_priority_min"},
    {SYS_sched_rr_get_interval, "sched_rr_get_interval"},
    {SYS_mlock, "mlock"},
    {SYS_munlock, "munlock"},
    {SYS_mlockall, "mlockall"},
    {SYS_munlockall, "munlockall"},
    {SYS_vhangup, "vhangup"},
    {SYS_modify_ldt, "modify_ldt"},
    {SYS_pivot_root, "pivot_root"},
    {SYS__sysctl, "_sysctl"},
    {SYS_prctl, "prctl"},
    {SYS_arch_prctl, "arch_prctl"},
    {SYS_adjtimex, "adjtimex"},
    {SYS_setrlimit, "setrlimit"},
    {SYS_chroot, "chroot"},
    {SYS_sync, "sync"},
    {SYS_acct, "acct"},
    {SYS_settimeofday, "settimeofday"},
    {SYS_mount, "mount"},
    {SYS_umount2, "umount2"},
    {SYS_swapon, "swapon"},
    {SYS_swapoff, "swapoff"},
    {SYS_reboot, "reboot"},
    {SYS_sethostname, "sethostname"},
    {SYS_setdomainname, "setdomainname"},
    {SYS_iopl, "iopl"},
    {SYS_ioperm, "ioperm"},
    {SYS_create_module, "create_module"},
    {SYS_init_module, "init_module"},
    {SYS_delete_module, "delete_module"},
    {SYS_get_kernel_syms, "get_kernel_syms"},
    {SYS_query_module, "query_module"},
    {SYS_quotactl, "quotactl"},
    {SYS_nfsservctl, "nfsservctl"},
    {SYS_getpmsg, "getpmsg"},
    {SYS_putpmsg, "putpmsg"},
    {SYS_afs_syscall, "afs_syscall"},
    {SYS_tuxcall, "tuxcall"},
    {SYS_security, "security"},
    {SYS_gettid, "gettid"},
    {SYS_readahead, "readahead"},
    {SYS_setxattr, "setxattr"},
    {SYS_lsetxattr, "lsetxattr"},
    {SYS_fsetxattr, "fsetxattr"},
    {SYS_getxattr, "getxattr"},
    {SYS_lgetxattr, "lgetxattr"},
    {SYS_fgetxattr, "fgetxattr"},
    {SYS_listxattr, "listxattr"},
    {SYS_llistxattr, "llistxattr"},
    {SYS_flistxattr, "flistxattr"},
    {SYS_removexattr, "removexattr"},
    {SYS_lremovexattr, "lremovexattr"},
    {SYS_fremovexattr, "fremovexattr"},
    {SYS_tkill, "tkill"},
    {SYS_time, "time"},
    {SYS_futex, "futex"},
    {SYS_sched_setaffinity, "sched_setaffinity"},
    {SYS_sched_getaffinity, "sched_getaffinity"},
    {SYS_set_thread_area, "set_thread_area"},
    {SYS_io_setup, "io_setup"},
    {SYS_io_destroy, "io_destroy"},
    {SYS_io_getevents, "io_getevents"},
    {SYS_io_submit, "io_submit"},
    {SYS_io_cancel, "io_cancel"},
    {SYS_get_thread_area, "get_thread_area"},
    {SYS_lookup_dcookie, "lookup_dcookie"},
    {SYS_epoll_create, "epoll_create"},
    {SYS_epoll_ctl_old, "epoll_ctl_old"},
    {SYS_epoll_wait_old, "epoll_wait_old"},
    {SYS_remap_file_pages, "remap_file_pages"},
    {SYS_getdents64, "getdents64"},
    {SYS_set_tid_address, "set_tid_address"},
    {SYS_restart_syscall, "restart_syscall"},
    {SYS_semtimedop, "semtimedop"},
    {SYS_fadvise64, "fadvise64"},
    {SYS_timer_create, "timer_create"},
    {SYS_timer_settime, "timer_settime"},
    {SYS_timer_gettime, "timer_gettime"},
    {SYS_timer_getoverrun, "timer_getoverrun"},
    {SYS_timer_delete, "timer_delete"},
    {SYS_clock_settime, "clock_settime"},
    {SYS_clock_gettime, "clock_gettime"},
    {SYS_clock_getres, "clock_getres"},
    {SYS_clock_nanosleep, "clock_nanosleep"},
    {SYS_exit_group, "exit_group"},
    {SYS_epoll_wait, "epoll_wait"},
    {SYS_epoll_ctl, "epoll_ctl"},
    {SYS_tgkill, "tgkill"},
    {SYS_utimes, "utimes"},
    {SYS_vserver, "vserver"},
    {SYS_mbind, "mbind"},
    {SYS_set_mempolicy, "set_mempolicy"},
    {SYS_get_mempolicy, "get_mempolicy"},
    {SYS_mq_open, "mq_open"},
    {SYS_mq_unlink, "mq_unlink"},
    {SYS_mq_timedsend, "mq_timedsend"},
    {SYS_mq_timedreceive, "mq_timedreceive"},
    {SYS_mq_notify, "mq_notify"},
    {SYS_mq_getsetattr, "mq_getsetattr"},
    {SYS_kexec_load, "kexec_load"},
    {SYS_waitid, "waitid"},
    {SYS_add_key, "add_key"},
    {SYS_request_key, "request_key"},
    {SYS_keyctl, "keyctl"},
    {SYS_ioprio_set, "ioprio_set"},
    {SYS_ioprio_get, "ioprio_get"},
    {SYS_inotify_init, "inotify_init"},
    {SYS_inotify_add_watch, "inotify_add_watch"},
    {SYS_inotify_rm_watch, "inotify_rm_watch"},
    {SYS_migrate_pages, "migrate_pages"},
    {SYS_openat, "openat"},
    {SYS_mkdirat, "mkdirat"},
    {SYS_mknodat, "mknodat"},
    {SYS_fchownat, "fchownat"},
    {SYS_futimesat, "futimesat"},
    {SYS_newfstatat, "newfstatat"},
    {SYS_unlinkat, "unlinkat"},
    {SYS_renameat, "renameat"},
    {SYS_linkat, "linkat"},
    {SYS_symlinkat, "symlinkat"},
    {SYS_readlinkat, "readlinkat"},
    {SYS_fchmodat, "fchmodat"},
    {SYS_faccessat, "faccessat"},
    {SYS_pselect6, "pselect6"},
    {SYS_ppoll, "ppoll"},
    {SYS_unshare, "unshare"},
    {SYS_set_robust_list, "set_robust_list"},
    {SYS_get_robust_list, "get_robust_list"},
    {SYS_splice, "splice"},
    {SYS_tee, "tee"},
    {SYS_sync_file_range, "sync_file_range"},
    {SYS_vmsplice, "vmsplice"},
    {SYS_move_pages, "move_pages"},
    {SYS_utimensat, "utimensat"},
    {SYS_epoll_pwait, "epoll_pwait"},
    {SYS_signalfd, "signalfd"},
    {SYS_timerfd_create, "timerfd_create"},
    {SYS_eventfd, "eventfd"},
    {SYS_fallocate, "fallocate"},
    {SYS_timerfd_settime, "timerfd_settime"},
    {SYS_timerfd_gettime, "timerfd_gettime"},
    {SYS_accept4, "accept4"},
    {SYS_signalfd4, "signalfd4"},
    {SYS_eventfd2, "eventfd2"},
    {SYS_epoll_create1, "epoll_create1"},
    {SYS_dup3, "dup3"},
    {SYS_pipe2, "pipe2"},
    {SYS_inotify_init1, "inotify_init1"},
    {SYS_preadv, "preadv"},
    {SYS_pwritev, "pwritev"},
    {SYS_rt_tgsigqueueinfo, "rt_tgsigqueueinfo"},
    {SYS_perf_event_open, "perf_event_open"},
    {SYS_recvmmsg, "recvmmsg"},
    {SYS_fanotify_init, "fanotify_init"},
    {SYS_fanotify_mark, "fanotify_mark"},
    {SYS_prlimit64, "prlimit64"},
    {SYS_name_to_handle_at, "name_to_handle_at"},
    {SYS_open_by_handle_at, "open_by_handle_at"},
    {SYS_clock_adjtime, "clock_adjtime"},
    {SYS_syncfs, "syncfs"},
    {SYS_sendmmsg, "sendmmsg"},
    {SYS_setns, "setns"},
    {SYS_getcpu, "getcpu"},
    {SYS_process_vm_readv, "process_vm_readv"},
    {SYS_process_vm_writev, "process_vm_writev"},
    {SYS_kcmp, "kcmp"},
    {SYS_finit_module, "finit_module"},
    {SYS_sched_setattr, "sched_setattr"},
    {SYS_sched_getattr, "sched_getattr"},
    {SYS_renameat2, "renameat2"},
    {SYS_seccomp, "seccomp"},
    {SYS_getrandom, "getrandom"},
    {SYS_memfd_create, "memfd_create"},
    {SYS_kexec_file_load, "kexec_file_load"},
    {SYS_bpf, "bpf"},
    {SYS_execveat, "execveat"},
    {SYS_userfaultfd, "userfaultfd"},
    {SYS_membarrier, "membarrier"},
    {SYS_mlock2, "mlock2"},
    {SYS_copy_file_range, "copy_file_range"},
    {SYS_preadv2, "preadv2"},
    {SYS_pwritev2, "pwritev2"},
    {SYS_pkey_mprotect, "pkey_mprotect"},
    {SYS_pkey_alloc, "pkey_alloc"},
    {SYS_pkey_free, "pkey_free"}};

// fused buffer wrap, split, and resolve
static inline tuple resolve_cstring(tuple root, char *f)
{
    buffer a = little_stack_buffer(50);
    char *x = f;
    tuple t = root;
    char y;

    if (strcmp(f, ".") == 0)
        return root;

    if (strcmp(f, "/") == 0)
        return filesystem_getroot(current->p->fs);

    while ((y = *x++)) {
        if (y == '/') {
            if (buffer_length(a)) {
                t = lookup(t, intern(a));
                if (!t) return t;
                buffer_clear(a);
            }                
        } else {
            push_character(a, y);
        }
    }
    
    if (buffer_length(a)) {
        t = lookup(t, intern(a));
        return t;
    }
    return 0;
}


char *syscall_name(int x)
{
    for (int i = 0; i < sizeof(syscall_codes)/sizeof(struct code); i++) {
        if (syscall_codes[i].c == x) 
            return syscall_codes[i].n;
    }
    return ("invalid syscall");
}

sysreturn read(int fd, u8 *dest, bytes length)
{
    file f = resolve_fd(current->p, fd);
    if (!f->read)
        return set_syscall_error(current, EINVAL);

    /* use (and update) file offset */
    return apply(f->read, dest, length, infinity);
}

sysreturn pread(int fd, u8 *dest, bytes length, s64 offset)
{
    file f = resolve_fd(current->p, fd);
    if (!f->read || offset < 0)
	return set_syscall_error(current, EINVAL);

    /* use given offset with no file offset update */
    return apply(f->read, dest, length, offset);
}

sysreturn write(int fd, u8 *body, bytes length)
{
    file f = resolve_fd(current->p, fd);        
    if (!f->write)
        return set_syscall_error(current, EINVAL);

    /* use (and update) file offset */
    return apply(f->write, body, length, infinity);
}

sysreturn pwrite(int fd, u8 *body, bytes length, s64 offset)
{
    file f = resolve_fd(current->p, fd);
    if (!f->write || offset < 0)
        return set_syscall_error(current, EINVAL);

    return apply(f->write, body, length, offset);
}

sysreturn sysreturn_from_fs_status(fs_status s)
{
    switch (s) {
    case FS_STATUS_OK:
        return 0;
    case FS_STATUS_NOENT:
        return -ENOENT;
    case FS_STATUS_EXIST:
        return -EEXIST;
    case FS_STATUS_NOTDIR:
        return -ENOTDIR;
    default:
        halt("status %d, update %s\n", s, __func__);
        return 0;               /* suppress warn */
    }
}

static sysreturn do_mkent(const char *pathname, int mode, boolean dir)
{
    heap h = heap_general(get_kernel_heaps());
    buffer cwd = wrap_buffer_cstring(h, "/"); /* XXX */

    if (!pathname)
        return set_syscall_error(current, EFAULT);

    /* canonicalize the path */
    char *final_path = canonicalize_path(h, cwd,
            wrap_buffer_cstring(h, (char *)pathname));

    thread_log(current, "%s: %s (mode %d) pathname %s => %s\n",
               __func__, dir ? "mkdir" : "creat", mode, pathname, final_path);

    sysreturn r = dir ? filesystem_mkdir(current->p->fs, final_path) :
        filesystem_creat(current->p->fs, final_path);
    return set_syscall_return(current, sysreturn_from_fs_status(r));
}

static boolean is_dir(tuple n)
{
    return children(n) ? true : false;
}

static boolean is_special(tuple n)
{
    return table_find(n, sym(special)) ? true : false;
}

static CLOSURE_4_2(file_op_complete, void, thread, file, fsfile, boolean, status, bytes);
static void file_op_complete(thread t, file f, fsfile fsf, boolean is_file_offset, status s, bytes length)
{
    thread_log(current, "%s: len %d, status %v (%s)\n", __func__,
            length, s, is_ok(s) ? "OK" : "NOTOK");
    if (is_ok(s)) {
        /* if regular file, update length */
        if (fsf)
            f->length = fsfile_get_length(fsf);
        if (is_file_offset)	/* vs specified offset (pread) */
            f->offset += length;
        set_syscall_return(t, length);
    } else {
        /* XXX should peek inside s and map to errno... */
        set_syscall_error(t, EIO);
    }
    thread_wakeup(t);
}

static CLOSURE_7_2(file_op_complete_internal, void, thread, file, fsfile, file, fsfile, int, void*, status, bytes);
static void file_op_complete_internal(thread t, file inf, fsfile inffs, file ouf, fsfile outfs, int offset_adjust, void* buf, status s, bytes length)
{
    buffer b;

    thread_log(current, "%s: len %d, status %v (%s)\n", __func__,
            length, s, is_ok(s) ? "OK" : "NOTOK");
    if (is_ok(s)) {
        if (inffs)
            inf->length = fsfile_get_length(inffs);
        if (offset_adjust)
	        inf->offset += length;
        b = wrap_buffer(heap_general(get_kernel_heaps()), buf, length);
        filesystem_write(current->p->fs, ouf->n, b, ouf->offset,
                closure(heap_general(get_kernel_heaps()), file_op_complete, current, ouf, outfs, 1));
    } else {
        deallocate_buffer(buf);
        set_syscall_error(t, EIO);
        thread_wakeup(current);
    }
}

static sysreturn sendfile(int outfile, int infile, unsigned long *offs, bytes count)
{
    file inf = resolve_fd(current->p, infile);
    fsfile inffs = fsfile_from_node(current->p->fs, inf->n);
    file ouf = resolve_fd(current->p, outfile);
    fsfile outfs = fsfile_from_node(current->p->fs, ouf->n);
    heap h = heap_general(get_kernel_heaps());
    void *buf = allocate(h, count);
    int offset_adjust = (offs == 0);	/* adjust only if offs is NULL */
    s64 offset = (s64)(offset_adjust == 1) ? inf->offset : *offs;

    if (!inf->read || !ouf->write)
      return set_syscall_error(current, EINVAL);
    if ((inf->offset + count) > inf->length)
        return set_syscall_error(current, EINVAL);

    filesystem_read(current->p->fs, inf->n, buf, count, offset,
	closure(h, file_op_complete_internal, current, inf, inffs, ouf, outfs, offset_adjust, buf));

    thread_sleep(current);
    return count;
}

static CLOSURE_2_3(file_read, sysreturn, file, fsfile, void *, u64, u64);
static sysreturn file_read(file f, fsfile fsf, void *dest, u64 length, u64 offset_arg)
{
    boolean is_file_offset = offset_arg == infinity;
    bytes offset = is_file_offset ? f->offset : offset_arg;
    thread_log(current, "%s: %v, dest %p, length %d, offset %d (%s), file length %d\n",
               __func__, f->n, dest, length, offset, is_file_offset ? "infinity" : "exact",
               f->length);

    if (is_special(f->n)) {
        return spec_read(f, dest, length, offset);
    }

    if (offset < f->length) {
        filesystem_read(current->p->fs, f->n, dest, length, offset,
                closure(heap_general(get_kernel_heaps()),
                        file_op_complete, current, f, fsf, is_file_offset));

        /* XXX Presently only support blocking file reads... */
        thread_sleep(current);
    } else {
        /* XXX special handling for holes will need to go here */
        return 0;
    }
}

#define PAD_WRITES 0

static CLOSURE_2_3(file_write, sysreturn, file, fsfile, void *, u64, u64);
static sysreturn file_write(file f, fsfile fsf, void *dest, u64 length, u64 offset_arg)
{
    thread_log(current, "%s: %v, dest %p, length %d, offset_arg %d\n",
            __func__, f->n, dest, length, offset_arg);
    boolean is_file_offset = offset_arg == infinity;
    bytes offset = is_file_offset ? f->offset : offset_arg;
    heap h = heap_general(get_kernel_heaps());

    u64 final_length = PAD_WRITES ? pad(length, SECTOR_SIZE) : length;
    void *buf = allocate(h, final_length);

    /* copy from userspace, XXX: check pointer safety */
    runtime_memset(buf, 0, final_length);
    runtime_memcpy(buf, dest, length);

    buffer b = wrap_buffer(h, buf, final_length);
    thread_log(current, "%s: b_ref: %p\n", __func__, buffer_ref(b, 0));

    if (is_special(f->n)) {
        return spec_write(f, b, length, offset);
    }

    filesystem_write(current->p->fs, f->n, b, offset,
                     closure(h, file_op_complete, current, f, fsf, is_file_offset));

    /* XXX Presently only support blocking file writes... */
    thread_sleep(current);
}

static CLOSURE_2_0(file_close, sysreturn, file, fsfile);
static sysreturn file_close(file f, fsfile fsf)
{
    unix_cache_free(get_unix_heaps(), file, f);
    return 0;
}

/* XXX this needs to move - with the notify stuff in netsyscall - to
   generic file routines (and make static inline) */
u32 edge_events(u32 masked, u32 eventmask, u32 last)
{
    u32 r;
    /* report only rising events if edge triggered */
    if ((eventmask & EPOLLET) && (masked != last)) {
	r = (masked ^ last) & masked;
    } else {
	r = masked;
    }
    return r;
}

static CLOSURE_2_3(file_check, boolean, file, fsfile, u32, u32 *, event_handler);
static boolean file_check(file f, fsfile fsf, u32 eventmask, u32 * last, event_handler eh)
{
    thread_log(current, "file_check: file %t, eventmask %P, last %P, event_handler %p\n",
	       f->n, eventmask, last ? *last : 0, eh);

    u32 events;
    if (is_special(f->n)) {
        events = spec_events(f);
    } else {
        /* No support for non-blocking XXXX
           Also, if and when we have some degree of file caching and want
           to support the above, don't rewrite it but factor out the
           notify list stuff from netsyscall.c to share with files.
        */
        events = f->length < infinity ? EPOLLOUT : 0;
        events |= f->offset < f->length ? EPOLLIN : EPOLLHUP;
    }
    u32 masked = events & eventmask;
    u32 r = edge_events(masked, eventmask, last ? *last : 0);
    if (last)
        *last = masked;
    if (r)
	return apply(eh, r);
    return true;
}

sysreturn open_internal(tuple root, char *name, int flags, int mode)
{
    heap h = heap_general(get_kernel_heaps());
    unix_heaps uh = get_unix_heaps();
    tuple n = resolve_cstring(root, name);

    if ((flags & O_CREAT)) {
        if (n && (flags & O_EXCL)) {
            msg_err("\"%s\" opened with O_EXCL but already exists\n", name);
            return set_syscall_error(current, EEXIST);
        } else if (!n) {
            sysreturn rv = do_mkent(name, mode, false);
            if (rv)
                return rv;
            /* XXX We could rearrange calls to return tuple instead of
               status; though this serves as a sanity check. */
            n = resolve_cstring(root, name);
        }
    }

    if (!n) {
        msg_err("\"%s\" - not found\n", name);
        return set_syscall_error(current, ENOENT);
    }
    u64 length = 0;
    fsfile fsf = 0;
    if (!is_dir(n) && !is_special(n)) {
        fsf = fsfile_from_node(current->p->fs, n);
        if (!fsf) {
            msg_err("\"%s\": can't find corresponding fsfile (%t)\n", name, n);
            return set_syscall_error(current, ENOENT);
        }
        length = fsfile_get_length(fsf);
    }
    // might be functional, or be a directory
    file f = unix_cache_alloc(uh, file);
    if (f == INVALID_ADDRESS) {
        msg_err("failed to allocate struct file\n");
        return set_syscall_error(current, ENOMEM);
    }
    int fd = allocate_fd(current->p, f);
    if (fd == INVALID_PHYSICAL) {
        msg_err("failed to allocate fd\n");
        unix_cache_free(uh, file, f);
        return set_syscall_error(current, EMFILE);
    }
    f->n = n;
    f->read = closure(h, file_read, f, fsf);
    f->write = closure(h, file_write, f, fsf);
    f->close = closure(h, file_close, f, fsf);
    f->check = closure(h, file_check, f, fsf);
    f->length = length;
    f->offset = 0;
    thread_log(current, "   fd %d, file length %d\n", fd, f->length);
    return fd;
}

sysreturn open(char *name, int flags, int mode)
{
    if (name == 0) 
        return set_syscall_error (current, EFAULT);
    thread_log(current, "open: \"%s\", flags %P, mode %P\n", name, flags, mode);
    return open_internal(current->p->cwd, name, flags, mode);
}

sysreturn mkdir(const char *pathname, int mode)
{
    return do_mkent(pathname, mode, true);
}

sysreturn creat(const char *pathname, int mode)
{
    if (!pathname)
        return set_syscall_error (current, EFAULT);
    thread_log(current, "creat: \"%s\", mode %P\n", pathname, mode);
    return open_internal(current->p->cwd, (char *)pathname, O_CREAT|O_WRONLY|O_TRUNC, mode);
}

sysreturn getrandom(void *buf, u64 buflen, unsigned int flags)
{
    heap h = heap_general(get_kernel_heaps());
    buffer b;

    if (!buf)
        return set_syscall_error(current, EFAULT);

    if (!buflen)
        return set_syscall_error(current, EINVAL);

    if (flags & ~(GRND_NONBLOCK | GRND_RANDOM))
        return set_syscall_error(current, EINVAL);

    b = wrap_buffer(h, buf, buflen);
    return do_getrandom(b, (u64) flags);
}

static int try_write_dirent(tuple root, struct linux_dirent *dirp, char *p,
        int *read_sofar, int *written_sofar, u64 *f_offset,
        unsigned int *count, int ft)
{
    int len = runtime_strlen(p);
    *read_sofar += len;
    if (*read_sofar > *f_offset) {
        int reclen = sizeof(struct linux_dirent) + len + 3;
        // include this element in the getdents output
        if (reclen > *count) {
            // can't include, there's no space
            *read_sofar -= len;
            return -1;
        } else {
            tuple n = resolve_cstring(root, p);
            // include the entry in the buffer
            runtime_memset((u8*)dirp, 0, reclen);
            dirp->d_ino = u64_from_pointer(n);
            dirp->d_reclen = reclen;
            runtime_memcpy(dirp->d_name, p, len + 1);
            dirp->d_off = dirp->d_reclen; // XXX: in the future, pad this.
            dirp->d_name[len + 2] = 0; /* some zero padding */
            ((char *)dirp)[dirp->d_reclen - 1] = ft;

            // advance dirp
            *written_sofar += reclen;
            *count -= reclen;
            return reclen;
        }
    }
    return 0;
}

sysreturn getdents(int fd, struct linux_dirent *dirp, unsigned int count)
{
    file f = resolve_fd(current->p, fd);
    tuple c = children(f->n);
    int read_sofar = 0, written_sofar = 0;

    if (!c)
        return -ENOTDIR;

    /* add reference to the current directory */
    int r = try_write_dirent(f->n, dirp, ".",
                &read_sofar, &written_sofar, &f->offset, &count,
                DT_DIR);
    if (r < 0)
        goto done;

    dirp = (struct linux_dirent *)(((char *)dirp) + r);

    /* add reference to the parent directory */
    r = try_write_dirent(f->n, dirp, "..",
                &read_sofar, &written_sofar, &f->offset, &count,
                DT_DIR);
    if (r < 0)
        goto done;

    dirp = (struct linux_dirent *)(((char *)dirp) + r);

    table_foreach(c, k, v) {
        char *p = cstring(symbol_string(k));
        r = try_write_dirent(f->n, dirp, p,
                    &read_sofar, &written_sofar, &f->offset, &count,
                    children(v) ? DT_DIR : DT_REG);
        if (r < 0)
            goto done;
        else
            dirp = (struct linux_dirent *)(((char *)dirp) + r);
    }

done:
    f->offset = read_sofar;
    if (r < 0 && written_sofar == 0)
        return -EINVAL;

    return written_sofar;
}

static int try_write_dirent64(tuple root, struct linux_dirent64 *dirp, char *p,
        int *read_sofar, int *written_sofar, u64 *f_offset,
        unsigned int *count, int ft)
{
    int len = runtime_strlen(p);
    *read_sofar += len;
    if (*read_sofar > *f_offset) {
        int reclen = sizeof(struct linux_dirent64) + len + 3;
        // include this element in the getdents output
        if (reclen > *count) {
            // can't include, there's no space
            *read_sofar -= len;
            return -1;
        } else {
            tuple n = resolve_cstring(root, p);
            // include the entry in the buffer
            runtime_memset((u8*)dirp, 0, reclen);
            dirp->d_ino = u64_from_pointer(n);
            dirp->d_reclen = reclen;
            runtime_memcpy(dirp->d_name, p, len + 1);
            dirp->d_off = dirp->d_reclen; // XXX: in the future, pad this.
            dirp->d_name[len + 2] = 0; /* some zero padding */
            dirp->d_type = ft;

            // advance dirp
            *written_sofar += reclen;
            *count -= reclen;
            return reclen;
        }
    }
    return 0;
}

sysreturn getdents64(int fd, struct linux_dirent64 *dirp, unsigned int count)
{
    file f = resolve_fd(current->p, fd);
    tuple c = children(f->n);
    int read_sofar = 0, written_sofar = 0;

    if (!c)
        return -ENOTDIR;

    /* add reference to the current directory */
    int r = try_write_dirent64(f->n, dirp, ".",
                &read_sofar, &written_sofar, &f->offset, &count,
                DT_DIR);
    if (r < 0)
        goto done;

    dirp = (struct linux_dirent64 *)(((char *)dirp) + r);

    /* add reference to the parent directory */
    r = try_write_dirent64(f->n, dirp, "..",
                &read_sofar, &written_sofar, &f->offset, &count,
                DT_DIR);
    if (r < 0)
        goto done;

    dirp = (struct linux_dirent64 *)(((char *)dirp) + r);

    table_foreach(c, k, v) {
        char *p = cstring(symbol_string(k));
        r = try_write_dirent64(f->n, dirp, p,
                    &read_sofar, &written_sofar, &f->offset, &count,
                    children(v) ? DT_DIR : DT_REG);
        if (r < 0)
            goto done;
        else
            dirp = (struct linux_dirent64 *)(((char *)dirp) + r);
    }

done:
    f->offset = read_sofar;
    if (r < 0 && written_sofar == 0)
        return -EINVAL;

    return written_sofar;
}


sysreturn writev(int fd, iovec v, int count)
{
    int res;
    resolve_fd(current->p, fd);
    for (int i = 0; i < count; i++) res += write(fd, v[i].address, v[i].length);
    return res;
}

static sysreturn access(char *name, int mode)
{
    if (!resolve_cstring(current->p->cwd, name)) {
        return set_syscall_error(current, ENOENT);
    }
    return 0;
}

/*
If the pathname given in pathname is relative, then it is interpreted
relative to the directory referred to by the file descriptor dirfd
(rather than relative to the current working directory of the calling
process, as is done by open() for a relative pathname).

If pathname is relative and dirfd is the special value AT_FDCWD, then
pathname is interpreted relative to the current working directory of
the calling process (like open()).

If pathname is absolute, then dirfd is ignore
*/
sysreturn openat(int dirfd, char *name, int flags, int mode)
{
    if (name == 0)
        return set_syscall_error (current, EINVAL);
    // dirfs == AT_FDCWS or path is absolute
    if (dirfd == AT_FDCWD || *name == '/') {
        return open(name, flags, mode);
    }
    file f = resolve_fd(current->p, dirfd);
    return open_internal(f->n, name, flags, mode);
}

static void fill_stat(tuple n, struct stat *s)
{
    s->st_dev = 0;
    s->st_ino = u64_from_pointer(n);
    s->st_size = 0;
    if (is_dir(n)) {
        s->st_mode = S_IFDIR | 0777;
        return;
    } else if (!is_special(n)) {
        fsfile f = fsfile_from_node(current->p->fs, n);
        if (!f) {
            msg_err("can't find fsfile\n");
            return;
        }
        s->st_size = fsfile_get_length(f);
    }
    fsfile f = fsfile_from_node(current->p->fs, n);
    if (!f) {
        msg_err("can't find fsfile\n");
        return;
    }
    s->st_mode = S_IFREG | 0644; /* TODO */
    s->st_size = fsfile_get_length(f);
    thread_log(current, "st_ino %P, st_mode %P, st_size %P\n",
            s->st_ino, s->st_mode, s->st_size);
}

static sysreturn fstat(int fd, struct stat *s)
{
    thread_log(current, "fd %d, stat %p\n", fd, s);
    file f = resolve_fd(current->p, fd);
    zero(s, sizeof(struct stat));
    // take this from tuple space
    if (fd == 0 || fd == 1 || fd == 2) {
        s->st_mode = S_IFIFO;
        return 0;
    }
    fill_stat(f->n, s);
    return 0;
}


static sysreturn stat(char *name, struct stat *s)
{
    tuple n;

    if (!(n = resolve_cstring(current->p->cwd, name))) {    
        return set_syscall_error(current, ENOENT);
    }
    fill_stat(n, s);
    return 0;
}

sysreturn lseek(int fd, s64 offset, int whence)
{
    thread_log(current, "%s: fd %d offset %d whence %s\n",
            __func__, fd, offset, whence == SEEK_SET ? "SEEK_SET" :
            whence == SEEK_CUR ? "SEEK_CUR" :
            whence == SEEK_END ? "SEEK_END" :
            "bugged");

    file f = resolve_fd(current->p, fd);
    s64 new;

    switch (whence) {
        case SEEK_SET:
            new = offset;
            break;
        case SEEK_CUR:
            new = f->offset + offset;
            break;
        case SEEK_END:
            new = f->length + offset;
            break;
        default:
            return set_syscall_error(current, EINVAL);
    }

    if (new < 0)
        return set_syscall_error(current, EINVAL);

    f->offset = new;

    /* XXX do this in write, too */
    if (f->offset > f->length) {
        msg_err("fd %d, offset %d, whence %d: file holes not supported\n",
                fd, offset, whence);
        halt("halt\n");
    }

    return f->offset;
}


sysreturn uname(struct utsname *v)
{
    char rel[]= "4.4.0-87";
    char sys[] = "pugnix";
    runtime_memcpy(v->sysname,sys, sizeof(sys));
    runtime_memcpy(v->release, rel, sizeof(rel));
    return 0;
}

// we dont limit anything now.
sysreturn setrlimit(int resource, const struct rlimit *rlim)
{
    return 0;
}

sysreturn getrlimit(int resource, struct rlimit *rlim)
{
    switch (resource) {
    case RLIMIT_STACK:
        rlim->rlim_cur = 2*1024*1024;
        rlim->rlim_max = 2*1024*1024;
        return 0;
    case RLIMIT_NOFILE:
        // we .. .dont really have one?
        rlim->rlim_cur = 65536;
        rlim->rlim_max = 65536;
        return 0;
    }
    return -1;
}

static sysreturn getcwd(char *buf, u64 length)
{
    runtime_memcpy(buf, "/", 2);
    return sysreturn_from_pointer(buf);
}

static sysreturn brk(void *x)
{
    process p = current->p;
    kernel_heaps kh = get_kernel_heaps();

    if (x) {
        if (p->brk > x) {
            p->brk = x;
            // free
        } else {
            // I guess assuming we're aligned
            u64 alloc = pad(u64_from_pointer(x), PAGESIZE) - pad(u64_from_pointer(p->brk), PAGESIZE);
            map(u64_from_pointer(p->brk), allocate_u64(heap_physical(kh), alloc), alloc, heap_pages(kh));
            // people shouldn't depend on this
            zero(p->brk, alloc);
            p->brk += alloc;         
        }
    }
    return sysreturn_from_pointer(p->brk);
}

// mkfs resolve all symbolic links, so we
// have no symbolic links.
sysreturn readlink(const char *pathname, char *buf, u64 bufsiz)
{
    return set_syscall_error(current, EINVAL);
}

sysreturn readlinkat(int dirfd, const char *pathname, char *buf, u64 bufsiz)
{
    return set_syscall_error(current, EINVAL);
}

sysreturn close(int fd)
{
    file f = resolve_fd(current->p, fd);
    deallocate_fd(current->p, fd, f);
    if (f->close)
	return apply(f->close);
    msg_err("no close handler for fd %d\n", fd);
    return 0;
}

sysreturn fcntl(int fd, int cmd)
{
    switch (cmd) {
    case F_GETFL:
        return O_RDWR;
    default:
        return set_syscall_error(current, ENOSYS);
    }
}

sysreturn ioctl(int fd, unsigned long request, ...)
{
    switch (request) {
    case FIONBIO:
        return 0;
    default:
        return set_syscall_error(current, ENOSYS);
    }
}

sysreturn syscall_ignore()
{
    return 0;
}

sysreturn getpid()
{
    return current->p->pid;
}

sysreturn sched_yield()
{
    thread_wakeup(current);
    thread_sleep(current);
    return 0;
}

void exit(int code)
{
    halt("");
    while(1); //compiler put a noreturn on exit
}

sysreturn  exit_group(int status){
    halt("exit_group");
    while(1);
    return 0;
}

sysreturn pipe2(int fds[2], int flags)
{
    if (flags & ~(O_CLOEXEC | O_NONBLOCK))
        return set_syscall_error(current, EINVAL);

    return do_pipe2(fds, flags);
}

sysreturn pipe(int fds[2])
{
    return pipe2(fds, 0);
}

void register_file_syscalls(void **map)
{
    register_syscall(map, SYS_read, read);
    register_syscall(map, SYS_pread64, pread);
    register_syscall(map, SYS_write, write);
    register_syscall(map, SYS_pwrite64, pwrite);
    register_syscall(map, SYS_open, open);
    register_syscall(map, SYS_openat, openat);
    register_syscall(map, SYS_fstat, fstat);
    register_syscall(map, SYS_sendfile, sendfile);
    register_syscall(map, SYS_stat, stat);
    register_syscall(map, SYS_lstat, stat);
    register_syscall(map, SYS_writev, writev);
    register_syscall(map, SYS_access, access);
    register_syscall(map, SYS_lseek, lseek);
    register_syscall(map, SYS_fcntl, fcntl);
    register_syscall(map, SYS_ioctl, (sysreturn (*)())ioctl);
    register_syscall(map, SYS_getcwd, getcwd);
    register_syscall(map, SYS_readlink, readlink);
    register_syscall(map, SYS_readlinkat, readlinkat);
    register_syscall(map, SYS_close, close);
    register_syscall(map, SYS_sched_yield, sched_yield);
    register_syscall(map, SYS_brk, brk);
    register_syscall(map, SYS_uname, uname);
    register_syscall(map, SYS_getrlimit, getrlimit);
    register_syscall(map, SYS_setrlimit, setrlimit);
    register_syscall(map, SYS_getpid, getpid);    
    register_syscall(map,SYS_exit_group, exit_group);
    register_syscall(map, SYS_exit, (sysreturn (*)())exit);
    register_syscall(map, SYS_getdents, getdents);
    register_syscall(map, SYS_getdents64, getdents64);
    register_syscall(map, SYS_mkdir, mkdir);
    register_syscall(map, SYS_getrandom, getrandom);
    register_syscall(map, SYS_pipe, pipe);
    register_syscall(map, SYS_pipe2, pipe2);
    register_syscall(map, SYS_creat, creat);
}

void *linux_syscalls[SYS_MAX];

#define offsetof(__t, __e) u64_from_pointer(&((__t)0)->__e)


// return value is fucked up and need ENOENT - enoent could be initialized
buffer install_syscall(heap h)
{
    buffer b = allocate_buffer(h, 100);
    int working = REGISTER_A;
    mov_64_imm(b, working, u64_from_pointer(current));
    indirect_displacement(b, REGISTER_A, REGISTER_A, offsetof(thread, p));
    indirect_displacement(b, REGISTER_A, REGISTER_A, offsetof(process, syscall_handlers));
    indirect_scale(b, REGISTER_A, 3, REGISTER_B, REGISTER_A);
    jump_indirect(b, REGISTER_A);
    return b;
}

extern char *syscall_name(int);
static void syscall_debug()
{
    u64 *f = current->frame;
    int call = f[FRAME_VECTOR];
    void *debugsyscalls = table_find(current->p->process_root, sym(debugsyscalls));
    if(debugsyscalls)  
        thread_log(current, syscall_name(call));
    sysreturn (*h)(u64, u64, u64, u64, u64, u64) = current->p->syscall_handlers[call];
    sysreturn res = -ENOSYS;
    if (h) {
        res = h(f[FRAME_RDI], f[FRAME_RSI], f[FRAME_RDX], f[FRAME_R10], f[FRAME_R8], f[FRAME_R9]);
    } else if (debugsyscalls) {
        rprintf("nosyscall %s\n", syscall_name(call));
    }
    set_syscall_return(current, res);
}

// should hang off the thread context, but the assembly handler needs
// to find it.
void *syscall;

void init_syscalls()
{
    //syscall = b->contents;
    // debug the synthesized version later, at least we have the table dispatch
    syscall = syscall_debug;
}
