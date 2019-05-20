#include <unix_internal.h>
#include <metadata.h>

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

void register_other_syscalls(struct syscall *map)
{
    register_syscall(map, rt_sigreturn, 0);
    register_syscall(map, msync, 0);
    register_syscall(map, shmget, 0);
    register_syscall(map, shmat, 0);
    register_syscall(map, shmctl, 0);
    register_syscall(map, dup2, 0);
    register_syscall(map, pause, 0);
    register_syscall(map, getitimer, 0);
    register_syscall(map, alarm, 0);
    register_syscall(map, setitimer, 0);
    register_syscall(map, sendmsg, 0);
    register_syscall(map, recvmsg, 0);
    register_syscall(map, shutdown, 0);
    register_syscall(map, fork, 0);
    register_syscall(map, vfork, 0);
    register_syscall(map, execve, 0);
    register_syscall(map, wait4, syscall_ignore);
    register_syscall(map, kill, 0);
    register_syscall(map, semget, 0);
    register_syscall(map, semop, 0);
    register_syscall(map, semctl, 0);
    register_syscall(map, shmdt, 0);
    register_syscall(map, msgget, 0);
    register_syscall(map, msgsnd, 0);
    register_syscall(map, msgrcv, 0);
    register_syscall(map, msgctl, 0);
    register_syscall(map, flock, 0);
    register_syscall(map, fsync, 0);
    register_syscall(map, fdatasync, 0);
    register_syscall(map, truncate, 0);
    register_syscall(map, ftruncate, 0);
    register_syscall(map, rename, 0);
    register_syscall(map, rmdir, 0);
    register_syscall(map, link, 0);
    register_syscall(map, unlink, 0);
    register_syscall(map, symlink, 0);
    register_syscall(map, chmod, syscall_ignore);
    register_syscall(map, fchmod, syscall_ignore);
    register_syscall(map, fchown, 0);
    register_syscall(map, lchown, 0);
    register_syscall(map, umask, 0);
    register_syscall(map, getrusage, 0);
    register_syscall(map, times, 0);
    register_syscall(map, ptrace, 0);
    register_syscall(map, syslog, 0);
    register_syscall(map, getgid, 0);
    register_syscall(map, getegid, 0);
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
    register_syscall(map, capget, 0);
    register_syscall(map, capset, 0);
    register_syscall(map, rt_sigpending, 0);
    register_syscall(map, rt_sigtimedwait, 0);
    register_syscall(map, rt_sigqueueinfo, 0);
    register_syscall(map, rt_sigsuspend, 0);
    register_syscall(map, utime, 0);
    register_syscall(map, mknod, 0);
    register_syscall(map, uselib, 0);
    register_syscall(map, personality, 0);
    register_syscall(map, ustat, 0);
    register_syscall(map, statfs, 0);
    register_syscall(map, fstatfs, 0);
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
    register_syscall(map, mlock, 0);
    register_syscall(map, munlock, 0);
    register_syscall(map, mlockall, 0);
    register_syscall(map, munlockall, 0);
    register_syscall(map, vhangup, 0);
    register_syscall(map, modify_ldt, 0);
    register_syscall(map, pivot_root, 0);
    register_syscall(map, _sysctl, 0);
    register_syscall(map, adjtimex, 0);
    register_syscall(map, chroot, 0);
    register_syscall(map, sync, 0);
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
    register_syscall(map, tkill, 0);
    register_syscall(map, set_thread_area, 0);
    register_syscall(map, io_setup, 0);
    register_syscall(map, io_destroy, 0);
    register_syscall(map, io_getevents, 0);
    register_syscall(map, io_submit, 0);
    register_syscall(map, io_cancel, 0);
    register_syscall(map, get_thread_area, 0);
    register_syscall(map, lookup_dcookie, 0);
    register_syscall(map, epoll_ctl_old, 0);
    register_syscall(map, epoll_wait_old, 0);
    register_syscall(map, remap_file_pages, 0);
    register_syscall(map, restart_syscall, 0);
    register_syscall(map, semtimedop, 0);
    register_syscall(map, fadvise64, 0);
    register_syscall(map, timer_create, 0);
    register_syscall(map, timer_settime, 0);
    register_syscall(map, timer_gettime, 0);
    register_syscall(map, timer_getoverrun, 0);
    register_syscall(map, timer_delete, 0);
    register_syscall(map, clock_settime, 0);
    register_syscall(map, tgkill, 0);
    register_syscall(map, utimes, 0);
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
    register_syscall(map, fchownat, 0);
    register_syscall(map, futimesat, 0);
    register_syscall(map, unlinkat, 0);
    register_syscall(map, renameat, 0);
    register_syscall(map, linkat, 0);
    register_syscall(map, symlinkat, 0);
    register_syscall(map, fchmodat, syscall_ignore);
    register_syscall(map, faccessat, 0);
    register_syscall(map, unshare, 0);
    register_syscall(map, set_robust_list, 0);
    register_syscall(map, get_robust_list, 0);
    register_syscall(map, splice, 0);
    register_syscall(map, tee, 0);
    register_syscall(map, sync_file_range, 0);
    register_syscall(map, vmsplice, 0);
    register_syscall(map, move_pages, 0);
    register_syscall(map, utimensat, 0);
    register_syscall(map, signalfd, 0);
    register_syscall(map, timerfd_create, 0);
    register_syscall(map, fallocate, 0);
    register_syscall(map, timerfd_settime, 0);
    register_syscall(map, timerfd_gettime, 0);
    register_syscall(map, signalfd4, 0);
    register_syscall(map, dup3, 0);
    register_syscall(map, inotify_init1, 0);
    register_syscall(map, preadv, 0);
    register_syscall(map, pwritev, 0);
    register_syscall(map, rt_tgsigqueueinfo, 0);
    register_syscall(map, perf_event_open, 0);
    register_syscall(map, recvmmsg, 0);
    register_syscall(map, fanotify_init, 0);
    register_syscall(map, fanotify_mark, 0);
    register_syscall(map, name_to_handle_at, 0);
    register_syscall(map, open_by_handle_at, 0);
    register_syscall(map, clock_adjtime, 0);
    register_syscall(map, syncfs, 0);
    register_syscall(map, sendmmsg, 0);
    register_syscall(map, setns, 0);
    register_syscall(map, getcpu, 0);
    register_syscall(map, process_vm_readv, 0);
    register_syscall(map, process_vm_writev, 0);
    register_syscall(map, kcmp, 0);
    register_syscall(map, finit_module, 0);
    register_syscall(map, sched_setattr, 0);
    register_syscall(map, sched_getattr, 0);
    register_syscall(map, renameat2, 0);
    register_syscall(map, seccomp, 0);
    register_syscall(map, memfd_create, 0);
    register_syscall(map, kexec_file_load, 0);
    register_syscall(map, bpf, 0);
    register_syscall(map, execveat, 0);
    register_syscall(map, userfaultfd, 0);
    register_syscall(map, membarrier, 0);
    register_syscall(map, mlock2, 0);
    register_syscall(map, copy_file_range, 0);
    register_syscall(map, preadv2, 0);
    register_syscall(map, pwritev2, 0);
    register_syscall(map, pkey_mprotect, 0);
    register_syscall(map, pkey_alloc, 0);
    register_syscall(map, pkey_free, 0);
}

// fused buffer wrap, split, and resolve
static inline tuple resolve_cstring(tuple cwd, const char *f)
{
    tuple t = *f == '/' ? filesystem_getroot(current->p->fs) : cwd;

    buffer a = little_stack_buffer(NAME_MAX);
    char y;
    while ((y = *f++)) {
        if (y == '/') {
            if (buffer_length(a)) {
                t = lookup(t, intern(a));
                if (!t)
                    return t;
                buffer_clear(a);
            }                
        } else {
            push_character(a, y);
        }
    }
    
    if (buffer_length(a)) {
        t = lookup(t, intern(a));
    }

    return t;
}

sysreturn read(int fd, u8 *dest, bytes length)
{
    fdesc f = resolve_fd(current->p, fd);
    if (!f->read)
        return set_syscall_error(current, EINVAL);

    /* use (and update) file offset */
    return apply(f->read, dest, length, infinity);
}

sysreturn pread(int fd, u8 *dest, bytes length, s64 offset)
{
    fdesc f = resolve_fd(current->p, fd);
    if (!f->read || offset < 0)
        return set_syscall_error(current, EINVAL);

    /* use given offset with no file offset update */
    return apply(f->read, dest, length, offset);
}

static CLOSURE_5_2(readv_complete, void, heap, thread, struct iovec*, u8*, u64, status, u64);
static void readv_complete(heap h, thread t, struct iovec *iov, u8* read_bytes, u64 total_len, status s, u64 read_len)
{
    int curr_pos = 0;
    int iv = 0;
    if(is_ok(s)) {

	while(curr_pos < read_len) {
	    struct iovec iovector = iov[iv];
	    int to_read = (iovector.iov_len < read_len - curr_pos) ? iovector.iov_len : read_len - curr_pos;
            runtime_memcpy(iovector.iov_base, read_bytes + curr_pos, to_read);
            curr_pos += iovector.iov_len;
            iv += 1;
	}
	deallocate(h, read_bytes, total_len);
	set_syscall_return(t, read_len);
    }
    else
	set_syscall_error(t, EINVAL);

    thread_wakeup(t);
}

sysreturn readv(int fd, struct iovec *iov, int iovcnt)
{
    u64 total_len = 0;
    heap h = heap_general(get_kernel_heaps());

    file f = resolve_fd(current->p, fd);
    if (!f->f.read || iovcnt < 0)
        return set_syscall_error(current, EINVAL);

    for(int i = 0; i < iovcnt; i++)
	total_len = iov[i].iov_len + total_len;

    u8 *read_bytes = allocate(h, total_len);

    filesystem_read(current->p->fs, f->n, read_bytes, total_len, 0,
		    closure(h, readv_complete, h, current, iov, read_bytes, total_len));
    thread_sleep(current);
}

sysreturn write(int fd, u8 *body, bytes length)
{
    fdesc f = resolve_fd(current->p, fd);
    if (!f->write)
        return set_syscall_error(current, EINVAL);

    /* use (and update) file offset */
    return apply(f->write, body, length, infinity);
}

sysreturn pwrite(int fd, u8 *body, bytes length, s64 offset)
{
    fdesc f = resolve_fd(current->p, fd);
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
    thread_log(current, "%s: len %d, status %v (%s)", __func__,
            length, s, is_ok(s) ? "OK" : "NOTOK");
    if (is_ok(s)) {
        /* if regular file, update length */
        if (fsf)
            f->length = fsfile_get_length(fsf);
        if (is_file_offset) /* vs specified offset (pread) */
            f->offset += length;
        set_syscall_return(t, length);
    } else {
        /* XXX should peek inside s and map to errno... */
        set_syscall_error(t, EIO);
    }
    thread_wakeup(t);
}

static CLOSURE_6_2(sendfile_read_complete, void, heap, thread, file, fdesc, int*, void*, status, bytes);
static void sendfile_read_complete(heap h, thread t, file in, fdesc out, int* offset, void* buf, status s, bytes length)
{
    if (is_ok(s)) {
        /* TODO:
            This has couple of issues.
            1. We don't wait for write to succeed before updating the offset. 
            2. buf is leaking, we can't release it unless we know write is done.
            I am looking at adding a generic completed handler for all file ops (ie sockets, files and pipe),
            and these completion handler can be invoked from bottom-half of operations allowing to chain 
            handler and do any necessary clean up.
        */
       if(!offset) {
           in->offset += length;
       } else {
            *offset += length;
       }
       apply(out->write, buf, length, 0);
    } else {
        deallocate(h,buf,length);
        set_syscall_error(t, EIO);
    }
}

// in_fd need to a regular file.
static sysreturn sendfile(int out_fd, int in_fd, int *offset, bytes count)
{
    file infile = resolve_fd(current->p, in_fd);
    fdesc outfile = resolve_fd(current->p, out_fd);
    heap h = heap_general(get_kernel_heaps());

    // infile need to a regular file
    if (!table_find(current->p->process_root, infile->n)) {
        return set_syscall_error(current, ENOSYS);
    }

    if (!infile->f.read || !outfile->write)
        return set_syscall_error(current, EINVAL);
    
    if ((infile->offset + count) > infile->length)
        return set_syscall_error(current, EINVAL);
    
    void *buf = allocate(h, count);
    u64 read_offset = 0;
    if(!offset) {
        read_offset = infile->offset;
    } else  {
        read_offset = *offset;
    }

    filesystem_read(current->p->fs, infile->n, buf, count, read_offset,
                closure(h, sendfile_read_complete, h, current, infile, outfile, offset, buf));
    thread_sleep(current);
    return set_syscall_return(current,count); // bogus
}


static CLOSURE_2_3(file_read, sysreturn, file, fsfile, void *, u64, u64);
static sysreturn file_read(file f, fsfile fsf, void *dest, u64 length, u64 offset_arg)
{
    boolean is_file_offset = offset_arg == infinity;
    u64 offset = is_file_offset ? f->offset : offset_arg;
    thread_log(current, "%s: f %p, dest %p, offset %ld (%s), length %ld, file length %ld",
               __func__, f, dest, offset, is_file_offset ? "file" : "specified",
               length, f->length);

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
    boolean is_file_offset = offset_arg == infinity;
    u64 offset = is_file_offset ? f->offset : offset_arg;
    thread_log(current, "%s: f %p, dest %p, offset %ld (%s), length %ld, file length %ld",
               __func__, f, dest, offset, is_file_offset ? "file" : "specified",
               length, f->length);
    heap h = heap_general(get_kernel_heaps());

    u64 final_length = PAD_WRITES ? pad(length, SECTOR_SIZE) : length;
    void *buf = allocate(h, final_length);

    /* XXX we shouldn't need to copy here, however if we at some point
       want to support non-blocking, we'll need to fix the unaligned
       block rmw in the extent write (prob just break it up into
       aligned and unaligned portions, copying aligned data straight
       to dma buffer and stashing unaligned portions to be copied post
       block read) */

    /* copy from userspace, XXX: check pointer safety */
    runtime_memset(buf, 0, final_length);
    runtime_memcpy(buf, dest, length);

    buffer b = wrap_buffer(h, buf, final_length);
    thread_log(current, "%s: b_ref: %p", __func__, buffer_ref(b, 0));

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

static CLOSURE_2_3(file_check, boolean, file, fsfile, u32, u32 *, event_handler);
static boolean file_check(file f, fsfile fsf, u32 eventmask, u32 * last, event_handler eh)
{
    thread_log(current, "file_check: file %t, eventmask %x, last %x, event_handler %p",
               f->n, eventmask, last ? *last : 0, eh);

    u32 events;
    if (is_special(f->n)) {
        events = spec_events(f);
    } else {
        /* XXX add nonblocking support */
        events = f->length < infinity ? EPOLLOUT : 0;
        events |= f->offset < f->length ? EPOLLIN : EPOLLHUP;
    }
    u32 report = edge_events(events, eventmask, last);
    /* bring in notify_set if we want threads to properly pick up file
       updates via select/poll */
    if (report) {
        if (apply(eh, report)) {
            if (last)
                *last = events & eventmask;
            return true;
        } else {
            return false;
        }
    }
    return true;
}

static int file_type_from_tuple(tuple n)
{
    if (is_dir(n))
        return FDESC_TYPE_DIRECTORY;
    else if (is_special(n))
        return FDESC_TYPE_SPECIAL;
    else
        return FDESC_TYPE_REGULAR;
}

sysreturn open_internal(tuple cwd, const char *name, int flags, int mode)
{
    heap h = heap_general(get_kernel_heaps());
    unix_heaps uh = get_unix_heaps();
    tuple n = resolve_cstring(cwd, name);

    if ((flags & O_CREAT)) {
        if (n && (flags & O_EXCL)) {
            thread_log(current, "\"%s\" opened with O_EXCL but already exists", name);
            return set_syscall_error(current, EEXIST);
        } else if (!n) {
            fs_status fs = filesystem_creat(current->p->fs, cwd, name, mode);
            if (fs != FS_STATUS_OK)
                return sysreturn_from_fs_status(fs);

            /* XXX We could rearrange calls to return tuple instead of
               status; though this serves as a sanity check. */
            n = resolve_cstring(cwd, name);
        }
    }

    if (!n) {
        thread_log(current, "\"%s\" - not found", name);
        return set_syscall_error(current, ENOENT);
    }

    u64 length = 0;
    fsfile fsf = 0;

    int type = file_type_from_tuple(n);
    if (type == FDESC_TYPE_REGULAR) {
        fsf = fsfile_from_node(current->p->fs, n);
        if (!fsf) {
            length = 0;
        } else {
            length = fsfile_get_length(fsf);
        }
    }

    file f = unix_cache_alloc(uh, file);
    if (f == INVALID_ADDRESS) {
        thread_log(current, "failed to allocate struct file");
        return set_syscall_error(current, ENOMEM);
    }

    int fd = allocate_fd(current->p, f);
    if (fd == INVALID_PHYSICAL) {
        thread_log(current, "failed to allocate fd");
        unix_cache_free(uh, file, f);
        return set_syscall_error(current, EMFILE);
    }

    fdesc_init(&f->f, type);
    f->f.read = closure(h, file_read, f, fsf);
    f->f.write = closure(h, file_write, f, fsf);
    f->f.close = closure(h, file_close, f, fsf);
    f->f.check = closure(h, file_check, f, fsf);
    f->f.flags = flags;
    f->n = n;
    f->length = length;
    f->offset = (flags & O_APPEND) ? length : 0;
    thread_log(current, "   fd %d, length %ld, offset %ld", fd, f->length, f->offset);
    return fd;
}

sysreturn open(const char *name, int flags, int mode)
{
    if (name == 0) 
        return set_syscall_error (current, EFAULT);
    thread_log(current, "open: \"%s\", flags %x, mode %x", name, flags, mode);
    return open_internal(current->p->cwd, name, flags, mode);
}

sysreturn dup(int fd)
{
    thread_log(current, "dup: fd %d", fd);
    fdesc f = resolve_fd(current->p, fd);

    int newfd = allocate_fd(current->p, f);
    if (newfd == INVALID_PHYSICAL) {
        thread_log(current, "failed to allocate fd");
        return set_syscall_error(current, EMFILE);
    }

    fetch_and_add(&f->refcnt, 1);
    return newfd;
}

sysreturn mkdir(const char *pathname, int mode)
{
    thread_log(current, "mkdir: \"%s\", mode 0x%x", pathname, mode);
    if (pathname == 0)
        return set_syscall_error(current, EINVAL);

    fs_status fs = filesystem_mkdir(current->p->fs, current->p->cwd, pathname, true);
    return sysreturn_from_fs_status(fs);
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
sysreturn mkdirat(int dirfd, char *pathname, int mode)
{
    thread_log(current, "mkdirat: \"%s\", dirfd %d, mode 0x%x", pathname, dirfd, mode);
    if (pathname == 0)
        return set_syscall_error(current, EINVAL);

    tuple cwd;
    if (dirfd == AT_FDCWD)
        cwd = current->p->cwd;
    else {
        file f = resolve_fd(current->p, dirfd);
        if (!is_dir(f->n))
            return -ENOTDIR;
        cwd = f->n;
    }

    fs_status fs = filesystem_mkdir(current->p->fs, cwd, pathname, true);
    return sysreturn_from_fs_status(fs);
}

sysreturn creat(const char *pathname, int mode)
{
    if (!pathname)
        return set_syscall_error (current, EFAULT);

    thread_log(current, "creat: \"%s\", mode 0x%x", pathname, mode);
    return open_internal(current->p->cwd, pathname, O_CREAT|O_WRONLY|O_TRUNC, mode);
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
    if (!c)
        return -ENOTDIR;

    int r = 0;
    int read_sofar = 0, written_sofar = 0;
    table_foreach(c, k, v) {
        char *p = cstring(symbol_string(k));
        r = try_write_dirent(f->n, dirp, p,
                    &read_sofar, &written_sofar, &f->offset, &count,
                    is_dir(v) ? DT_DIR : DT_REG);
        if (r < 0)
            goto done;

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
    if (!c)
        return -ENOTDIR;

    int r = 0;
    int read_sofar = 0, written_sofar = 0;
    table_foreach(c, k, v) {
        char *p = cstring(symbol_string(k));
        r = try_write_dirent64(f->n, dirp, p,
                    &read_sofar, &written_sofar, &f->offset, &count,
                    is_dir(v) ? DT_DIR : DT_REG);
        if (r < 0)
            goto done;

        dirp = (struct linux_dirent64 *)(((char *)dirp) + r);
    }

done:
    f->offset = read_sofar;
    if (r < 0 && written_sofar == 0)
        return -EINVAL;

    return written_sofar;
}

sysreturn chdir(const char *path)
{
    tuple n;
    if (path == 0)
        return set_syscall_error(current, EINVAL);

    if (!(n = resolve_cstring(current->p->cwd, path)) || !is_dir(n)) {
        return set_syscall_error(current, ENOENT);
    }
    current->p->cwd = n;
    return set_syscall_return(current, 0);
}

sysreturn fchdir(int dirfd)
{
    file f = resolve_fd(current->p, dirfd);
    tuple children = table_find(f->n, sym(children));
    if (!children)
        return set_syscall_error(current, -ENOTDIR);

    current->p->cwd = f->n;
    return set_syscall_return(current, 0);
}

sysreturn writev(int fd, iovec v, int count)
{
    int res = 0;
    resolve_fd(current->p, fd);
    for (int i = 0; i < count; i++) res += write(fd, v[i].iov_base, v[i].iov_len);
    return res;
}

static sysreturn access(const char *name, int mode)
{
    thread_log(current, "access: \"%s\", mode %d", name, mode);
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
sysreturn openat(int dirfd, const char *name, int flags, int mode)
{
    if (name == 0)
        return set_syscall_error(current, EINVAL);

    tuple cwd;
    if (dirfd == AT_FDCWD)
        cwd = current->p->cwd;
    else {
        file f = resolve_fd(current->p, dirfd);
        if (!is_dir(f->n))
            return -ENOTDIR;
        cwd = f->n;
    }

    return open_internal(cwd, name, flags, mode);
}

static void fill_stat(int type, tuple n, struct stat *s)
{
    switch (type) {
    case FDESC_TYPE_REGULAR:
        s->st_mode = S_IFREG | 0644;
        break;
    case FDESC_TYPE_DIRECTORY:
        s->st_mode = S_IFDIR | 0777;
        break;
    case FDESC_TYPE_SPECIAL:
        s->st_mode = S_IFCHR;   /* assuming only character devs now */
        break;
    case FDESC_TYPE_SOCKET:
        s->st_mode = S_IFSOCK;
        break;
    case FDESC_TYPE_PIPE:
    case FDESC_TYPE_STDIO:
        s->st_mode = S_IFIFO;
        break;
    case FDESC_TYPE_EPOLL:
        s->st_mode = S_IFCHR;   /* XXX not clear - EBADF? */
        break;
    }
    s->st_dev = 0;
    s->st_ino = u64_from_pointer(n);
    s->st_size = 0;
    if (type == FDESC_TYPE_REGULAR) {
        fsfile f = fsfile_from_node(current->p->fs, n);
        if (f)
            s->st_size = fsfile_get_length(f);
    }
    thread_log(current, "st_ino %lx, st_mode 0x%x, st_size %lx",
            s->st_ino, s->st_mode, s->st_size);
}

static sysreturn fstat(int fd, struct stat *s)
{
    thread_log(current, "fd %d, stat %p", fd, s);
    fdesc f = resolve_fd(current->p, fd);
    zero(s, sizeof(struct stat));
    fill_stat(f->type, ((file)f)->n, s);
    return 0;
}

static sysreturn stat(const char *name, struct stat *buf)
{
    thread_log(current, "stat: \"%s\", buf %p", name, buf);
    tuple n;

    if (!(n = resolve_cstring(current->p->cwd, name))) {    
        return set_syscall_error(current, ENOENT);
    }

    fill_stat(file_type_from_tuple(n), n, buf);
    return 0;
}

static sysreturn newfstatat(int dfd, const char *name, struct stat *s, int flags)
{
    tuple n;

    // if !relative or AT_FDCWD, just treat as normal stat
    if ((*name == '/') || (dfd == AT_FDCWD))
        return stat(name, s);

    // if relative, but AT_EMPTY_PATH set, works just like fstat()
    if (flags & AT_EMPTY_PATH)
        return fstat(dfd, s);

    // Else, if we have a fd of a directory, resolve name to it.
    file f = resolve_fd(current->p, dfd);
    tuple children = table_find(f->n, sym(children));
    if (!is_dir(children))
        return set_syscall_error(current, -ENOTDIR);
    
    if (!(n = resolve_cstring(children, name))) {    
        return set_syscall_error(current, ENOENT);
    }

    fill_stat(file_type_from_tuple(n), n, s);
    return 0;
}

sysreturn lseek(int fd, s64 offset, int whence)
{
    thread_log(current, "%s: fd %d offset %ld whence %s",
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
    return f->offset;
}


sysreturn uname(struct utsname *v)
{
    char sysname[] = "pugnix";
    char release[]= "4.4.0-87";
    char nodename[] = "nanovms"; // TODO: later we probably would want to get this from /etc/hostname
    char version[] = "Nanos unikernel";
    char machine[] = "x86_64";

    runtime_memcpy(v->sysname, sysname, sizeof(sysname));
    runtime_memcpy(v->release, release, sizeof(release));
    runtime_memcpy(v->nodename, nodename, sizeof(nodename));
    runtime_memcpy(v->version, version, sizeof(version));
    runtime_memcpy(v->machine, machine, sizeof(machine));

    return 0;
}

// we dont limit anything now.
sysreturn setrlimit(int resource, const struct rlimit *rlim)
{
    return 0;
}

sysreturn getrlimit(int resource, struct rlimit *rlim)
{
    thread_log(current, "getrlimit: resource %d, rlim %p", resource, rlim);

    switch (resource) {
    case RLIMIT_STACK:
        if (!rlim)
            return set_syscall_error(current, EINVAL);
        rlim->rlim_cur = 2*1024*1024;
        rlim->rlim_max = 2*1024*1024;
        return 0;
    case RLIMIT_NOFILE:
        if (!rlim)
            return set_syscall_error(current, EINVAL);
        // we .. .dont really have one?
        rlim->rlim_cur = 65536;
        rlim->rlim_max = 65536;
        return 0;
    }

    return set_syscall_error(current, EINVAL);
}

sysreturn prlimit64(int pid, int resource, const struct rlimit *new_limit, struct rlimit *old_limit)
{
    thread_log(current, "getrlimit: pid %d, resource %d, new_limit %p, old_limit %p",
        pid, resource, new_limit, old_limit);

    if (old_limit != 0) {
        sysreturn ret = getrlimit(resource, old_limit);
        if (ret < 0)
            return ret;
    }

    // setting new limits is not implemented
    return 0;
}

static sysreturn getcwd(char *buf, u64 length)
{
    static const char cwd[] = "/";
    int cwd_len = sizeof(cwd);

    if (length < cwd_len)
        return set_syscall_error(current, ERANGE);

    runtime_memcpy(buf, cwd, cwd_len);
    return cwd_len;
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
            u64 phys = allocate_u64(heap_physical(kh), alloc);
            if (phys == INVALID_PHYSICAL)
                return -ENOMEM;
            /* XXX no exec configurable? */
            map(u64_from_pointer(p->brk), phys, alloc, PAGE_WRITABLE | PAGE_NO_EXEC | PAGE_USER , heap_pages(kh));
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
    thread_log(current, "readlink: \"%s\"", pathname);

    // special case for /proc/self/exe for $ORIGIN handling in ld-linux.so(8)
    if (runtime_strcmp(pathname, "/proc/self/exe") == 0) {
        value p = table_find(current->p->process_root, sym(program));
        assert(p != 0);
        sysreturn retval = MIN(bufsiz, buffer_length(p));
        // readlink(2) does not NUL-terminate
        runtime_memcpy(buf, buffer_ref(p, 0), retval);
        thread_log(current, "readlink: returning \"%v\"", alloca_wrap_buffer(buf, retval));
        return retval;
    }

    return set_syscall_error(current, EINVAL);
}

sysreturn readlinkat(int dirfd, const char *pathname, char *buf, u64 bufsiz)
{
    thread_log(current, "readlinkat: \"%s\", dirfd %d", pathname, dirfd);
    return set_syscall_error(current, EINVAL);
}

sysreturn close(int fd)
{
    thread_log(current, "close: fd %d", fd);
    fdesc f = resolve_fd(current->p, fd);
    deallocate_fd(current->p, fd);

    if (fetch_and_add(&f->refcnt, -1) == 1) {
        if (f->close)
            return apply(f->close);
        msg_err("no close handler for fd %d\n", fd);
    }

    return 0;
}

sysreturn fcntl(int fd, int cmd, int arg)
{
    fdesc f = resolve_fd(current->p, fd);

    thread_log(current, "fcntl: fd %d, cmd %d, arg %d", fd, cmd, arg);

    switch (cmd) {
    case F_GETFD:
        return set_syscall_return(current, f->flags & O_CLOEXEC);
    case F_SETFD:
        f->flags = (f->flags & ~O_CLOEXEC) | (arg & O_CLOEXEC);
        return set_syscall_return(current, 0);
    case F_GETFL:
        return set_syscall_return(current, f->flags & ~O_CLOEXEC);
    case F_SETFL:
        thread_log(current, "fcntl: fd %d, F_SETFL, %x", fd, arg);

        /* Ignore file access mode and file creation flags. */
        arg &= ~(O_RDONLY | O_WRONLY | O_RDWR | O_CREAT | O_EXCL | O_NOCTTY |
                O_TRUNC);

        f->flags = arg & ~O_CLOEXEC;
        return set_syscall_return(current, 0);
    default:
        return set_syscall_error(current, ENOSYS);
    }
}

sysreturn ioctl(int fd, unsigned long request, ...)
{
    // checks if fd is valid
    resolve_fd(current->p, fd);

    switch (request) {
    case FIONBIO:
    case FIONCLEX:
    case FIOCLEX:
        return 0;
    default:
        thread_log(current, "ioctl: fd %d, request %x - not implemented", fd, request);
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
    exit_thread(current);
    runloop();
}

sysreturn exit_group(int status)
{
    vm_exit(status);
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

sysreturn eventfd(unsigned int count)
{
    return do_eventfd2(count, 0);
}

sysreturn eventfd2(unsigned int count, int flags)
{
    return do_eventfd2(count, flags);
}

sysreturn sched_getaffinity(int pid, u64 cpusetsize, cpu_set_t *mask)
{
    if (!mask || cpusetsize < sizeof(mask->mask[0]))
        return set_syscall_error(current, EINVAL);
    mask->mask[0] = 1;      /* always cpu 0 */
    return sizeof(mask->mask[0]);
}

sysreturn prctl(int option, u64 arg2, u64 arg3, u64 arg4, u64 arg5)
{
    thread_log(current, "prctl: option %d, arg2 0x%lx, arg3 0x%lx, arg4 0x%lx, arg5 0x%lx",
               option, arg2, arg3, arg4, arg5);

    switch (option) {
    case PR_SET_NAME:
        runtime_memcpy(current->name, (void *) arg2, sizeof(current->name));
        current->name[sizeof(current->name) - 1] = '\0';
        break;
    case PR_GET_NAME:
        runtime_memcpy((void *) arg2, current->name, sizeof(current->name));
        break;
    }

    return 0;
}

sysreturn sysinfo(struct sysinfo *info)
{
    if (info == 0)
        return set_syscall_error(current, EINVAL);

    kernel_heaps kh = get_kernel_heaps();
    runtime_memset((u8 *) info, 0, sizeof(*info));
    info->uptime = uptime();
    info->totalram = id_heap_total(kh->physical);
    info->freeram = info->totalram < kh->physical->allocated ? 0 : info->totalram - kh->physical->allocated;
    info->procs = 1;
    info->mem_unit = 1;
    return 0;
}

void register_file_syscalls(struct syscall *map)
{
    register_syscall(map, read, read);
    register_syscall(map, pread64, pread);
    register_syscall(map, write, write);
    register_syscall(map, pwrite64, pwrite);
    register_syscall(map, open, open);
    register_syscall(map, openat, openat);
    register_syscall(map, dup, dup);
    register_syscall(map, fstat, fstat);
    register_syscall(map, sendfile, sendfile);
    register_syscall(map, stat, stat);
    register_syscall(map, lstat, stat);
    register_syscall(map, readv, readv);
    register_syscall(map, writev, writev);
    register_syscall(map, access, access);
    register_syscall(map, lseek, lseek);
    register_syscall(map, fcntl, fcntl);
    register_syscall(map, ioctl, (sysreturn (*)())ioctl);
    register_syscall(map, getcwd, getcwd);
    register_syscall(map, readlink, readlink);
    register_syscall(map, readlinkat, readlinkat);
    register_syscall(map, close, close);
    register_syscall(map, sched_yield, sched_yield);
    register_syscall(map, brk, brk);
    register_syscall(map, uname, uname);
    register_syscall(map, getrlimit, getrlimit);
    register_syscall(map, setrlimit, setrlimit);
    register_syscall(map, prlimit64, prlimit64);
    register_syscall(map, getpid, getpid);
    register_syscall(map, exit_group, exit_group);
    register_syscall(map, exit, (sysreturn (*)())exit);
    register_syscall(map, getdents, getdents);
    register_syscall(map, getdents64, getdents64);
    register_syscall(map, mkdir, mkdir);
    register_syscall(map, mkdirat, mkdirat);
    register_syscall(map, getrandom, getrandom);
    register_syscall(map, pipe, pipe);
    register_syscall(map, pipe2, pipe2);
    register_syscall(map, socketpair, socketpair);
    register_syscall(map, eventfd, eventfd);
    register_syscall(map, eventfd2, eventfd2);
    register_syscall(map, creat, creat);
    register_syscall(map, chdir, chdir);
    register_syscall(map, fchdir, fchdir);
    register_syscall(map, newfstatat, newfstatat);
    register_syscall(map, sched_getaffinity, sched_getaffinity);
    register_syscall(map, sched_setaffinity, syscall_ignore);
    register_syscall(map, getuid, syscall_ignore);
    register_syscall(map, geteuid, syscall_ignore);
    register_syscall(map, chown, syscall_ignore);
    register_syscall(map, setgroups, syscall_ignore);
    register_syscall(map, setuid, syscall_ignore);
    register_syscall(map, setgid, syscall_ignore);
    register_syscall(map, prctl, prctl);
    register_syscall(map, sysinfo, sysinfo);
}

#define SYSCALL_F_NOTRACE 0x1

struct syscall {
    void *handler;
    const char *name;
    int flags;
};

static struct syscall _linux_syscalls[SYS_MAX];
struct syscall *linux_syscalls = _linux_syscalls;

static context syscall_frame;

static void syscall_debug()
{
    u64 *f = current->frame;
    int call = f[FRAME_VECTOR];
    if (call < 0 || call >= sizeof(_linux_syscalls) / sizeof(_linux_syscalls[0])) {
        thread_log(current, "invalid syscall %d", call);
        set_syscall_return(current, -ENOSYS);
        return;
    }
    current->syscall = call;
    void *debugsyscalls = table_find(current->p->process_root, sym(debugsyscalls));
    struct syscall *s = current->p->syscalls + call;
    if (debugsyscalls) {
        if (s->name)
            thread_log(current, s->name);
        else
            thread_log(current, "syscall %d", call);
    }
    sysreturn (*h)(u64, u64, u64, u64, u64, u64) = s->handler;
    sysreturn res = -ENOSYS;
    if (h) {
        /* exchange frames so that a fault won't clobber the syscall
           context, but retain the fault handler that has current enclosed */
        context saveframe = running_frame;
        running_frame = syscall_frame;
        running_frame[FRAME_FAULT_HANDLER] = f[FRAME_FAULT_HANDLER];

        res = h(f[FRAME_RDI], f[FRAME_RSI], f[FRAME_RDX], f[FRAME_R10], f[FRAME_R8], f[FRAME_R9]);
        if (debugsyscalls)
            thread_log(current, "direct return: %ld, rsp 0x%lx", res, f[FRAME_RSP]);
        running_frame = saveframe;
    } else if (debugsyscalls) {
        if (s->name)
            thread_log(current, "nosyscall %s", s->name);
        else
            thread_log(current, "nosyscall %d", call);
    }
    set_syscall_return(current, res);
    current->syscall = -1;
}

boolean syscall_notrace(int syscall)
{
    if (syscall < 0 || syscall >= sizeof(_linux_syscalls) / sizeof(_linux_syscalls[0]))
        return false;
    struct syscall *s = current->p->syscalls + syscall;
    return (s->flags & SYSCALL_F_NOTRACE) != 0;
}

// should hang off the thread context, but the assembly handler needs
// to find it.
void *syscall;

void init_syscalls()
{
    //syscall = b->contents;
    // debug the synthesized version later, at least we have the table dispatch
    heap h = heap_general(get_kernel_heaps());
    syscall = syscall_debug;
    syscall_frame = allocate_frame(h);
}

void _register_syscall(struct syscall *m, int n, sysreturn (*f)(), const char *name)
{
    assert(m[n].handler == 0);
    m[n].handler = f;
    m[n].name = name;
}

void configure_syscalls(process p)
{
    void *notrace = table_find(p->process_root, sym(notrace));
    if (notrace) {
        table_foreach(notrace, k, v) {
            (void) &k;

            for (int i = 0; i < sizeof(_linux_syscalls) / sizeof(_linux_syscalls[0]); i++) {
                struct syscall *s = current->p->syscalls + i;
                if (!s->name)
                    continue;

                buffer name = alloca_wrap_buffer(s->name, runtime_strlen(s->name));
                if (!buffer_compare(name, v))
                    continue;

                s->flags |= SYSCALL_F_NOTRACE;
                break;
            }
        }
    }
}
