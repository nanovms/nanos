#include <unix_internal.h>
#include <filesystem.h>
#include <page.h>

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

sysreturn close(int fd);

io_completion syscall_io_complete;

void register_other_syscalls(struct syscall *map)
{
    register_syscall(map, msync, 0);
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
    register_syscall(map, fchown, 0);
    register_syscall(map, lchown, 0);
    register_syscall(map, getrusage, 0);
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
    register_syscall(map, set_thread_area, 0);
    register_syscall(map, io_cancel, 0);
    register_syscall(map, get_thread_area, 0);
    register_syscall(map, lookup_dcookie, 0);
    register_syscall(map, epoll_ctl_old, 0);
    register_syscall(map, epoll_wait_old, 0);
    register_syscall(map, remap_file_pages, 0);
    register_syscall(map, restart_syscall, 0);
    register_syscall(map, semtimedop, 0);
    register_syscall(map, fadvise64, 0);
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
    register_syscall(map, fchownat, 0);
    register_syscall(map, futimesat, 0);
    register_syscall(map, linkat, 0);
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
    register_syscall(map, syncfs, 0);
    register_syscall(map, setns, 0);
    register_syscall(map, getcpu, 0);
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
    register_syscall(map, mlock2, 0);
    register_syscall(map, copy_file_range, 0);
    register_syscall(map, preadv2, 0);
    register_syscall(map, pwritev2, 0);
    register_syscall(map, pkey_mprotect, 0);
    register_syscall(map, pkey_alloc, 0);
    register_syscall(map, pkey_free, 0);
}

static int file_get_path(tuple n, char *buf, u64 len)
{
    if (len < 2) {
        return -1;
    }
    tuple c = children(n);
    if (!c) {   /* Retrieving path of non-directory tuples is not supported. */
        return -1;
    }
    buf[0] = '\0';
    int cur_len = 1;
    buffer tmpbuf = little_stack_buffer(NAME_MAX + 1);
next:
    table_foreach(c, k, v) {
        char *name = cstring(symbol_string(k), tmpbuf);
        if (!runtime_strcmp(name, "..")) {
            if (v == n) {   /* this is the root directory */
                if (cur_len == 1) {
                    buf[0] = '/';
                    buf[1] = '\0';
                    cur_len = 2;
                }
                c = 0;
            }
            else {
                c = children(v);
            }
            if (!c) {
                goto done;
            }
            table_foreach(c, k, v) {
                if (v == n) {
                    char *name = cstring(symbol_string(k), tmpbuf);
                    int name_len = runtime_strlen(name);
                    if (len < 1 + name_len + cur_len) {
                        return -1;
                    }
                    runtime_memcpy(buf + 1 + name_len, buf, cur_len);
                    buf[0] = '/';
                    runtime_memcpy(buf + 1, name, name_len);
                    cur_len += 1 + name_len;
                    break;
                }
            }
            n = v;
            goto next;
        }
    }
done:
    return cur_len;
}

/* Check if fp1 is a (direct or indirect) ancestor if fp2. */
static inline boolean filepath_is_ancestor(tuple wd1, const char *fp1,
        tuple wd2, const char *fp2)
{
    tuple t1;
    int ret = resolve_cstring(wd1, fp1, &t1, 0);
    if (ret) {
        return false;
    }
    tuple t2 = (*fp2 == '/' ? filesystem_getroot(current->p->fs) : wd2);
    tuple p2 = t2;
    buffer a = little_stack_buffer(NAME_MAX);
    char y;
    int nbytes;
    
    while ((y = *fp2)) {
        if (y == '/') {
            if (buffer_length(a)) {
                if (t2 == t1) {
                    return true;
                }
                p2 = t2;
                t2 = lookup(t2, intern(a));
                if (!t2) {
                    return false;
                }
                if (filesystem_follow_links(t2, p2, &t2) < 0) {
                    return false;
                }
                buffer_clear(a);
            }
            fp2++;
        }
        else {
            nbytes = push_utf8_character(a, fp2);
            if (!nbytes) {
                thread_log(current, "Invalid UTF-8 sequence.\n");
                return 0;
            }
            fp2 += nbytes;
        }
    }
    if (buffer_length(a) && (t2 == t1)) {
        return true;
    }
    return false;
}

struct iov_progress {
    boolean initialized;
    int curr;
    u64 curr_offset;
    u64 total_len;
    io_completion completion;
};

closure_function(4, 2, void, iov_op_each_complete,
                 io, op, struct iovec *, iov, int, iovcnt, struct iov_progress, progress,
                 thread, t, sysreturn, rv)
{
    io_completion c;
    int iovcnt = bound(iovcnt);
    struct iov_progress * p = &bound(progress);
    struct iovec * iov = bound(iov);
    thread_log(t, "%s: rv %ld, curr %d, iovcnt %d", __func__, rv, p->curr, iovcnt);

    /* If these ops were truly atomic, we would have to rewind file
       state on failure... */
    if (rv < 0) {
        goto out_complete;
    }

    /* Increment offset and total by io op retval, advancing to next
       (non-zero-len) buffer if needed. */
    p->total_len += rv;
    p->curr_offset += rv;
    if (p->curr_offset == bound(iov)[p->curr].iov_len) {
        p->curr_offset = 0;
        do {
            p->curr++;
        } while (p->curr < iovcnt && iov[p->curr].iov_len == 0);
    } else {
        assert(p->curr_offset < iov[p->curr].iov_len);
    }

    /* If we're done, return the total length... */
    if (p->curr == iovcnt) {
        rv = p->total_len;
        goto out_complete;
    }

    boolean initialized = p->initialized;
    p->initialized = true;

    /* ...else issue the next request. */
    thread_log(t, "   op: curr %d, offset %ld, @ %p, len %ld, init %d",
               p->curr, p->curr_offset,
               iov[p->curr].iov_base + p->curr_offset,
               iov[p->curr].iov_len - p->curr_offset, initialized);
    apply(bound(op), iov[p->curr].iov_base + p->curr_offset,
          iov[p->curr].iov_len - p->curr_offset,
          infinity /* file offset */, t, initialized,
          (io_completion)closure_self());
    return;
  out_complete:
    c = p->completion;
    closure_finish();
    apply(c, t, rv);
}

static sysreturn iov_op(fdesc f, io op, struct iovec *iov, int iovcnt, io_completion completion)
{
    if (iovcnt < 0 || iovcnt > IOV_MAX)
        return set_syscall_error(current, EINVAL);
    if (iovcnt == 0)
        return 0;

    heap h = heap_general(get_kernel_heaps());
    struct iov_progress p;
    p.initialized = false;
    p.curr = 0;
    p.curr_offset = 0;
    p.total_len = 0;
    p.completion = completion;
    io_completion each = closure(h, iov_op_each_complete, op, iov, iovcnt, p);
    apply(each, current, 0);
    return get_syscall_return(current);
}

sysreturn read(int fd, u8 *dest, bytes length)
{
    fdesc f = resolve_fd(current->p, fd);
    if (!f->read)
        return set_syscall_error(current, EINVAL);

    /* use (and update) file offset */
    return apply(f->read, dest, length, infinity, current, false, syscall_io_complete);
}

sysreturn pread(int fd, u8 *dest, bytes length, s64 offset)
{
    fdesc f = resolve_fd(current->p, fd);
    if (!f->read || offset < 0)
        return set_syscall_error(current, EINVAL);

    /* use given offset with no file offset update */
    return apply(f->read, dest, length, offset, current, false, syscall_io_complete);
}

sysreturn readv(int fd, struct iovec *iov, int iovcnt)
{
    fdesc f = resolve_fd(current->p, fd);
    return iov_op(f, f->read, iov, iovcnt, syscall_io_complete);
}

sysreturn write(int fd, u8 *body, bytes length)
{
    fdesc f = resolve_fd(current->p, fd);
    if (!f->write)
        return set_syscall_error(current, EINVAL);

    /* use (and update) file offset */
    return apply(f->write, body, length, infinity, current, false, syscall_io_complete);
}

sysreturn pwrite(int fd, u8 *body, bytes length, s64 offset)
{
    fdesc f = resolve_fd(current->p, fd);
    if (!f->write || offset < 0)
        return set_syscall_error(current, EINVAL);

    return apply(f->write, body, length, offset, current, false, syscall_io_complete);
}

sysreturn writev(int fd, struct iovec *iov, int iovcnt)
{
    fdesc f = resolve_fd(current->p, fd);
    return iov_op(f, f->write, iov, iovcnt, syscall_io_complete);
}

static boolean is_special(tuple n)
{
    return table_find(n, sym(special)) ? true : false;
}

static inline void file_op_complete_internal(thread t, file f, fsfile fsf, boolean is_file_offset,
                                             io_completion completion, status s, bytes length)
{
    thread_log(t, "%s: len %d, status %v (%s)", __func__,
            length, s, is_ok(s) ? "OK" : "NOTOK");
    sysreturn rv;
    if (is_ok(s)) {
        /* if regular file, update length */
        if (fsf)
            f->length = fsfile_get_length(fsf);
        if (is_file_offset) /* vs specified offset (pread) */
            f->offset += length;
        rv = length;
    } else {
        /* report these to console for now */
        msg_err("file op failed with %v\n", s);
        rv = -EIO;
    }
    apply(completion, t, rv);
}

closure_function(5, 2, void, file_op_complete,
                 thread, t, file, f, fsfile, fsf, boolean, is_file_offset, io_completion, completion,
                 status, s, bytes, length)
{
    file_op_complete_internal(bound(t), bound(f), bound(fsf), bound(is_file_offset),
                              bound(completion), s, length);
    closure_finish();
}

closure_function(6, 1, void, file_op_complete_sg,
                 thread, t, file, f, fsfile, fsf, sg_list, sg, boolean, is_file_offset, io_completion, completion,
                 status, s)
{
    file_op_complete_internal(bound(t), bound(f), bound(fsf), bound(is_file_offset),
                              bound(completion), s, bound(sg)->count);
    closure_finish();
}

closure_function(9, 2, void, sendfile_bh,
                 fdesc, in, fdesc, out, int *, offset, sg_list, sg, sg_buf, cur_buf, bytes, count, bytes, readlen, bytes, written, boolean, bh,
                 thread, t, sysreturn, rv)
{
    thread_log(t, "%s: readlen %ld, written %ld, bh %d, rv %ld",
               __func__, bound(readlen), bound(written), bound(bh), rv);

    if (rv <= 0) {
        if (bound(bh) && rv == -EAGAIN) { /* result of a write */
            if (!bound(offset) && bound(in)->type == FDESC_TYPE_REGULAR) {
                /* rewind file offset ... another reason to create an sg read method */
                file f_in = (file)bound(in);
                s64 rewind = bound(count) - bound(written);
                assert(rewind >= 0);
                f_in->offset -= rewind;
                thread_log(t, "   rewound %ld bytes to %ld", rewind, f_in->offset);
            }
            rv = bound(written) == 0 ? -EAGAIN : bound(written);
            thread_log(t, "   write would block, returning %ld", rv);
        } else {
            thread_log(t, "   zero or error, rv %ld", rv);
        }
        goto out_complete;
    }

    /* !bh means read complete (rv == bytes read) */
    if (!bound(bh)) {
        bound(bh) = true;
        bound(readlen) = rv;

        /* this whole offset advance / rewind thing can go away if we
           redo the io methods so that the file_op_complete* only
           happens at the end of the chain, using only status_handlers
           (io_status_handler for linear) in the middle */
        if (bound(offset))
            *bound(offset) += rv;
        bound(cur_buf) = sg_list_head_remove(bound(sg)); /* initial dequeue */
        assert(bound(cur_buf) != INVALID_ADDRESS);
        bound(cur_buf)->misc = 0; /* offset for our use */
        thread_log(t, "   read %ld bytes\n", rv);
    } else {
        bound(written) += rv;
        bound(cur_buf)->misc += rv;
        assert(bound(cur_buf)->length >= rv);
        if (bound(cur_buf)->misc == bound(cur_buf)->length) {
            sg_buf_release(bound(cur_buf));
            if (bound(written) == bound(readlen)) {
                rv = bound(written);
                goto out_complete;
            }
            bound(cur_buf) = sg_list_head_remove(bound(sg));
            assert(bound(cur_buf) != INVALID_ADDRESS);
            bound(cur_buf)->misc = 0; /* offset for our use */
        }
    }

    /* issue next write */
    assert(bound(cur_buf));
    void *buf = bound(cur_buf)->buf + bound(cur_buf)->misc;
    u32 n = bound(cur_buf)->length - bound(cur_buf)->misc;
    thread_log(t, "   writing %d bytes from %p", rv, n, buf);
    apply(bound(out)->write, buf, n, 0, t, true, (io_completion)closure_self());
    return;
out_complete:
    sg_list_release(bound(sg));
    deallocate_sg_list(bound(sg));
    set_syscall_return(t, rv);
    if (bound(bh))
        file_op_maybe_wake(t);
    closure_finish();
}

/* Should be determined more intelligently based on available
   buffering on output side, modulated by link capacity
   (e.g. bandwidth delay product). Right now assuming the common mode
   is tcp output with 64kB max window size... */

#define SENDFILE_READ_MAX (64 * KB)

/* requires infile to have sg_read method - so sendfile from special files isn't supported */
static sysreturn sendfile(int out_fd, int in_fd, int *offset, bytes count)
{
    thread_log(current, "%s: out %d, in %d, offset %p, *offset %d, count %ld",
               __func__, out_fd, in_fd, offset, offset ? *offset : 0, count);
    fdesc infile = resolve_fd(current->p, in_fd);
    fdesc outfile = resolve_fd(current->p, out_fd);
    if (!infile->sg_read || !outfile->write)
        return set_syscall_error(current, EINVAL);

    sg_list sg = allocate_sg_list();
    if (sg == INVALID_ADDRESS)
        return set_syscall_error(current, ENOMEM);

    u64 n = MIN(count, SENDFILE_READ_MAX);
    io_completion read_complete = closure(heap_general(get_kernel_heaps()), sendfile_bh, infile, outfile,
                                          offset, sg, 0, n, 0, 0, false);
    apply(infile->sg_read, sg, n, offset ? *offset : infinity, current, false, read_complete);
    return sysreturn_value(current);
}

static void begin_file_read(thread t, file f)
{
    if ((f->length > 0) && !(f->f.flags & O_NOATIME)) {
        filesystem_update_atime(t->p->fs, f->n);
    }
    file_op_begin(t);
}

closure_function(2, 6, sysreturn, file_read,
                 file, f, fsfile, fsf,
                 void *, dest, u64, length, u64, offset_arg, thread, t, boolean, bh, io_completion, completion)
{
    file f = bound(f);
    fsfile fsf = bound(fsf);

    boolean is_file_offset = offset_arg == infinity;
    u64 offset = is_file_offset ? f->offset : offset_arg;
    thread_log(t, "%s: f %p, dest %p, offset %ld (%s), length %ld, file length %ld",
               __func__, f, dest, offset, is_file_offset ? "file" : "specified",
               length, f->length);

    if (is_special(f->n)) {
        return spec_read(f, dest, length, offset, t, bh, completion);
    }
    if (offset >= f->length) {
        return 0;
    }
    begin_file_read(t, f);
    filesystem_read_linear(t->p->fs, f->n, dest, length, offset,
                           closure(heap_general(get_kernel_heaps()),
                                   file_op_complete, t, f, fsf, is_file_offset,
                                   completion));

    /* possible direct return in top half */
    return bh ? SYSRETURN_CONTINUE_BLOCKING : file_op_maybe_sleep(t);
}

closure_function(2, 6, sysreturn, file_sg_read,
                 file, f, fsfile, fsf,
                 sg_list, sg, u64, length, u64, offset_arg, thread, t, boolean, bh, io_completion, completion)
{
    file f = bound(f);
    fsfile fsf = bound(fsf);

    boolean is_file_offset = offset_arg == infinity;
    u64 offset = is_file_offset ? f->offset : offset_arg;
    thread_log(t, "%s: f %p, sg %p, offset %ld (%s), length %ld, file length %ld",
               __func__, f, sg, offset, is_file_offset ? "file" : "specified",
               length, f->length);

    /* TODO: special files not supported yet */
    if (is_special(f->n)) {
        apply(completion, t, -EIO);
        goto out;
    }

    begin_file_read(t, f);
    filesystem_read_sg(t->p->fs, f->n, sg, length, offset,
                       closure(heap_general(get_kernel_heaps()),
                               file_op_complete_sg, t, f, fsf, sg, is_file_offset,
                               completion));

  out:
    /* possible direct return in top half */
    return bh ? SYSRETURN_CONTINUE_BLOCKING : file_op_maybe_sleep(t);
}

#define PAD_WRITES 0

closure_function(2, 6, sysreturn, file_write,
                 file, f, fsfile, fsf,
                 void *, dest, u64, length, u64, offset_arg, thread, t, boolean, bh, io_completion, completion)
{
    file f = bound(f);
    fsfile fsf = bound(fsf);
    boolean is_file_offset = offset_arg == infinity;
    u64 offset = is_file_offset ? f->offset : offset_arg;
    thread_log(t, "%s: f %p, dest %p, offset %ld (%s), length %ld, file length %ld",
               __func__, f, dest, offset, is_file_offset ? "file" : "specified",
               length, f->length);
    heap h = heap_general(get_kernel_heaps());

    u64 final_length = 0;
    void *buf = INVALID_ADDRESS;
    while (length != 0) {
        final_length = PAD_WRITES ? pad(length, SECTOR_SIZE) : length;
        buf = allocate(h, final_length);
        if (buf != INVALID_ADDRESS) {
            break;
        } else {
            /* Couldn't allocate that much memory, retry with a smaller size. */
            length >>= 1;
        }
    }

    /* XXX we shouldn't need to copy here, however if we at some point
       want to support non-blocking, we'll need to fix the unaligned
       block rmw in the extent write (prob just break it up into
       aligned and unaligned portions, copying aligned data straight
       to dma buffer and stashing unaligned portions to be copied post
       block read) */

    /* copy from userspace, XXX: check pointer safety */
    runtime_memset(buf, 0, final_length);
    runtime_memcpy(buf, dest, length);

    if (is_special(f->n)) {
        return spec_write(f, buf, length, offset, t, bh, completion);
    }

    buffer b = wrap_buffer(h, buf, final_length);
    thread_log(t, "%s: b_ref: %p", __func__, buffer_ref(b, 0));

    if (final_length > 0) {
        filesystem_update_mtime(t->p->fs, f->n);
    }
    file_op_begin(t);
    filesystem_write(t->p->fs, f->n, b, offset,
                     closure(h, file_op_complete, t, f, fsf, is_file_offset,
                     completion));

    /* possible direct return in top half */
    return bh ? SYSRETURN_CONTINUE_BLOCKING : file_op_maybe_sleep(t);
}

closure_function(2, 0, sysreturn, file_close,
                 file, f, fsfile, fsf)
{
    sysreturn ret = 0;
    file f = bound(f);

    if (is_special(f->n)) {
        ret = spec_close(f);
    }
        
    if (ret == 0)
        unix_cache_free(get_unix_heaps(), file, f);
    return 0;
}

closure_function(1, 1, u32, file_events,
                 file, f,
                 thread, t /* ignore */)
{
    file f = bound(f);
    u32 events;
    if (is_special(f->n)) {
        events = spec_events(f);
    } else {
        /* XXX add nonblocking support */
        events = f->length < infinity ? EPOLLOUT : 0;
        events |= f->offset < f->length ? EPOLLIN : EPOLLHUP;
    }
    return events;
}

static int file_type_from_tuple(tuple n)
{
    if (is_dir(n))
        return FDESC_TYPE_DIRECTORY;
    else if (is_symlink(n))
        return FDESC_TYPE_SYMLINK;
    else if (is_special(n))
        return FDESC_TYPE_SPECIAL;
    else if (is_socket(n))
        return FDESC_TYPE_SOCKET;
    else
        return FDESC_TYPE_REGULAR;
}

static int dt_from_tuple(tuple n)
{
    if (is_dir(n))
        return DT_DIR;
    else if (is_symlink(n))
        return DT_LNK;
    else if (is_socket(n))
        return DT_SOCK;
    else
        return DT_REG;
}

sysreturn open_internal(tuple cwd, const char *name, int flags, int mode)
{
    heap h = heap_general(get_kernel_heaps());
    unix_heaps uh = get_unix_heaps();
    tuple n;
    tuple parent;
    int ret;

    if (flags & O_NOFOLLOW) {
        ret = resolve_cstring(cwd, name, &n, &parent);
        if (!ret && is_symlink(n) && !(flags & O_PATH)) {
            ret = -ELOOP;
        }
    } else {
        ret = resolve_cstring_follow(cwd, name, &n, &parent);
    }
    if ((flags & O_CREAT)) {
        if (!ret && (flags & O_EXCL)) {
            thread_log(current, "\"%s\" opened with O_EXCL but already exists", name);
            return set_syscall_error(current, EEXIST);
        } else if ((ret == -ENOENT) && parent) {
            n = filesystem_creat(current->p->fs, parent,
                    filename_from_path(name), ignore_status);
            if (n) {
                filesystem_update_mtime(current->p->fs, parent);
                ret = 0;
            } else {
                ret = -ENOMEM;
            }
        }
    }

    if (ret) {
        thread_log(current, "\"%s\" - not found", name);
        return set_syscall_return(current, ret);
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

    init_fdesc(h, &f->f, type);
    f->f.read = closure(h, file_read, f, fsf);
    f->f.write = closure(h, file_write, f, fsf);
    f->f.sg_read = closure(h, file_sg_read, f, fsf);
    f->f.close = closure(h, file_close, f, fsf);
    f->f.events = closure(h, file_events, f);
    f->f.flags = flags;
    f->n = n;
    f->length = length;
    f->offset = (flags & O_APPEND) ? length : 0;

    if (is_special(f->n)) {
        int spec_ret = spec_open(f);
        if (spec_ret != 0) {
            assert(spec_ret < 0);
            thread_log(current, "spec_open failed (%d)\n", spec_ret);
            deallocate_fd(current->p, fd);
            unix_cache_free(uh, file, f);
            return set_syscall_return(current, spec_ret);
        }
    }

    thread_log(current, "   fd %d, length %ld, offset %ld", fd, f->length, f->offset);
    return fd;
}

sysreturn open(const char *name, int flags, int mode)
{
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

sysreturn dup2(int oldfd, int newfd)
{
    thread_log(current, "%s: oldfd %d, newfd %d", __func__, oldfd, newfd);
    fdesc f = resolve_fd(current->p, oldfd);
    if (newfd != oldfd) {
        if (resolve_fd_noret(current->p, newfd)) {
            /* The code below assumes that close() never blocks the calling
             * thread. If there is a close() implementation that potentially
             * blocks, this will need to be revisited. */
            close(newfd);
        }
        int fd = allocate_fd_gte(current->p, newfd, f);
        if (fd != newfd) {
            thread_log(current, "failed to reuse newfd");
            return -EMFILE;
        }
        fetch_and_add(&f->refcnt, 1);
    }
    return newfd;
}

sysreturn dup3(int oldfd, int newfd, int flags)
{
    if ((newfd == oldfd) || (flags & ~O_CLOEXEC)) {
        return -EINVAL;
    }

    /* Setting file descriptor flags on newfd is not supported. */
    if (flags & O_CLOEXEC) {
        msg_warn("close-on-exec flag not supported, ignored\n");
    }
    return dup2(oldfd, newfd);
}

closure_function(1, 1, void, mkdir_complete,
                 thread, t,
                 status, s)
{
    thread t = bound(t);
    thread_log(current, "%s: status %v (%s)", __func__, s,
            is_ok(s) ? "OK" : "NOTOK");
    set_syscall_return(t, is_ok(s) ? 0 : -EIO);
    file_op_maybe_wake(t);
    closure_finish();
}

static sysreturn mkdir_internal(tuple cwd, const char *pathname, int mode)
{
    tuple parent;
    int ret = resolve_cstring(cwd, pathname, 0, &parent);
    if ((ret != -ENOENT) || !parent) {
        return set_syscall_return(current, ret);
    }
    filesystem_update_mtime(current->p->fs, parent);
    file_op_begin(current);
    filesystem_mkdir(current->p->fs, parent, filename_from_path(pathname),
            closure(heap_general(get_kernel_heaps()), mkdir_complete, current));
    return file_op_maybe_sleep(current);
}

sysreturn mkdir(const char *pathname, int mode)
{
    thread_log(current, "mkdir: \"%s\", mode 0x%x", pathname, mode);
    return mkdir_internal(current->p->cwd, pathname, mode);
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
    tuple cwd;
    cwd = resolve_dir(dirfd, pathname);

    return mkdir_internal(cwd, pathname, mode);
}

sysreturn creat(const char *pathname, int mode)
{
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
    return random_buffer(b);
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
            tuple n;
            resolve_cstring(root, p, &n, 0);
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
    if (!dirp)
        return set_syscall_error(current, EFAULT);
    file f = resolve_fd(current->p, fd);
    tuple c = children(f->n);
    if (!c)
        return -ENOTDIR;

    int r = 0;
    int read_sofar = 0, written_sofar = 0;
    buffer tmpbuf = little_stack_buffer(NAME_MAX + 1);
    table_foreach(c, k, v) {
        char *p = cstring(symbol_string(k), tmpbuf);
        r = try_write_dirent(f->n, dirp, p,
                    &read_sofar, &written_sofar, &f->offset, &count,
                    dt_from_tuple(v));
        if (r < 0)
            goto done;

        dirp = (struct linux_dirent *)(((char *)dirp) + r);
    }

done:
    filesystem_update_atime(current->p->fs, f->n);
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
            tuple n;
            resolve_cstring(root, p, &n, 0);
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
    if (!dirp)
        return set_syscall_error(current, EFAULT);
    file f = resolve_fd(current->p, fd);
    tuple c = children(f->n);
    if (!c)
        return -ENOTDIR;

    int r = 0;
    int read_sofar = 0, written_sofar = 0;
    buffer tmpbuf = little_stack_buffer(NAME_MAX + 1);
    table_foreach(c, k, v) {
        char *p = cstring(symbol_string(k), tmpbuf);
        r = try_write_dirent64(f->n, dirp, p,
                    &read_sofar, &written_sofar, &f->offset, &count,
                    dt_from_tuple(v));
        if (r < 0)
            goto done;

        dirp = (struct linux_dirent64 *)(((char *)dirp) + r);
    }

done:
    filesystem_update_atime(current->p->fs, f->n);
    f->offset = read_sofar;
    if (r < 0 && written_sofar == 0)
        return -EINVAL;

    return written_sofar;
}

sysreturn chdir(const char *path)
{
    int ret;
    tuple n;

    ret = resolve_cstring_follow(current->p->cwd, path, &n, 0);
    if (ret) {
        return set_syscall_return(current, ret);
    }
    if (!is_dir(n)) {
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

closure_function(1, 1, void, truncate_complete,
                 thread, t,
                 status, s)
{
    thread t = bound(t);
    thread_log(current, "%s: status %v (%s)", __func__, s,
            is_ok(s) ? "OK" : "NOTOK");
    set_syscall_return(t, is_ok(s) ? 0 : -EIO);
    file_op_maybe_wake(t);
    closure_finish();
}

static sysreturn truncate_internal(tuple t, long length)
{
    if (is_dir(t)) {
        return set_syscall_error(current, EISDIR);
    }
    if (length < 0) {
        return set_syscall_error(current, EINVAL);
    }
    fsfile fsf = fsfile_from_node(current->p->fs, t);
    if (!fsf) {
        return set_syscall_error(current, ENOENT);
    }
    file_op_begin(current);
    if (filesystem_truncate(current->p->fs, fsf, length,
            closure(heap_general(get_kernel_heaps()), truncate_complete,
            current))) {
        /* Nothing to do. */
        return 0;
    }
    filesystem_update_mtime(current->p->fs, t);
    return file_op_maybe_sleep(current);
}

sysreturn truncate(const char *path, long length)
{
    thread_log(current, "%s \"%s\" %d", __func__, path, length);
    tuple t;
    int ret = resolve_cstring_follow(current->p->cwd, path, &t, 0);
    if (ret) {
        return set_syscall_return(current, ret);
    }
    return truncate_internal(t, length);
}

sysreturn ftruncate(int fd, long length)
{
    thread_log(current, "%s %d %d", __func__, fd, length);
    file f = resolve_fd(current->p, fd);
    if (!(f->f.flags & (O_RDWR | O_WRONLY)) ||
            (f->f.type != FDESC_TYPE_REGULAR)) {
        return set_syscall_error(current, EINVAL);
    }
    return truncate_internal(f->n, length);
}

closure_function(2, 1, void, fsync_complete,
                 thread, t, file, f,
                 status, s)
{
    thread t = bound(t);
    thread_log(current, "%s: status %v (%s)", __func__, s,
            is_ok(s) ? "OK" : "NOTOK");
    set_syscall_return(t, is_ok(s) ? 0 : -EIO);
    file_op_maybe_wake(t);
    closure_finish();
}

sysreturn fsync(int fd)
{
    file f = resolve_fd(current->p, fd);

    file_op_begin(current);
    filesystem_flush(current->p->fs, f->n,
                     closure(heap_general(get_kernel_heaps()),
                             fsync_complete, current, f));
    return file_op_maybe_sleep(current);
}

sysreturn fdatasync(int fd)
{
    return fsync(fd);
}

sysreturn access(const char *name, int mode)
{
    thread_log(current, "access: \"%s\", mode %d", name, mode);
    int ret = resolve_cstring_follow(current->p->cwd, name, 0, 0);
    if (ret) {
        return set_syscall_return(current, ret);
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
    cwd = resolve_dir(dirfd, name);

    return open_internal(cwd, name, flags, mode);
}

static void fill_stat(int type, tuple n, struct stat *s)
{
    zero(s, sizeof(struct stat));
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
    case FDESC_TYPE_SYMLINK:
        s->st_mode = S_IFLNK;
        break;
    }
    s->st_ino = u64_from_pointer(n);
    if (type == FDESC_TYPE_REGULAR) {
        fsfile f = fsfile_from_node(current->p->fs, n);
        if (f)
            s->st_size = fsfile_get_length(f);
    }
    if (n) {
        struct timespec ts;
        timespec_from_time(&ts, filesystem_get_atime(current->p->fs, n));
        s->st_atime = ts.tv_sec;
        s->st_atime_nsec = ts.tv_nsec;
        timespec_from_time(&ts, filesystem_get_mtime(current->p->fs, n));
        s->st_mtime = ts.tv_sec;
        s->st_mtime_nsec = ts.tv_nsec;
    }
    thread_log(current, "st_ino %lx, st_mode 0x%x, st_size %lx",
            s->st_ino, s->st_mode, s->st_size);
}

static sysreturn fstat(int fd, struct stat *s)
{
    thread_log(current, "fd %d, stat %p", fd, s);
    fdesc f = resolve_fd(current->p, fd);
    tuple n;
    switch (f->type) {
    case FDESC_TYPE_REGULAR:
    case FDESC_TYPE_DIRECTORY:
    case FDESC_TYPE_SPECIAL:
    case FDESC_TYPE_SYMLINK:
        n = ((file)f)->n;
        break;
    default:
        n = 0;
        break;
    }
    fill_stat(f->type, n, s);
    return 0;
}

static sysreturn stat_internal(tuple cwd, const char *name, boolean follow,
        struct stat *buf)
{
    tuple n;
    int ret;

    if (!follow) {
        ret = resolve_cstring(cwd, name, &n, 0);
    } else {
        ret = resolve_cstring_follow(cwd, name, &n, 0);
    }
    if (ret) {
        return set_syscall_return(current, ret);
    }

    fill_stat(file_type_from_tuple(n), n, buf);
    return 0;
}

static sysreturn stat(const char *name, struct stat *buf)
{
    thread_log(current, "stat: \"%s\", buf %p", name, buf);
    return stat_internal(current->p->cwd, name, true, buf);
}

static sysreturn lstat(const char *name, struct stat *buf)
{
    thread_log(current, "lstat: \"%s\", buf %p", name, buf);
    return stat_internal(current->p->cwd, name, false, buf);
}

static sysreturn newfstatat(int dfd, const char *name, struct stat *s, int flags)
{
    tuple n;

    // if relative, but AT_EMPTY_PATH set, works just like fstat()
    if (flags & AT_EMPTY_PATH)
        return fstat(dfd, s);

    // Else, if we have a fd of a directory, resolve name to it.
    n = resolve_dir(dfd, name);
    return stat_internal(n, name, !(flags & AT_SYMLINK_NOFOLLOW), s);
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
    int cwd_len = file_get_path(current->p->cwd, buf, length);

    if (cwd_len < 0)
        return set_syscall_error(current, ERANGE);

    return cwd_len;
}

static sysreturn brk(void *x)
{
    process p = current->p;
    kernel_heaps kh = get_kernel_heaps();

    if (x) {
        if (p->brk > x) {
            /* on failure, return the current break */
            if (u64_from_pointer(x) < p->heap_base)
                goto fail;
            p->brk = x;
            assert(adjust_process_heap(p, irange(p->heap_base, u64_from_pointer(x))));
            // free
        } else if (p->brk < x) {
            // I guess assuming we're aligned
            u64 alloc = pad(u64_from_pointer(x), PAGESIZE) - pad(u64_from_pointer(p->brk), PAGESIZE);
            assert(adjust_process_heap(p, irange(p->heap_base, u64_from_pointer(p->brk) + alloc)));
            u64 phys = allocate_u64((heap)heap_physical(kh), alloc);
            if (phys == INVALID_PHYSICAL)
                goto fail;
            /* XXX no exec configurable? */
            map(u64_from_pointer(p->brk), phys, alloc, PAGE_WRITABLE | PAGE_NO_EXEC | PAGE_USER , heap_pages(kh));
            // people shouldn't depend on this
            zero(p->brk, alloc);
            p->brk += alloc;         
        }
    }
  fail:
    return sysreturn_from_pointer(p->brk);
}

static sysreturn readlink_internal(tuple cwd, const char *pathname, char *buf,
        u64 bufsiz)
{
    tuple n;
    int ret = resolve_cstring(cwd, pathname, &n, 0);
    if (ret) {
        return set_syscall_return(current, ret);
    }
    if (!is_symlink(n)) {
        return set_syscall_error(current, EINVAL);
    }
    buffer target = linktarget(n);
    bytes len = buffer_length(target);
    if (bufsiz < len) {
        len = bufsiz;
    }
    runtime_memcpy(buf, buffer_ref(target, 0), len);
    filesystem_update_atime(current->p->fs, n);
    return set_syscall_return(current, len);
}

sysreturn readlink(const char *pathname, char *buf, u64 bufsiz)
{
    thread_log(current, "readlink: \"%s\"", pathname);
    return readlink_internal(current->p->cwd, pathname, buf, bufsiz);
}

sysreturn readlinkat(int dirfd, const char *pathname, char *buf, u64 bufsiz)
{
    thread_log(current, "readlinkat: \"%s\", dirfd %d", pathname, dirfd);
    tuple cwd = resolve_dir(dirfd, pathname);
    return readlink_internal(cwd, pathname, buf, bufsiz);
}

closure_function(1, 1, void, file_delete_complete,
                 thread, t,
                 status, s)
{
    thread t = bound(t);
    thread_log(current, "%s: status %v (%s)", __func__, s,
            is_ok(s) ? "OK" : "NOTOK");
    if (is_ok(s)) {
        set_syscall_return(t, 0);
    }
    else {
        set_syscall_error(t, EIO);
    }
    file_op_maybe_wake(t);
    closure_finish();
}

static sysreturn unlink_internal(tuple cwd, const char *pathname)
{
    tuple n;
    tuple parent;
    int ret = resolve_cstring(cwd, pathname, &n, &parent);
    if (ret) {
        return set_syscall_return(current, ret);
    }
    if (is_dir(n)) {
        return set_syscall_error(current, EISDIR);
    }
    filesystem_update_mtime(current->p->fs, parent);
    file_op_begin(current);
    filesystem_delete(current->p->fs, parent, lookup_sym(parent, n),
            closure(heap_general(get_kernel_heaps()), file_delete_complete,
            current));
    return file_op_maybe_sleep(current);
}

static sysreturn rmdir_internal(tuple cwd, const char *pathname)
{
    tuple n;
    tuple parent;
    int ret = resolve_cstring(cwd, pathname, &n, &parent);
    if (ret) {
        return set_syscall_return(current, ret);
    }
    if (!is_dir(n)) {
        return set_syscall_error(current, ENOTDIR);
    }
    tuple c = children(n);
    buffer tmpbuf = little_stack_buffer(NAME_MAX + 1);
    table_foreach(c, k, v) {
        char *p = cstring(symbol_string(k), tmpbuf);

        if (runtime_strcmp(p, ".") && runtime_strcmp(p, "..")) {
            thread_log(current, "%s: found entry '%s'", __func__, p);
            return set_syscall_error(current, ENOTEMPTY);
        }
    }
    filesystem_update_mtime(current->p->fs, parent);
    file_op_begin(current);
    filesystem_delete(current->p->fs, parent, lookup_sym(parent, n),
            closure(heap_general(get_kernel_heaps()), file_delete_complete,
            current));
    return file_op_maybe_sleep(current);
}

sysreturn unlink(const char *pathname)
{
    thread_log(current, "unlink %s", pathname);
    return unlink_internal(current->p->cwd, pathname);
}

sysreturn unlinkat(int dirfd, const char *pathname, int flags)
{
    thread_log(current, "unlinkat %d %s 0x%x", dirfd, pathname, flags);
    if (flags & ~AT_REMOVEDIR) {
        return set_syscall_error(current, EINVAL);
    }
    tuple cwd = resolve_dir(dirfd, pathname);
    if (flags & AT_REMOVEDIR) {
        return rmdir_internal(cwd, pathname);
    }
    else {
        return unlink_internal(cwd, pathname);
    }
}

sysreturn rmdir(const char *pathname)
{
    thread_log(current, "rmdir %s", pathname);
    return rmdir_internal(current->p->cwd, pathname);
}

closure_function(1, 1, void, file_rename_complete,
                 thread, t,
                 status, s)
{
    thread t = bound(t);
    thread_log(current, "%s: status %v (%s)", __func__, s,
            is_ok(s) ? "OK" : "NOTOK");
    set_syscall_return(t, is_ok(s) ? 0 : -EIO);
    file_op_maybe_wake(t);
    closure_finish();
}

static sysreturn rename_internal(tuple oldwd, const char *oldpath, tuple newwd,
        const char *newpath)
{
    if (!oldpath[0] || !newpath[0]) {
        return set_syscall_error(current, ENOENT);
    }
    int ret;
    tuple old;
    tuple oldparent;
    ret = resolve_cstring(oldwd, oldpath, &old, &oldparent);
    if (ret) {
        return set_syscall_return(current, ret);
    }
    tuple new, newparent;
    ret = resolve_cstring(newwd, newpath, &new, &newparent);
    if (ret && (ret != -ENOENT)) {
        return set_syscall_return(current, ret);
    }
    if (!newparent) {
        return set_syscall_error(current, ENOENT);
    }
    if (!ret && is_dir(new)) {
        if (!is_dir(old)) {
            return set_syscall_error(current, EISDIR);
        }
        tuple c = children(new);
        buffer tmpbuf = little_stack_buffer(NAME_MAX + 1);
        table_foreach(c, k, v) {
            char *p = cstring(symbol_string(k), tmpbuf);

            if (runtime_strcmp(p, ".") && runtime_strcmp(p, "..")) {
                thread_log(current, "%s: found entry '%s'", __func__, p);
                return set_syscall_error(current, ENOTEMPTY);
            }
        }
    }
    if (new && !is_dir(new) && is_dir(old)) {
        return set_syscall_error(current, ENOTDIR);
    }
    if (filepath_is_ancestor(oldwd, oldpath, newwd, newpath)) {
        return set_syscall_error(current, EINVAL);
    }
    filesystem_update_mtime(current->p->fs, oldparent);
    filesystem_update_mtime(current->p->fs, newparent);
    file_op_begin(current);
    filesystem_rename(current->p->fs, oldparent, lookup_sym(oldparent, old),
            newparent, filename_from_path(newpath),
            closure(heap_general(get_kernel_heaps()), file_rename_complete,
            current));
    return file_op_maybe_sleep(current);
}

sysreturn rename(const char *oldpath, const char *newpath)
{
    thread_log(current, "rename \"%s\" \"%s\"", oldpath, newpath);
    return rename_internal(current->p->cwd, oldpath, current->p->cwd, newpath);
}

sysreturn renameat(int olddirfd, const char *oldpath, int newdirfd,
        const char *newpath)
{
    thread_log(current, "renameat %d \"%s\" %d \"%s\"", olddirfd, oldpath,
            newdirfd, newpath);
    tuple oldwd = resolve_dir(olddirfd, oldpath);
    tuple newwd = resolve_dir(newdirfd, newpath);
    return rename_internal(oldwd, oldpath, newwd, newpath);
}

sysreturn renameat2(int olddirfd, const char *oldpath, int newdirfd,
        const char *newpath, unsigned int flags)
{
    thread_log(current, "renameat2 %d \"%s\" %d \"%s\", flags 0x%x", olddirfd,
            oldpath, newdirfd, newpath, flags);
    if ((flags & ~(RENAME_EXCHANGE | RENAME_NOREPLACE)) ||
            ((flags & RENAME_EXCHANGE) && (flags & RENAME_NOREPLACE))) {
        return set_syscall_error(current, EINVAL);
    }
    tuple oldwd = resolve_dir(olddirfd, oldpath);
    tuple newwd = resolve_dir(newdirfd, newpath);
    if (flags & RENAME_EXCHANGE) {
        if (filepath_is_ancestor(oldwd, oldpath, newwd, newpath) ||
                filepath_is_ancestor(newwd, newpath, oldwd, oldpath)) {
            return set_syscall_error(current, EINVAL);
        }
        int ret;
        tuple old, new;
        tuple oldparent, newparent;
        ret = resolve_cstring(oldwd, oldpath, &old, &oldparent);
        if (ret) {
            return set_syscall_return(current, ret);
        }
        ret = resolve_cstring(newwd, newpath, &new, &newparent);
        if (ret) {
            return set_syscall_return(current, ret);
        }
        filesystem_update_mtime(current->p->fs, oldparent);
        filesystem_update_mtime(current->p->fs, newparent);
        file_op_begin(current);
        filesystem_exchange(current->p->fs, oldparent,
                lookup_sym(oldparent, old), newparent,
                lookup_sym(newparent, new),
                closure(heap_general(get_kernel_heaps()), file_rename_complete,
                current));
        return file_op_maybe_sleep(current);
    }
    else {
        if ((flags & RENAME_NOREPLACE) &&
                !resolve_cstring(newwd, newpath, 0, 0)) {
            return set_syscall_error(current, EEXIST);
        }
        return rename_internal(oldwd, oldpath, newwd, newpath);
    }
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

sysreturn fcntl(int fd, int cmd, s64 arg)
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
    case F_GETLK:
        if (arg) {
            ((struct flock *)arg)->l_type = F_UNLCK;
        }
        return set_syscall_return(current, 0);
    case F_SETLK:
    case F_SETLKW:
        return set_syscall_return(current, 0);
    case F_DUPFD:
    case F_DUPFD_CLOEXEC: {
        if (arg < 0) {
            return set_syscall_error(current, EINVAL);
        }
        int newfd = allocate_fd_gte(current->p, arg, f);
        if (newfd == INVALID_PHYSICAL) {
            thread_log(current, "failed to allocate fd");
            return set_syscall_error(current, EMFILE);
        }
        fetch_and_add(&f->refcnt, 1);
        return set_syscall_return(current, newfd);
    }
    default:
        return set_syscall_error(current, ENOSYS);
    }
}

sysreturn ioctl(int fd, unsigned long request, ...)
{
    // checks if fd is valid
    fdesc f = resolve_fd(current->p, fd);

    if (f->ioctl) {
        vlist args;
        vstart(args, request);
        sysreturn rv = apply(f->ioctl, request, args);
        vend(args);
        return set_syscall_return(current, rv);
    }
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
    thread_yield();             /* noreturn */
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

static thread lookup_thread(int pid)
{
    thread t;
    if (pid== 0) {
        t = current;
    } else {
        if ((t = thread_from_tid(current->p, pid)) == INVALID_ADDRESS)
            return 0;
    }
    return t;
}

sysreturn sched_setaffinity(int pid, u64 cpusetsize, cpu_set_t *mask)
{
    thread t;
    if (!(t = lookup_thread(pid)) ||
        (!mask || cpusetsize < sizeof(mask->mask[0])))
            return set_syscall_error(current, EINVAL);                
    runtime_memcpy(&t->affinity, mask, sizeof(mask->mask[0]));
    return 0;
}

sysreturn sched_getaffinity(int pid, u64 cpusetsize, cpu_set_t *mask)
{
    thread t;
    if (!(t = lookup_thread(pid)) ||
        (!mask || cpusetsize < sizeof(mask->mask[0])))
            return set_syscall_error(current, EINVAL);                    
    runtime_memcpy(mask, &t->affinity, sizeof(mask->mask[0]));        
    return sizeof(mask->mask[0]);
}

sysreturn capget(cap_user_header_t hdrp, cap_user_data_t datap)
{
    if (datap) {
        zero(datap, sizeof(*datap));
    }
    return 0;
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
    info->uptime = sec_from_timestamp(uptime());
    info->totalram = heap_total((heap)kh->physical);
    u64 allocated = heap_allocated((heap)kh->physical);
    info->freeram = info->totalram < allocated ? 0 : info->totalram - allocated;
    info->procs = 1;
    info->mem_unit = 1;
    return 0;
}

sysreturn umask(int mask)
{
	return mask;
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
    register_syscall(map, dup2, dup2);
    register_syscall(map, dup3, dup3);
    register_syscall(map, fstat, fstat);
    register_syscall(map, fallocate, fallocate);
    register_syscall(map, sendfile, sendfile);
    register_syscall(map, stat, stat);
    register_syscall(map, lstat, lstat);
    register_syscall(map, readv, readv);
    register_syscall(map, writev, writev);
    register_syscall(map, truncate, truncate);
    register_syscall(map, ftruncate, ftruncate);
    register_syscall(map, fdatasync, fdatasync);
    register_syscall(map, fsync, fsync);
    register_syscall(map, io_setup, io_setup);
    register_syscall(map, io_submit, io_submit);
    register_syscall(map, io_getevents, io_getevents);
    register_syscall(map, io_destroy, io_destroy);
    register_syscall(map, access, access);
    register_syscall(map, lseek, lseek);
    register_syscall(map, fcntl, fcntl);
    register_syscall(map, ioctl, (sysreturn (*)())ioctl);
    register_syscall(map, getcwd, getcwd);
    register_syscall(map, symlink, symlink);
    register_syscall(map, symlinkat, symlinkat);
    register_syscall(map, readlink, readlink);
    register_syscall(map, readlinkat, readlinkat);
    register_syscall(map, unlink, unlink);
    register_syscall(map, unlinkat, unlinkat);
    register_syscall(map, rmdir, rmdir);
    register_syscall(map, rename, rename);
    register_syscall(map, renameat, renameat);
    register_syscall(map, renameat2, renameat2);
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
    register_syscall(map, utime, utime);
    register_syscall(map, utimes, utimes);
    register_syscall(map, newfstatat, newfstatat);
    register_syscall(map, sched_getaffinity, sched_getaffinity);
    register_syscall(map, sched_setaffinity, sched_setaffinity);
    register_syscall(map, getuid, syscall_ignore);
    register_syscall(map, geteuid, syscall_ignore);
    register_syscall(map, chown, syscall_ignore);
    register_syscall(map, setgroups, syscall_ignore);
    register_syscall(map, setuid, syscall_ignore);
    register_syscall(map, setgid, syscall_ignore);
    register_syscall(map, capget, capget);
    register_syscall(map, capset, syscall_ignore);
    register_syscall(map, prctl, prctl);
    register_syscall(map, sysinfo, sysinfo);
    register_syscall(map, umask, umask);
    register_syscall(map, statfs, statfs);
    register_syscall(map, fstatfs, fstatfs);
}

#define SYSCALL_F_NOTRACE 0x1

struct syscall {
    void *handler;
    const char *name;
    int flags;
};

static struct syscall _linux_syscalls[SYS_MAX];
struct syscall *linux_syscalls = _linux_syscalls;

extern u64 kernel_lock;

void syscall_debug(context f)
{
    u64 call = f[FRAME_VECTOR];
    thread t = current;
    set_syscall_return(t, -ENOSYS);

    if (call >= sizeof(_linux_syscalls) / sizeof(_linux_syscalls[0])) {
        schedule_frame(f);
        thread_log(current, "invalid syscall %d", call);
        runloop();
    }
    t->syscall = call;
    // should we cache this for performance?
    void *debugsyscalls = table_find(current->p->process_root, sym(debugsyscalls));
    struct syscall *s = current->p->syscalls + call;
    if (debugsyscalls) {
        if (s->name)
            thread_log(current, s->name);
        else
            thread_log(current, "syscall %d", call);
    }
    sysreturn (*h)(u64, u64, u64, u64, u64, u64) = s->handler;
    if (h) {
        proc_enter_system(current->p);

        sysreturn rv = h(f[FRAME_RDI], f[FRAME_RSI], f[FRAME_RDX], f[FRAME_R10], f[FRAME_R8], f[FRAME_R9]);
        set_syscall_return(current, rv);
        if (debugsyscalls)
            thread_log(current, "direct return: %ld, rsp 0x%lx", rv, f[FRAME_RSP]);
    } else if (debugsyscalls) {
        if (s->name)
            thread_log(current, "nosyscall %s", s->name);
        else
            thread_log(current, "nosyscall %d", call);
    }
    current->syscall = -1;
    // i dont know that we actually want to defer the syscall return...its just easier for the moment to hew
    // to the general model and make exceptions later
    schedule_frame(f);
    runloop();
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

closure_function(0, 2, void, syscall_io_complete_cfn,
                 thread, t, sysreturn, rv)
{
    set_syscall_return(t, rv);
    file_op_maybe_wake(t);
}

// some validation can be moved up here
static void syscall_schedule(context f, u64 call)
{
    /* kernel context set on syscall entry */
    if (kern_try_lock()) {
        current_cpu()->state = cpu_kernel;
        syscall_debug(f);
    } else {
        enqueue(runqueue, &current->deferred_syscall);
        runloop();
    }
}

void init_syscalls()
{
    //syscall = b->contents;
    // debug the synthesized version later, at least we have the table dispatch
    heap h = heap_general(get_kernel_heaps());
    syscall = syscall_schedule;
    syscall_io_complete = closure(h, syscall_io_complete_cfn);
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
