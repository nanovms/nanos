#include <unix_internal.h>
#include <filesystem.h>
#include <storage.h>

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

typedef struct syscall_stat {
    u64 calls;
    u64 errors;
    u64 usecs;
} *syscall_stat;

static struct syscall_stat stats[SYS_MAX];
BSS_RO_AFTER_INIT boolean do_syscall_stats;
BSS_RO_AFTER_INIT static boolean do_missing_files;
BSS_RO_AFTER_INIT static vector missing_files;

sysreturn close(int fd);

BSS_RO_AFTER_INIT io_completion syscall_io_complete;
BSS_RO_AFTER_INIT io_completion io_completion_ignore;
BSS_RO_AFTER_INIT shutdown_handler print_syscall_stats;
BSS_RO_AFTER_INIT shutdown_handler print_missing_files;

boolean validate_iovec(struct iovec *iov, u64 len, boolean write)
{
    if (!validate_user_memory(iov, sizeof(struct iovec) * len, false))
        return false;
    for (u64 i = 0; i < len; i++) {
        if ((iov[i].iov_len != 0) &&
                !validate_user_memory(iov[i].iov_base, iov[i].iov_len, write))
            return false;
    }
    return true;
}

declare_closure_struct(2, 2, void, iov_op_each_complete,
                       int, iovcnt, struct iov_progress *, progress,
                       thread, t, sysreturn, rv);

declare_closure_struct(2, 0, void, iov_bh,
                       struct iov_progress *, p, thread, t);

struct iov_progress {
    heap h;
    fdesc f;
    boolean write;
    struct iovec *iov;
    boolean initialized;
    boolean blocking;
    u64 file_offset;
    int curr;
    u64 curr_offset;
    u64 total_len;
    io_completion completion;
    closure_struct(iov_op_each_complete, each_complete);
    closure_struct(iov_bh, bh);
};

static void iov_op_each(struct iov_progress *p, thread t)
{
    struct iovec *iov = p->iov;
    file_io op = p->write ? p->f->write : p->f->read;
    boolean blocking = p->blocking;
    p->blocking = false;

    /* Issue the next request. */
    thread_log(t, "   op: curr %d, offset %ld, @ %p, len %ld, blocking %d",
               p->curr, p->curr_offset, iov[p->curr].iov_base + p->curr_offset,
               iov[p->curr].iov_len - p->curr_offset, blocking);
    apply(op, iov[p->curr].iov_base + p->curr_offset,
          iov[p->curr].iov_len - p->curr_offset, p->file_offset, t, !blocking,
          (io_completion)&p->each_complete);
}

define_closure_function(2, 2, void, iov_op_each_complete,
                 int, iovcnt, struct iov_progress *, progress,
                 thread, t, sysreturn, rv)
{
    io_completion c;
    int iovcnt = bound(iovcnt);
    struct iov_progress *p = bound(progress);
    fdesc f = p->f;
    boolean write = p->write;
    thread_log(t, "%s: rv %ld, curr %d, iovcnt %d", __func__, rv, p->curr, iovcnt);

    file_io op = write ? f->write : f->read;
    if (!op)
        rv = -EOPNOTSUPP;

    /* If these ops were truly atomic, we would have to rewind file
       state on failure... */
    if (rv < 0) {
        goto out_complete;
    }

    /* Increment offset and total by io op retval, advancing to next
       (non-zero-len) buffer if needed. */
    struct iovec *iov = p->iov;
    p->total_len += rv;
    p->curr_offset += rv;

    if (p->curr_offset == iov[p->curr].iov_len) {
        p->curr_offset = 0;
        do {
            p->curr++;
        } while (p->curr < iovcnt && iov[p->curr].iov_len == 0);
    } else {
        assert(p->curr_offset < iov[p->curr].iov_len);
    }

    /* If we're done, return the total length... */
    if ((p->curr == iovcnt) || ((rv == 0) && p->initialized) ||
            ((p->total_len != 0) && f->events &&
            !(apply(f->events, t) & (write ? EPOLLOUT : EPOLLIN)))) {
        rv = p->total_len;
        goto out_complete;
    }

    if (!p->initialized) {
        p->initialized = true;
        iov_op_each(p, t);
    } else {
        if (p->file_offset != infinity)
            p->file_offset += rv;
        enqueue_irqsafe(runqueue, &p->bh);
    }
    return;
  out_complete:
    c = p->completion;
    deallocate(p->h, p, sizeof(*p));
    apply(c, t, rv);
}

define_closure_function(2, 0, void, iov_bh,
                        struct iov_progress *, p, thread, t)
{
    iov_op_each(bound(p), bound(t));
}

closure_function(4, 2, void, iov_read_complete,
                 sg_list, sg, struct iovec *, iov, int, iovcnt, io_completion, completion,
                 thread, t, sysreturn, rv)
{
    sg_list sg = bound(sg);
    io_completion completion = bound(completion);
    thread_log(t, "%s: sg %p, completion %F, rv %ld", __func__, sg, completion,
               rv);
    if (rv > 0) {
        sg_to_iov(sg, bound(iov), bound(iovcnt));
    }
    deallocate_sg_list(sg);
    apply(completion, t, rv);
    closure_finish();
}

closure_function(2, 2, void, iov_write_complete,
                 sg_list, sg, io_completion, completion,
                 thread, t, sysreturn, rv)
{
    sg_list sg = bound(sg);
    io_completion completion = bound(completion);
    thread_log(t, "%s: sg %p, completion %F, rv %ld", __func__, sg, completion,
               rv);
    sg_list_release(sg);
    deallocate_sg_list(sg);
    apply(completion, t, rv);
    closure_finish();
}

void iov_op(fdesc f, boolean write, struct iovec *iov, int iovcnt, u64 offset,
            boolean blocking, io_completion completion)
{
    sysreturn rv;
    if ((write && !fdesc_is_writable(f)) || (!write && !fdesc_is_readable(f))) {
        rv = -EBADF;
        goto out;
    }
    if (iovcnt < 0 || iovcnt > IOV_MAX) {
        rv = -EINVAL;
        goto out;
    }
    if (iovcnt == 0) {
        rv = 0;
        goto out;
    }

    heap h = heap_locked(get_kernel_heaps());
    if (write ? (f->sg_write != 0) : (f->sg_read != 0)) {
        sg_list sg = allocate_sg_list();
        if (sg == INVALID_ADDRESS) {
            rv = -ENOMEM;
            goto out;
        }
        io_completion iov_complete;
        if (write) {
            iov_to_sg(sg, iov, iovcnt);
            iov_complete = closure(h, iov_write_complete, sg, completion);

        } else {
            iov_complete = closure(h, iov_read_complete, sg, iov, iovcnt,
                completion);
        }
        apply(write ? f->sg_write : f->sg_read, sg, iov_total_len(iov, iovcnt),
                offset, current, !blocking, iov_complete);
        return;
    }
    struct iov_progress *p = allocate(h, sizeof(struct iov_progress));
    if (p == INVALID_ADDRESS) {
        rv = -ENOMEM;
        goto out;
    }
    p->h = h;
    p->f = f;
    p->write = write;
    p->iov = iov;
    p->initialized = false;
    p->blocking = blocking;
    p->file_offset = offset;
    p->curr = 0;
    p->curr_offset = 0;
    p->total_len = 0;
    p->completion = completion;
    init_closure(&p->bh, iov_bh, p, current);
    apply_context_to_closure(&p->bh, get_current_context(current_cpu()));
    init_closure(&p->each_complete, iov_op_each_complete, iovcnt,
        p);
    io_completion each = (io_completion)&p->each_complete;
    apply(each, current, 0);
    return;
out:
    apply(completion, current, rv);
}

sysreturn read(int fd, u8 *dest, bytes length)
{
    if (!validate_user_memory(dest, length, true))
        return -EFAULT;
    fdesc f = resolve_fd(current->p, fd);
    sysreturn rv;
    if (!fdesc_is_readable(f)) {
        rv = -EBADF;
        goto out;
    }
    if (!f->read) {
        rv = -EINVAL;
        goto out;
    }

    /* use (and update) file offset */
    return apply(f->read, dest, length, infinity, current, false, (io_completion)&f->io_complete);

  out:
    fdesc_put(f);
    return rv;
}

sysreturn pread(int fd, u8 *dest, bytes length, s64 offset)
{
    if (!validate_user_memory(dest, length, true))
        return -EFAULT;
    fdesc f = resolve_fd(current->p, fd);
    sysreturn rv;
    if (!fdesc_is_readable(f)) {
        rv = -EBADF;
        goto out;
    }
    if (!f->read || offset < 0) {
        rv = -EINVAL;
        goto out;
    }

    /* use given offset with no file offset update */
    return apply(f->read, dest, length, offset, current, false, (io_completion)&f->io_complete);

  out:
    fdesc_put(f);
    return rv;
}

sysreturn readv(int fd, struct iovec *iov, int iovcnt)
{
    if (!validate_iovec(iov, iovcnt, true))
        return -EFAULT;
    fdesc f = resolve_fd(current->p, fd);
    if (fdesc_type(f) == FDESC_TYPE_DIRECTORY) {
        fdesc_put(f);
        return -EISDIR;
    }
    iov_op(f, false, iov, iovcnt, infinity, true, (io_completion)&f->io_complete);
    return thread_maybe_sleep_uninterruptible(current);
}

sysreturn write(int fd, u8 *body, bytes length)
{
    if (!validate_user_memory(body, length, false))
        return -EFAULT;
    fdesc f = resolve_fd(current->p, fd);
    sysreturn rv;
    if (!fdesc_is_writable(f)) {
        rv = -EBADF;
        goto out;
    }
    if (!f->write) {
        rv = -EINVAL;
        goto out;
    }

    /* use (and update) file offset */
    return apply(f->write, body, length, infinity, current, false, (io_completion)&f->io_complete);

  out:
    fdesc_put(f);
    return rv;
}

sysreturn pwrite(int fd, u8 *body, bytes length, s64 offset)
{
    if (!validate_user_memory(body, length, false))
        return -EFAULT;
    fdesc f = resolve_fd(current->p, fd);
    sysreturn rv;
    if (!fdesc_is_writable(f)) {
        rv = -EBADF;
        goto out;
    }
    if (!f->write || offset < 0) {
        rv = -EINVAL;
        goto out;
    }

    return apply(f->write, body, length, offset, current, false, (io_completion)&f->io_complete);
  out:
    fdesc_put(f);
    return rv;
}

sysreturn writev(int fd, struct iovec *iov, int iovcnt)
{
    if (!validate_iovec(iov, iovcnt, false))
        return -EFAULT;
    fdesc f = resolve_fd(current->p, fd);
    iov_op(f, true, iov, iovcnt, infinity, true, (io_completion)&f->io_complete);
    return thread_maybe_sleep_uninterruptible(current);
}

static boolean is_special(tuple n)
{
    return get(n, sym(special)) ? true : false;
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
            sg_buf_release(bound(cur_buf));
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
        bound(cur_buf)->offset = 0; /* offset for our use */
        thread_log(t, "   read %ld bytes\n", rv);
    } else {
        bound(written) += rv;
        bound(cur_buf)->offset += rv;
        if (bound(cur_buf)->offset == bound(cur_buf)->size) {
            sg_buf_release(bound(cur_buf));
            if (bound(written) == bound(readlen)) {
                rv = bound(written);
                goto out_complete;
            }
            bound(cur_buf) = sg_list_head_remove(bound(sg));
            assert(bound(cur_buf) != INVALID_ADDRESS);
            bound(cur_buf)->offset = 0; /* offset for our use */
        }
        assert(bound(cur_buf)->offset < bound(cur_buf)->size);
    }

    /* issue next write */
    assert(bound(cur_buf));
    void *buf = bound(cur_buf)->buf + bound(cur_buf)->offset;
    u32 n = bound(cur_buf)->size - bound(cur_buf)->offset;
    thread_log(t, "   writing %d bytes from %p", rv, n, buf);
    apply(bound(out)->write, buf, n, 0, t, true, (io_completion)closure_self());
    return;
out_complete:
    sg_list_release(bound(sg));
    deallocate_sg_list(bound(sg));
    fdesc_put(bound(in));
    fdesc_put(bound(out));
    syscall_return(t, rv);
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
    if (offset && !validate_user_memory(offset, sizeof(int), true))
        return -EFAULT;
    fdesc infile = resolve_fd(current->p, in_fd);
    fdesc outfile = fdesc_get(current->p, out_fd);
    if (!outfile) {
        fdesc_put(infile);
        return -EBADF;
    }
    sysreturn rv;
    if (!fdesc_is_readable(infile) || !fdesc_is_writable(outfile)) {
        rv = -EBADF;
        goto out;
    }
    if (!infile->sg_read || !outfile->write) {
        rv = -EINVAL;
        goto out;
    }

    sg_list sg = allocate_sg_list();
    if (sg == INVALID_ADDRESS) {
        rv = -ENOMEM;
        goto out;
    }

    u64 n = MIN(count, SENDFILE_READ_MAX);
    io_completion read_complete = closure(heap_locked(get_kernel_heaps()), sendfile_bh, infile, outfile,
                                          offset, sg, 0, n, 0, 0, false);
    apply(infile->sg_read, sg, n, offset ? *offset : infinity, current, false, read_complete);
    return get_syscall_return(current);
  out:
    fdesc_put(infile);
    fdesc_put(outfile);
    return rv;
}

static void begin_file_read(thread t, file f)
{
    tuple md = filesystem_get_meta(f->fs, f->n);
    if (md) {
        if ((f->length > 0) && !(f->f.flags & O_NOATIME))
            filesystem_update_atime(f->fs, md);
        fs_notify_event(md, IN_ACCESS);
        filesystem_put_meta(f->fs, md);
    }
}

closure_function(7, 1, void, file_read_complete,
                 thread, t, sg_list, sg, void *, dest, u64, limit, file, f, boolean, is_file_offset, io_completion, completion,
                 status, s)
{
    thread_log(bound(t), "%s: status %v", __func__, s);
    sysreturn rv;
    if (is_ok(s)) {
        file f = bound(f);
        u64 count = sg_copy_to_buf_and_release(bound(dest), bound(sg), bound(limit));
        thread_log(bound(t), "   read count %ld\n", count);
        if (bound(is_file_offset)) /* vs specified offset (pread) */
            f->offset += count;
        rv = count;
    } else {
        rv = sysreturn_from_fs_status_value(s);
    }
    apply(bound(completion), bound(t), rv);
    closure_finish();
}

closure_function(2, 6, sysreturn, file_read,
                 file, f, fsfile, fsf,
                 void *, dest, u64, length, u64, offset_arg, thread, t, boolean, bh, io_completion, completion)
{
    file f = bound(f);
    if (fdesc_type(&f->f) == FDESC_TYPE_DIRECTORY)
        return io_complete(completion, t, -EISDIR);
    boolean is_file_offset = offset_arg == infinity;
    u64 offset = is_file_offset ? f->offset : offset_arg;
    thread_log(t, "%s: f %p, dest %p, offset %ld (%s), length %ld, file length %ld",
               __func__, f, dest, offset, is_file_offset ? "file" : "specified",
               length, f->length);

    if (offset >= f->length) {
        return io_complete(completion, t, 0);
    }
    sg_list sg = allocate_sg_list();
    if (sg == INVALID_ADDRESS) {
        thread_log(t, "   unable to allocate sg list");
        return io_complete(completion, t, -ENOMEM);
    }
    begin_file_read(t, f);
    apply(f->fs_read, sg, irangel(offset, length),
          contextual_closure(file_read_complete, t, sg, dest, length,
                             f, is_file_offset, completion));
    file_readahead(f, offset, length);
    /* possible direct return in top half */
    return bh ? SYSRETURN_CONTINUE_BLOCKING : thread_maybe_sleep_uninterruptible(t);
}

closure_function(5, 1, void, file_sg_read_complete,
                 thread, t, file, f, sg_list, sg, boolean, is_file_offset, io_completion, completion,
                 status, s)
{
    thread_log(bound(t), "%s: status %v", __func__, s);
    sysreturn rv;
    if (is_ok(s)) {
       u64 length = bound(sg)->count;
       file f = bound(f);
        if (bound(is_file_offset)) /* vs specified offset (pread) */
            f->offset += length;
        rv = length;
    } else {
        rv = -EIO;
    }
    apply(bound(completion), bound(t), rv);
    closure_finish();
}

closure_function(2, 6, sysreturn, file_sg_read,
                 file, f, fsfile, fsf,
                 sg_list, sg, u64, length, u64, offset_arg, thread, t, boolean, bh, io_completion, completion)
{
    file f = bound(f);

    boolean is_file_offset = offset_arg == infinity;
    u64 offset = is_file_offset ? f->offset : offset_arg;
    thread_log(t, "%s: f %p, sg %p, offset %ld (%s), length %ld, file length %ld",
               __func__, f, sg, offset, is_file_offset ? "file" : "specified",
               length, f->length);

    begin_file_read(t, f);
    // validate ctx save upstream
    apply(f->fs_read, sg, irangel(offset, length),
          contextual_closure(file_sg_read_complete, t, f, sg, is_file_offset, completion));
    file_readahead(f, offset, length);

    /* possible direct return in top half */
    return bh ? SYSRETURN_CONTINUE_BLOCKING : thread_maybe_sleep_uninterruptible(t);
}

static void begin_file_write(thread t, file f, u64 len)
{
    if (len > 0) {
        tuple md = filesystem_get_meta(f->fs, f->n);
        if (md) {
            filesystem_update_mtime(f->fs, md);
            fs_notify_event(md, IN_MODIFY);
            filesystem_put_meta(f->fs, md);
        }
    }
}

static void file_write_complete_internal(thread t, file f, u64 len,
                                         boolean is_file_offset,
                                         io_completion completion, status s)
{
    sysreturn rv;
    if (is_ok(s)) {
        /* if regular file, update length */
        if (f->fsf)
            f->length = fsfile_get_length(f->fsf);
        if (is_file_offset)
            f->offset += len;
        rv = len;
    } else {
        rv = sysreturn_from_fs_status_value(s);
    }
    apply(completion, t, rv);
}

closure_function(6, 1, void, file_write_complete,
                 thread, t, file, f, sg_list, sg, u64, length, boolean, is_file_offset, io_completion, completion,
                 status, s)
{
    thread_log(bound(t), "%s: f %p, sg, %p, completion %F, status %v",
               __func__, bound(f), bound(sg), bound(completion), s);
    sg_list_release(bound(sg));
    deallocate_sg_list(bound(sg));
    file_write_complete_internal(bound(t), bound(f), bound(length),
                                 bound(is_file_offset), bound(completion), s);
    closure_finish();
}

closure_function(2, 6, sysreturn, file_write,
                 file, f, fsfile, fsf,
                 void *, src, u64, length, u64, offset_arg, thread, t, boolean, bh, io_completion, completion)
{
    file f = bound(f);
    boolean is_file_offset = offset_arg == infinity;
    u64 offset = is_file_offset ? f->offset : offset_arg;
    thread_log(t, "%s: f %p, src %p, offset %ld (%s), length %ld, file length %ld",
               __func__, f, src, offset, is_file_offset ? "file" : "specified",
               length, f->length);

    sg_list sg = allocate_sg_list();
    if (sg == INVALID_ADDRESS) {
        thread_log(t, "   unable to allocate sg list");
        return io_complete(completion, t, -ENOMEM);
    }
    sg_buf sgb = sg_list_tail_add(sg, length);
    sgb->buf = src;
    sgb->size = length;
    sgb->offset = 0;
    sgb->refcount = 0;

    begin_file_write(t, f, length);
    // validate ctx save upstream
    apply(f->fs_write, sg, irangel(offset, length),
          contextual_closure(file_write_complete, t, f, sg, length, is_file_offset, completion));
    /* possible direct return in top half */
    return bh ? SYSRETURN_CONTINUE_BLOCKING : thread_maybe_sleep_uninterruptible(t);
}

closure_function(5, 1, void, file_sg_write_complete,
                 thread, t, file, f, u64, len, boolean, is_file_offset, io_completion, completion,
                 status, s)
{
    thread t = bound(t);
    file f = bound(f);
    u64 len = bound(len);
    io_completion completion = bound(completion);
    thread_log(t, "%s: f %p, len %ld, completion %F, status %v",
               __func__, f, len, completion, s);
    file_write_complete_internal(t, f, len, bound(is_file_offset), completion,
                                 s);
    closure_finish();
}

closure_function(2, 6, sysreturn, file_sg_write,
                 file, f, fsfile, fsf,
                 sg_list, sg, u64, len, u64, offset_arg, thread, t, boolean, bh, io_completion, completion)
{
    file f = bound(f);
    sysreturn rv;

    boolean is_file_offset = offset_arg == infinity;
    u64 offset = is_file_offset ? f->offset : offset_arg;
    thread_log(t, "%s: f %p, sg %p, offset %ld (%s), len %ld, file length %ld",
               __func__, f, sg, offset, is_file_offset ? "file" : "specified",
               len, f->length);
    status_handler sg_complete = contextual_closure(file_sg_write_complete, t, f, len,
                                                    is_file_offset, completion);
    if (sg_complete == INVALID_ADDRESS) {
        rv = -ENOMEM;
        goto out;
    }
    begin_file_write(t, f, len);
    apply(f->fs_write, sg, irangel(offset, len), sg_complete);
    return bh ? SYSRETURN_CONTINUE_BLOCKING : thread_maybe_sleep_uninterruptible(t);
  out:
    return io_complete(completion, t, rv);
}

closure_function(2, 2, sysreturn, file_close,
                 file, f, fsfile, fsf,
                 thread, t, io_completion, completion)
{
    file f = bound(f);
    tuple md = filesystem_get_meta(f->fs, f->n);
    if (md) {
        fs_notify_event(md, ((f->f.flags & O_ACCMODE) == O_RDONLY) ?
                        IN_CLOSE_NOWRITE : IN_CLOSE_WRITE);
        filesystem_put_meta(f->fs, md);
    }
    fsfile fsf = bound(fsf);
    if (fsf)
        fsfile_release(fsf);
    deallocate_closure(f->f.read);
    deallocate_closure(f->f.write);
    deallocate_closure(f->f.sg_read);
    deallocate_closure(f->f.sg_write);
    deallocate_closure(f->f.events);
    deallocate_closure(f->f.close);
    file_release(f);
    return io_complete(completion, t, 0);
}

closure_function(1, 1, u32, file_events,
                 file, f,
                 thread, t /* ignore */)
{
    file f = bound(f);
    u32 events;
    /* XXX add nonblocking support */
    events = f->length < infinity ? EPOLLOUT : 0;
    events |= f->offset < f->length ? EPOLLIN : EPOLLHUP;
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

boolean validate_user_string(const char *name)
{
    /* validate a page at a time */
    u64 a = u64_from_pointer(name);
    while (validate_user_memory(pointer_from_u64(a & ~PAGEMASK),
                                PAGESIZE, false)) {
        u64 lim = (a & ~PAGEMASK) + PAGESIZE;
        while (a < lim) {
            if (*(u8*)pointer_from_u64(a++) == '\0')
                return true;
        }
    }
    return false;
}

sysreturn open_internal(filesystem fs, inode cwd, const char *name, int flags,
                        int mode)
{
    heap h = heap_locked(get_kernel_heaps());
    unix_heaps uh = get_unix_heaps();
    tuple n;
    int ret;
    buffer b = 0;

    if (!validate_user_string(name))
        return -EFAULT;

    fsfile fsf;
    fs_status fss = filesystem_get_node(&fs, cwd, name, !!(flags & O_NOFOLLOW), !!(flags & O_CREAT),
        !!(flags & O_EXCL), &n, &fsf);
    ret = sysreturn_from_fs_status(fss);
    if ((ret == 0) && (flags & O_NOFOLLOW) && is_symlink(n) && !(flags & O_PATH)) {
        filesystem_put_node(fs, n);
        ret = -ELOOP;
    }

    if (do_missing_files) {
        b = buffer_cstring(h, name);
        assert(b != INVALID_ADDRESS);
        b = buffer_basename(b);
    }
    if (ret) {
        if (do_missing_files) {
            boolean found = false;
            for (int i = 0; i < vector_length(missing_files); i++) {
                buffer lb = vector_get(missing_files, i);
                if (buffer_compare(b, lb)) {
                    found = true;
                    break;
                }
            }
            if (!found)
                vector_push(missing_files, b);
            else
                deallocate_buffer(b);
        }
        thread_log(current, "\"%s\" - not found", name);
        return set_syscall_return(current, ret);
    }

    if (flags & O_TMPFILE)
        flags |= O_DIRECTORY;

    switch (flags & O_ACCMODE) {
    case O_RDONLY:
        if ((flags & O_TMPFILE)) {
            ret = -EINVAL;
            goto out;
        }
        break;
    case O_WRONLY:
    case O_RDWR:
        if (!(file_meta_perms(current->p, n) & ACCESS_PERM_WRITE)) {
            ret = -EACCES;
            goto out;
        }
        if (is_dir(n) && !(flags & O_TMPFILE)) {
            ret = -EISDIR;
            goto out;
        }
        break;
    default:
        ret = -EINVAL;
        goto out;
    }

    if ((flags & (O_CREAT|O_DIRECTORY)) == O_DIRECTORY && !is_dir(n)) {
        thread_log(current, "\"%s\" opened with O_DIRECTORY but is not a directory", name);
        ret = -ENOTDIR;
        goto out;
    }

    u64 length = 0;
    int type;

    if (flags & O_TMPFILE) {
        fsf = filesystem_creat_unnamed(fs);
        type = FDESC_TYPE_REGULAR;
    } else {
        type = file_type_from_tuple(n);
        if (type == FDESC_TYPE_REGULAR) {
            assert(fsf);
            length = fsfile_get_length(fsf);
        }
    }

    file f = type == FDESC_TYPE_SPECIAL ? spec_allocate(n) : unix_cache_alloc(uh, file);
    if (f == INVALID_ADDRESS) {
        thread_log(current, "failed to allocate struct file");
        ret = -ENOMEM;
        goto out;
    }

    init_fdesc(h, &f->f, type);
    f->f.flags = flags;
    f->fs = fs;
    if (type == FDESC_TYPE_REGULAR) {
        f->fsf = fsf;
        f->fs_read = fsfile_get_reader(fsf);
        assert(f->fs_read);
        f->fs_write = fsfile_get_writer(fsf);
        assert(f->fs_write);
        f->fadv = POSIX_FADV_NORMAL;
        fsfile_reserve(fsf);
        if (flags & O_TMPFILE)
            fsfile_release(fsf);
    }
    f->n = inode_from_tuple(n);
    f->length = length;
    f->offset = (flags & O_APPEND) ? length : 0;

    if (type == FDESC_TYPE_SPECIAL) {
        int spec_ret = spec_open(f, n);
        if (spec_ret != 0) {
            assert(spec_ret < 0);
            thread_log(current, "spec_open failed (%d)\n", spec_ret);
            spec_deallocate(f);
            ret = spec_ret;
            goto out;
        }
    } else {
        f->f.read = closure(h, file_read, f, fsf);
        f->f.write = closure(h, file_write, f, fsf);
        f->f.sg_read = closure(h, file_sg_read, f, fsf);
        f->f.sg_write = closure(h, file_sg_write, f, fsf);
        f->f.close = closure(h, file_close, f, fsf);
        f->f.events = closure(h, file_events, f);
    }

    int fd = allocate_fd(current->p, f);
    if (fd == INVALID_PHYSICAL) {
        thread_log(current, "failed to allocate fd");
        filesystem_put_node(fs, n);
        apply(f->f.close, 0, io_completion_ignore);
        return -EMFILE;
    }

    if (do_missing_files) {
        for (int i = 0; i < vector_length(missing_files); i++) {
            buffer mf = vector_get(missing_files, i);
            if (buffer_compare(b, mf)) {
                vector_delete(missing_files, i);
                deallocate_buffer(mf);
                break;
            }
        }
        deallocate_buffer(b);
    }
    thread_log(current, "   fd %d, length %ld, offset %ld", fd, f->length, f->offset);
    filesystem_reserve(fs);
    fs_notify_event(n, IN_OPEN);
    ret = fd;
  out:
    filesystem_put_node(fs, n);
    return ret;
}

#ifdef __x86_64__
sysreturn open(const char *name, int flags, int mode)
{
    thread_log(current, "open: \"%s\", flags %x, mode %x", name, flags, mode);
    filesystem cwd_fs;
    inode cwd;
    process_get_cwd(current->p, &cwd_fs, &cwd);
    sysreturn rv = open_internal(cwd_fs, cwd, name, flags, mode);
    filesystem_release(cwd_fs);
    return rv;
}
#endif

sysreturn dup(int fd)
{
    thread_log(current, "dup: fd %d", fd);
    fdesc f = resolve_fd(current->p, fd);

    int newfd = allocate_fd(current->p, f);
    if (newfd == INVALID_PHYSICAL) {
        thread_log(current, "failed to allocate fd");
        fdesc_put(f);
        return set_syscall_error(current, EMFILE);
    }

    return newfd;
}

sysreturn dup2(int oldfd, int newfd)
{
    thread_log(current, "%s: oldfd %d, newfd %d", __func__, oldfd, newfd);
    process p = current->p;
    fdesc f = resolve_fd(p, oldfd);
    if (newfd != oldfd) {
        fdesc newf = fdesc_get(p, newfd);
        if (newf) {
            process_lock(p);
            assert(vector_set(p->files, newfd, f));
            process_unlock(p);
            if (fetch_and_add(&newf->refcnt, -2) == 2)
                apply(newf->close, current, io_completion_ignore);
        } else {
            newfd = allocate_fd_gte(p, newfd, f);
            if (newfd == INVALID_PHYSICAL) {
                thread_log(current, "  failed to use newfd");
                fdesc_put(f);
                return -EMFILE;
            }
        }
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

sysreturn mkdir(const char *pathname, int mode)
{
    if (!validate_user_string(pathname))
        return -EFAULT;
    thread_log(current, "mkdir: \"%s\", mode 0x%x", pathname, mode);
    filesystem cwd_fs;
    inode cwd;
    process_get_cwd(current->p, &cwd_fs, &cwd);
    sysreturn rv = sysreturn_from_fs_status(filesystem_mkdir(cwd_fs, cwd, pathname));
    filesystem_release(cwd_fs);
    return rv;
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
    if (!validate_user_string(pathname))
        return -EFAULT;
    thread_log(current, "mkdirat: \"%s\", dirfd %d, mode 0x%x", pathname, dirfd, mode);
    filesystem fs;
    inode cwd;
    cwd = resolve_dir(fs, dirfd, pathname);

    sysreturn rv = sysreturn_from_fs_status(filesystem_mkdir(fs, cwd, pathname));
    filesystem_release(fs);
    return rv;
}

sysreturn creat(const char *pathname, int mode)
{
    thread_log(current, "creat: \"%s\", mode 0x%x", pathname, mode);
    filesystem cwd_fs;
    inode cwd;
    process_get_cwd(current->p, &cwd_fs, &cwd);
    sysreturn rv = open_internal(cwd_fs, cwd, pathname,
        O_CREAT|O_WRONLY|O_TRUNC, mode);
    filesystem_release(cwd_fs);
    return rv;
}

sysreturn getrandom(void *buf, u64 buflen, unsigned int flags)
{
    buffer b;

    if (!buflen)
        return set_syscall_error(current, EINVAL);

    if (!validate_user_memory(buf, buflen, true))
        return set_syscall_error(current, EFAULT);

    if (flags & ~(GRND_NONBLOCK | GRND_RANDOM))
        return set_syscall_error(current, EINVAL);

    b = alloca_wrap_buffer(buf, buflen);
    return random_buffer(b);
}

static int try_write_dirent(void *dirp, boolean dirent64, char *p,
        int *read_sofar, int *written_sofar, u64 *f_offset,
        unsigned int *count, tuple n)
{
    int len = runtime_strlen(p);
    *read_sofar += len;
    if (*read_sofar > *f_offset) {
        int reclen = (dirent64 ? sizeof(struct linux_dirent64) : sizeof(struct linux_dirent)) +
                     len + 3;
        // include this element in the getdents output
        if (reclen > *count) {
            // can't include, there's no space
            *read_sofar -= len;
            return -1;
        } else {
            // include the entry in the buffer
            runtime_memset((u8*)dirp, 0, reclen);
            if (dirent64) {
                struct linux_dirent64 *dp = dirp;
                dp->d_ino = u64_from_pointer(n);
                dp->d_reclen = reclen;
                runtime_memcpy(dp->d_name, p, len + 1);
                dp->d_off = dp->d_reclen;   // XXX: in the future, pad this.
                dp->d_name[len + 2] = 0;    /* some zero padding */
            } else {
                struct linux_dirent *dp = dirp;
                dp->d_ino = u64_from_pointer(n);
                dp->d_reclen = reclen;
                runtime_memcpy(dp->d_name, p, len + 1);
                dp->d_off = dp->d_reclen;   // XXX: in the future, pad this.
                dp->d_name[len + 2] = 0;    /* some zero padding */
            }
            ((char *)dirp)[reclen - 1] = dt_from_tuple(n);

            // advance dirp
            *written_sofar += reclen;
            *count -= reclen;
            return reclen;
        }
    }
    return 0;
}

closure_function(7, 2, boolean, getdents_each,
                 file, f, void **, dirp, boolean, dirent64, int *, read_sofar, int *, written_sofar, unsigned int *, count, int *, r,
                 value, k, value, v)
{
    assert(is_symbol(k));
    buffer tmpbuf = little_stack_buffer(NAME_MAX + 1);
    char *p = cstring(symbol_string(k), tmpbuf);
    *bound(r) = try_write_dirent(*bound(dirp), bound(dirent64), p,
                                 bound(read_sofar), bound(written_sofar), &bound(f)->offset, bound(count),
                                 v);
    if (*bound(r) < 0)
        return false;

    *bound(dirp) = *bound(dirp) + *bound(r);
    return true;
}

static sysreturn getdents_internal(int fd, void *dirp, unsigned int count, boolean dirent64)
{
    if (!validate_user_memory(dirp, count, true))
        return set_syscall_error(current, EFAULT);
    file f = resolve_fd(current->p, fd);
    tuple md = filesystem_get_meta(f->fs, f->n);
    tuple c;
    sysreturn rv;
    if (!md || !(c = children(md))) {
        rv = -ENOTDIR;
        goto out;
    }

    int r = 0;
    int read_sofar = 0, written_sofar = 0;
    binding_handler h = stack_closure(getdents_each, f, &dirp, dirent64,
                                      &read_sofar, &written_sofar, &count, &r);
    symbol parent_sym = sym_this("..");
    if (apply(h, sym_this("."), md) && apply(h, parent_sym, get_tuple(md, parent_sym)))
        iterate(c, h);
    fs_notify_event(md, IN_ACCESS);
    filesystem_update_atime(f->fs, md);
    f->offset = read_sofar;
    if (r < 0 && written_sofar == 0)
        rv = -EINVAL;
    else
        rv = written_sofar;
  out:
    if (md)
        filesystem_put_meta(f->fs, md);
    fdesc_put(&f->f);
    return rv;
}

sysreturn getdents(int fd, struct linux_dirent *dirp, unsigned int count)
{
    return getdents_internal(fd, dirp, count, false);
}

sysreturn getdents64(int fd, struct linux_dirent64 *dirp, unsigned int count)
{
    return getdents_internal(fd, dirp, count, true);
}

sysreturn chdir(const char *path)
{
    if (!validate_user_string(path))
        return set_syscall_error(current, EFAULT);
    return sysreturn_from_fs_status(filesystem_chdir(current->p, path));
}

sysreturn fchdir(int dirfd)
{
    process p = current->p;
    file f = resolve_fd(p, dirfd);
    tuple cwd = filesystem_get_meta(f->fs, f->n);
    sysreturn rv;
    if (!cwd || !is_dir(cwd)) {
        rv = -ENOTDIR;
        goto out;
    }

    process_lock(p);
    if (f->fs != p->cwd_fs) {
        filesystem_release(p->cwd_fs);
        filesystem_reserve(f->fs);
        p->cwd_fs = f->fs;
    }
    p->cwd = f->n;
    process_unlock(p);
    rv = 0;
  out:
    if (cwd)
        filesystem_put_meta(f->fs, cwd);
    fdesc_put(&f->f);
    return rv;
}

static sysreturn truncate_internal(filesystem fs, fsfile fsf, file f, long length)
{
    if (length < 0) {
        return set_syscall_error(current, EINVAL);
    }
    if (length == fsfile_get_length(fsf))
        return 0;
    fs_status s = filesystem_truncate(fs, fsf, length);
    if (s == FS_STATUS_OK) {
        truncate_file_maps(current->p, fsf, length);
        if (f)
            f->length = length;
    }
    return sysreturn_from_fs_status(s);
}

sysreturn truncate(const char *path, long length)
{
    if (!validate_user_string(path))
        return -EFAULT;
    thread_log(current, "%s \"%s\" %d", __func__, path, length);
    tuple t;
    filesystem fs;
    inode cwd;
    process_get_cwd(current->p, &fs, &cwd);
    filesystem cwd_fs = fs;
    fsfile fsf;
    fs_status fss = filesystem_get_node(&fs, cwd, path, false, false, false, &t, &fsf);
    sysreturn rv;
    if (fss != FS_STATUS_OK) {
        rv = sysreturn_from_fs_status(fss);
    } else {
        if (!(file_meta_perms(current->p, t) & ACCESS_PERM_WRITE)) {
            rv = -EACCES;
        } else if (is_dir(t)) {
            rv = -EISDIR;
        } else if (!fsf) {
            rv = -EINVAL;
        } else {
            fsfile_reserve(fsf);
            rv = 0;
        }
        filesystem_put_node(fs, t);
    }
    if (rv == 0) {
        rv = truncate_internal(fs, fsf, 0, length);
        fsfile_release(fsf);
    }
    filesystem_release(cwd_fs);
    return rv;
}

sysreturn ftruncate(int fd, long length)
{
    thread_log(current, "%s %d %d", __func__, fd, length);
    file f = resolve_fd(current->p, fd);
    sysreturn rv;
    if (!(f->f.flags & (O_RDWR | O_WRONLY)) ||
            (f->f.type != FDESC_TYPE_REGULAR)) {
        rv = -EINVAL;
    } else {
        rv = truncate_internal(f->fs, f->fsf, f, length);
    }
    fdesc_put(&f->f);
    return rv;
}

closure_function(2, 1, void, sync_complete,
                 thread, t, fdesc, f,
                 status, s)
{
    assert(is_syscall_context(get_current_context(current_cpu())));
    thread t = bound(t);
    thread_log(current, "%s: status %v", __func__, s);
    fdesc f = bound(f);
    if (f)
        fdesc_put(f);
    syscall_return(t, is_ok(s) ? 0 : -EIO);
    closure_finish();
}

sysreturn sync(void)
{
    // XXX only if syscall_context?
    status_handler sh = contextual_closure(sync_complete, current, 0);
    if (sh == INVALID_ADDRESS)
        return -ENOMEM;
    storage_sync(sh);
    return thread_maybe_sleep_uninterruptible(current);
}

sysreturn syncfs(int fd)
{
    /* Resolve to check validity of fd.
       When multiple volume support is added, we could grab the fs from the fsfile... */
    fdesc_put(resolve_fd(current->p, fd));
    return sync();
}

sysreturn fsync(int fd)
{
    fdesc f = resolve_fd(current->p, fd);
    sysreturn rv;
    switch (f->type) {
    case FDESC_TYPE_REGULAR:
        assert(((file)f)->fsf);
        filesystem_sync_node(((file)f)->fs,
                             fsfile_get_cachenode(((file)f)->fsf),
                             contextual_closure(sync_complete, current, f));
        return thread_maybe_sleep_uninterruptible(current);
    case FDESC_TYPE_DIRECTORY:
    case FDESC_TYPE_SYMLINK:
        rv = 0;
        break;
    default:
        rv = -EINVAL;
    }
    fdesc_put(f);
    return rv;
}

sysreturn fdatasync(int fd)
{
    return fsync(fd);
}

static sysreturn access_internal(filesystem fs, inode cwd, const char *pathname, int mode)
{
    tuple m = 0;
    fs_status fss = filesystem_get_node(&fs, cwd, pathname, false, false, false, &m, 0);
    if (fss != FS_STATUS_OK)
        return sysreturn_from_fs_status(fss);
    u32 perms = file_meta_perms(current->p, m);
    filesystem_put_node(fs, m);
    if (mode == F_OK)
        return 0;
    if (((mode & R_OK) && !(perms & ACCESS_PERM_READ)) ||
            ((mode & W_OK) && !(perms & ACCESS_PERM_WRITE)) ||
            ((mode & X_OK) && !(perms & ACCESS_PERM_EXEC)))
        return -EACCES;
    return 0;
}

sysreturn access(const char *pathname, int mode)
{
    thread_log(current, "access: \"%s\", mode %d", pathname, mode);
    if (!validate_user_string(pathname))
        return -EFAULT;
    filesystem cwd_fs;
    inode cwd;
    process_get_cwd(current->p, &cwd_fs, &cwd);
    sysreturn rv = access_internal(cwd_fs, cwd, pathname, mode);
    filesystem_release(cwd_fs);
    return rv;
}

sysreturn faccessat(int dirfd, const char *pathname, int mode)
{
    thread_log(current, "faccessat: dirfd %d, \"%s\", mode %d", dirfd, pathname, mode);
    if (!validate_user_string(pathname))
        return -EFAULT;
    filesystem fs;
    inode cwd = resolve_dir(fs, dirfd, pathname);
    sysreturn rv = access_internal(fs, cwd, pathname, mode);
    filesystem_release(fs);
    return rv;
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

    filesystem fs;
    inode cwd;
    cwd = resolve_dir(fs, dirfd, name);

    sysreturn rv = open_internal(fs, cwd, name, flags, mode);
    filesystem_release(fs);
    return rv;
}

static void fill_stat(int type, filesystem fs, fsfile f, tuple n, struct stat *s)
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
        if (f) {
            s->st_size = fsfile_get_length(f);
            s->st_blocks = fsfile_get_blocks(f);
        }
        s->st_blksize = PAGESIZE;   /* "preferred" block size for efficient filesystem I/O */
    }
    if (n) {
        struct timespec ts;
        timespec_from_time(&ts, filesystem_get_atime(fs, n));
        s->st_atime = ts.tv_sec;
        s->st_atime_nsec = ts.tv_nsec;
        timespec_from_time(&ts, filesystem_get_mtime(fs, n));
        s->st_mtime = ts.tv_sec;
        s->st_mtime_nsec = ts.tv_nsec;
    }
}

static sysreturn fstat(int fd, struct stat *s)
{
    thread_log(current, "fd %d, stat %p", fd, s);
    if (!validate_user_memory(s, sizeof(struct stat), true))
        return -EFAULT;
    fdesc f = resolve_fd(current->p, fd);
    filesystem fs;
    tuple n;
    fsfile fsf = 0;
    switch (f->type) {
    case FDESC_TYPE_REGULAR:
        fsf = ((file)f)->fsf;
        /* no break */
    case FDESC_TYPE_DIRECTORY:
    case FDESC_TYPE_SPECIAL:
    case FDESC_TYPE_SYMLINK:
        fs = ((file)f)->fs;
        n = filesystem_get_meta(fs, ((file)f)->n);
        break;
    default:
        fs = 0;
        n = 0;
        break;
    }
    fill_stat(f->type, fs, fsf, n, s);
    if (n)
        filesystem_put_meta(fs, n);
    thread_log(current, "st_ino %lx, st_mode 0x%x, st_size %lx", s->st_ino, s->st_mode, s->st_size);
    fdesc_put(f);
    return 0;
}

static sysreturn stat_internal(filesystem fs, inode cwd, const char *name, boolean follow,
        struct stat *buf)
{
    tuple n;
    fsfile fsf;

    if (!validate_user_string(name) ||
        !validate_user_memory(buf, sizeof(struct stat), true))
        return -EFAULT;

    fs_status fss = filesystem_get_node(&fs, cwd, name, !follow, false, false, &n, &fsf);
    if (fss != FS_STATUS_OK)
        return sysreturn_from_fs_status(fss);

    fill_stat(file_type_from_tuple(n), fs, fsf, n, buf);
    filesystem_put_node(fs, n);
    thread_log(current, "st_ino %lx, st_mode 0x%x, st_size %lx",
               buf->st_ino, buf->st_mode, buf->st_size);
    return 0;
}

#ifdef __x86_64__

static sysreturn stat_cwd(const char *name, boolean follow, struct stat *buf)
{
    filesystem cwd_fs;
    inode cwd;
    process_get_cwd(current->p, &cwd_fs, &cwd);
    sysreturn rv = stat_internal(cwd_fs, cwd, name, follow, buf);
    filesystem_release(cwd_fs);
    return rv;
}

static sysreturn stat(const char *name, struct stat *buf)
{
    thread_log(current, "stat: \"%s\", buf %p", name, buf);
    return stat_cwd(name, true, buf);
}

static sysreturn lstat(const char *name, struct stat *buf)
{
    thread_log(current, "lstat: \"%s\", buf %p", name, buf);
    return stat_cwd(name, false, buf);
}
#endif

static sysreturn newfstatat(int dfd, const char *name, struct stat *s, int flags)
{
    if (!validate_user_string(name) ||
        !validate_user_memory(s, sizeof(struct stat), true))
        return -EFAULT;

    // if relative, but AT_EMPTY_PATH set, works just like fstat()
    if (flags & AT_EMPTY_PATH)
        return fstat(dfd, s);

    // Else, if we have a fd of a directory, resolve name to it.
    filesystem fs;
    inode n = resolve_dir(fs, dfd, name);
    sysreturn rv = stat_internal(fs, n, name, !(flags & AT_SYMLINK_NOFOLLOW), s);
    filesystem_release(fs);
    return rv;
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
    sysreturn rv;

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
            new = -1;
    }

    if (new < 0)
        rv = -EINVAL;
    else
        rv = f->offset = new;
    fdesc_put(&f->f);
    return rv;
}


sysreturn uname(struct utsname *v)
{
    char sysname[] = "Nanos";
    char nodename[] = "nanovms"; // TODO: later we probably would want to get this from /etc/hostname
    char machine[] =
#ifdef __x86_64__
        "x86_64";
#endif
#ifdef __aarch64__
        "aarch64";
#endif

    if (!validate_user_memory(v, sizeof(struct utsname), true))
        return -EFAULT;

    runtime_memcpy(v->sysname, sysname, sizeof(sysname));
    runtime_memcpy(v->nodename, nodename, sizeof(nodename));
    runtime_memcpy(v->machine, machine, sizeof(machine));

    /* gitversion shouldn't exceed the field, but just in case... */
    bytes len = MIN(runtime_strlen(gitversion), sizeof(v->version) - 1);
    runtime_memcpy(v->version, gitversion, len);
    v->version[len] = '\0';     /* TODO: append build seq / time */

    /* The "5.0-" dummy prefix placates the glibc dynamic loader. */
    tuple env = get_environment();
    string release = aprintf(heap_locked(get_kernel_heaps()), "5.0-%v",
                             get_string(env, sym(NANOS_VERSION)));
    len = MIN(buffer_length(release), sizeof(v->release) - 1);
    runtime_memcpy(v->release, buffer_ref(release, 0), len);
    v->release[len] = '\0';
    deallocate_buffer(release);
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

    if (!validate_user_memory(rlim, sizeof(struct rlimit), true))
        return -EFAULT;

    switch (resource) {
    case RLIMIT_DATA:
        /* not entirely accurate, but a reasonable approximation */
        rlim->rlim_cur = rlim->rlim_max =
                heap_total(&heap_physical(get_kernel_heaps())->h);
        return 0;
    case RLIMIT_STACK:
        rlim->rlim_cur = 2*1024*1024;
        rlim->rlim_max = 2*1024*1024;
        return 0;
    case RLIMIT_CORE:
        rlim->rlim_cur = rlim->rlim_max = 0;    // core dump not supported
        return 0;
    case RLIMIT_NOFILE:
        // we .. .dont really have one?
        rlim->rlim_cur = 65536;
        rlim->rlim_max = 65536;
        return 0;
    case RLIMIT_AS:
        rlim->rlim_cur = rlim->rlim_max = heap_total(current->p->virtual);
        return 0;
    }

    return set_syscall_error(current, EINVAL);
}

sysreturn prlimit64(int pid, int resource, const struct rlimit *new_limit, struct rlimit *old_limit)
{
    thread_log(current, "prlimit64: pid %d, resource %d, new_limit %p, old_limit %p",
        pid, resource, new_limit, old_limit);

    if (old_limit) {
        if (!validate_user_memory(old_limit, sizeof(struct rlimit), true))
            return -EFAULT;
        sysreturn ret = getrlimit(resource, old_limit);
        if (ret < 0)
            return ret;
    }

    // setting new limits is not implemented
    return 0;
}

static sysreturn getrusage(int who, struct rusage *usage)
{
    thread_log(current, "%s: who %d", __func__, who);
    if (!validate_user_memory(usage, sizeof(*usage), true))
        return -EFAULT;
    zero(usage, sizeof(*usage));
    switch (who) {
        case RUSAGE_SELF:
            timeval_from_time(&usage->ru_utime, proc_utime(current->p));
            timeval_from_time(&usage->ru_stime, proc_stime(current->p));
            break;
        case RUSAGE_CHILDREN:
            /* There are no children. */
            break;
        case RUSAGE_THREAD:
            timeval_from_time(&usage->ru_utime, thread_utime(current));
            timeval_from_time(&usage->ru_stime, thread_stime(current));
            break;
        default:
            return -EINVAL;
    }
    return 0;
}

static sysreturn getcwd(char *buf, u64 length)
{
    if (!validate_user_memory(buf, length, true))
        return -EFAULT;
    process p = current->p;
    int cwd_len = file_get_path(p->cwd_fs, p->cwd, buf, length);

    if (cwd_len < 0)
        return set_syscall_error(current, ERANGE);

    return cwd_len;
}

static sysreturn brk(void *addr)
{
    process p = current->p;
    process_lock(p);

    /* on failure, return the current break */
    if (!addr || p->brk == addr)
        goto out;

    u64 old_end = pad(u64_from_pointer(p->brk), PAGESIZE);
    u64 new_end = pad(u64_from_pointer(addr), PAGESIZE);
    if (old_end > new_end) {
        if (u64_from_pointer(addr) < p->heap_base ||
            !adjust_process_heap(p, irange(p->heap_base, new_end)))
            goto out;
        write_barrier();
        unmap_and_free_phys(new_end, old_end - new_end);
    } else if (new_end > old_end) {
        u64 alloc = new_end - old_end;
        if (!validate_user_memory(pointer_from_u64(old_end), alloc, true) ||
            !adjust_process_heap(p, irange(p->heap_base, new_end)))
            goto out;
        pageflags flags = pageflags_writable(pageflags_noexec(pageflags_user(pageflags_memory())));
        if (new_zeroed_pages(old_end, alloc, flags, 0) == INVALID_PHYSICAL) {
            adjust_process_heap(p, irange(p->heap_base, old_end));
            goto out;
        }
    }
    p->brk = addr;
  out:
    addr = p->brk;
    process_unlock(p);
    return sysreturn_from_pointer(addr);
}

static sysreturn readlink_internal(filesystem fs, inode cwd, const char *pathname, char *buf,
        u64 bufsiz)
{
    if (!validate_user_string(pathname) || !validate_user_memory(buf, bufsiz, true)) {
        return set_syscall_error(current, EFAULT);
    }
    tuple n;
    fs_status fss = filesystem_get_node(&fs, cwd, pathname, true, false, false, &n, 0);
    if (fss != FS_STATUS_OK)
        return sysreturn_from_fs_status(fss);
    sysreturn rv;
    if (is_symlink(n)) {
        buffer target = linktarget(n);
        bytes len = buffer_length(target);
        if (bufsiz < len)
            len = bufsiz;
        runtime_memcpy(buf, buffer_ref(target, 0), len);
        rv = len;
    } else {
        rv = -EINVAL;
    }
    filesystem_put_node(fs, n);
    return rv;
}

sysreturn readlink(const char *pathname, char *buf, u64 bufsiz)
{
    thread_log(current, "readlink: \"%s\"", pathname);
    filesystem cwd_fs;
    inode cwd;
    process_get_cwd(current->p, &cwd_fs, &cwd);
    sysreturn rv = readlink_internal(cwd_fs, cwd, pathname, buf, bufsiz);
    filesystem_release(cwd_fs);
    return rv;
}

sysreturn readlinkat(int dirfd, const char *pathname, char *buf, u64 bufsiz)
{
    thread_log(current, "readlinkat: \"%s\", dirfd %d", pathname, dirfd);
    filesystem fs;
    inode cwd = resolve_dir(fs, dirfd, pathname);
    sysreturn rv = readlink_internal(fs, cwd, pathname, buf, bufsiz);
    filesystem_release(fs);
    return rv;
}

sysreturn unlink(const char *pathname)
{
    if (!validate_user_string(pathname))
        return -EFAULT;
    thread_log(current, "unlink %s", pathname);
    filesystem cwd_fs;
    inode cwd;
    process_get_cwd(current->p, &cwd_fs, &cwd);
    sysreturn rv = sysreturn_from_fs_status(filesystem_delete(cwd_fs, cwd, pathname, false));
    filesystem_release(cwd_fs);
    return rv;
}

sysreturn unlinkat(int dirfd, const char *pathname, int flags)
{
    if (!validate_user_string(pathname))
        return -EFAULT;
    thread_log(current, "unlinkat %d %s 0x%x", dirfd, pathname, flags);
    if (flags & ~AT_REMOVEDIR) {
        return set_syscall_error(current, EINVAL);
    }
    filesystem fs;
    inode cwd = resolve_dir(fs, dirfd, pathname);
    sysreturn rv;
    rv = sysreturn_from_fs_status(filesystem_delete(fs, cwd, pathname, !!(flags & AT_REMOVEDIR)));
    filesystem_release(fs);
    return rv;
}

sysreturn rmdir(const char *pathname)
{
    if (!validate_user_string(pathname))
        return -EFAULT;
    thread_log(current, "rmdir %s", pathname);
    filesystem cwd_fs;
    inode cwd;
    process_get_cwd(current->p, &cwd_fs, &cwd);
    sysreturn rv = sysreturn_from_fs_status(filesystem_delete(cwd_fs, cwd, pathname, true));
    filesystem_release(cwd_fs);
    return rv;
}

sysreturn rename(const char *oldpath, const char *newpath)
{
    if (!validate_user_string(oldpath) || !validate_user_string(newpath))
        return -EFAULT;
    thread_log(current, "rename \"%s\" \"%s\"", oldpath, newpath);
    filesystem cwd_fs;
    inode cwd;
    process_get_cwd(current->p, &cwd_fs, &cwd);
    sysreturn rv = sysreturn_from_fs_status(filesystem_rename(cwd_fs, cwd, oldpath,
        cwd_fs, cwd, newpath, false));
    filesystem_release(cwd_fs);
    return rv;
}

sysreturn renameat(int olddirfd, const char *oldpath, int newdirfd,
        const char *newpath)
{
    if (!validate_user_string(oldpath) || !validate_user_string(newpath))
        return -EFAULT;
    thread_log(current, "renameat %d \"%s\" %d \"%s\"", olddirfd, oldpath,
            newdirfd, newpath);
    filesystem oldfs, newfs;
    inode oldwd = resolve_dir(oldfs, olddirfd, oldpath);
    inode newwd = resolve_dir(newfs, newdirfd, newpath);
    sysreturn rv = sysreturn_from_fs_status(filesystem_rename(oldfs, oldwd, oldpath,
        newfs, newwd, newpath, false));
    filesystem_release(oldfs);
    filesystem_release(newfs);
    return rv;
}

sysreturn renameat2(int olddirfd, const char *oldpath, int newdirfd,
        const char *newpath, unsigned int flags)
{
    if (!validate_user_string(oldpath) || !validate_user_string(newpath))
        return -EFAULT;
    thread_log(current, "renameat2 %d \"%s\" %d \"%s\", flags 0x%x", olddirfd,
            oldpath, newdirfd, newpath, flags);
    if ((flags & ~(RENAME_EXCHANGE | RENAME_NOREPLACE)) ||
            ((flags & RENAME_EXCHANGE) && (flags & RENAME_NOREPLACE))) {
        return set_syscall_error(current, EINVAL);
    }
    filesystem oldfs, newfs;
    inode oldwd = resolve_dir(oldfs, olddirfd, oldpath);
    inode newwd = resolve_dir(newfs, newdirfd, newpath);
    fs_status fss;
    if (flags & RENAME_EXCHANGE) {
        fss = filesystem_exchange(oldfs, oldwd, oldpath, newfs, newwd, newpath);
    }
    else {
        fss = filesystem_rename(oldfs, oldwd, oldpath, newfs, newwd, newpath,
            !!(flags & RENAME_NOREPLACE));
    }
    filesystem_release(oldfs);
    filesystem_release(newfs);
    return sysreturn_from_fs_status(fss);
}

/* File paths are treated as absolute paths. */
sysreturn fs_rename(buffer oldpath, buffer newpath)
{
    filesystem fs = get_root_fs();
    inode root = inode_from_tuple(filesystem_getroot(fs));
    return sysreturn_from_fs_status(filesystem_rename(fs, root, buffer_to_cstring(oldpath),
        fs, root, buffer_to_cstring(newpath), false));
}

sysreturn close(int fd)
{
    thread_log(current, "close: fd %d", fd);
    fdesc f = resolve_fd(current->p, fd);
    deallocate_fd(current->p, fd);

    if (fetch_and_add(&f->refcnt, -2) == 2) {
        if (f->close)
            return apply(f->close, current, syscall_io_complete);
        msg_err("no close handler for fd %d\n", fd);
    }

    return 0;
}

sysreturn fcntl(int fd, int cmd, s64 arg)
{
    fdesc f = resolve_fd(current->p, fd);
    sysreturn rv = 0;

    thread_log(current, "fcntl: fd %d, cmd %d, arg %d", fd, cmd, arg);

    fdesc_lock(f);
    switch (cmd) {
    case F_GETFD:
        rv = f->flags & O_CLOEXEC;
        break;
    case F_SETFD:
        f->flags = (f->flags & ~O_CLOEXEC) | (arg & O_CLOEXEC);
        break;
    case F_GETFL:
        rv = f->flags & ~O_CLOEXEC;
        break;
    case F_SETFL:
        thread_log(current, "fcntl: fd %d, F_SETFL, %x", fd, arg);

        /* Ignore file access mode and file creation flags. */
        arg &= ~(O_ACCMODE | O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC);

        f->flags = (f->flags & O_ACCMODE) | (arg & ~O_CLOEXEC);
        break;
    case F_GETLK:
        if (arg) {
            if (!validate_user_memory(pointer_from_u64(arg), sizeof(struct flock), true))
                rv = -EFAULT;
            else
                ((struct flock *)arg)->l_type = F_UNLCK;
        }
        break;
    case F_SETLK:
    case F_SETLKW:
        break;
    case F_DUPFD:
    case F_DUPFD_CLOEXEC: {
        if (arg < 0) {
            rv = -EINVAL;
        }
        int newfd = allocate_fd_gte(current->p, arg, f);
        if (newfd == INVALID_PHYSICAL) {
            thread_log(current, "failed to allocate fd");
            rv = -EMFILE;
        } else {
            fdesc_unlock(f);
            return newfd;
        }
        break;
    }
    case F_SETPIPE_SZ:
        if (f->type == FDESC_TYPE_PIPE) {
            rv = pipe_set_capacity(f, (int)arg);
        } else {
            rv = -EINVAL;
        }
        break;
    case F_GETPIPE_SZ:
        if (f->type == FDESC_TYPE_PIPE) {
            rv = pipe_get_capacity(f);
        } else {
            rv = -EINVAL;
        }
        break;
    default:
        rv = -ENOSYS;
    }
    fdesc_unlock(f);
    fdesc_put(f);
    return rv;
}

sysreturn ioctl_generic(fdesc f, unsigned long request, vlist ap)
{
    switch (request) {
    case FIONBIO: {
        int *opt = varg(ap, int *);
        if (!validate_user_memory(opt, sizeof(int), false))
            return -EFAULT;
        fdesc_lock(f);
        if (*opt) {
            f->flags |= O_NONBLOCK;
        }
        else {
            f->flags &= ~O_NONBLOCK;
        }
        fdesc_unlock(f);
        return 0;
    }
    case FIONCLEX:
    case FIOCLEX:
        return 0;
    default:
        return -ENOSYS;
    }
}

sysreturn ioctl(int fd, unsigned long request, ...)
{
    thread_log(current, "ioctl: fd %d, request 0x%x", fd, request);

    // checks if fd is valid
    fdesc f = resolve_fd(current->p, fd);

    vlist args;
    sysreturn rv;
    vstart(args, request);
    if (f->ioctl)
        rv = apply(f->ioctl, request, args);
    else
        rv = ioctl_generic(f, request, args);
    vend(args);
    fdesc_put(f);
    return rv;
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
    syscall_finish(false);
}

sysreturn exit_group(int status)
{
    /* Set shutting_down to prevent user threads from being scheduled
     * and then try to interrupt the other cpus back into runloop
     * so they will idle while running kernel_shutdown */
    shutting_down = true;
    wakeup_or_interrupt_cpu_all();
    kernel_shutdown(status);
}

sysreturn pipe2(int fds[2], int flags)
{
    if (!validate_user_memory(fds, 2 * sizeof(int), true))
        return set_syscall_error(current, EFAULT);
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
        thread_reserve(t);
    } else {
        if ((t = thread_from_tid(current->p, pid)) == INVALID_ADDRESS)
            return 0;
    }
    return t;
}

sysreturn sched_setaffinity(int pid, u64 cpusetsize, u64 *mask)
{
    if (!validate_user_memory(mask, cpusetsize, false))
        return set_syscall_error(current, EFAULT);
    thread t;
    if (!(t = lookup_thread(pid)))
            return set_syscall_error(current, EINVAL);                
    u64 cpus = pad(MIN(total_processors, 64 * (cpusetsize / sizeof(u64))), 64);
    thread_lock(t);
    runtime_memcpy(bitmap_base(t->affinity), mask, cpus / 8);
    if (cpus < total_processors)
        bitmap_range_check_and_set(t->affinity, cpus, total_processors - cpus, false, false);
    thread_unlock(t);
    thread_release(t);
    return 0;
}

sysreturn sched_getaffinity(int pid, u64 cpusetsize, u64 *mask)
{
    if (!validate_user_memory(mask, cpusetsize, true))
        return set_syscall_error(current, EFAULT);
    thread t;
    if (!(t = lookup_thread(pid)) ||
        (64 * (cpusetsize / sizeof(u64)) < total_processors))
            return set_syscall_error(current, EINVAL);                    
    cpusetsize = pad(total_processors, 64) / 8;
    thread_lock(t);
    runtime_memcpy(mask, bitmap_base(t->affinity), cpusetsize);
    thread_unlock(t);
    thread_release(t);
    return cpusetsize;
}

sysreturn capget(cap_user_header_t hdrp, cap_user_data_t datap)
{
    if (datap) {
        if (!validate_user_memory(datap, sizeof(struct user_cap_data), true))
            return -EFAULT;
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
        if (!validate_user_string((void *)arg2))
            return -EFAULT;
        runtime_memcpy(current->name, (void *) arg2, sizeof(current->name));
        current->name[sizeof(current->name) - 1] = '\0';
        break;
    case PR_GET_NAME:
        if (!validate_user_memory((void *)arg2, sizeof(current->name), true))
            return -EFAULT;
        runtime_memcpy((void *) arg2, current->name, sizeof(current->name));
        break;
    }

    return 0;
}

sysreturn sysinfo(struct sysinfo *info)
{
    if (!validate_user_memory(info, sizeof(struct sysinfo), true))
        return set_syscall_error(current, EFAULT);

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

sysreturn getcpu(unsigned int *cpu, unsigned int *node, void *tcache)
{
    cpuinfo ci = current_cpu();
    if ((cpu != 0 && !validate_user_memory(cpu, sizeof *cpu, true)) ||
            (node != 0 && !validate_user_memory(node, sizeof *node, true)))
        return -EFAULT;
    if (cpu)
        *cpu = ci->id;
    /* XXX to do */
    if (node)
        *node = 0;
    return 0;
}

void register_file_syscalls(struct syscall *map)
{
    register_syscall(map, read, read);
    register_syscall(map, pread64, pread);
    register_syscall(map, write, write);
    register_syscall(map, pwrite64, pwrite);
#ifdef __x86_64__
    register_syscall(map, open, open);
    register_syscall(map, dup2, dup2);
    register_syscall(map, stat, stat);
    register_syscall(map, lstat, lstat);
    register_syscall(map, access, access);
    register_syscall(map, readlink, readlink);
    register_syscall(map, unlink, unlink);
    register_syscall(map, rmdir, rmdir);
    register_syscall(map, rename, rename);
    register_syscall(map, getdents, getdents);
    register_syscall(map, mkdir, mkdir);
    register_syscall(map, pipe, pipe);
    register_syscall(map, eventfd, eventfd);
    register_syscall(map, creat, creat);
    register_syscall(map, utime, utime);
    register_syscall(map, utimes, utimes);
    register_syscall(map, chown, syscall_ignore);
    register_syscall(map, symlink, symlink);
    register_syscall(map, inotify_init, inotify_init);
#endif
    register_syscall(map, inotify_init1, inotify_init1);
    register_syscall(map, inotify_add_watch, inotify_add_watch);
    register_syscall(map, inotify_rm_watch, inotify_rm_watch);
    register_syscall(map, openat, openat);
    register_syscall(map, dup, dup);
    register_syscall(map, dup3, dup3);
    register_syscall(map, fallocate, fallocate);
    register_syscall(map, faccessat, faccessat);
    register_syscall(map, fadvise64, fadvise64);
    register_syscall(map, fstat, fstat);
    register_syscall(map, newfstatat, newfstatat);
    register_syscall(map, readv, readv);
    register_syscall(map, writev, writev);
    register_syscall(map, sendfile, sendfile);
    register_syscall(map, truncate, truncate);
    register_syscall(map, ftruncate, ftruncate);
    register_syscall(map, fdatasync, fdatasync);
    register_syscall(map, fsync, fsync);
    register_syscall(map, sync, sync);
    register_syscall(map, syncfs, syncfs);
    register_syscall(map, io_setup, io_setup);
    register_syscall(map, io_submit, io_submit);
    register_syscall(map, io_getevents, io_getevents);
    register_syscall(map, io_destroy, io_destroy);
    register_syscall(map, lseek, lseek);
    register_syscall(map, fcntl, fcntl);
    register_syscall(map, ioctl, (sysreturn (*)())ioctl);
    register_syscall(map, getcwd, getcwd);
    register_syscall(map, symlinkat, symlinkat);
    register_syscall(map, readlinkat, readlinkat);
    register_syscall(map, unlinkat, unlinkat);
    register_syscall(map, renameat, renameat);
    register_syscall(map, renameat2, renameat2);
    register_syscall(map, close, close);
    register_syscall(map, sched_yield, sched_yield);
    register_syscall(map, brk, brk);
    register_syscall(map, uname, uname);
    register_syscall(map, getrlimit, getrlimit);
    register_syscall(map, setrlimit, setrlimit);
    register_syscall(map, prlimit64, prlimit64);
    register_syscall(map, getrusage, getrusage);
    register_syscall(map, getpid, getpid);
    register_syscall(map, exit_group, exit_group);
    register_syscall(map, exit, (sysreturn (*)())exit);
    register_syscall(map, getdents64, getdents64);
    register_syscall(map, mkdirat, mkdirat);
    register_syscall(map, getrandom, getrandom);
    register_syscall(map, pipe2, pipe2);
    register_syscall(map, socketpair, socketpair);
    register_syscall(map, eventfd2, eventfd2);
    register_syscall(map, chdir, chdir);
    register_syscall(map, fchdir, fchdir);
    register_syscall(map, sched_getaffinity, sched_getaffinity);
    register_syscall(map, sched_setaffinity, sched_setaffinity);
    register_syscall(map, getuid, syscall_ignore);
    register_syscall(map, geteuid, syscall_ignore);
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
    register_syscall(map, io_uring_setup, io_uring_setup);
    register_syscall(map, io_uring_enter, io_uring_enter);
    register_syscall(map, io_uring_register, io_uring_register);
    register_syscall(map, getcpu, getcpu);
}

#define SYSCALL_F_NOTRACE 0x1

struct syscall {
    void *handler;
    const char *name;
    int flags;
};

static struct syscall _linux_syscalls[SYS_MAX];
struct syscall * const linux_syscalls = _linux_syscalls;

void count_syscall(thread t, sysreturn rv)
{
    if (t->last_syscall == -1)
        return;
    syscall_stat ss = &stats[t->last_syscall];
    t->last_syscall = -1;
    fetch_and_add(&ss->calls, 1);
    if (rv < 0 && rv >= -255)
        fetch_and_add(&ss->errors, 1);
    u64 us;
    if (t->syscall_enter_ts)
        us = usec_from_timestamp(now(CLOCK_ID_MONOTONIC_RAW) - t->syscall_enter_ts) + t->syscall_time;
    else
        us = t->syscall_time;
    fetch_and_add(&ss->usecs, us);
    t->syscall_time = 0;
}

static boolean debugsyscalls;

define_closure_function(1, 0, void, free_syscall_context,
                        syscall_context, sc)
{
    /* TODO we can dealloc after some maximum... */
    list_insert_after(&current_cpu()->free_syscall_contexts, &bound(sc)->l);
}

define_closure_function(1, 0, void, syscall_context_pause,
                        syscall_context, sc)
{
    /* rprintf("%s, sc %p, from %p %d, cpu %d\n", __func__, bound(sc), */
    /*         __builtin_return_address(0), bound(sc)->t->tid, */
    /*         current_cpu()->id); */
    syscall_context sc = bound(sc);
    syscall_accumulate_stime(sc);
    count_syscall_save(sc->t);
}

define_closure_function(1, 0, void, syscall_context_resume,
                        syscall_context, sc)
{
    /* rprintf("%s, sc %p, from %p %d, cpu %d\n", __func__, bound(sc), */
    /*         __builtin_return_address(0), bound(sc)->t->tid, */
    /*         current_cpu()->id); */
    thread t = bound(sc)->t;
    syscall_context sc = bound(sc);
    assert(sc->start_time == 0); // XXX tmp debug
    timestamp here = now(CLOCK_ID_MONOTONIC_RAW);
    sc->start_time = here == 0 ? 1 : here;
    count_syscall_resume(t);
}

define_closure_function(1, 0, void, syscall_context_return,
                        syscall_context, sc)
{
    /* rprintf("%s: sc %p, cpu %d\n", __func__, bound(sc), current_cpu()->id); */
    context_frame f = bound(sc)->context.frame;
    assert(f[FRAME_FULL]);
    /* rprintf("sc resume frame return, sp 0x%lx\n", f[FRAME_RSP]); */
    /* print_frame(f); */
    /* print_stack(f); */
    context_switch(&bound(sc)->context);
    frame_return(f);
}

syscall_context allocate_syscall_context(void)
{
    heap h = heap_locked(get_kernel_heaps());
    syscall_context sc = allocate(h, sizeof(struct syscall_context));
    if (sc == INVALID_ADDRESS)
        return sc;
    context c = &sc->context;
    init_context(c, CONTEXT_TYPE_SYSCALL);
    sc->context.pause = init_closure(&sc->pause, syscall_context_pause, sc);
    sc->context.resume = apply_context_to_closure(init_closure(&sc->resume, syscall_context_resume, sc), &sc->context);
    init_closure(&sc->_return, syscall_context_return, sc);
    sc->context.transient_heap = h;
    init_refcount(&sc->refcount, 1, init_closure(&sc->free, free_syscall_context, sc));
    void *stack = allocate_stack(h, SYSCALL_STACK_SIZE);
    frame_set_stack_top(c->frame, stack);
    install_runloop_trampoline(c, runloop);
    return sc;
}

void syscall_handler(thread t)
{
    /* The syscall_context stored in ci was set as current on syscall entry in
       order to get a usable stack. We still need to finish initializing it
       and complete the context switch. */
    cpuinfo ci = current_cpu();
    ci->state = cpu_kernel;
    //rprintf("%s: type %d\n", __func__, t->context.type);
    assert(is_thread_context(&t->context));
    context_frame f = t->context.frame;
    u64 call = f[FRAME_VECTOR];
    u64 arg0 = f[SYSCALL_FRAME_ARG0]; /* aliases retval on arm; cache arg */
    syscall_restart_arch_setup(f);
    set_syscall_return(t, -ENOSYS);

    if (shutting_down)
        goto out;

    if (call >= sizeof(_linux_syscalls) / sizeof(_linux_syscalls[0])) {
        thread_log(t, "invalid syscall %d", call);
        goto out;
    }

    syscall_context sc = (syscall_context)get_current_context(ci);
    assert(is_syscall_context(&sc->context));
    sc->t = t;
    sc->context.fault_handler = t->context.fault_handler;
    sc->start_time = 0;
    sc->call = call;
    assert(sc->refcount.c == 1);
    t->syscall = sc;
    install_runloop_trampoline(&sc->context, runloop);
    context_pause(&t->context);
    context_resume(&sc->context);

    /* In the future, interrupt enable can go here. */
    if (do_syscall_stats) {
        assert(t->last_syscall == -1);
        t->last_syscall = call;
        t->syscall_enter_ts = now(CLOCK_ID_MONOTONIC_RAW);
    }
    struct syscall *s = t->p->syscalls + call;
    if (debugsyscalls) {
        if (s->name)
            thread_log(t, s->name);
        else
            thread_log(t, "syscall %d", call);
    }

    sysreturn (*h)(u64, u64, u64, u64, u64, u64) = s->handler;
    if (h) {
        t->syscall_complete = false;
        reserve_syscall_context(sc);
        sysreturn rv = h(arg0, f[SYSCALL_FRAME_ARG1], f[SYSCALL_FRAME_ARG2],
                         f[SYSCALL_FRAME_ARG3], f[SYSCALL_FRAME_ARG4], f[SYSCALL_FRAME_ARG5]);
        assert(sc->refcount.c > 1); // XXX tmp
        release_syscall_context(sc);
        set_syscall_return(t, rv);
        if (do_syscall_stats)
            count_syscall(t, rv);
        if (debugsyscalls)
            thread_log(t, "direct return: %ld, rsp 0x%lx", rv, f[SYSCALL_FRAME_SP]);
    } else if (debugsyscalls) {
        if (s->name)
            thread_log(t, "nosyscall %s", s->name);
        else
            thread_log(t, "nosyscall %d", call);
    }
    if (do_syscall_stats)
        count_syscall(t, 0);
  out:
    t->syscall = 0;
    schedule_thread(t);
    kern_yield();
}

boolean syscall_notrace(process p, int syscall)
{
    if (syscall < 0 || syscall >= sizeof(_linux_syscalls) / sizeof(_linux_syscalls[0]))
        return false;
    struct syscall *s = p->syscalls + syscall;
    return (s->flags & SYSCALL_F_NOTRACE) != 0;
}

// should hang off the thread context, but the assembly handler needs
// to find it.
BSS_RO_AFTER_INIT void (*syscall)(thread t);

closure_function(0, 2, void, syscall_io_complete_cfn,
                 thread, t, sysreturn, rv)
{
    syscall_return(t, rv);
}

closure_function(0, 2, void, io_complete_ignore,
                 thread, t, sysreturn, rv)
{
}

static boolean stat_compare(void *za, void *zb)
{
    syscall_stat sa = za;
    syscall_stat sb = zb;
    return sb->usecs > sa->usecs;
}

static inline char *print_usecs(buffer b, u64 x)
{
    buffer_clear(b);
    bprintf(b, "%d.%06d", x / MILLION, x % MILLION);
    buffer_write_byte(b, 0);
    return buffer_ref(b, 0);
}

static inline char *print_pct(buffer b, u64 x, u64 y)
{
    buffer_clear(b);
    x *= 100;
    bprintf(b, "%d.%02d", x / y, (x * 100 / y) % 100);
    buffer_write_byte(b, 0);
    return buffer_ref(b, 0);
}

#define LINE "------"
#define LINE2 LINE LINE
#define LINE3 LINE LINE LINE
#define SEPARATOR LINE " " LINE2 " " LINE2 " " LINE2 " " LINE2 " " LINE3 "\n"
#define HDR_FMT "%6s %12s %12s %12s %12s %-18s\n"
#define DATA_FMT "%6s %12s %12d %12d %12.0d %-18s\n"
#define SUM_FMT "%6s %12s %12.0d %12d %12.0d %-18s\n"

#define ROUNDED_IDIV(x, y) (((x)* 10 / (y) + 5) / 10)

closure_function(0, 2, void, print_syscall_stats_cfn,
                 int, status, merge, m)
{
    u64 tot_usecs = 0;
    u64 tot_calls = 0;
    u64 tot_errs = 0;
    buffer tbuf = little_stack_buffer(24);
    buffer pbuf = little_stack_buffer(24);
    pqueue pq = allocate_pqueue(heap_locked(get_kernel_heaps()), stat_compare);
    syscall_stat ss;

    if (status != 0)
        return;
    rprintf("\n" HDR_FMT SEPARATOR, "% time", "seconds", "usecs/call", "calls", "errors", "syscall");
    for (int i = 0; i < SYS_MAX; i++) {
        ss = &stats[i];
        if (ss->calls == 0)
            continue;
        tot_usecs += ss->usecs;
        pqueue_insert(pq, ss);
    }
    while ((ss = pqueue_pop(pq)) != INVALID_ADDRESS) {
        tot_calls += ss->calls;
        tot_errs += ss->errors;
        rprintf(DATA_FMT, print_pct(pbuf, ss->usecs, tot_usecs), print_usecs(tbuf, ss->usecs),
            ROUNDED_IDIV(ss->usecs, ss->calls), ss->calls, ss->errors, _linux_syscalls[ss - stats].name);
    }
    rprintf(SEPARATOR SUM_FMT, "100.00", print_usecs(tbuf, tot_usecs), 0, tot_calls, tot_errs, "total");
    deallocate_pqueue(pq);
}

static boolean syscall_defer;

static char *missing_files_exclude[] = {
    "ld.so.cache",
};

closure_function(0, 2, void, print_missing_files_cfn,
                 int, status, merge, m)
{
    buffer b;
    rprintf("missing_files_begin\n");
    vector_foreach(missing_files, b) {
        for (int i = 0; i < sizeof(missing_files_exclude)/sizeof(missing_files_exclude[0]); i++) {
            if (buffer_compare_with_cstring(b, missing_files_exclude[i]))
                goto next;
        }
        rprintf("%v\n", b);
next:
        continue;
    }
    rprintf("missing_files_end\n");
}

void init_syscalls(tuple root)
{
    heap h = heap_locked(get_kernel_heaps());
    syscall = syscall_handler;
    syscall_io_complete = closure(h, syscall_io_complete_cfn);
    io_completion_ignore = closure(h, io_complete_ignore);
    do_syscall_stats = get(root, sym(syscall_summary)) != 0;
    if (do_syscall_stats) {
        print_syscall_stats = closure(h, print_syscall_stats_cfn);
        add_shutdown_completion(print_syscall_stats);
    }
    do_missing_files = get(root, sym(missing_files)) != 0;
    if (do_missing_files) {
        missing_files = allocate_vector(h, 8);
        assert(missing_files != INVALID_ADDRESS);
        print_missing_files = closure(h, print_missing_files_cfn);
        add_shutdown_completion(print_missing_files);
    }
}

void _register_syscall(struct syscall *m, int n, sysreturn (*f)(), const char *name)
{
    assert(m[n].handler == 0);
    m[n].handler = f;
    m[n].name = name;
}

static void notrace_reset(process p)
{
    for (int i = 0; i < sizeof(_linux_syscalls) / sizeof(_linux_syscalls[0]); i++) {
        struct syscall *s = p->syscalls + i;
        s->flags &= ~SYSCALL_F_NOTRACE;
    }
}

closure_function(1, 2, boolean, notrace_each,
                 process, p,
                 value, k, value, v)
{
    for (int i = 0; i < sizeof(_linux_syscalls) / sizeof(_linux_syscalls[0]); i++) {
        struct syscall *s = bound(p)->syscalls + i;
        if (!s->name)
            continue;

        buffer name = alloca_wrap_buffer(s->name, runtime_strlen(s->name));
        if (!buffer_compare(name, v))
            continue;

        s->flags |= SYSCALL_F_NOTRACE;
        break;
    }
    return true;
}

closure_function(0, 1, boolean, debugsyscalls_notify,
                 value, v)
{
    debugsyscalls = !!v;
    return true;
}

closure_function(0, 1, boolean, syscall_defer_notify,
                 value, v)
{
    syscall_defer = !!v;
    return true;
}

closure_function(1, 1, boolean, notrace_notify,
                 process, p,
                 value, v)
{
    notrace_reset(bound(p));
    if (is_tuple(v))
        iterate(v, stack_closure(notrace_each, bound(p)));
    return true;
}

void configure_syscalls(process p)
{
    heap h = heap_locked(&p->uh->kh);
    register_root_notify(sym(debugsyscalls), closure(h, debugsyscalls_notify));
    register_root_notify(sym(syscall_defer), closure(h, syscall_defer_notify));
    register_root_notify(sym(notrace), closure(h, notrace_notify, p));
}
