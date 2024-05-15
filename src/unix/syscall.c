#include <unix_internal.h>
#include <filesystem.h>
#include <lwip.h>
#include <storage.h>

typedef struct syscall_stat {
    u64 calls;
    u64 errors;
    u64 usecs;
} *syscall_stat;

static buffer hostname;

static struct syscall_stat stats[SYS_MAX];
BSS_RO_AFTER_INIT boolean do_syscall_stats;
BSS_RO_AFTER_INIT static boolean do_missing_files;
BSS_RO_AFTER_INIT static vector missing_files;

sysreturn close(int fd);

BSS_RO_AFTER_INIT io_completion syscall_io_complete;
BSS_RO_AFTER_INIT io_completion io_completion_ignore;

boolean validate_iovec(struct iovec *iov, u64 len, boolean write)
{
    if (!validate_user_memory(iov, sizeof(struct iovec) * len, false))
        return false;
    context ctx = get_current_context(current_cpu());
    if (context_set_err(ctx))
        return false;
    for (u64 i = 0; i < len; i++) {
        if ((iov[i].iov_len != 0) &&
                !validate_user_memory(iov[i].iov_base, iov[i].iov_len, write))
            return false;
    }
    context_clear_err(ctx);
    return true;
}

struct iov_progress {
    heap h;
    fdesc f;
    boolean write;
    struct iovec *iov;
    int iovcnt;
    boolean initialized;
    boolean blocking;
    u64 file_offset;
    int curr;
    u64 curr_offset;
    u64 total_len;
    context ctx;
    io_completion completion;
    closure_struct(io_completion, each_complete);
    closure_struct(thunk, bh);
};

static void iov_op_each(struct iov_progress *p)
{
    struct iovec *iov = p->iov;
    file_io op = p->write ? p->f->write : p->f->read;
    boolean blocking = p->blocking;
    p->blocking = false;

    /* Issue the next request. */
    thread_log(current, "   op: curr %d, offset %ld, @ %p, len %ld, blocking %d",
               p->curr, p->curr_offset, iov[p->curr].iov_base + p->curr_offset,
               iov[p->curr].iov_len - p->curr_offset, blocking);
    apply(op, iov[p->curr].iov_base + p->curr_offset,
          iov[p->curr].iov_len - p->curr_offset, p->file_offset, p->ctx, !blocking,
          (io_completion)&p->each_complete);
}

closure_func_basic(io_completion, void, iov_op_each_complete,
                   sysreturn rv)
{
    io_completion c;
    struct iov_progress *p = struct_from_closure(struct iov_progress *, each_complete);
    int iovcnt = p->iovcnt;
    fdesc f = p->f;
    boolean write = p->write;
    thread t = current;
    thread_log(t, "%s: rv %ld, curr %d, iovcnt %d", func_ss, rv, p->curr, iovcnt);

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
        iov_op_each(p);
    } else {
        if (p->file_offset != infinity)
            p->file_offset += rv;
        async_apply((thunk)&p->bh);
    }
    return;
  out_complete:
    c = p->completion;
    deallocate(p->h, p, sizeof(*p));
    apply(c, rv);
}

closure_func_basic(thunk, void, iov_bh)
{
    iov_op_each(struct_from_field(closure_self(), struct iov_progress *, bh));
}

closure_function(4, 1, void, iov_read_complete,
                 sg_list, sg, struct iovec *, iov, int, iovcnt, io_completion, completion,
                 sysreturn rv)
{
    sg_list sg = bound(sg);
    io_completion completion = bound(completion);
    thread_log(current, "%s: sg %p, completion %F, rv %ld", func_ss, sg, completion,
               rv);
    if (rv > 0) {
        if (!sg_to_iov(sg, bound(iov), bound(iovcnt)))
            rv = -EFAULT;
    }
    deallocate_sg_list(sg);
    apply(completion, rv);
    closure_finish();
}

closure_function(2, 1, void, iov_write_complete,
                 sg_list, sg, io_completion, completion,
                 sysreturn rv)
{
    sg_list sg = bound(sg);
    io_completion completion = bound(completion);
    thread_log(current, "%s: sg %p, completion %F, rv %ld", func_ss, sg, completion,
               rv);
    sg_list_release(sg);
    deallocate_sg_list(sg);
    apply(completion, rv);
    closure_finish();
}

void iov_op(fdesc f, boolean write, struct iovec *iov, int iovcnt, u64 offset,
            context ctx, boolean blocking, io_completion completion)
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
                offset, ctx, !blocking, iov_complete);
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
    p->iovcnt = iovcnt;
    p->initialized = false;
    p->blocking = blocking;
    p->file_offset = offset;
    p->curr = 0;
    p->curr_offset = 0;
    p->total_len = 0;
    p->ctx = ctx;
    p->completion = completion;
    init_closure_func(&p->bh, thunk, iov_bh);
    closure_set_context(&p->bh, ctx);
    init_closure_func(&p->each_complete, io_completion, iov_op_each_complete);
    io_completion each = (io_completion)&p->each_complete;
    apply(each, 0);
    return;
out:
    apply(completion, rv);
}

static sysreturn iov_internal(int fd, boolean write, struct iovec *iov, int iovcnt, u64 offset)
{
    if (!validate_iovec(iov, iovcnt, !write))
        return -EFAULT;
    fdesc f = resolve_fd(current->p, fd);
    context ctx = get_current_context(current_cpu());
    iov_op(f, write, iov, iovcnt, offset, ctx, true, (io_completion)&f->io_complete);
    return thread_maybe_sleep_uninterruptible(current);
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
    context ctx = get_current_context(current_cpu());
    return apply(f->read, dest, length, infinity, ctx, false, (io_completion)&f->io_complete);

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
    context ctx = get_current_context(current_cpu());
    return apply(f->read, dest, length, offset, ctx, false, (io_completion)&f->io_complete);

  out:
    fdesc_put(f);
    return rv;
}

sysreturn readv(int fd, struct iovec *iov, int iovcnt)
{
    return iov_internal(fd, false, iov, iovcnt, infinity);
}

sysreturn preadv(int fd, struct iovec *iov, int iovcnt, s64 offset)
{
    if (offset < 0)
        return -EINVAL;
    return iov_internal(fd, false, iov, iovcnt, offset);
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
    context ctx = get_current_context(current_cpu());
    return apply(f->write, body, length, infinity, ctx, false, (io_completion)&f->io_complete);

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

    context ctx = get_current_context(current_cpu());
    return apply(f->write, body, length, offset, ctx, false, (io_completion)&f->io_complete);
  out:
    fdesc_put(f);
    return rv;
}

sysreturn writev(int fd, struct iovec *iov, int iovcnt)
{
    return iov_internal(fd, true, iov, iovcnt, infinity);
}

sysreturn pwritev(int fd, struct iovec *iov, int iovcnt, s64 offset)
{
    if (offset < 0)
        return -EINVAL;
    return iov_internal(fd, true, iov, iovcnt, offset);
}

closure_function(9, 1, void, sendfile_bh,
                 fdesc, in, fdesc, out, long *, offset, sg_list, sg, sg_buf, cur_buf, bytes, count, bytes, readlen, bytes, written, boolean, bh,
                 sysreturn rv)
{
    thread t = current;
    thread_log(t, "%s: readlen %ld, written %ld, bh %d, rv %ld",
               func_ss, bound(readlen), bound(written), bound(bh), rv);

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
        if (bound(offset)) {
            context ctx = get_current_context(current_cpu());
            if (!context_set_err(ctx)) {
                *bound(offset) += rv;
                context_clear_err(ctx);
            } else {
                rv = -EFAULT;
                goto out_complete;
            }
        }
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
    u32 n = sg_buf_len(bound(cur_buf));
    thread_log(t, "   writing %d bytes from %p", n, buf);
    context ctx = get_current_context(current_cpu());
    apply(bound(out)->write, buf, n, infinity, ctx, true, (io_completion)closure_self());
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
static sysreturn sendfile(int out_fd, int in_fd, long *offset, bytes count)
{
    thread_log(current, "%s: out %d, in %d, offset %p, *offset %d, count %ld",
               func_ss, out_fd, in_fd, offset, offset ? *offset : 0, count);
    u64 read_offset;
    if (offset) {
        if (!get_user_value(offset, &read_offset))
            return -EFAULT;
        if ((s64)read_offset < 0)
            return -EINVAL;
    } else {
        read_offset = infinity;
    }
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
    context ctx = get_current_context(current_cpu());
    apply(infile->sg_read, sg, n, read_offset, ctx, false, read_complete);
    return get_syscall_return(current);
  out:
    fdesc_put(infile);
    fdesc_put(outfile);
    return rv;
}

static boolean check_file_read(file f, u64 offset, sysreturn *rv)
{
    if (fdesc_type(&f->f) == FDESC_TYPE_DIRECTORY)
        *rv = -EISDIR;
    else if (!f->fsf)
        *rv = -EBADF;
    else
        return true;
    return false;
}

static void begin_file_read(file f, u64 length)
{
    if (length == 0)
        return;
    tuple md = filesystem_get_meta(f->fs, f->n);
    if (md) {
        if (!(f->f.flags & O_NOATIME))
            filesystem_update_relatime(f->fs, md);
        fs_notify_event(md, IN_ACCESS);
        filesystem_put_meta(f->fs, md);
    }
}

closure_function(6, 1, void, file_read_complete,
                 sg_list, sg, void *, dest, u64, limit, file, f, boolean, is_file_offset, io_completion, completion,
                 status s)
{
    thread t = current;
    thread_log(t, "%s: status %v", func_ss, s);
    sysreturn rv;
    sg_list sg = bound(sg);
    context ctx = get_current_context(current_cpu());
    if (context_set_err(ctx)) {
        /* sg_copy_to_buf_and_release() was aborted during a runtime_memcpy(), and the SG buffer
         * being copied when the fault happened has been removed from the SG list but not released:
         * release it here. */
        sg_buf_release(sg_list_peek_at(sg, -1));

        s = timm("result", "invalid user memory");
        s = timm_append(s, "fsstatus", "%d", FS_STATUS_FAULT);
    }
    if (is_ok(s)) {
        file f = bound(f);
        u64 count = sg_copy_to_buf_and_release(bound(dest), sg, bound(limit));
        thread_log(t, "   read count %ld", count);
        if (bound(is_file_offset)) /* vs specified offset (pread) */
            f->offset += count;
        rv = count;
    } else {
        sg_list_release(sg);
        deallocate_sg_list(sg);
        rv = sysreturn_from_fs_status_value(s);
        timm_dealloc(s);
    }
    if (rv != -EFAULT)
        context_clear_err(ctx);
    apply(bound(completion), rv);
    closure_finish();
}

closure_func_basic(file_io, sysreturn, file_read,
                   void *dest, u64 length, u64 offset_arg, context ctx, boolean bh, io_completion completion)
{
    file f = struct_from_field(closure_self(), file, read);
    boolean is_file_offset = offset_arg == infinity;
    u64 offset = is_file_offset ? f->offset : offset_arg;
    thread t = current;
    thread_log(t, "%s: f %p, dest %p, offset %ld (%s), length %ld, file length %ld",
               func_ss, f, dest, offset, is_file_offset ? ss("file") : ss("specified"),
               length, f->fsf ? fsfile_get_length(f->fsf) : 0);

    sysreturn rv;
    if (!check_file_read(f, offset, &rv))
        return io_complete(completion, rv);
    sg_list sg = allocate_sg_list();
    if (sg == INVALID_ADDRESS) {
        thread_log(t, "   unable to allocate sg list");
        return io_complete(completion, -ENOMEM);
    }
    status_handler sh = closure_from_context(ctx, file_read_complete, sg, dest, length, f,
                                             is_file_offset, completion);
    if (sh == INVALID_ADDRESS) {
        deallocate_sg_list(sg);
        return io_complete(completion, -ENOMEM);
    }
    begin_file_read(f, length);
    apply(f->fs_read, sg, irangel(offset, length), sh);
    file_readahead(f, offset, length);
    /* possible direct return in top half */
    return bh ? SYSRETURN_CONTINUE_BLOCKING : thread_maybe_sleep_uninterruptible(t);
}

closure_function(4, 1, void, file_sg_read_complete,
                 file, f, sg_list, sg, boolean, is_file_offset, io_completion, completion,
                 status s)
{
    thread_log(current, "%s: status %v", func_ss, s);
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
    apply(bound(completion), rv);
    closure_finish();
}

closure_func_basic(sg_file_io, sysreturn, file_sg_read,
                   sg_list sg, u64 length, u64 offset_arg, context ctx, boolean bh, io_completion completion)
{
    file f = struct_from_field(closure_self(), file, sg_read);

    boolean is_file_offset = offset_arg == infinity;
    u64 offset = is_file_offset ? f->offset : offset_arg;
    thread t = current;
    thread_log(t, "%s: f %p, sg %p, offset %ld (%s), length %ld, file length %ld",
               func_ss, f, sg, offset, is_file_offset ? ss("file") : ss("specified"),
               length, f->fsf ? fsfile_get_length(f->fsf) : 0);

    sysreturn rv;
    if (!check_file_read(f, offset, &rv))
        return io_complete(completion, rv);
    begin_file_read(f, length);
    apply(f->fs_read, sg, irangel(offset, length),
          closure_from_context(ctx, file_sg_read_complete, f, sg, is_file_offset, completion));
    file_readahead(f, offset, length);

    /* possible direct return in top half */
    return bh ? SYSRETURN_CONTINUE_BLOCKING : thread_maybe_sleep_uninterruptible(t);
}

static sysreturn file_write_check(file f, u64 offset, u64 len)
{
    fsfile fsf = f->fsf;
    if (!fsf)
        return -EBADF;
    if (len == 0)
        return 0;
    filesystem fs = f->fs;
    if (fs->get_seals) {
        u64 seals;
        if (fs->get_seals(fs, fsf, &seals) == FS_STATUS_OK) {
            if ((seals & (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE)) ||
                ((seals & F_SEAL_GROW) && (offset + len > fsfile_get_length(fsf))))
                return -EPERM;
        }
    }
    return 0;
}

static void begin_file_write(file f, u64 len)
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

static void file_write_complete_internal(file f, u64 len,
                                         boolean is_file_offset,
                                         io_completion completion, status s)
{
    sysreturn rv;
    if (is_ok(s)) {
        if (is_file_offset)
            f->offset += len;
        rv = len;
    } else {
        rv = sysreturn_from_fs_status_value(s);
        timm_dealloc(s);
    }
    apply(completion, rv);
}

closure_function(6, 1, void, file_write_complete,
                 file, f, sg_list, sg, u64, length, boolean, is_file_offset, io_completion, completion, boolean, flush,
                 status s)
{
    if (!bound(flush)) {
        thread_log(current, "%s: f %p, sg, %p, completion %F, status %v",
                   func_ss, bound(f), bound(sg), bound(completion), s);
        sg_list_release(bound(sg));
        deallocate_sg_list(bound(sg));
        file f = bound(f);
        if (f->f.flags & O_DSYNC) {
            bound(flush) = true;
            fsfile_flush(f->fsf, !(f->f.flags & _O_SYNC), (status_handler)closure_self());
            return;
        }
    }
    file_write_complete_internal(bound(f), bound(length),
                                 bound(is_file_offset), bound(completion), s);
    closure_finish();
}

closure_func_basic(file_io, sysreturn, file_write,
                   void *src, u64 length, u64 offset_arg, context ctx, boolean bh, io_completion completion)
{
    file f = struct_from_field(closure_self(), file, write);
    boolean is_file_offset = offset_arg == infinity;
    u64 offset = is_file_offset ? f->offset : offset_arg;
    thread t = current;
    thread_log(t, "%s: f %p, src %p, offset %ld (%s), length %ld, file length %ld",
               func_ss, f, src, offset, is_file_offset ? ss("file") : ss("specified"),
               length, f->fsf ? fsfile_get_length(f->fsf) : 0);

    sysreturn rv = file_write_check(f, offset, length);
    if (rv < 0)
        return io_complete(completion, rv);
    sg_list sg = allocate_sg_list();
    if (sg == INVALID_ADDRESS) {
        thread_log(t, "   unable to allocate sg list");
        return io_complete(completion, -ENOMEM);
    }
    sg_buf sgb = sg_list_tail_add(sg, length);
    if (sgb == INVALID_ADDRESS) {
        thread_log(t, "   unable to allocate sg buf");
        goto no_mem;
    }
    sgb->buf = src;
    sgb->size = length;
    sgb->offset = 0;
    sgb->refcount = 0;

    status_handler sh = closure_from_context(ctx, file_write_complete, f, sg, length,
                                             is_file_offset, completion, false);
    if (sh == INVALID_ADDRESS)
        goto no_mem;
    begin_file_write(f, length);
    apply(f->fs_write, sg, irangel(offset, length), sh);
    /* possible direct return in top half */
    return bh ? SYSRETURN_CONTINUE_BLOCKING : thread_maybe_sleep_uninterruptible(t);
  no_mem:
    deallocate_sg_list(sg);
    return io_complete(completion, -ENOMEM);
}

closure_function(5, 1, void, file_sg_write_complete,
                 file, f, u64, len, boolean, is_file_offset, io_completion, completion, boolean, flush,
                 status s)
{
    file f = bound(f);
    if (!bound(flush) && (f->f.flags & O_DSYNC)) {
        bound(flush) = true;
        fsfile_flush(f->fsf, !(f->f.flags & _O_SYNC), (status_handler)closure_self());
        return;
    }
    u64 len = bound(len);
    io_completion completion = bound(completion);
    thread_log(current, "%s: f %p, len %ld, completion %F, status %v",
               func_ss, f, len, completion, s);
    file_write_complete_internal(f, len, bound(is_file_offset), completion,
                                 s);
    closure_finish();
}

closure_func_basic(sg_file_io, sysreturn, file_sg_write,
                   sg_list sg, u64 len, u64 offset_arg, context ctx, boolean bh, io_completion completion)
{
    file f = struct_from_field(closure_self(), file, sg_write);
    sysreturn rv;

    boolean is_file_offset = offset_arg == infinity;
    u64 offset = is_file_offset ? f->offset : offset_arg;
    thread t = current;
    thread_log(t, "%s: f %p, sg %p, offset %ld (%s), len %ld, file length %ld",
               func_ss, f, sg, offset, is_file_offset ? ss("file") : ss("specified"),
               len, f->fsf ? fsfile_get_length(f->fsf) : 0);
    rv = file_write_check(f, offset, len);
    if (rv < 0)
        goto out;
    status_handler sg_complete = closure_from_context(ctx, file_sg_write_complete, f, len,
                                                      is_file_offset, completion, false);
    if (sg_complete == INVALID_ADDRESS) {
        rv = -ENOMEM;
        goto out;
    }
    begin_file_write(f, len);
    apply(f->fs_write, sg, irangel(offset, len), sg_complete);
    return bh ? SYSRETURN_CONTINUE_BLOCKING : thread_maybe_sleep_uninterruptible(t);
  out:
    return io_complete(completion, rv);
}

closure_func_basic(fdesc_close, sysreturn, file_close,
                   context ctx, io_completion completion)
{
    file f = struct_from_field(closure_self(), file, close);
    tuple md = filesystem_get_meta(f->fs, f->n);
    if (md) {
        fs_notify_event(md, ((f->f.flags & O_ACCMODE) == O_RDONLY) ?
                        IN_CLOSE_NOWRITE : IN_CLOSE_WRITE);
        filesystem_put_meta(f->fs, md);
    }
    fsfile fsf = f->fsf;
    if (fsf)
        fsfile_release(fsf);
    file_release(f);
    return io_complete(completion, 0);
}

closure_func_basic(fdesc_events, u32, file_events,
                   thread t /* ignore */)
{
    file f = struct_from_field(closure_self(), file, events);
    u32 events;
    switch (fdesc_type(&f->f)) {
    case FDESC_TYPE_REGULAR:
    case FDESC_TYPE_DIRECTORY:
        events = EPOLLIN | EPOLLOUT;
        break;
    default:
        events = EPOLLNVAL;
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

int unix_file_new(filesystem fs, tuple md, int type, int flags, fsfile fsf)
{
    thread t = current;
    unix_heaps uh = get_unix_heaps();
    file f = type == FDESC_TYPE_SPECIAL ? spec_allocate(md) : unix_cache_alloc(uh, file);
    if (f == INVALID_ADDRESS) {
        thread_log(t, "failed to allocate struct file");
        return -ENOMEM;
    }
    heap h = heap_locked(get_kernel_heaps());
    init_fdesc(h, &f->f, type);
    f->f.flags = flags;
    f->fs = fs;
    f->fsf = fsf;
    u64 length;
    if (fsf) {
        f->fs_read = fsfile_get_reader(fsf);
        assert(f->fs_read);
        f->fs_write = fsfile_get_writer(fsf);
        assert(f->fs_write);
        f->fadv = POSIX_FADV_NORMAL;
        length = fsfile_get_length(fsf);
    } else {
        length = 0;
    }
    f->n = fs->get_inode(fs, md);
    f->offset = (flags & O_APPEND) ? length : 0;

    if (type == FDESC_TYPE_SPECIAL) {
        int spec_ret = spec_open(f, md);
        if (spec_ret != 0) {
            assert(spec_ret < 0);
            thread_log(t, "spec_open failed (%d)", spec_ret);
            spec_deallocate(f);
            return spec_ret;
        }
    } else {
        f->f.read = init_closure_func(&f->read, file_io, file_read);
        f->f.write = init_closure_func(&f->write, file_io, file_write);
        f->f.sg_read = init_closure_func(&f->sg_read, sg_file_io, file_sg_read);
        f->f.sg_write = init_closure_func(&f->sg_write, sg_file_io, file_sg_write);
        f->f.close = init_closure_func(&f->close, fdesc_close, file_close);
        f->f.events = init_closure_func(&f->events, fdesc_events, file_events);
    }
    filesystem_reserve(fs);
    process p = t->p;
    int fd = allocate_fd(p, f);
    if (fd == INVALID_PHYSICAL) {
        thread_log(t, "failed to allocate fd");
        file_release(f);
        return -EMFILE;
    }
    thread_log(t, "file fd %d, length %ld, offset %ld", fd, length, f->offset);
    return fd;
}

int file_open(filesystem fs, tuple n, int flags, fsfile fsf)
{
    thread t = current;
    process p = t->p;

    if (flags & O_TMPFILE)
        flags |= O_DIRECTORY;

    switch (flags & O_ACCMODE) {
    case O_RDONLY:
        if ((flags & O_TMPFILE)) {
            return -EINVAL;
        }
        break;
    case O_WRONLY:
    case O_RDWR:
        if (filesystem_is_readonly(fs)) {
            return -EROFS;
        }
        if (!(file_meta_perms(p, n) & ACCESS_PERM_WRITE)) {
            return -EACCES;
        }
        if (is_dir(n) && !(flags & O_TMPFILE)) {
            return -EISDIR;
        }
        break;
    default:
        return -EINVAL;
    }
    if ((flags & (O_CREAT|O_DIRECTORY)) == O_DIRECTORY && !is_dir(n)) {
        return -ENOTDIR;
    }

    int type;

    if (flags & O_TMPFILE) {
        fs_status fss = filesystem_creat_unnamed(fs, &fsf);
        if (fss != FS_STATUS_OK) {
            return sysreturn_from_fs_status(fss);
        }
        type = FDESC_TYPE_REGULAR;
    } else {
        type = file_type_from_tuple(n);
        if (type == FDESC_TYPE_REGULAR) {
            assert(fsf);
            if (flags & O_TRUNC)
                truncate_file_maps(p, fsf, 0);
        }
    }

    int fd = unix_file_new(fs, n, type, flags, fsf);
    if (fd >= 0)
        fs_notify_event(n, IN_OPEN);
    else if (flags & O_TMPFILE)
        fsfile_release(fsf);
    return fd;
}

sysreturn open_internal(filesystem fs, inode cwd, sstring name, int flags,
                        int mode)
{
    tuple n;
    int ret;
    buffer b = 0;

    fsfile fsf = 0;
    fs_status fss = filesystem_get_node(&fs, cwd, name, !!(flags & O_NOFOLLOW),
                                        !!(flags & O_CREAT), !!(flags & O_EXCL),
                                        !!(flags & O_TRUNC), &n, &fsf);
    ret = sysreturn_from_fs_status(fss);
    if (ret == -EFAULT)
        return ret;
    if ((ret == 0) && (flags & O_NOFOLLOW) && is_symlink(n) && !(flags & O_PATH)) {
        filesystem_put_node(fs, n);
        ret = -ELOOP;
    }

    if (do_missing_files) {
        b = wrap_string_sstring(name);
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

    ret = file_open(fs, n, flags, fsf);
    if (ret < 0)
        goto out;

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
  out:
    filesystem_put_node(fs, n);
    if ((ret < 0) && fsf)
        fsfile_release(fsf);
    return ret;
}

#ifdef __x86_64__
sysreturn open(const char *name, int flags, int mode)
{
    sstring name_ss;
    if (!fault_in_user_string(name, &name_ss))
        return -EFAULT;
    thread_log(current, "open: \"%s\", flags %x, mode %x", name_ss, flags, mode);
    filesystem cwd_fs;
    inode cwd;
    process_get_cwd(current->p, &cwd_fs, &cwd);
    sysreturn rv = open_internal(cwd_fs, cwd, name_ss, flags, mode);
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
    thread_log(current, "%s: oldfd %d, newfd %d", func_ss, oldfd, newfd);
    process p = current->p;
    fdesc f = resolve_fd(p, oldfd);
    if (newfd != oldfd) {
        fdesc newf = fdesc_get(p, newfd);
        if (newf) {
            process_lock(p);
            assert(vector_set(p->files, newfd, f));
            process_unlock(p);
            if (fetch_and_add(&newf->refcnt, -2) == 2) {
                if (newf->close)
                    apply(newf->close, get_current_context(current_cpu()), io_completion_ignore);
            }
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
    sstring pathname_ss;
    if (!fault_in_user_string(pathname, &pathname_ss))
        return -EFAULT;
    thread_log(current, "mkdir: \"%s\", mode 0x%x", pathname_ss, mode);
    filesystem cwd_fs;
    inode cwd;
    process_get_cwd(current->p, &cwd_fs, &cwd);
    sysreturn rv = sysreturn_from_fs_status(filesystem_mkdir(cwd_fs, cwd, pathname_ss));
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
    sstring pathname_ss;
    filesystem fs;
    inode cwd;
    cwd = resolve_dir(fs, dirfd, pathname, pathname_ss);
    thread_log(current, "mkdirat: \"%s\", dirfd %d, mode 0x%x", pathname_ss, dirfd, mode);

    sysreturn rv = sysreturn_from_fs_status(filesystem_mkdir(fs, cwd, pathname_ss));
    filesystem_release(fs);
    return rv;
}

sysreturn creat(const char *pathname, int mode)
{
    sstring pathname_ss;
    if (!fault_in_user_string(pathname, &pathname_ss))
        return -EFAULT;
    thread_log(current, "creat: \"%s\", mode 0x%x", pathname_ss, mode);
    filesystem cwd_fs;
    inode cwd;
    process_get_cwd(current->p, &cwd_fs, &cwd);
    sysreturn rv = open_internal(cwd_fs, cwd, pathname_ss,
        O_CREAT|O_WRONLY|O_TRUNC, mode);
    filesystem_release(cwd_fs);
    return rv;
}

/* small enough to not exhaust entropy resources without scheduling */
#define GETRANDOM_MAX_BUFLEN (1ull << 20)

static inline boolean fill_random(void *buf, u64 buflen)
{
    context ctx = get_current_context(current_cpu());
    if (context_set_err(ctx)) {
        random_buffer_aborted();
        return false;
    }
    random_buffer(alloca_wrap_buffer(buf, buflen));
    context_clear_err(ctx);
    return true;
}

closure_function(3, 0, void, getrandom_deferred,
                 void *, buf, u64, buflen, u64, written)
{
    u64 len = MIN(GETRANDOM_MAX_BUFLEN, bound(buflen) - bound(written));
    if (fill_random(bound(buf) + bound(written), len)) {
        bound(written) += len;
        if (bound(written) < bound(buflen)) {
            async_apply((thunk)closure_self());
            kern_yield();
        }
    }
    syscall_return(current, bound(written));
    closure_finish();
}

sysreturn getrandom(void *buf, u64 buflen, unsigned int flags)
{
    if (!buflen)
        return set_syscall_error(current, EINVAL);

    if (flags & ~(GRND_NONBLOCK | GRND_RANDOM))
        return set_syscall_error(current, EINVAL);

    u64 n = MIN(GETRANDOM_MAX_BUFLEN, buflen);
    if (!validate_user_memory(buf, buflen, true) || !fill_random(buf, n))
        return -EFAULT;

    if (n < buflen) {
        thunk t = contextual_closure(getrandom_deferred, buf, buflen, n);
        assert(t != INVALID_ADDRESS);
        async_apply(t);
        /* not really sleeping */
        thread_maybe_sleep_uninterruptible(current);
    }
    return buflen;
}

static int try_write_dirent(void *dirp, boolean dirent64, string p,
        int *read_sofar, int *written_sofar, u64 *f_offset,
        unsigned int *count, filesystem fs, tuple n)
{
    int len = buffer_length(p);
    *read_sofar += len;
    if (*read_sofar > *f_offset) {
        int reclen = dirent64 ? (offsetof(struct linux_dirent64 *, d_name) + len + 1) :
                     (offsetof(struct linux_dirent *, d_name) + len + 2);
        reclen = pad(reclen, 8);    /* so that all dirent structures have natural alignment */
        // include this element in the getdents output
        if (reclen > *count) {
            // can't include, there's no space
            *read_sofar -= len;
            return -1;
        } else {
            // include the entry in the buffer
            if (dirent64) {
                struct linux_dirent64 *dp = dirp;
                dp->d_ino = fs->get_inode(fs, n);
                dp->d_reclen = reclen;
                runtime_memcpy(dp->d_name, buffer_ref(p, 0), len);
                dp->d_name[len] = '\0';
                dp->d_off = reclen + *written_sofar;
                dp->d_type = dt_from_tuple(n);
            } else {
                struct linux_dirent *dp = dirp;
                dp->d_ino = fs->get_inode(fs, n);
                dp->d_reclen = reclen;
                runtime_memcpy(dp->d_name, buffer_ref(p, 0), len);
                zero(dp->d_name + len, reclen - (((void *)dp->d_name) - dirp) - len - 1);
                dp->d_off = reclen + *written_sofar;
                ((char *)dirp)[reclen - 1] = dt_from_tuple(n);
            }

            // advance dirp
            *written_sofar += reclen;
            *count -= reclen;
            return reclen;
        }
    }
    return 0;
}

closure_function(8, 2, boolean, getdents_each,
                 file, f, void **, dirp, boolean, dirent64, int *, read_sofar, int *, written_sofar, unsigned int *, count, int *, r, filesystem, fs,
                 value k, value v)
{
    assert(is_symbol(k));
    string p = symbol_string(k);
    *bound(r) = try_write_dirent(*bound(dirp), bound(dirent64), p,
                                 bound(read_sofar), bound(written_sofar), &bound(f)->offset, bound(count),
                                 bound(fs), v);
    if (*bound(r) < 0)
        return false;

    *bound(dirp) = *bound(dirp) + *bound(r);
    return true;
}

static sysreturn getdents_internal(int fd, void *dirp, unsigned int count, boolean dirent64)
{
    file f = resolve_fd(current->p, fd);
    tuple md = 0;
    sysreturn rv;
    if (!fault_in_user_memory(dirp, count, true)) {
        rv = -EFAULT;
        goto out;
    }
    md = filesystem_get_meta(f->fs, f->n);
    tuple c;
    if (!md || !(c = children(md))) {
        rv = -ENOTDIR;
        goto out;
    }

    int r = 0;
    int read_sofar = 0, written_sofar = 0;
    binding_handler h = stack_closure(getdents_each, f, &dirp, dirent64,
                                      &read_sofar, &written_sofar, &count, &r, f->fs);
    symbol parent_sym = sym_this("..");
    if (apply(h, sym_this("."), md) && apply(h, parent_sym, get_tuple(md, parent_sym)))
        iterate(c, h);
    fs_notify_event(md, IN_ACCESS);
    filesystem_update_relatime(f->fs, md);
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
    sstring path_ss;
    if (!fault_in_user_string(path, &path_ss))
        return -EFAULT;
    return sysreturn_from_fs_status(filesystem_chdir(current->p, path_ss));
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
    u64 cur_len = fsfile_get_length(fsf);
    if (length == cur_len)
        return 0;
    if (fs->get_seals) {
        u64 seals;
        if (fs->get_seals(fs, fsf, &seals) == FS_STATUS_OK) {
            if (((seals & F_SEAL_SHRINK) && (length < cur_len)) ||
                ((seals & F_SEAL_GROW) && (length > cur_len)))
                return -EPERM;
        }
    }
    fs_status s = filesystem_truncate(fs, fsf, length);
    if (s == FS_STATUS_OK)
        truncate_file_maps(current->p, fsf, length);
    return sysreturn_from_fs_status(s);
}

sysreturn truncate(const char *path, long length)
{
    sstring path_ss;
    if (!fault_in_user_string(path, &path_ss))
        return -EFAULT;
    tuple t;
    filesystem fs;
    inode cwd;
    process_get_cwd(current->p, &fs, &cwd);
    filesystem cwd_fs = fs;
    fsfile fsf;
    fs_status fss = filesystem_get_node(&fs, cwd, path_ss, false, false, false, false, &t, &fsf);
    thread_log(current, "%s \"%s\" %d", func_ss, path_ss, length);
    sysreturn rv;
    if (fss != FS_STATUS_OK) {
        rv = sysreturn_from_fs_status(fss);
        goto out;
    }
    if (!(file_meta_perms(current->p, t) & ACCESS_PERM_WRITE))
        rv = -EACCES;
    else if (is_dir(t))
        rv = -EISDIR;
    else if (!fsf)
        rv = -EINVAL;
    else
        rv = 0;
    filesystem_put_node(fs, t);
    if (rv == 0)
        rv = truncate_internal(fs, fsf, 0, length);
    if (fsf)
        fsfile_release(fsf);
  out:
    filesystem_release(cwd_fs);
    return rv;
}

sysreturn ftruncate(int fd, long length)
{
    thread_log(current, "%s %d %d", func_ss, fd, length);
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

closure_function(1, 1, void, sync_complete,
                 fdesc, f,
                 status s)
{
    assert(is_syscall_context(get_current_context(current_cpu())));
    thread t = current;
    thread_log(current, "%s: status %v", func_ss, s);
    fdesc f = bound(f);
    if (f)
        fdesc_put(f);
    syscall_return(t, is_ok(s) ? 0 : -EIO);
    closure_finish();
}

sysreturn sync(void)
{
    status_handler sh = contextual_closure(sync_complete, 0);
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

static sysreturn fsync_internal(int fd, boolean datasync)
{
    fdesc f = resolve_fd(current->p, fd);
    sysreturn rv;
    switch (f->type) {
    case FDESC_TYPE_REGULAR:
        assert(((file)f)->fsf);
        break;
    case FDESC_TYPE_DIRECTORY:
        if (datasync) {
            rv = 0;
            goto done;
        }
        break;
    case FDESC_TYPE_SYMLINK:
        rv = -EBADF;
        goto done;
    default:
        rv = -EINVAL;
        goto done;
    }
    status_handler completion = contextual_closure(sync_complete, f);
    if (completion == INVALID_ADDRESS) {
        rv = -ENOMEM;
        goto done;
    }
    if (((file)f)->fsf)
        fsfile_flush(((file)f)->fsf, datasync, completion);
    else
        filesystem_flush(((file)f)->fs, completion);
    return thread_maybe_sleep_uninterruptible(current);
  done:
    fdesc_put(f);
    return rv;
}

sysreturn fsync(int fd)
{
    return fsync_internal(fd, false);
}

sysreturn fdatasync(int fd)
{
    return fsync_internal(fd, true);
}

static sysreturn access_internal(filesystem fs, inode cwd, sstring pathname, int mode)
{
    tuple m = 0;
    fs_status fss = filesystem_get_node(&fs, cwd, pathname, false, false, false, false, &m, 0);
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
    sstring pathname_ss;
    if (!fault_in_user_string(pathname, &pathname_ss))
        return -EFAULT;
    thread_log(current, "access: \"%s\", mode %d", pathname_ss, mode);
    filesystem cwd_fs;
    inode cwd;
    process_get_cwd(current->p, &cwd_fs, &cwd);
    sysreturn rv = access_internal(cwd_fs, cwd, pathname_ss, mode);
    filesystem_release(cwd_fs);
    return rv;
}

sysreturn faccessat(int dirfd, const char *pathname, int mode)
{
    sstring pathname_ss;
    filesystem fs;
    inode cwd = resolve_dir(fs, dirfd, pathname, pathname_ss);
    thread_log(current, "faccessat: dirfd %d, \"%s\", mode %d", dirfd, pathname_ss, mode);
    sysreturn rv = access_internal(fs, cwd, pathname_ss, mode);
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

    sstring name_ss;
    filesystem fs;
    inode cwd;
    cwd = resolve_dir(fs, dirfd, name, name_ss);

    sysreturn rv = open_internal(fs, cwd, name_ss, flags, mode);
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
    case FDESC_TYPE_STDIO:
        s->st_mode = S_IFCHR;
        /* Describing stdout as a pseudo-tty makes glibc apply line buffering (instead of full
         * buffering) when the process writes to stdout. */
        s->st_rdev = makedev(UNIX98_PTY_SLAVE_MAJOR, 0);
        break;
    case FDESC_TYPE_SPECIAL:
        s->st_mode = S_IFCHR;   /* assuming only character devs now */
        s->st_rdev = filesystem_get_rdev(fs, n);
        break;
    case FDESC_TYPE_SOCKET:
        s->st_mode = S_IFSOCK;
        break;
    case FDESC_TYPE_PIPE:
        s->st_mode = S_IFIFO;
        break;
    case FDESC_TYPE_EPOLL:
        s->st_mode = S_IFCHR;   /* XXX not clear - EBADF? */
        break;
    case FDESC_TYPE_SYMLINK:
        s->st_mode = S_IFLNK;
        break;
    }
    if (type == FDESC_TYPE_REGULAR) {
        if (f) {
            s->st_size = fsfile_get_length(f);
            s->st_blocks = fsfile_get_blocks(f);
        }
        s->st_blksize = PAGESIZE;   /* "preferred" block size for efficient filesystem I/O */
    }
    if (n) {
        s->st_ino = fs->get_inode(fs, n);
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
    fdesc f = resolve_fd(current->p, fd);
    filesystem fs;
    tuple n;
    fsfile fsf = 0;
    sysreturn rv = 0;
    if (!fault_in_user_memory(s, sizeof(struct stat), true)) {
        rv = -EFAULT;
        goto out;
    }
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
  out:
    fdesc_put(f);
    return rv;
}

static sysreturn stat_internal(filesystem fs, inode cwd, sstring name, boolean follow,
        struct stat *buf)
{
    tuple n;
    fsfile fsf;

    if (!fault_in_user_memory(buf, sizeof(struct stat), true))
        return -EFAULT;

    thread_log(current, "stat: cwd 0x%lx, \"%s\", %sfollow, buf %p", cwd, name,
               follow ? sstring_empty() : ss("no "), buf);
    fs_status fss = filesystem_get_node(&fs, cwd, name, !follow, false, false, false, &n, &fsf);
    if (fss != FS_STATUS_OK)
        return sysreturn_from_fs_status(fss);

    fill_stat(file_type_from_tuple(n), fs, fsf, n, buf);
    filesystem_put_node(fs, n);
    if (fsf)
        fsfile_release(fsf);
    thread_log(current, "st_ino %lx, st_mode 0x%x, st_size %lx",
               buf->st_ino, buf->st_mode, buf->st_size);
    return 0;
}

#ifdef __x86_64__

static sysreturn stat_cwd(const char *name, boolean follow, struct stat *buf)
{
    sstring name_ss;
    if (!fault_in_user_string(name, &name_ss))
        return -EFAULT;
    filesystem cwd_fs;
    inode cwd;
    process_get_cwd(current->p, &cwd_fs, &cwd);
    sysreturn rv = stat_internal(cwd_fs, cwd, name_ss, follow, buf);
    filesystem_release(cwd_fs);
    return rv;
}

static sysreturn stat(const char *name, struct stat *buf)
{
    return stat_cwd(name, true, buf);
}

static sysreturn lstat(const char *name, struct stat *buf)
{
    return stat_cwd(name, false, buf);
}
#endif

static sysreturn newfstatat(int dfd, const char *name, struct stat *s, int flags)
{
    // if relative, but AT_EMPTY_PATH set, works just like fstat()
    if (flags & AT_EMPTY_PATH)
        return fstat(dfd, s);

    // Else, if we have a fd of a directory, resolve name to it.
    sstring name_ss;
    filesystem fs;
    inode n = resolve_dir(fs, dfd, name, name_ss);
    sysreturn rv = stat_internal(fs, n, name_ss, !(flags & AT_SYMLINK_NOFOLLOW), s);
    filesystem_release(fs);
    return rv;
}

sysreturn lseek(int fd, s64 offset, int whence)
{
    thread_log(current, "%s: fd %d offset %ld whence %s",
               func_ss, fd, offset, whence == SEEK_SET ? ss("SEEK_SET") :
               whence == SEEK_CUR ? ss("SEEK_CUR") :
               whence == SEEK_END ? ss("SEEK_END") :
               ss("invalid"));

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
            new = (f->fsf ? fsfile_get_length(f->fsf) : S64_MAX) + offset;
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
    char machine[] =
#ifdef __x86_64__
        "x86_64";
#endif
#ifdef __aarch64__
        "aarch64";
#endif
#ifdef __riscv
        "riscv64";
#endif

    if (!fault_in_user_memory(v, sizeof(struct utsname), true))
        return -EFAULT;

    tuple cfg = get_tuple(get_root_tuple(), sym_this("uname"));
    string sysname;
    if (cfg)
        sysname = get_string(cfg, sym_this("sysname"));
    else
        sysname = 0;
    if (!sysname)
        sysname = alloca_wrap_cstring("Nanos");
    bytes sysname_len = MIN(buffer_length(sysname), sizeof(v->sysname) - 1);
    runtime_memcpy(v->sysname, buffer_ref(sysname, 0), sysname_len);
    v->sysname[sysname_len] = '\0';
    if (hostname) {
        bytes length = MIN(buffer_length(hostname), sizeof(v->nodename) - 1);
        runtime_memcpy(v->nodename, buffer_ref(hostname, 0), length);
        v->nodename[length] = '\0';
    } else {
        v->nodename[0] = 0;
        struct netif *netif_default = netif_get_default();
        if (netif_default) {
            /* Derive nodename from the IP address of the default network interface. */
            const ip4_addr_t *addr = netif_ip4_addr(netif_default);
            if (!ip4_addr_isany_val(*addr))
                rsnprintf(v->nodename, sizeof(v->nodename), "%d-%d-%d-%d",
                          ip4_addr1(addr), ip4_addr2(addr), ip4_addr3(addr), ip4_addr4(addr));
            netif_unref(netif_default);
        }
        if (!v->nodename[0])
            runtime_memcpy(v->nodename, sysname, sizeof(sysname));
    }
    runtime_memcpy(v->machine, machine, sizeof(machine));

    /* gitversion shouldn't exceed the field, but just in case... */
    bytes len = MIN(gitversion.len, sizeof(v->version) - 1);
    runtime_memcpy(v->version, gitversion.ptr, len);
    v->version[len] = '\0';     /* TODO: append build seq / time */

    /* The "5.0-" dummy prefix placates the glibc dynamic loader. */
    tuple env = get_environment();
    string release;
    if (cfg)
        release = get_string(cfg, sym_this("release"));
    else
        release = 0;
    if (!release) {
        release = little_stack_buffer(sizeof(v->release) - 1);
        bprintf(release, "5.0-%v_aaa", get_string(env, sym(NANOS_VERSION)));
    }
    len = MIN(buffer_length(release), sizeof(v->release) - 1);
    runtime_memcpy(v->release, buffer_ref(release, 0), len);
    v->release[len] = '\0';
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

    context ctx = get_current_context(current_cpu());
    if (!validate_user_memory(rlim, sizeof(struct rlimit), true) || context_set_err(ctx))
        return -EFAULT;

    sysreturn rv = 0;
    switch (resource) {
    case RLIMIT_DATA:
        /* not entirely accurate, but a reasonable approximation */
        rlim->rlim_cur = rlim->rlim_max =
                heap_total(&heap_physical(get_kernel_heaps())->h);
        break;
    case RLIMIT_STACK:
        rlim->rlim_cur = 2*1024*1024;
        rlim->rlim_max = 2*1024*1024;
        break;
    case RLIMIT_CORE:
        rlim->rlim_cur = rlim->rlim_max = 0;    // core dump not supported
        break;
    case RLIMIT_NOFILE:
        // we .. .dont really have one?
        rlim->rlim_cur = 65536;
        rlim->rlim_max = 65536;
        break;
    case RLIMIT_AS:
        rlim->rlim_cur = rlim->rlim_max = heap_total(current->p->virtual);
        break;
    default:
        rv = -EINVAL;
    }

    context_clear_err(ctx);
    return rv;
}

sysreturn prlimit64(int pid, int resource, const struct rlimit *new_limit, struct rlimit *old_limit)
{
    thread_log(current, "prlimit64: pid %d, resource %d, new_limit %p, old_limit %p",
        pid, resource, new_limit, old_limit);

    if (old_limit) {
        sysreturn ret = getrlimit(resource, old_limit);
        if (ret < 0)
            return ret;
    }

    // setting new limits is not implemented
    return 0;
}

static sysreturn getrusage(int who, struct rusage *usage)
{
    thread_log(current, "%s: who %d", func_ss, who);
    context ctx = get_current_context(current_cpu());
    if (!validate_user_memory(usage, sizeof(*usage), true) || context_set_err(ctx))
        return -EFAULT;
    zero(usage, sizeof(*usage));
    sysreturn rv = 0;
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
            rv = -EINVAL;
    }
    context_clear_err(ctx);
    return rv;
}

static sysreturn getcwd(char *buf, u64 length)
{
    if (!fault_in_user_memory(buf, length, true))
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
    }
    p->brk = addr;
  out:
    addr = p->brk;
    process_unlock(p);
    return sysreturn_from_pointer(addr);
}

static sysreturn readlink_internal(filesystem fs, inode cwd, sstring pathname, char *buf,
        u64 bufsiz)
{
    if (!fault_in_user_memory(buf, bufsiz, true)) {
        return set_syscall_error(current, EFAULT);
    }
    tuple n;
    fs_status fss = filesystem_get_node(&fs, cwd, pathname, true, false, false, false, &n, 0);
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
    sstring pathname_ss;
    if (!fault_in_user_string(pathname, &pathname_ss))
        return -EFAULT;
    thread_log(current, "readlink: \"%s\"", pathname_ss);
    filesystem cwd_fs;
    inode cwd;
    process_get_cwd(current->p, &cwd_fs, &cwd);
    sysreturn rv = readlink_internal(cwd_fs, cwd, pathname_ss, buf, bufsiz);
    filesystem_release(cwd_fs);
    return rv;
}

sysreturn readlinkat(int dirfd, const char *pathname, char *buf, u64 bufsiz)
{
    sstring pathname_ss;
    filesystem fs;
    inode cwd = resolve_dir(fs, dirfd, pathname, pathname_ss);
    thread_log(current, "readlinkat: \"%s\", dirfd %d", pathname_ss, dirfd);
    sysreturn rv = readlink_internal(fs, cwd, pathname_ss, buf, bufsiz);
    filesystem_release(fs);
    return rv;
}

sysreturn unlink(const char *pathname)
{
    sstring pathname_ss;
    if (!fault_in_user_string(pathname, &pathname_ss))
        return -EFAULT;
    thread_log(current, "unlink %s", pathname_ss);
    filesystem cwd_fs;
    inode cwd;
    process_get_cwd(current->p, &cwd_fs, &cwd);
    sysreturn rv = sysreturn_from_fs_status(filesystem_delete(cwd_fs, cwd, pathname_ss, false));
    filesystem_release(cwd_fs);
    return rv;
}

sysreturn unlinkat(int dirfd, const char *pathname, int flags)
{
    if (flags & ~AT_REMOVEDIR) {
        return set_syscall_error(current, EINVAL);
    }
    sstring path_ss;
    filesystem fs;
    inode cwd = resolve_dir(fs, dirfd, pathname, path_ss);
    thread_log(current, "unlinkat %d %s 0x%x", dirfd, path_ss, flags);
    sysreturn rv;
    rv = sysreturn_from_fs_status(filesystem_delete(fs, cwd, path_ss, !!(flags & AT_REMOVEDIR)));
    filesystem_release(fs);
    return rv;
}

sysreturn rmdir(const char *pathname)
{
    sstring pathname_ss;
    if (!fault_in_user_string(pathname, &pathname_ss))
        return -EFAULT;
    thread_log(current, "rmdir %s", pathname_ss);
    filesystem cwd_fs;
    inode cwd;
    process_get_cwd(current->p, &cwd_fs, &cwd);
    sysreturn rv = sysreturn_from_fs_status(filesystem_delete(cwd_fs, cwd, pathname_ss, true));
    filesystem_release(cwd_fs);
    return rv;
}

sysreturn rename(const char *oldpath, const char *newpath)
{
    sstring oldpath_ss, newpath_ss;
    if (!fault_in_user_string(oldpath, &oldpath_ss) || !fault_in_user_string(newpath, &newpath_ss))
        return -EFAULT;
    thread_log(current, "rename \"%s\" \"%s\"", oldpath_ss, newpath_ss);
    filesystem cwd_fs;
    inode cwd;
    process_get_cwd(current->p, &cwd_fs, &cwd);
    sysreturn rv = sysreturn_from_fs_status(filesystem_rename(cwd_fs, cwd, oldpath_ss,
                                                              cwd_fs, cwd, newpath_ss, false));
    filesystem_release(cwd_fs);
    return rv;
}

sysreturn renameat(int olddirfd, const char *oldpath, int newdirfd,
        const char *newpath)
{
    sstring oldpath_ss, newpath_ss;
    filesystem oldfs, newfs;
    inode oldwd = resolve_dir(oldfs, olddirfd, oldpath, oldpath_ss);
    inode newwd = resolve_dir(newfs, newdirfd, newpath, newpath_ss);
    thread_log(current, "renameat %d \"%s\" %d \"%s\"", olddirfd, oldpath_ss, newdirfd, newpath_ss);
    sysreturn rv = sysreturn_from_fs_status(filesystem_rename(oldfs, oldwd, oldpath_ss,
                                                              newfs, newwd, newpath_ss, false));
    filesystem_release(oldfs);
    filesystem_release(newfs);
    return rv;
}

sysreturn renameat2(int olddirfd, const char *oldpath, int newdirfd,
        const char *newpath, unsigned int flags)
{
    if ((flags & ~(RENAME_EXCHANGE | RENAME_NOREPLACE)) ||
            ((flags & RENAME_EXCHANGE) && (flags & RENAME_NOREPLACE))) {
        return set_syscall_error(current, EINVAL);
    }
    sstring oldpath_ss, newpath_ss;
    filesystem oldfs, newfs;
    inode oldwd = resolve_dir(oldfs, olddirfd, oldpath, oldpath_ss);
    inode newwd = resolve_dir(newfs, newdirfd, newpath, newpath_ss);
    thread_log(current, "renameat2 %d \"%s\" %d \"%s\", flags 0x%x", olddirfd, oldpath_ss,
               newdirfd, newpath_ss, flags);
    fs_status fss;
    if (flags & RENAME_EXCHANGE) {
        fss = filesystem_exchange(oldfs, oldwd, oldpath_ss, newfs, newwd, newpath_ss);
    }
    else {
        fss = filesystem_rename(oldfs, oldwd, oldpath_ss, newfs, newwd, newpath_ss,
            !!(flags & RENAME_NOREPLACE));
    }
    filesystem_release(oldfs);
    filesystem_release(newfs);
    return sysreturn_from_fs_status(fss);
}

/* File paths are treated as absolute paths. */
sysreturn fs_rename(sstring oldpath, sstring newpath)
{
    filesystem fs = get_root_fs();
    inode root = fs->get_inode(fs, filesystem_getroot(fs));
    return sysreturn_from_fs_status(filesystem_rename(fs, root, oldpath, fs, root, newpath, false));
}

sysreturn close(int fd)
{
    thread_log(current, "close: fd %d", fd);
    fdesc f = resolve_fd(current->p, fd);
    deallocate_fd(current->p, fd);

    if (fetch_and_add(&f->refcnt, -2) == 2) {
        if (f->close)
            return apply(f->close, get_current_context(current_cpu()), syscall_io_complete);
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
            s16 l_type = F_UNLCK;
            if (!set_user_value(&((struct flock *)arg)->l_type, l_type))
                rv = -EFAULT;
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
    case F_ADD_SEALS:
        if (f->type == FDESC_TYPE_REGULAR)
            rv = fsfile_add_seals(((file)f)->fsf, (int)arg);
        else
            rv = -EINVAL;
        break;
    case F_GET_SEALS:
        if (f->type == FDESC_TYPE_REGULAR) {
            u64 seals;
            rv = fsfile_get_seals(((file)f)->fsf, &seals);
            if (rv == 0)
                rv = seals;
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
        int opt;
        if (!get_user_value(varg(ap, int *), &opt))
            return -EFAULT;
        fdesc_lock(f);
        if (opt) {
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

sysreturn exit_group(int status)
{
    kernel_shutdown(status);
}

void exit(int code)
{
    process p = current->p;
    exit_thread(current);
    spin_lock(&p->threads_lock);
    int cnt = rbtree_get_count(p->threads);
    spin_unlock(&p->threads_lock);
    if (cnt == 0)
        exit_group(code);
    else
        syscall_finish(true);
}

sysreturn pipe2(int fds[2], int flags)
{
    if (!fault_in_user_memory(fds, 2 * sizeof(int), true))
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
    context ctx = get_current_context(current_cpu());
    u64 first_cpu = -1ull;
    u64 i;
    if (context_set_err(ctx))
        return -EFAULT;
    for (i = 0; (first_cpu == -1ull) && (i + sizeof(u64) <= cpusetsize); i += sizeof(u64))
        first_cpu = i * 8 + lsb(mask[i / sizeof(u64)]);
    for (; (first_cpu == -1ull) && (i < cpusetsize); i++)
        first_cpu = i * 8 + lsb(((u8 *)mask)[i]);
    context_clear_err(ctx);
    if (first_cpu >= total_processors)
        return -EINVAL;
    thread t;
    if (!(t = lookup_thread(pid)))
            return set_syscall_error(current, EINVAL);
    cpusetsize = MIN(cpusetsize, pad(total_processors, 8) / 8);
    bitmap affinity = t->task.affinity;
    sysreturn rv;
    thread_lock(t);
    if (!copy_from_user(mask, bitmap_base(affinity), cpusetsize)) {
        rv = -EFAULT;
        goto out;
    }
    u64 cpus = cpusetsize * 8;
    if (cpus < total_processors)
        bitmap_range_check_and_set(affinity, cpus, total_processors - cpus, false, false);

    /* If the thread has last run on a non-affine CPU, move it to the first CPU in the affinity
     * mask. Note: this does not guarantee that the thread is migrated immediately to the affine CPU
     * (e.g. if it's already enqueued in its current scheduling queue it will most likely do another
     * run on its current CPU), but the migration will happen the next time the thread is scheduled
     * to run. */
    cpuinfo ci = struct_from_field(t->scheduling_queue, cpuinfo, thread_queue);
    if (!bitmap_get(affinity, ci->id))
        t->scheduling_queue = &cpuinfo_from_id(first_cpu)->thread_queue;

    rv = 0;
  out:
    thread_unlock(t);
    thread_release(t);
    return rv;
}

sysreturn sched_getaffinity(int pid, u64 cpusetsize, u64 *mask)
{
    if (!fault_in_user_memory(mask, cpusetsize, true))
        return set_syscall_error(current, EFAULT);
    thread t;
    if (64 * (cpusetsize / sizeof(u64)) < total_processors)
        return set_syscall_error(current, EINVAL);
    if (!(t = lookup_thread(pid)))
        return set_syscall_error(current, EINVAL);
    cpusetsize = pad(total_processors, 64) / 8;
    thread_lock(t);
    runtime_memcpy(mask, bitmap_base(t->task.affinity), cpusetsize);
    thread_unlock(t);
    thread_release(t);
    return cpusetsize;
}

sysreturn capget(cap_user_header_t hdrp, cap_user_data_t datap)
{
    if (datap) {
        context ctx = get_current_context(current_cpu());
        if (!validate_user_memory(datap, sizeof(struct user_cap_data), true) ||
            context_set_err(ctx))
            return -EFAULT;
        zero(datap, sizeof(*datap));
        context_clear_err(ctx);
    }
    return 0;
}

sysreturn prctl(int option, u64 arg2, u64 arg3, u64 arg4, u64 arg5)
{
    thread_log(current, "prctl: option %d, arg2 0x%lx, arg3 0x%lx, arg4 0x%lx, arg5 0x%lx",
               option, arg2, arg3, arg4, arg5);

    switch (option) {
    case PR_SET_NAME:
        if (!copy_from_user((void *)arg2, current->name, sizeof(current->name)))
            return -EFAULT;
        current->name[sizeof(current->name) - 1] = '\0';
        break;
    case PR_GET_NAME:
        if (!copy_to_user((void *)arg2, current->name, sizeof(current->name)))
            return -EFAULT;
        break;
    }

    return 0;
}

sysreturn sysinfo(struct sysinfo *info)
{
    context ctx = get_current_context(current_cpu());
    if (!validate_user_memory(info, sizeof(struct sysinfo), true) || context_set_err(ctx))
        return set_syscall_error(current, EFAULT);

    kernel_heaps kh = get_kernel_heaps();
    runtime_memset((u8 *) info, 0, sizeof(*info));
    info->uptime = sec_from_timestamp(uptime());
    info->totalram = heap_total((heap)kh->physical);
    u64 allocated = heap_allocated((heap)kh->physical);
    info->freeram = info->totalram < allocated ? 0 : info->totalram - allocated;
    info->procs = 1;
    info->mem_unit = 1;
    context_clear_err(ctx);
    return 0;
}

sysreturn umask(int mask)
{
    return mask;
}

sysreturn getcpu(unsigned int *cpu, unsigned int *node, void *tcache)
{
    cpuinfo ci = current_cpu();
    context ctx = get_current_context(ci);
    if ((cpu != 0 && !validate_user_memory(cpu, sizeof *cpu, true)) ||
        (node != 0 && !validate_user_memory(node, sizeof *node, true)) ||
        context_set_err(ctx))
        return -EFAULT;
    if (cpu)
        *cpu = ci->id;
    /* XXX to do */
    if (node)
        *node = 0;
    context_clear_err(ctx);
    return 0;
}

void register_file_syscalls(struct syscall *map)
{
    register_syscall(map, read, read, SYSCALL_F_SET_DESC);
    register_syscall(map, pread64, pread, SYSCALL_F_SET_DESC);
    register_syscall(map, write, write, SYSCALL_F_SET_DESC);
    register_syscall(map, pwrite64, pwrite, SYSCALL_F_SET_DESC);
#ifdef __x86_64__
    register_syscall(map, open, open, SYSCALL_F_SET_FILE|SYSCALL_F_SET_DESC);
    register_syscall(map, dup2, dup2, SYSCALL_F_SET_DESC);
    register_syscall(map, stat, stat, SYSCALL_F_SET_FILE);
    register_syscall(map, lstat, lstat, SYSCALL_F_SET_FILE);
    register_syscall(map, access, access, SYSCALL_F_SET_FILE);
    register_syscall(map, readlink, readlink, SYSCALL_F_SET_FILE);
    register_syscall(map, unlink, unlink, SYSCALL_F_SET_FILE);
    register_syscall(map, rmdir, rmdir, SYSCALL_F_SET_FILE);
    register_syscall(map, rename, rename, SYSCALL_F_SET_FILE);
    register_syscall(map, getdents, getdents, SYSCALL_F_SET_DESC);
    register_syscall(map, mkdir, mkdir, SYSCALL_F_SET_FILE);
    register_syscall(map, pipe, pipe, SYSCALL_F_SET_DESC);
    register_syscall(map, eventfd, eventfd, SYSCALL_F_SET_DESC);
    register_syscall(map, creat, creat, SYSCALL_F_SET_FILE|SYSCALL_F_SET_DESC);
    register_syscall(map, utime, utime, SYSCALL_F_SET_FILE);
    register_syscall(map, utimes, utimes, SYSCALL_F_SET_FILE);
    register_syscall(map, chown, syscall_ignore, SYSCALL_F_SET_FILE);
    register_syscall(map, symlink, symlink, SYSCALL_F_SET_FILE);
    register_syscall(map, inotify_init, inotify_init, SYSCALL_F_SET_DESC);
#endif
    register_syscall(map, inotify_init1, inotify_init1, SYSCALL_F_SET_DESC);
    register_syscall(map, inotify_add_watch, inotify_add_watch, SYSCALL_F_SET_FILE|SYSCALL_F_SET_DESC);
    register_syscall(map, inotify_rm_watch, inotify_rm_watch, SYSCALL_F_SET_DESC);
    register_syscall(map, openat, openat, SYSCALL_F_SET_FILE|SYSCALL_F_SET_DESC);
    register_syscall(map, dup, dup, SYSCALL_F_SET_DESC);
    register_syscall(map, dup3, dup3, SYSCALL_F_SET_DESC);
    register_syscall(map, fallocate, fallocate, SYSCALL_F_SET_DESC);
    register_syscall(map, faccessat, faccessat, SYSCALL_F_SET_FILE|SYSCALL_F_SET_DESC);
    register_syscall(map, fadvise64, fadvise64, SYSCALL_F_SET_DESC);
    register_syscall(map, fstat, fstat, SYSCALL_F_SET_DESC);
    register_syscall(map, newfstatat, newfstatat, SYSCALL_F_SET_FILE|SYSCALL_F_SET_DESC);
    register_syscall(map, readv, readv, SYSCALL_F_SET_DESC);
    register_syscall(map, writev, writev, SYSCALL_F_SET_DESC);
    register_syscall(map, preadv, preadv, SYSCALL_F_SET_DESC);
    register_syscall(map, pwritev, pwritev, SYSCALL_F_SET_DESC);
    register_syscall(map, sendfile, sendfile, SYSCALL_F_SET_DESC|SYSCALL_F_SET_NET);
    register_syscall(map, truncate, truncate, SYSCALL_F_SET_FILE);
    register_syscall(map, ftruncate, ftruncate, SYSCALL_F_SET_DESC);
    register_syscall(map, fdatasync, fdatasync, SYSCALL_F_SET_DESC);
    register_syscall(map, fsync, fsync, SYSCALL_F_SET_DESC);
    register_syscall(map, sync, sync, 0);
    register_syscall(map, syncfs, syncfs, SYSCALL_F_SET_DESC);
    register_syscall(map, io_setup, io_setup, SYSCALL_F_SET_MEM);
    register_syscall(map, io_submit, io_submit, 0);
    register_syscall(map, io_getevents, io_getevents, 0);
    register_syscall(map, io_destroy, io_destroy, SYSCALL_F_SET_MEM);
    register_syscall(map, lseek, lseek, SYSCALL_F_SET_DESC);
    register_syscall(map, fcntl, fcntl, SYSCALL_F_SET_DESC);
    register_syscall(map, ioctl, (sysreturn (*)())ioctl, SYSCALL_F_SET_DESC);
    register_syscall(map, getcwd, getcwd, SYSCALL_F_SET_FILE);
    register_syscall(map, symlinkat, symlinkat, SYSCALL_F_SET_FILE|SYSCALL_F_SET_DESC);
    register_syscall(map, readlinkat, readlinkat, SYSCALL_F_SET_FILE|SYSCALL_F_SET_DESC);
    register_syscall(map, unlinkat, unlinkat, SYSCALL_F_SET_FILE|SYSCALL_F_SET_DESC);
    register_syscall(map, renameat, renameat, SYSCALL_F_SET_FILE|SYSCALL_F_SET_DESC);
    register_syscall(map, renameat2, renameat2, SYSCALL_F_SET_FILE|SYSCALL_F_SET_DESC);
    register_syscall(map, utimensat, utimensat, SYSCALL_F_SET_FILE|SYSCALL_F_SET_DESC);
    register_syscall(map, close, close, SYSCALL_F_SET_DESC);
    register_syscall(map, sched_yield, sched_yield, 0);
    register_syscall(map, brk, brk, SYSCALL_F_SET_MEM);
    register_syscall(map, uname, uname, 0);
    register_syscall(map, getrlimit, getrlimit, 0);
    register_syscall(map, setrlimit, setrlimit, 0);
    register_syscall(map, prlimit64, prlimit64, 0);
    register_syscall(map, getrusage, getrusage, 0);
    register_syscall(map, getpid, getpid, 0);
    register_syscall(map, exit_group, exit_group, SYSCALL_F_SET_PROC);
    register_syscall(map, exit, (sysreturn (*)())exit, SYSCALL_F_SET_PROC);
    register_syscall(map, getdents64, getdents64, SYSCALL_F_SET_DESC);
    register_syscall(map, mkdirat, mkdirat, SYSCALL_F_SET_FILE|SYSCALL_F_SET_DESC);
    register_syscall(map, getrandom, getrandom, 0);
    register_syscall(map, pipe2, pipe2, SYSCALL_F_SET_DESC);
    register_syscall(map, socketpair, socketpair, SYSCALL_F_SET_NET);
    register_syscall(map, eventfd2, eventfd2, SYSCALL_F_SET_DESC);
    register_syscall(map, chdir, chdir, SYSCALL_F_SET_FILE);
    register_syscall(map, fchdir, fchdir, SYSCALL_F_SET_DESC);
    register_syscall(map, sched_getaffinity, sched_getaffinity, 0);
    register_syscall(map, sched_setaffinity, sched_setaffinity, 0);
    register_syscall(map, getuid, syscall_ignore, 0);
    register_syscall(map, geteuid, syscall_ignore, 0);
    register_syscall(map, setgroups, syscall_ignore, 0);
    register_syscall(map, setuid, syscall_ignore, 0);
    register_syscall(map, setgid, syscall_ignore, 0);
    register_syscall(map, capget, capget, 0);
    register_syscall(map, capset, syscall_ignore, 0);
    register_syscall(map, prctl, prctl, 0);
    register_syscall(map, sysinfo, sysinfo, 0);
    register_syscall(map, umask, umask, 0);
    register_syscall(map, statfs, statfs, SYSCALL_F_SET_FILE);
    register_syscall(map, fstatfs, fstatfs, SYSCALL_F_SET_DESC);
    register_syscall(map, io_uring_setup, io_uring_setup, SYSCALL_F_SET_DESC);
    register_syscall(map, io_uring_enter, io_uring_enter, SYSCALL_F_SET_DESC);
    register_syscall(map, io_uring_register, io_uring_register, SYSCALL_F_SET_DESC);
    register_syscall(map, getcpu, getcpu, 0);
}


struct syscall {
    void *handler;
    sstring name;
    u64 flags;
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
}

static boolean debugsyscalls;

static void syscall_context_pause(context ctx)
{
    syscall_context sc = (syscall_context)ctx;
    syscall_accumulate_stime(sc);
    if (sc->call >= 0)
        count_syscall_save(sc->t);
    context_release_refcount(ctx);
}

static void syscall_context_resume(context ctx)
{
    syscall_context sc = (syscall_context)ctx;
    assert(sc->start_time == 0); // XXX tmp debug
    timestamp here = now(CLOCK_ID_MONOTONIC_RAW);
    sc->start_time = here == 0 ? 1 : here;
    if (sc->call >= 0)
        count_syscall_resume(sc->t);
    context_reserve_refcount(ctx);
}

static void syscall_context_pre_suspend(context ctx)
{
    check_syscall_context_replace(current_cpu(), ctx);
}

syscall_context allocate_syscall_context(cpuinfo ci)
{
    build_assert((SYSCALL_CONTEXT_SIZE & (SYSCALL_CONTEXT_SIZE - 1)) == 0);
    syscall_context sc = allocate(heap_locked(get_kernel_heaps()),
                                  SYSCALL_CONTEXT_SIZE);
    if (sc == INVALID_ADDRESS)
        return sc;
    context c = &sc->uc.kc.context;
    init_unix_context(&sc->uc, CONTEXT_TYPE_SYSCALL, SYSCALL_CONTEXT_SIZE,
                      ci->free_syscall_contexts);
    c->pause = syscall_context_pause;
    c->resume = syscall_context_resume;
    c->pre_suspend = syscall_context_pre_suspend;
    return sc;
}

void syscall_handler(thread t)
{
    /* The syscall_context stored in ci was set as current on syscall entry in
       order to get a usable stack. We still need to finish initializing it
       and complete the context switch. */
    cpuinfo ci = current_cpu();
    ci->state = cpu_kernel;
    assert(is_thread_context(&t->context));
    context_frame f = thread_frame(t);
    f[FRAME_FULL] = true;
    thread_reserve(t); /* frame save reference */
    u64 call = f[FRAME_VECTOR];
    u64 arg0 = f[SYSCALL_FRAME_ARG0]; /* aliases retval on arm; cache arg */
    syscall_restart_arch_setup(f);
    set_syscall_return(t, -ENOSYS);

    syscall_context sc = (syscall_context)get_current_context(ci);
    context ctx = &sc->uc.kc.context;
    assert(is_syscall_context(ctx));
    sc->t = t;
    ctx->fault_handler = t->context.fault_handler;
    sc->start_time = 0;
    sc->call = call;
    assert(ctx->refcount.c == 1);
    t->syscall = sc;
    context_pause(&t->context);
    context_release(&t->context);
    context_resume(ctx);

    if (shutting_down & SHUTDOWN_ONGOING)
        goto out;

    if (call >= sizeof(_linux_syscalls) / sizeof(_linux_syscalls[0])) {
        thread_log(t, "invalid syscall %d", call);
        goto out;
    }

    /* In the future, interrupt enable can go here. */
    if (do_syscall_stats) {
        assert(t->last_syscall == -1);
        t->last_syscall = call;
        t->syscall_enter_ts = now(CLOCK_ID_MONOTONIC_RAW);
        t->syscall_time = 0;
    }
    struct syscall *s = t->p->syscalls + call;
    if (debugsyscalls) {
        if (!sstring_is_null(s->name))
            thread_log(t, "%s", s->name);
        else
            thread_log(t, "syscall %d", call);
    }

    sysreturn (*h)(u64, u64, u64, u64, u64, u64) = s->handler;
    if (h) {
        t->syscall_complete = false;
        context_reserve_refcount(ctx);
        sysreturn rv = h(arg0, f[SYSCALL_FRAME_ARG1], f[SYSCALL_FRAME_ARG2],
                         f[SYSCALL_FRAME_ARG3], f[SYSCALL_FRAME_ARG4], f[SYSCALL_FRAME_ARG5]);
        assert(ctx->refcount.c > 1);
        context_release_refcount(ctx);
        set_syscall_return(t, rv);
        if (do_syscall_stats)
            count_syscall(t, rv);
        if (debugsyscalls)
            thread_log(t, "direct return: %ld, rsp 0x%lx", rv, f[SYSCALL_FRAME_SP]);
    } else if (debugsyscalls) {
        if (!sstring_is_null(s->name))
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

closure_func_basic(io_completion, void, syscall_io_complete_cfn,
                   sysreturn rv)
{
    thread t = ((syscall_context)get_current_context(current_cpu()))->t;
    syscall_return(t, rv);
}

closure_func_basic(buffer_handler, status, hostname_done,
                   buffer b)
{
    hostname = b;

    /* Remove trailing CR and LF, if any. */
    while (buffer_length(hostname) > 0) {
        char last_char = *(char *)(buffer_end(hostname) - 1);
        if ((last_char == '\r') || (last_char == '\n'))
            hostname->end--;
        else
            break;
    }

    closure_finish();
    return STATUS_OK;
}

closure_func_basic(io_completion, void, io_complete_ignore,
                   sysreturn rv)
{
}

static boolean stat_compare(void *za, void *zb)
{
    syscall_stat sa = za;
    syscall_stat sb = zb;
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

closure_func_basic(shutdown_handler, void, print_syscall_stats_cfn,
                   int status, merge m)
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
    rprintf("\n" HDR_FMT SEPARATOR, ss("% time"), ss("seconds"), ss("usecs/call"), ss("calls"),
            ss("errors"), ss("syscall"));
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
    rprintf(SEPARATOR SUM_FMT, ss("100.00"), print_usecs(tbuf, tot_usecs), 0, tot_calls, tot_errs,
            ss("total"));
    deallocate_pqueue(pq);
}

static const sstring missing_files_exclude[] = {
    ss_static_init("ld.so.cache"),
};

closure_func_basic(shutdown_handler, void, print_missing_files_cfn,
                   int status, merge m)
{
    buffer b;
    rprintf("missing_files_begin\n");
    vector_foreach(missing_files, b) {
        for (int i = 0; i < sizeof(missing_files_exclude)/sizeof(missing_files_exclude[0]); i++) {
            if (!buffer_compare_with_sstring(b, missing_files_exclude[i]))
                goto next;
        }
        rprintf("%v\n", b);
next:
        continue;
    }
    rprintf("missing_files_end\n");
}

void init_syscalls(process p)
{
    heap h = heap_locked(get_kernel_heaps());
    syscall = syscall_handler;
    syscall_io_complete = closure_func(h, io_completion, syscall_io_complete_cfn);
    io_completion_ignore = closure_func(h, io_completion, io_complete_ignore);
    filesystem fs = p->root_fs;
    vector hostname_v = split(h, alloca_wrap_cstring("etc/hostname"), '/');
    tuple hostname_t = resolve_path(filesystem_getroot(fs), hostname_v);
    split_dealloc(hostname_v);
    if (hostname_t)
        filesystem_read_entire(fs, hostname_t, h,
                               closure_func(h, buffer_handler, hostname_done), ignore_status);
    tuple root = p->process_root;
    do_syscall_stats = get(root, sym(syscall_summary)) != 0;
    if (do_syscall_stats) {
        shutdown_handler print_syscall_stats = closure_func(h, shutdown_handler,
                                                            print_syscall_stats_cfn);
        add_shutdown_completion(print_syscall_stats);
    }
    do_missing_files = get(root, sym(missing_files)) != 0;
    if (do_missing_files) {
        missing_files = allocate_vector(h, 8);
        assert(missing_files != INVALID_ADDRESS);
        shutdown_handler print_missing_files = closure_func(h, shutdown_handler,
                                                            print_missing_files_cfn);
        add_shutdown_completion(print_missing_files);
    }
}

void _init_syscall(struct syscall *m, int n, sstring name, u64 flags)
{
    m[n].name = name;
    m[n].flags = flags;
}

void _register_syscall(struct syscall *m, int n, sysreturn (*f)(), sstring name, u64 flags)
{
    assert(m[n].handler == 0);
    m[n].handler = f;
    m[n].name = name;
    m[n].flags = flags;
}

void *swap_syscall_handler(struct syscall *m, int n, sysreturn (*f)())
{
    sysreturn (*ret)() = m[n].handler;
    m[n].handler = f;
    return ret;
}

static struct trace_set {
    sstring name;
    u64 flag;
} trace_sets[] = {
    { ss_static_init("%file"), SYSCALL_F_SET_FILE },
    { ss_static_init("%desc"), SYSCALL_F_SET_DESC },
    { ss_static_init("%memory"), SYSCALL_F_SET_MEM },
    { ss_static_init("%process"), SYSCALL_F_SET_PROC },
    { ss_static_init("%signal"), SYSCALL_F_SET_SIG },
    { ss_static_init("%net"), SYSCALL_F_SET_NET },
    { ss_static_init("%network"), SYSCALL_F_SET_NET },
};

static void notrace_configure(process p, boolean set)
{
    for (int i = 0; i < sizeof(_linux_syscalls) / sizeof(_linux_syscalls[0]); i++) {
        struct syscall *s = p->syscalls + i;
        if (set)
            s->flags |= SYSCALL_F_NOTRACE;
        else
            s->flags &= ~SYSCALL_F_NOTRACE;
    }
}

closure_function(2, 2, boolean, notrace_each,
                 process, p, boolean, set,
                 value k, value v)
{
    if (peek_char(v) == '%') {
        for (int j = 0; j < sizeof(trace_sets) / sizeof(trace_sets[0]); j++) {
            struct trace_set *ts = trace_sets + j;
            if (buffer_compare_with_sstring(v, ts->name))
                continue;

            for (int i = 0; i < sizeof(_linux_syscalls) / sizeof(_linux_syscalls[0]); i++) {
                struct syscall *s = bound(p)->syscalls + i;
                if (sstring_is_null(s->name) || !(s->flags & ts->flag))
                    continue;

                if (bound(set))
                    s->flags |= SYSCALL_F_NOTRACE;
                else
                    s->flags &= ~SYSCALL_F_NOTRACE;
            }
            break;
        }
    } else {
        for (int i = 0; i < sizeof(_linux_syscalls) / sizeof(_linux_syscalls[0]); i++) {
            struct syscall *s = bound(p)->syscalls + i;
            if (sstring_is_null(s->name) || buffer_compare_with_sstring(v, s->name))
                continue;

            if (bound(set))
                s->flags |= SYSCALL_F_NOTRACE;
            else
                s->flags &= ~SYSCALL_F_NOTRACE;
            break;
        }
    }
    return true;
}

closure_func_basic(set_value_notify, boolean, debugsyscalls_notify,
                   value v)
{
    debugsyscalls = !!v;
    return true;
}

closure_function(1, 1, boolean, notrace_notify,
                 process, p,
                 value v)
{
    notrace_configure(bound(p), false);
    if (is_composite(v))
        iterate(v, stack_closure(notrace_each, bound(p), true));
    return true;
}

closure_function(1, 1, boolean, tracelist_notify,
                 process, p,
                 value v)
{
    notrace_configure(bound(p), true);
    if (is_composite(v))
        iterate(v, stack_closure(notrace_each, bound(p), false));
    return true;
}

void configure_syscalls(process p)
{
    heap h = heap_locked(&p->uh->kh);
    register_root_notify(sym(debugsyscalls),
                         closure_func(h, set_value_notify, debugsyscalls_notify));
    register_root_notify(sym(notrace), closure(h, notrace_notify, p));
    register_root_notify(sym(tracelist), closure(h, tracelist_notify, p));
}
