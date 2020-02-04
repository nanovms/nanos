#include <unix_internal.h>

//#define PIPE_DEBUG
#ifdef PIPE_DEBUG
#define pipe_debug(x, ...) do {log_printf("PIPE", x, ##__VA_ARGS__);} while(0)
#else
#define pipe_debug(x, ...)
#endif

#define INITIAL_PIPE_DATA_SIZE  100
#define DEFAULT_PIPE_MAX_SIZE   (16 * PAGESIZE) /* see pipe(7) */
#define PIPE_READ               0
#define PIPE_WRITE              1

typedef struct pipe *pipe;

typedef struct pipe_file *pipe_file;

struct pipe_file {
    struct fdesc f;       /* must be first */
    int fd;
    pipe pipe;
    blockq bq;
};

struct pipe {
    struct pipe_file files[2];
    process proc;
    heap h;
    u64 ref_cnt;
    u64 max_size;               /* XXX: can change with F_SETPIPE_SZ */
    buffer data;
};

#define BUFFER_DEBUG(BUF,LENGTH) do { \
    pipe_debug("%s:%d - requested %d -- contents %p start/end %d/%d  -- len %d %d\n", \
        __func__, __LINE__, \
        (LENGTH), \
        (BUF)->contents, \
        (BUF)->start, \
        (BUF)->end, \
        (BUF)->length, buffer_length((BUF))); \
} while(0)

boolean pipe_init(unix_heaps uh)
{
    heap general = heap_general((kernel_heaps)uh);
    heap backed = heap_backed((kernel_heaps)uh);

    uh->pipe_cache = allocate_objcache(general, backed, sizeof(struct pipe), PAGESIZE);
    return (uh->pipe_cache == INVALID_ADDRESS ? false : true);
}

static inline void pipe_notify_reader(pipe_file pf, int events)
{
    pipe_file read_pf = &pf->pipe->files[PIPE_READ];
    if (read_pf->fd != -1) {
        if (events & EPOLLHUP)
            blockq_flush(read_pf->bq);
        else
            blockq_wake_one(read_pf->bq);
        notify_dispatch(read_pf->f.ns, events);
    }
}

static inline void pipe_notify_writer(pipe_file pf, int events)
{
    pipe_file write_pf = &pf->pipe->files[PIPE_WRITE];
    if (write_pf->fd != -1) {
        if (events & EPOLLHUP)
            blockq_flush(write_pf->bq);
        else
            blockq_wake_one(write_pf->bq);
        notify_dispatch(write_pf->f.ns, events);
    }
}

static void pipe_file_release(pipe_file pf)
{
    release_fdesc(&(pf->f));

    if (pf->fd > 0) {
        /* sys_close could have deallocated fds already */
        if (resolve_fd_noret(pf->pipe->proc, pf->fd))
            deallocate_fd(pf->pipe->proc, pf->fd);

        pf->fd = -1;
    }

    if (pf->bq != INVALID_ADDRESS) {
        deallocate_blockq(pf->bq);
        pf->bq = INVALID_ADDRESS;
    }
}

static void pipe_release(pipe p)
{
    if (!p->ref_cnt || (fetch_and_add(&p->ref_cnt, -1) == 1)) {
        pipe_debug("%s(%p): deallocating pipe\n", __func__, p);
        if (p->data != INVALID_ADDRESS)
            deallocate_buffer(p->data);

        pipe_file_release(&(p->files[PIPE_READ]));
        pipe_file_release(&(p->files[PIPE_WRITE]));

        unix_cache_free(get_unix_heaps(), pipe, p);
    }
}

static inline void pipe_dealloc_end(pipe p, pipe_file pf)
{
    if (pf->fd != -1) {
        if (&p->files[PIPE_READ] == pf) {
            pipe_notify_writer(pf, EPOLLHUP);
            pipe_debug("%s(%p): writer notified\n", __func__, p);
            deallocate_closure(pf->f.read);
            deallocate_closure(pf->f.close);
            deallocate_closure(pf->f.events);
        }
        if (&p->files[PIPE_WRITE] == pf) {
            pipe_notify_reader(pf, EPOLLIN | EPOLLHUP);
            pipe_debug("%s(%p): reader notified\n", __func__, p);
            deallocate_closure(pf->f.write);
            deallocate_closure(pf->f.close);
            deallocate_closure(pf->f.events);
        }

        pipe_release(p);
    }
}

closure_function(1, 0, sysreturn, pipe_close,
                 pipe_file, pf)
{
    pipe_dealloc_end(bound(pf)->pipe, bound(pf));
    return 0;
}

closure_function(5, 1, sysreturn, pipe_read_bh,
                 pipe_file, pf, thread, t, void *, dest, u64, length, io_completion, completion,
                 u64, flags)
{
    pipe_file pf = bound(pf);
    int rv;

    if (flags & BLOCKQ_ACTION_NULLIFY) {
        rv = -EINTR;
        goto out;
    }

    buffer b = pf->pipe->data;
    rv = MIN(buffer_length(b), bound(length));
    if (rv == 0) {
        if (pf->pipe->files[PIPE_WRITE].fd == -1)
            goto out;
        if (pf->f.flags & O_NONBLOCK) {
            rv = -EAGAIN;
            goto out;
        }
        return BLOCKQ_BLOCK_REQUIRED;
    }

    buffer_read(b, bound(dest), rv);
    pipe_notify_writer(pf, EPOLLOUT);

    // If we have consumed all of the buffer, reset it. This might prevent future writes to allocte new buffer
    // in buffer_write/buffer_extend. Can improve things until a proper circular buffer is available
    if (buffer_length(b) == 0) {
        buffer_clear(b);
        notify_dispatch(pf->f.ns, 0); /* for edge trigger */
    }
  out:
    blockq_handle_completion(pf->bq, flags, bound(completion), bound(t), rv);
    closure_finish();
    return rv;
}

closure_function(1, 6, sysreturn, pipe_read,
                 pipe_file, pf,
                 void *, dest, u64, length, u64, offset_arg, thread, t, boolean, bh, io_completion, completion)
{
    pipe_file pf = bound(pf);

    if (length == 0)
        return 0;

    blockq_action ba = closure(pf->pipe->h, pipe_read_bh, pf, t, dest, length,
                               completion);
    return blockq_check(pf->bq, t, ba, bh);
}

closure_function(5, 1, sysreturn, pipe_write_bh,
                 pipe_file, pf, thread, t, void *, dest, u64, length, io_completion, completion,
                 u64, flags)
{
    sysreturn rv = 0;
    pipe_file pf = bound(pf);

    if (flags & BLOCKQ_ACTION_NULLIFY) {
        rv = -EINTR;
        goto out;
    }

    u64 length = bound(length);
    pipe p = pf->pipe;
    buffer b = p->data;
    u64 avail = p->max_size - buffer_length(b);

    if (avail == 0) {
        if (pf->pipe->files[PIPE_READ].fd == -1) {
            rv = -EPIPE;
            goto out;
        }
        if (pf->f.flags & O_NONBLOCK) {
            rv = -EAGAIN;
            goto out;
        }
        return BLOCKQ_BLOCK_REQUIRED;
    }

    u64 real_length = MIN(length, avail);
    buffer_write(b, bound(dest), real_length);
    if (avail == length)
        notify_dispatch(pf->f.ns, 0); /* for edge trigger */

    pipe_notify_reader(pf, EPOLLIN);

    rv = real_length;
  out:
    blockq_handle_completion(pf->bq, flags, bound(completion), bound(t), rv);
    closure_finish();
    return rv;
}

closure_function(1, 6, sysreturn, pipe_write,
                 pipe_file, pf,
                 void *, dest, u64, length, u64, offset, thread, t, boolean, bh, io_completion, completion)
{
    if (length == 0)
        return 0;

    pipe_file pf = bound(pf);
    blockq_action ba = closure(pf->pipe->h, pipe_write_bh, pf, t, dest, length,
            completion);
    return blockq_check(pf->bq, t, ba, bh);
}

closure_function(1, 1, u32, pipe_read_events,
                 pipe_file, pf,
                 thread, t /* ignore */)
{
    pipe_file pf = bound(pf);
    assert(pf->f.read);
    u32 events = buffer_length(pf->pipe->data) ? EPOLLIN : 0;
    if (pf->pipe->files[PIPE_WRITE].fd == -1)
        events |= EPOLLIN | EPOLLHUP;
    return events;
}

closure_function(1, 1, u32, pipe_write_events,
                 pipe_file, pf,
                 thread, t /* ignore */)
{
    pipe_file pf = bound(pf);
    assert(pf->f.write);
    u32 events = buffer_length(pf->pipe->data) < pf->pipe->max_size ? EPOLLOUT : 0;
    if (pf->pipe->files[PIPE_READ].fd == -1)
        events |= EPOLLHUP;
    return events;
}

int do_pipe2(int fds[2], int flags)
{
    unix_heaps uh = get_unix_heaps();

    pipe pipe = unix_cache_alloc(get_unix_heaps(), pipe);
    if (pipe == INVALID_ADDRESS) {
        msg_err("failed to allocate struct pipe\n");
        return -ENOMEM;
    }

    if (flags & ~(O_CLOEXEC | O_DIRECT | O_NONBLOCK))
        return -EINVAL;

    if (flags & O_DIRECT) {
        msg_err("O_DIRECT unsupported\n");
        return -EOPNOTSUPP;
    }

    pipe->h = heap_general((kernel_heaps)uh);
    pipe->data = INVALID_ADDRESS;
    pipe->proc = current->p;

    pipe->files[PIPE_READ].fd = -1;
    pipe->files[PIPE_READ].pipe = pipe;
    pipe->files[PIPE_READ].bq = INVALID_ADDRESS;

    pipe->files[PIPE_WRITE].fd = -1;
    pipe->files[PIPE_WRITE].pipe = pipe;
    pipe->files[PIPE_WRITE].bq = INVALID_ADDRESS;

    pipe->ref_cnt = 0;
    pipe->max_size = DEFAULT_PIPE_MAX_SIZE;

    pipe->data = allocate_buffer(pipe->h, INITIAL_PIPE_DATA_SIZE);
    if (pipe->data == INVALID_ADDRESS) {
        msg_err("failed to allocate pipe's data buffer\n");
        goto err;
    }

    /* init reader */
    {
        pipe_file reader = &pipe->files[PIPE_READ];
        init_fdesc(pipe->h, &reader->f, FDESC_TYPE_PIPE);

        reader->fd = fds[PIPE_READ] = allocate_fd(pipe->proc, reader);
        if (reader->fd == INVALID_PHYSICAL) {
            msg_err("failed to allocate fd\n");
            goto err;
        }

        reader->f.read = closure(pipe->h, pipe_read, reader);
        reader->f.close = closure(pipe->h, pipe_close, reader);
        reader->f.events = closure(pipe->h, pipe_read_events, reader);
        reader->f.flags = (flags & O_NONBLOCK) | O_RDONLY;

        reader->bq = allocate_blockq(pipe->h, "pipe read");
        if (reader->bq == INVALID_ADDRESS) {
            msg_err("failed to allocate blockq\n");
            goto err;
        }
    }

    /* init writer */
    {
        pipe_file writer = &pipe->files[PIPE_WRITE];
        init_fdesc(pipe->h, &writer->f, FDESC_TYPE_PIPE);

        writer->fd = fds[PIPE_WRITE] = allocate_fd(pipe->proc, writer);
        if (writer->fd == INVALID_PHYSICAL) {
            msg_err("failed to allocate fd\n");
            goto err;
        }

        writer->f.write = closure(pipe->h, pipe_write, writer);
        writer->f.close = closure(pipe->h, pipe_close, writer);
        writer->f.events = closure(pipe->h, pipe_write_events, writer);
        writer->f.flags = (flags & O_NONBLOCK) | O_WRONLY;

        writer->bq = allocate_blockq(pipe->h, "pipe write");
        if (writer->bq == INVALID_ADDRESS) {
            msg_err("failed to allocate blockq\n");
            goto err;
        }
    }

    pipe->ref_cnt = 2;
    return 0;

err:
    pipe_release(pipe);
    return -ENOMEM;
}
