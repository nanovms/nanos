#include <unix_internal.h>
#include <buffer.h>

#ifdef PIPE_DEBUG
#define pipe_debug(x, ...) do {log_printf("PIPE", x, ##__VA_ARGS__);} while(0)
#else
#define pipe_debug(x, ...)
#endif

#define INITIAL_PIPE_DATA_SIZE  100
#define DEFAULT_PIPE_MAX_SIZE   (16 * PAGESIZE) /* see pipe(7) */
#define PIPE_READ               0
#define PIPE_WRITE              1

struct pipe_struct;

typedef struct pipe_file_struct {
    struct file f;
    int fd;
    struct pipe_struct *pipe;
    notify_set ns;
    blockq bq;
} *pipe_file;

typedef struct pipe_struct {
    struct pipe_file_struct files[2];
    process p;
    heap h;
    u64 ref_cnt;
    u64 max_size;               /* XXX: can change with F_SETPIPE_SZ */
    buffer data;
} *pipe;

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

    uh->pipe_cache = allocate_objcache(general, backed, sizeof(struct pipe_struct), PAGESIZE);
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
        notify_dispatch(read_pf->ns, events);
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
        notify_dispatch(write_pf->ns, events);
    }
}

static void pipe_release(pipe p)
{
    if (!p->ref_cnt || (fetch_and_add(&p->ref_cnt, -1) == 0)) {
        pipe_debug("%s(%p): deallocating pipe\n", __func__, p);
        if (p->data != INVALID_ADDRESS)
            deallocate_buffer(p->data);

        unix_cache_free(get_unix_heaps(), pipe, p);
    }
}

static inline void pipe_dealloc_end(pipe p, pipe_file pf)
{
    if (pf->fd != -1) {
        if (&p->files[PIPE_READ] == pf) {
            pipe_notify_writer(pf, EPOLLHUP);
            pipe_debug("%s(%p): writer notified\n", __func__, p);
        }
        if (&p->files[PIPE_WRITE] == pf) {
            pipe_notify_reader(pf, EPOLLIN | EPOLLHUP);
            pipe_debug("%s(%p): reader notified\n", __func__, p);
        }
        deallocate_notify_set(pf->ns);
        deallocate_blockq(pf->bq);
        pf->fd = -1;
        pipe_release(p);
    }
}

static CLOSURE_1_0(pipe_close, sysreturn, file);
static sysreturn pipe_close(file f)
{
    pipe_file pf = (pipe_file)f;
    pipe_dealloc_end(pf->pipe, pf);
    return 0;
}

static CLOSURE_4_1(pipe_read_bh, sysreturn, pipe_file, thread, void *, u64, boolean);
static sysreturn pipe_read_bh(pipe_file pf, thread t, void *dest, u64 length, boolean blocked)
{
    buffer b = pf->pipe->data;
    int real_length = MIN(buffer_length(b), length);
    if (real_length == 0) {
        if (pf->pipe->files[PIPE_WRITE].fd == -1)
            goto out;
        return infinity;
    }

    buffer_read(b, dest, real_length);
    pipe_notify_writer(pf, EPOLLOUT);

    // If we have consumed all of the buffer, reset it. This might prevent future writes to allocte new buffer
    // in buffer_write/buffer_extend. Can improve things until a proper circular buffer is available
    if (buffer_length(b) == 0) {
        buffer_clear(b);
        notify_dispatch(pf->ns, 0); /* for edge trigger */
    }
  out:
    if (blocked)
        thread_wakeup(t);

    return set_syscall_return(t, real_length);
}

static CLOSURE_1_3(pipe_read, sysreturn, file, void *, u64, u64);
static sysreturn pipe_read(file f, void *dest, u64 length, u64 offset_arg)
{
    pipe_file pf = (pipe_file)f;

    if (length == 0)
        return 0;

    blockq_action ba = closure(pf->pipe->h, pipe_read_bh, pf, current, dest, length);
    sysreturn rv = blockq_check(pf->bq, current, ba);

    /* direct return */
    if (rv != infinity)
        return rv;

    /* XXX ideally we could just prevent this case if we had growing
       queues... for now bark and return EAGAIN */
    msg_err("thread %d unable to block; queue full\n", current->tid);
    return -EAGAIN;
}

static CLOSURE_4_1(pipe_write_bh, sysreturn, pipe_file, thread, void *, u64, boolean);
static sysreturn pipe_write_bh(pipe_file pf, thread t, void *dest, u64 length, boolean blocked)
{
    sysreturn rv = 0;
    pipe p = pf->pipe;
    buffer b = p->data;
    u64 avail = p->max_size - buffer_length(b);

    if (avail == 0) {
        if (pf->pipe->files[PIPE_READ].fd == -1) {
            rv = -EPIPE;
            goto out;
        }
        return infinity;
    }

    u64 real_length = MIN(length, avail);
    buffer_write(b, dest, real_length);
    if (avail == length)
        notify_dispatch(pf->ns, 0); /* for edge trigger */

    pipe_notify_reader(pf, EPOLLIN);

    rv = real_length;
  out:
    if (blocked)
        thread_wakeup(t);

    return set_syscall_return(t, rv);
}

static CLOSURE_1_3(pipe_write, sysreturn, file, void *, u64, u64);
static sysreturn pipe_write(file f, void * dest, u64 length, u64 offset)
{
    pipe_file pf = (pipe_file)f;

    if (length == 0)
        return 0;

    blockq_action ba = closure(pf->pipe->h, pipe_write_bh, pf, current, dest, length);
    sysreturn rv = blockq_check(pf->bq, current, ba);

    /* direct return */
    if (rv != infinity)
        return rv;

    /* bogus */
    msg_err("thread %d unable to block; queue full\n", current->tid);
    return set_syscall_error(current, EAGAIN);
}

static boolean pipe_check_internal(pipe_file pf, u32 events, u32 eventmask,
                                   u32 * last, event_handler eh)
{
    u32 report = edge_events(events, eventmask, last);
    if (report) {
        return apply(eh, report);
    } else {
        if (!notify_add(pf->ns, eventmask, last, eh))
	    msg_err("notify enqueue fail: out of memory\n");
        return true;
    }
}

static CLOSURE_1_3(pipe_read_check, boolean, file, u32, u32 *, event_handler);
static boolean pipe_read_check(file f, u32 eventmask, u32 * last, event_handler eh)
{
    pipe_file pf = (pipe_file)f;
    assert(f->read);
    u32 events = buffer_length(pf->pipe->data) ? EPOLLIN : 0;
    if (pf->pipe->files[PIPE_WRITE].fd == -1)
        events |= EPOLLIN | EPOLLHUP;
    return pipe_check_internal(pf, events, eventmask, last, eh);
}

static CLOSURE_1_3(pipe_write_check, boolean, file, u32, u32 *, event_handler);
static boolean pipe_write_check(file f, u32 eventmask, u32 * last, event_handler eh)
{
    pipe_file pf = (pipe_file)f;
    assert(f->write);
    u32 events = buffer_length(pf->pipe->data) < pf->pipe->max_size ? EPOLLOUT : 0;
    if (pf->pipe->files[PIPE_READ].fd == -1)
        events |= EPOLLHUP;
    return pipe_check_internal(pf, events, eventmask, last, eh);
}

#define PIPE_BLOCKQ_LEN         32

int do_pipe2(int fds[2], int flags)
{
    unix_heaps uh = get_unix_heaps();

    pipe pipe = unix_cache_alloc(get_unix_heaps(), pipe);
    if (pipe == INVALID_ADDRESS) {
        msg_err("failed to allocate struct pipe\n");
        return -ENOMEM;
    }

    pipe->data = INVALID_ADDRESS;
    pipe->files[PIPE_READ].fd = -1;
    pipe->files[PIPE_WRITE].fd = -1;
    pipe->h = heap_general((kernel_heaps)uh);
    pipe->p = current->p;
    pipe->files[PIPE_READ].pipe = pipe;
    pipe->files[PIPE_WRITE].pipe = pipe;
    pipe->ref_cnt = 0;
    pipe->max_size = DEFAULT_PIPE_MAX_SIZE;
    pipe->data = allocate_buffer(pipe->h, INITIAL_PIPE_DATA_SIZE);
    if (pipe->data == INVALID_ADDRESS) {
        msg_err("failed to allocate pipe's data buffer\n");
        pipe_release(pipe);
        return -ENOMEM;
    }

    file reader = (file)&pipe->files[PIPE_READ];
    file writer = (file)&pipe->files[PIPE_WRITE];

    pipe->files[PIPE_READ].fd = fds[PIPE_READ] = allocate_fd(pipe->p, reader);
    pipe->files[PIPE_READ].ns = allocate_notify_set(pipe->h);
    pipe->files[PIPE_READ].bq = allocate_blockq(pipe->h, "pipe read",
                                                     PIPE_BLOCKQ_LEN, 0);
    pipe->files[PIPE_WRITE].fd = fds[PIPE_WRITE] = allocate_fd(pipe->p, writer);
    pipe->files[PIPE_WRITE].ns = allocate_notify_set(pipe->h);
    pipe->files[PIPE_WRITE].bq = allocate_blockq(pipe->h, "pipe write",
                                                      PIPE_BLOCKQ_LEN, 0);
    pipe->ref_cnt = 2;

    writer->write = closure(pipe->h, pipe_write, writer);
    writer->read = 0;
    writer->close = closure(pipe->h, pipe_close, writer);
    writer->check = closure(pipe->h, pipe_write_check, writer);

    reader->read = closure(pipe->h, pipe_read, reader);
    reader->write = 0;
    reader->close = closure(pipe->h, pipe_close, reader);
    reader->check = closure(pipe->h, pipe_read_check, reader);
    return 0;
}
