#include <unix_internal.h>
#include <buffer.h>

#define  PIPE_DEBUG
#ifdef PIPE_DEBUG
#define pipe_debug(x, ...) do {log_printf("PIPE", x, ##__VA_ARGS__);} while(0)
#else
#define pipe_debug(x, ...)
#endif

#define INITIAL_PIPE_DATA_SIZE  100

struct pipe_struct;

typedef struct pipe_file_struct {
    struct file f;
    int fd;
    struct pipe_struct *pipe;
} *pipe_file;

typedef struct pipe_struct {
    struct pipe_file_struct files[2];
    process p;
    heap h;
    u64 ref_cnt;
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

static void pipe_release(pipe p)
{
    if (!p->ref_cnt || (fetch_and_add(&p->ref_cnt, -1) == 0)) {
        if (p->data != INVALID_ADDRESS)
            deallocate_buffer(p->data);

        if (p->files[0].fd != -1)
            deallocate_fd(p->p, p->files[0].fd, &p->files[0].f);
        if (p->files[1].fd != -1)
            deallocate_fd(p->p, p->files[1].fd, &p->files[1].f);

        unix_cache_free(get_unix_heaps(), pipe, p);
    }
}

static CLOSURE_1_0(pipe_close, sysreturn, file);
static sysreturn pipe_close(file f)
{
    pipe_file pf = (pipe_file)f;    
    pipe_release(pf->pipe);
    return 0;
}

static CLOSURE_1_3(pipe_read, sysreturn, file, void *, u64, u64);
static sysreturn pipe_read(file f, void *dest, u64 length, u64 offset_arg)
{
    pipe_file pf = (pipe_file)f;    
    buffer b = pf->pipe->data;

    int real_length = buffer_length(b);

    real_length = MIN(real_length, length); 
    buffer_read(b, dest, real_length);
    // If we have consumed all of the buffer, reset it. This might prevent future writes to allocte new buffer
    // in buffer_write/buffer_extend. Can improve things until a proper circular buffer is available 
    if (!buffer_length(b))
        buffer_clear(b);
    return real_length;
}

static CLOSURE_1_4(pipe_write, sysreturn, file, void*, u64, u64, int);
static sysreturn pipe_write(file f, void *d, u64 length, u64 offset, int is_blocking)
{
    pipe_file pf = (pipe_file)f;    
    buffer_write(pf->pipe->data, d, length);
    return length;
}

int do_pipe2(int fds[2], int flags)
{
    unix_heaps uh = get_unix_heaps();

    pipe pipe = unix_cache_alloc(get_unix_heaps(), pipe);
    if (pipe == INVALID_ADDRESS) {
        msg_err("failed to allocate struct pipe\n");
        return -ENOMEM;
    }

    pipe->data = INVALID_ADDRESS;
    pipe->files[0].fd = -1;
    pipe->files[1].fd = -1;
    pipe->h = heap_general((kernel_heaps)uh);
    pipe->p = current->p;
    pipe->files[0].pipe = pipe;
    pipe->files[1].pipe = pipe;
    pipe->ref_cnt = 0;
    pipe->data = allocate_buffer(pipe->h, INITIAL_PIPE_DATA_SIZE);
    if (pipe->data == INVALID_ADDRESS) {
        msg_err("failed to allocate pipe's data buffer\n");
        pipe_release(pipe);
        return -ENOMEM;
    }

    file reader = (file)&pipe->files[0];
    file writer = (file)&pipe->files[1];

    pipe->files[0].fd = fds[0] = allocate_fd(pipe->p, reader);
    pipe->files[1].fd = fds[1] = allocate_fd(pipe->p, writer);
    pipe->ref_cnt = 2;

    writer->write = closure(pipe->h, pipe_write, writer);
    writer->sendfile = 0;
    writer->type = FILE_PIPE;
    writer->read = 0;
    writer->close = closure(pipe->h, pipe_close, writer);

    reader->read = closure(pipe->h, pipe_read, reader);
    reader->sendfile = 0;
    reader->type = FILE_PIPE;
    reader->write = 0;
    reader->close = closure(pipe->h, pipe_close, reader);
    return 0;
}
