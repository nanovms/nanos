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
    u64 ref_cnt;;
    buffer data;
} *pipe;

boolean pipe_init(unix_heaps uh)
{
    heap general = heap_general((kernel_heaps)uh);
    heap backed = heap_backed((kernel_heaps)uh);

    uh->pipe_cache = allocate_objcache(general, backed, sizeof(struct pipe_struct), PAGESIZE);
    return (uh->pipe_cache == INVALID_ADDRESS ? false : true);
}

static void pipe_release(pipe p)
{
    pipe_debug("pipe_release:cnt %d\n", p->ref_cnt);
    if (!p->ref_cnt || (fetch_and_add(&p->ref_cnt, -1) == 0))
        unix_cache_free(get_unix_heaps(), pipe, p);
}

static CLOSURE_1_0(pipe_close, sysreturn, file);
static sysreturn pipe_close(file f)
{
    pipe_file pf = (pipe_file)f;    
    pipe_debug("closing - %p\n", pf);
    pipe_release(pf->pipe);
    return 0;
}

static CLOSURE_1_3(pipe_read, sysreturn, file, void *, u64, u64);
static sysreturn pipe_read(file f, void *dest, u64 length, u64 offset_arg)
{
    pipe_file pf = (pipe_file)f;    
    int real_length = buffer_length(pf->pipe->data);

    real_length = MIN(real_length, length); 
    pipe_debug("read - %p\n", f);
    thread_log(current, "%s: dest %p, length %d, offset_arg %d\n",
	       __func__, dest, length, offset_arg);
    buffer_read(pf->pipe->data, dest, real_length);
    return real_length;
}

static CLOSURE_1_3(pipe_write, sysreturn, file, void*, u64, u64);
static sysreturn pipe_write(file f, void *d, u64 length, u64 offset)
{
    pipe_file pf = (pipe_file)f;    
    pipe_debug("write - %p\n", f);
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

    pipe_debug("reader %p writer %p\n", reader, writer);

    pipe->files[0].fd = fds[0] = allocate_fd(pipe->p, reader);
    pipe->files[1].fd = fds[1] = allocate_fd(pipe->p, writer);
    pipe->ref_cnt = 2;

    writer->write = closure(pipe->h, pipe_write, writer);
    reader->read = closure(pipe->h, pipe_read, reader);
    reader->close = closure(pipe->h, pipe_close, reader);
    writer->close = closure(pipe->h, pipe_close, writer);
    return 0;
}


