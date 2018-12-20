#include <unix_internal.h>

#define  PIPE_DEBUG
#ifdef PIPE_DEBUG
#define pipe_debug(x, ...) do {log_printf("PIPE", x, ##__VA_ARGS__);} while(0)
#else
#define pipe_debug(x, ...)
#endif

static CLOSURE_0_3(pipe_read, sysreturn, void *, u64, u64);
static sysreturn pipe_read(void *dest, u64 length, u64 offset_arg)
{
    thread_log(current, "%s: dest %p, length %d, offset_arg %d\n",
	       __func__, dest, length, offset_arg);
    return 0;
}

static CLOSURE_1_0(pipe_close, sysreturn, file);
static sysreturn pipe_close(file f)
{
    pipe_debug("closing - %p\n", f);
    unix_cache_free(get_unix_heaps(), file, f);
    return 0;
}

static CLOSURE_0_3(pipe_write, sysreturn, void*, u64, u64);
static sysreturn pipe_write(void *d, u64 length, u64 offset)
{
    pipe_debug("write - %p\n", d);
    u8 *z = d;
    return length;
}


int do_pipe2(heap h, int fds[2], int flags)
{
    unix_heaps uh = get_unix_heaps();
    h = heap_general((kernel_heaps)uh);
    file in = unix_cache_alloc(uh, file);
    file out = unix_cache_alloc(uh, file);

    if (!in || !out) {
        msg_err("failed to allocate files\n");
        return -ENOMEM;
    }
    fds[0] = allocate_fd(current->p, in);
    fds[1] = allocate_fd(current->p, out);
    in->write = out->write = closure(h, pipe_write);
    in->read = out->read = closure(h, pipe_read);
    in->close = closure(h, pipe_close, in);
    out->close = closure(h, pipe_close, out);
    return 0;
}


