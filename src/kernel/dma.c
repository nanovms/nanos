#include <kernel.h>
#include <dma.h>

closure_function(2, 3, void, dma_simple_io,
                 sg_io_func, io, void *, priv,
                 sg_list sg, range r, status_handler completion)
{
    bound(io)(bound(priv), sg, r, completion);
}

BSS_RO_AFTER_INIT static struct {
    heap general;
    heap io;
    boolean bounce_buffering;
} dma;

void dma_init(kernel_heaps kh)
{
    dma.general = heap_locked(kh);
    dma.io = kh->dma;
    dma.bounce_buffering = (dma.io != dma.general);
}

closure_function(6, 1, void, dma_sg_io_complete,
                 sg_list, sg, sg_list, dma_sg, void *, buf, u64, buf_size, boolean, write, status_handler, completion,
                 status s)
{
    sg_list sg = bound(sg);
    sg_list dma_sg = bound(dma_sg);
    void *buf = bound(buf);
    u64 buf_size = bound(buf_size);
    if (!bound(write) && is_ok(s))
        sg_copy_from_buf(buf, sg, buf_size - dma_sg->count);
    deallocate(dma.io, buf, buf_size);
    deallocate_sg_list(dma_sg);
    apply(bound(completion), s);
    closure_finish();
}

static void dma_sg_io(sg_io_func op, void *priv, sg_list sg, range r, boolean write,
                      status_handler completion)
{
    sg_list dma_sg = allocate_sg_list();
    if (dma_sg == INVALID_ADDRESS)
        goto oom;
    u64 len = sg->count;
    void *buf = allocate(dma.io, len);
    if (buf == INVALID_ADDRESS)
        goto err_buf;
    status_handler dma_completion = closure(dma.general, dma_sg_io_complete, sg, dma_sg, buf, len,
                                            write, completion);
    if (dma_completion == INVALID_ADDRESS)
        goto err_closure;
    sg_buf sgb = sg_list_tail_add(dma_sg, len);
    sgb->buf = buf;
    sgb->size = len;
    sgb->offset = 0;
    sgb->refcount = 0;
    if (write)
        sg_copy_to_buf(buf, sg, len);
    op(priv, dma_sg, r, dma_completion);
    return;
  err_closure:
    deallocate(dma.io, buf, len);
  err_buf:
    deallocate_sg_list(dma_sg);
  oom:
    apply(completion, timm_oom);
}

closure_function(2, 3, void, dma_read,
                 sg_io_func, io, void *, priv,
                 sg_list sg, range r, status_handler completion)
{
    dma_sg_io(bound(io), bound(priv), sg, r, false, completion);
}

sg_io dma_new_reader(heap h, sg_io_func read, void *priv)
{
    sg_io reader;
    if (dma.bounce_buffering) {
        reader = closure(h, dma_read, read, priv);
    } else {
        reader = closure(h, dma_simple_io, read, priv);
    }
    return reader;
}

closure_function(2, 3, void, dma_write,
                 sg_io_func, io, void *, priv,
                 sg_list sg, range r, status_handler completion)
{
    dma_sg_io(bound(io), bound(priv), sg, r, true, completion);
}

sg_io dma_new_writer(heap h, sg_io_func write, void *priv)
{
    sg_io writer;
    if (dma.bounce_buffering) {
        writer = closure(h, dma_write, write, priv);
    } else {
        writer = closure(h, dma_simple_io, write, priv);
    }
    return writer;
}
