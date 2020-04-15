#include <runtime.h>

//#define SG_DEBUG
#if defined(SG_DEBUG)
#define sg_debug(x, ...) do {rprintf("SG:  " x, ##__VA_ARGS__);} while(0)
#else
#define sg_debug(x, ...)
#endif

#define DEFAULT_SG_FRAGS 8

static heap sg_heap;
static struct list free_sg_lists;

#ifndef BOOT
static struct spinlock sg_spinlock;   /* for free list */
static inline void sg_lock_init(void)
{
    spin_lock_init(&sg_spinlock);
}

static inline void sg_lock(void)
{
    spin_lock(&sg_spinlock);
}

static inline void sg_unlock(void)
{
    spin_unlock(&sg_spinlock);
}
#else
#define sg_lock_init()
#define sg_lock()
#define sg_unlock()
#endif

/* copy content of sg, up to limit bytes, into target, consuming and
   deallocating everything */
u64 sg_copy_to_buf_and_release(void *target, sg_list sg, u64 limit)
{
    sg_buf sgb;
    u64 written = 0;

    sg_debug("%s: target %p, sg %p, limit 0x%lx, count %ld\n", __func__, target, sg, limit, sg->count);
    while ((sgb = sg_list_head_remove(sg)) != INVALID_ADDRESS) {
        u64 len = MIN(sgb->length, limit);
        if (len > 0) {
            runtime_memcpy(target + written, sgb->buf, len);
            written += len;
            limit -= len;
        }
        /* release all buffers */
        sg_buf_release(sgb);
    }
    deallocate_sg_list(sg);
    sg_debug("   total written: %ld\n", written);
    return written;
}

sg_list allocate_sg_list(void)
{
    sg_lock();
    list l = list_get_next(&free_sg_lists);
    if (l) {
        list_delete(l);
        sg_unlock();
        return struct_from_list(l, sg_list, l);
    }
    sg_unlock();

    sg_list sg = allocate(sg_heap, sizeof(struct sg_list));
    if (!sg)
        return sg;
    sg->b = allocate_buffer(sg_heap, sizeof(struct sg_buf) * DEFAULT_SG_FRAGS);
    if (sg->b == INVALID_ADDRESS) {
        deallocate(sg_heap, sg, sizeof(struct sg_list));
        return INVALID_ADDRESS;
    }
    list_init(&sg->l);
    sg->count = 0;
    return sg;
}

void deallocate_sg_list(sg_list sg)
{
    buffer_clear(sg->b);
    sg->count = 0;
    sg_lock();
    list_insert_after(&free_sg_lists, &sg->l);
    sg_unlock();
}

closure_function(4, 0, void, sg_wrapped_buf_release,
                 refcount, refcount, heap, backed, void *, buf, bytes, padlen)
{
    deallocate(sg_heap, bound(refcount), sizeof(struct refcount));
    deallocate(bound(backed), bound(buf), bound(padlen));
    closure_finish();
}

/* wrap linear block io into an sg reader - for uses without pagecache (stage2, dump) */
closure_function(3, 3, void, sg_wrapped_read,
                 block_io, block_read, int, block_order, heap, backed,
                 sg_list, sg, range, q, status_handler, sh)
{
    int block_order = bound(block_order);
    bytes length = range_span(q);
    bytes padlen = pad(length, 1 << block_order);
    void *buf = allocate(bound(backed), padlen);
    sg_debug("%s: io %p, order %d, backed %p, sg %p, range %R, sh %p\n",
             __func__, bound(block_read), block_order, bound(backed), sg, q, sh);

    if (buf == INVALID_ADDRESS) {
        apply(sh, timm("result", "%s: failed to allocate backed buffer of size %ld",
                       __func__, padlen));
        return;
    }
    refcount refcount = allocate(sg_heap, sizeof(struct refcount));
    if (refcount == INVALID_ADDRESS) {
        apply(sh, timm("result", "%s: alloc failed", __func__));
        return;
    }
    init_refcount(refcount, 1, closure(sg_heap, sg_wrapped_buf_release,
                                       refcount, bound(backed), buf, padlen));
    sg_buf sgb = sg_list_tail_add(sg, length);
    sgb->buf = buf;
    sgb->length = length;
    sgb->refcount = refcount;
    assert((q.start & MASK(block_order)) == 0);
    range blocks = range_rshift(irange(q.start, q.start + padlen), block_order);
    sg_debug("   reading into sgb %p, buf %p, blocks %R\n", sgb, buf, blocks);
    apply(bound(block_read), buf, blocks, sh);
}

sg_block_io sg_wrapped_block_reader(block_io bio, int block_order, heap backed)
{
    sg_debug("%s, heap %p, bio %p, order %d, backed %p\n", __func__, sg_heap, bio, block_order, backed);
    return closure(sg_heap, sg_wrapped_read, bio, block_order, backed);
}

void init_sg(heap h)
{
    sg_debug("%s\n", __func__);
    sg_heap = h;
    list_init(&free_sg_lists);
    sg_lock_init();
}
