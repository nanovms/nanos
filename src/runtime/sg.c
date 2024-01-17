#ifdef KERNEL
#include <kernel.h>
#else
#include <runtime.h>
#endif

//#define SG_DEBUG
#if defined(SG_DEBUG)
#define sg_debug(x, ...) do {rprintf("SG:  " x, ##__VA_ARGS__);} while(0)
#else
#define sg_debug(x, ...)
#endif

#define DEFAULT_SG_FRAGS 8

BSS_RO_AFTER_INIT static heap sg_heap;
static struct list free_sg_lists;

#ifdef KERNEL
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

void sg_consume(sg_list sg, u64 length)
{
    sg_list_foreach(sg, sgb) {
        if (length + sgb->offset >= sgb->size) {
            sg_list_head_remove(sg);
            length -= sg_buf_len(sgb);
            sg_buf_release(sgb);
            if (length == 0)
                break;
        } else {
            sgb->offset += length;
            break;
        }
    }
}

/* TODO clean up redundant parts of loop with macros or static closures */

static u64 sg_copy(void *buf, sg_list sg, u64 n, boolean to_buf)
{
    sg_buf sgb;
    u64 remain = n;

    sg_debug("%s: target %p, sg %p, length 0x%lx, count %ld\n", func_ss, target, sg, length, sg->count);
    while (remain > 0 && (sgb = sg_list_head_peek(sg)) != INVALID_ADDRESS) {
        assert(sgb->size > sgb->offset); /* invariant: no null-length bufs */
        void *sg_buf = sgb->buf + sgb->offset;
        u64 len = MIN(remain, sg_buf_len(sgb));
        if (to_buf)
            runtime_memcpy(buf, sg_buf, len);
        else
            runtime_memcpy(sg_buf, buf, len);
        buf += len;
        sgb->offset += len;
        remain -= len;
        if (sgb->offset < sgb->size)
            break;
        sg_list_head_remove(sg);
        sg_buf_release(sgb);
    }
    return n - remain;
}

/* copy content of sg, up to length bytes, into target, releasing consumed buffers */
u64 sg_copy_to_buf(void *target, sg_list sg, u64 length)
{
    return sg_copy(target, sg, length, true);
}

/* copy content of src, up to length bytes, into sg, releasing consumed buffers */
u64 sg_copy_from_buf(void *src, sg_list sg, u64 length)
{
    return sg_copy(src, sg, length, false);
}

u64 sg_move(sg_list dest, sg_list src, u64 n)
{
    sg_buf ssgb;
    u64 remain = n;
    while (remain > 0 && (ssgb = sg_list_head_peek(src)) != INVALID_ADDRESS) {
        assert(ssgb->size > ssgb->offset);
        u64 len = MIN(remain, sg_buf_len(ssgb));
        sg_buf dsgb = sg_list_tail_add(dest, len);
        assert(dsgb != INVALID_ADDRESS);
        dsgb->buf = ssgb->buf;
        dsgb->size = ssgb->offset + len;
        dsgb->offset = ssgb->offset;
        refcount_reserve(ssgb->refcount);
        dsgb->refcount = ssgb->refcount;
        ssgb->offset += len;
        remain -= len;
        if (ssgb->offset < ssgb->size)
            break;
        sg_list_head_remove(src);
        sg_buf_release(ssgb);
    }
    return n - remain;
}

u64 sg_zero_fill(sg_list sg, u64 n)
{
    sg_buf sgb;
    u64 remain = n;
    while (remain > 0 && (sgb = sg_list_head_peek(sg)) != INVALID_ADDRESS) {
        assert(sgb->size > sgb->offset);
        u64 len = MIN(remain, sg_buf_len(sgb));
        zero(sgb->buf + sgb->offset, len);
        sgb->offset += len;
        remain -= len;
        if (sgb->offset < sgb->size)
            break;
        sg_list_head_remove(sg);
        sg_buf_release(sgb);
    }
   return n - remain;
}

/* copy content of sg, up to limit bytes, into target, consuming and
   deallocating everything */
u64 sg_copy_to_buf_and_release(void *target, sg_list sg, u64 n)
{
    sg_buf sgb;
    u64 remain = n;

    sg_debug("%s: target %p, sg %p, limit 0x%lx, count %ld\n", func_ss, target, sg, limit, sg->count);
    while ((sgb = sg_list_head_remove(sg)) != INVALID_ADDRESS) {
        assert(sgb->size > sgb->offset);
        u64 len = MIN(remain, sg_buf_len(sgb));
        if (len > 0) {
            runtime_memcpy(target, sgb->buf, len);
            target += len;
            sgb->offset += len;
            remain -= len;
        }
        /* release all buffers */
        sg_buf_release(sgb);
    }
    deallocate_sg_list(sg);
    return n - remain;
}

#ifdef KERNEL

/* Touch n bytes from sg, without consuming the SG list or its buffers, and return whether the
 * buffers being accessed point to valid memory. */
boolean sg_fault_in(sg_list sg, u64 n)
{
    sg_buf sgb;
    u64 sgb_index = 0;
    context ctx = get_current_context(current_cpu());
    if (context_set_err(ctx))
        return false;
    while (n > 0 && (sgb = sg_list_peek_at(sg, sgb_index)) != INVALID_ADDRESS) {
        s64 len = MIN(n, sg_buf_len(sgb));
        n -= len;
        volatile u8 *bp = sgb->buf + sgb->offset;
        while (len > 0) {
            (void)*bp;
            bp += PAGESIZE;
            len -= PAGESIZE;
        }
        sgb_index++;
    }
    context_clear_err(ctx);
    return true;
}

#endif

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
    /* Recycle extremely large fragment buffers */
    if (buffer_space(sg->b) > SG_FRAG_BYTE_THRESHOLD)
        assert(buffer_set_capacity(sg->b, SG_FRAG_BYTE_THRESHOLD) == SG_FRAG_BYTE_THRESHOLD);
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
             func_ss, bound(block_read), block_order, bound(backed), sg, q, sh);

    if (buf == INVALID_ADDRESS) {
        apply(sh, timm("result", "%s: failed to allocate backed buffer of size %ld",
                       func_ss, padlen));
        return;
    }
    refcount refcount = allocate(sg_heap, sizeof(struct refcount));
    if (refcount == INVALID_ADDRESS) {
        apply(sh, timm("result", "%s: alloc failed", func_ss));
        return;
    }
    init_refcount(refcount, 1, closure(sg_heap, sg_wrapped_buf_release,
                                       refcount, bound(backed), buf, padlen));
    sg_buf sgb = sg_list_tail_add(sg, length);
    assert(sgb != INVALID_ADDRESS);
    sgb->buf = buf;
    sgb->size = length;
    sgb->offset = 0;
    sgb->refcount = refcount;
    assert((q.start & MASK(block_order)) == 0);
    range blocks = range_rshift(irange(q.start, q.start + padlen), block_order);
    sg_debug("   reading into sgb %p, buf %p, blocks %R\n", sgb, buf, blocks);
    apply(bound(block_read), buf, blocks, sh);
}

sg_io sg_wrapped_block_reader(block_io bio, int block_order, heap backed)
{
    sg_debug("%s, heap %p, bio %p, order %d, backed %p\n", func_ss, sg_heap, bio, block_order, backed);
    return closure(sg_heap, sg_wrapped_read, bio, block_order, backed);
}

void init_sg(heap h)
{
    sg_debug("%s\n", func_ss);
    sg_heap = h;
    list_init(&free_sg_lists);
    sg_lock_init();
}
