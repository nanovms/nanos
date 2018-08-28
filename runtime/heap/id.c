#include <runtime.h>

typedef struct id_heap {
    struct heap h;
    u64 base;
    bitmap b;
} *id_heap;

#define page_order(i) msb(i->h.pagesize)

static inline int find_order(id_heap i, bytes alloc_size)
{
    int order = pad(alloc_size, i->h.pagesize) >> page_order(i);
    return order > 1 ? msb(order - 1) + 1 : 0;	/* round up to next power of 2 */
}

static u64 id_alloc(heap h, bytes count)
{
    id_heap i = (id_heap)h;

    if (count == 0)
	return INVALID_PHYSICAL;

    int order = find_order(i, count);
    u64 bit = bitmap_alloc(i->b, order);
    if (bit == INVALID_PHYSICAL)
	return bit;

    u64 offset = (u64)bit << page_order(i);
#ifdef ID_HEAP_DEBUG
    msg_debug("heap %p, size %d: got offset (%d << %d = %P)\t>%P\n",
	      h, alloc_bits, bit, page_order(i), offset, b->base + offset);
#endif
    return i->base + offset;
}

static void id_dealloc(heap h, u64 a, bytes count)
{
    id_heap i = (id_heap)h;

    if (count == 0)
	return;

    u64 offset = a - i->base;
    u64 pagemask = h->pagesize - 1;
    if (((offset & pagemask) | (count & pagemask))) {
	msg_err("heap %p, offset %P, count %d: not aligned to pagesize; leaking\n");
	return;
    }

    int order = find_order(i, count);
    int bit = offset >> page_order(i);

    if (!bitmap_dealloc(i->b, bit, order)) {
	msg_err("heap %p, offset %P, count %d: bitmap dealloc failed; leaking\n");
    }
}

static void id_destroy(heap h)
{
    id_heap i = (id_heap)h;
    if (i->b)
	deallocate_bitmap(i->b);
}

heap create_id_heap(heap h, u64 base, u64 length, u64 pagesize)
{
    assert((pagesize & (pagesize-1)) == 0); /* pagesize is power of 2 */
    assert(length >= pagesize);
    assert((length & (pagesize-1)) == 0); /* multiple of pagesize */

    id_heap i = allocate(h, sizeof(struct id_heap));
    i->h.alloc = id_alloc;
    i->h.dealloc = id_dealloc;
    i->h.pagesize = pagesize;
    i->h.destroy = id_destroy;
    i->base = base;

    u64 bits = length >> page_order(i);
    i->b = allocate_bitmap(h, bits);
    if (i->b == INVALID_ADDRESS) {
	/* use console() because this gets invoked in early startup */
	console("create_id_heap: failed to allocate bitmap of length ");
	print_u64(bits);
	console("\n");
	return INVALID_ADDRESS;
    }
    return((heap)i);
}
