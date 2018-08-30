#include <runtime.h>

typedef struct id_range {
    u64 base;
    u64 length;
    bitmap b;
} *id_range;

typedef struct id_heap {
    struct heap h;
    heap meta;
    vector ranges;
} *id_heap;

#define page_order(i) msb(i->h.pagesize)
#define page_mask(i) (i->h.pagesize - 1)

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

    id_range r;
    vector_foreach(i->ranges, r) {
	u64 bit = bitmap_alloc(r->b, order);
	if (bit == INVALID_PHYSICAL)
	    continue;

	u64 offset = (u64)bit << page_order(i);
#ifdef ID_HEAP_DEBUG
	msg_debug("heap %p, size %d: got offset (%d << %d = %P)\t>%P\n",
		  h, alloc_bits, bit, page_order(i), offset, b->base + offset);
#endif
	h->allocated += 1 << order;
	return r->base + offset;
    }

    return INVALID_PHYSICAL;
}

static void id_dealloc(heap h, u64 a, bytes count)
{
    id_heap i = (id_heap)h;

    if (count == 0)
	return;

    id_range r;
    char * s;
    int order = find_order(i, count);

    vector_foreach(i->ranges, r) {
	if (a < r->base || (a + count) > r->base + r->length)
	    continue;
	u64 offset = a - r->base;
	int bit = offset >> page_order(i);
	if ((offset & page_mask(i)) != 0) {
	    s = "allocation not aligned to pagesize";
	    goto fail;
	}
	if (!bitmap_dealloc(r->b, bit, order)) {
	    s = "bitmap dealloc failed";
	    goto fail;
	}
	assert(h->allocated >= 1 << order);
	h->allocated -= 1 << order;
	return;
    }
    s = "allocation doesn't match any range";
  fail:
    msg_err("heap %p, offset %P, count %d: %s; leaking\n", h, a, count, s);
}

static void id_destroy(heap h)
{
    id_heap i = (id_heap)h;
    id_range r;
    vector_foreach(i->ranges, r) {
	deallocate_bitmap(r->b);
    }
    deallocate_vector(i->ranges);
    deallocate(i->meta, i, sizeof(struct id_heap));
}

heap create_id_heap(heap h, u64 base, u64 length, u64 pagesize)
{
    assert((pagesize & (pagesize-1)) == 0); /* pagesize is power of 2 */
    assert(length >= pagesize);
    assert((length & (pagesize-1)) == 0); /* multiple of pagesize */

    id_heap i = allocate(h, sizeof(struct id_heap));
    if (i == INVALID_ADDRESS)
	goto fail;
    i->h.alloc = id_alloc;
    i->h.dealloc = id_dealloc;
    i->h.pagesize = pagesize;
    i->h.destroy = id_destroy;
    i->h.allocated = 0;
    i->meta = h;
    i->ranges = allocate_vector(h, 1);

    id_range r = allocate(h, sizeof(struct id_range));
    if (r == INVALID_ADDRESS)
	goto fail;
    r->base = base;
    r->length = length;
    vector_set(i->ranges, 0, r);

    u64 bits = length >> page_order(i);
    r->b = allocate_bitmap(h, bits);
    if (r->b == INVALID_ADDRESS)
	goto fail;
    return((heap)i);
  fail:
    /* use console() because this gets invoked in early startup */
    console("create_id_heap: failed to allocate heap\n");
    return INVALID_ADDRESS;
}
