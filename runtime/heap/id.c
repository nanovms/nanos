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

#define page_size(i) (i->h.pagesize)
#define page_order(i) msb(page_size(i))
#define page_mask(i) (page_size(i) - 1)

static inline int find_order(id_heap i, bytes alloc_size)
{
    int order = pad(alloc_size, page_size(i)) >> page_order(i);
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

static id_heap id_alloc_heap(heap h, u64 pagesize)
{
    assert((pagesize & (pagesize-1)) == 0); /* pagesize is power of 2 */

    id_heap i = allocate(h, sizeof(struct id_heap));
    if (i == INVALID_ADDRESS)
	return i;
    i->h.alloc = id_alloc;
    i->h.dealloc = id_dealloc;
    i->h.pagesize = pagesize;
    i->h.destroy = id_destroy;
    i->h.allocated = 0;
    i->meta = h;
    i->ranges = allocate_vector(h, 1);
    if (i->ranges == INVALID_ADDRESS) {
	deallocate(h, i, sizeof(struct id_heap));
	return INVALID_ADDRESS;
    }
    return i;
}

static boolean id_add_range(id_heap i, u64 base, u64 length)
{
    assert(length >= page_size(i));
    assert((length & page_mask(i)) == 0); /* multiple of pagesize */
    id_range r = allocate(i->meta, sizeof(struct id_range));
    if (r == INVALID_ADDRESS)
	return false;
    r->base = base;
    r->length = length;
    u64 bits = length >> page_order(i);
    r->b = allocate_bitmap(i->meta, bits);
    if (r->b == INVALID_ADDRESS) {
	deallocate(i->meta, r, sizeof(struct id_range));
	return false;
    }
    vector_push(i->ranges, r);
    return true;
}

heap create_id_heap(heap h, u64 base, u64 length, u64 pagesize)
{
    id_heap i = id_alloc_heap(h, pagesize);
    if (i == INVALID_ADDRESS)
	return INVALID_ADDRESS;
    if (!id_add_range(i, base, length)) {
	id_destroy((heap)i);
	return INVALID_ADDRESS;
    }
    return((heap)i);
}
