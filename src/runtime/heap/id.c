#include <runtime.h>

typedef struct id_range {
    u64 base;
    u64 length;
    bitmap b;
} *id_range;

typedef struct id_heap {
    struct heap h;
    u64 page_order;
    heap meta;
    heap parent;
    vector ranges;
} *id_heap;

#define page_size(i) (i->h.pagesize)
#define page_order(i) (i->page_order)
#define page_mask(i) (page_size(i) - 1)

static inline int find_order(id_heap i, bytes alloc_size)
{
    int order = pad(alloc_size, page_size(i)) >> page_order(i);
    return order > 1 ? msb(order - 1) + 1 : 0;	/* round up to next power of 2 */
}

static id_range id_add_range(id_heap i, u64 base, u64 length)
{
    /* -1 = unlimited; make maximum possible range */
    if (length == -1ull) {
	length -= base;
	/* bitmap will round up to next 64 page boundary, don't wrap */
	length &= ~((1ull << (page_order(i) + 6)) - 1);
    }
    assert(length >= page_size(i));
    assert((length & page_mask(i)) == 0); /* multiple of pagesize */

    /* check that this won't overlap with an existing range */
    id_range r;
    u64 end = base + length - 1;
    vector_foreach(i->ranges, r) {
	u64 r_end = r->base + r->length - 1;
	if ((base >= r->base && base <= r_end) ||
	    (end >= r->base && end <= r_end)) {
	    msg_err("range [%P, %P] overlaps range [%P, %P]; fail\n",
		    base, end, r->base, r_end);
	    return INVALID_ADDRESS;
	}
    }
    r = allocate(i->meta, sizeof(struct id_range));
    if (r == INVALID_ADDRESS)
	return r;
    r->base = base;
    r->length = length;
    u64 bits = length >> page_order(i);
    r->b = allocate_bitmap(i->meta, bits);
    if (r->b == INVALID_ADDRESS) {
	deallocate(i->meta, r, sizeof(struct id_range));
	return INVALID_ADDRESS;
    }
    vector_push(i->ranges, r);
#ifdef ID_HEAP_DEBUG
    msg_debug("added range base %P, length %P\n", base, length);
#endif
    return r;
}

static id_range id_get_backed_page(id_heap i)
{
    u64 length = i->parent->pagesize;
    u64 base = allocate_u64(i->parent, length);
    if (base == INVALID_PHYSICAL)
	return INVALID_ADDRESS;
    return id_add_range(i, base, length);
}

static u64 id_alloc_from_range(id_heap i, id_range r, int order)
{
    u64 bit = bitmap_alloc(r->b, order);
    u64 alloc_bits = 1ull << order;
    if (bit == INVALID_PHYSICAL)
	return bit;

    u64 offset = bit << page_order(i);
    i->h.allocated += alloc_bits;
#ifdef ID_HEAP_DEBUG
    msg_debug("heap %p, size %d: got offset (%d << %d = %P)\t>%P\n",
	      i, alloc_bits, bit, page_order(i), offset, r->base + offset);
#endif
    return r->base + offset;
}

static u64 id_alloc(heap h, bytes count)
{
    id_heap i = (id_heap)h;
    if (count == 0)
	return INVALID_PHYSICAL;
    int order = find_order(i, count);

    id_range r;
    vector_foreach(i->ranges, r) {
	u64 a = id_alloc_from_range(i, r, order);
	if (a != INVALID_PHYSICAL)
	    return a;
    }

    /* All parent allocations are the same size, so if it doesn't fit
       the next one, fail. */
    if (i->parent && (r = id_get_backed_page(i)) != INVALID_ADDRESS)
	return id_alloc_from_range(i, r, order);

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
	u64 deallocated = 1ull << order;
	assert(h->allocated >= deallocated);
	h->allocated -= deallocated;
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

heap allocate_id_heap(heap h, u64 pagesize)
{
    assert((pagesize & (pagesize-1)) == 0); /* pagesize is power of 2 */

    id_heap i = allocate(h, sizeof(struct id_heap));
    if (i == INVALID_ADDRESS)
	return INVALID_ADDRESS;
    i->h.alloc = id_alloc;
    i->h.dealloc = id_dealloc;
    i->h.pagesize = pagesize;
    i->h.destroy = id_destroy;
    i->h.allocated = 0;
    i->page_order = msb(pagesize);
    i->meta = h;
    i->parent = 0;
    i->ranges = allocate_vector(h, 1);
    if (i->ranges == INVALID_ADDRESS) {
	deallocate(h, i, sizeof(struct id_heap));
	return INVALID_ADDRESS;
    }
    return (heap)i;
}

/* external version */
boolean id_heap_add_range(heap h, u64 base, u64 length)
{
    return id_add_range((id_heap)h, base, length) != INVALID_ADDRESS;
}

heap create_id_heap(heap h, u64 base, u64 length, u64 pagesize)
{
    id_heap i = (id_heap)allocate_id_heap(h, pagesize);
    if (i == INVALID_ADDRESS)
	return INVALID_ADDRESS;

#ifdef ID_HEAP_DEBUG
    msg_debug("heap %p, pagesize %d\n", i, pagesize);
#endif

    if (id_add_range(i, base, length) == INVALID_ADDRESS) {
	id_destroy((heap)i);
	return INVALID_ADDRESS;
    }
    return ((heap)i);
}

heap create_id_heap_backed(heap h, heap parent, u64 pagesize)
{
    id_heap i = (id_heap)allocate_id_heap(h, pagesize);
    if (i == INVALID_ADDRESS)
	return INVALID_ADDRESS;
    i->parent = parent;

#ifdef ID_HEAP_DEBUG
    msg_debug("heap %p, parent %p, pagesize %d\n", i, parent, pagesize);
#endif

    /* get initial address range from parent */
    if (id_get_backed_page(i) == INVALID_ADDRESS) {
	id_destroy((heap)i);
	return INVALID_ADDRESS;
    }
    return ((heap)i);
}
