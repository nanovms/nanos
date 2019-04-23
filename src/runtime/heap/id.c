#include <runtime.h>

typedef struct id_range {
    u64 base;
    u64 length;
    bitmap b;
} *id_range;

#define ID_HEAP_FLAG_RANDOMIZE  1

typedef struct id_heap {
    struct heap h;
    u64 page_order;
    u64 total;
    u64 flags;
    heap meta;
    heap parent;
    vector ranges;
} *id_heap;

#define page_size(i) (i->h.pagesize)
#define page_order(i) (i->page_order)
#define page_mask(i) (page_size(i) - 1)

static inline int find_page_order(id_heap i, bytes alloc_size)
{
    int npages = pad(alloc_size, page_size(i)) >> page_order(i);
    return find_order(npages);  /* round up to next power of 2 */
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
	    msg_err("range [%lx, %lx] overlaps range [%lx, %lx]; fail\n",
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
    i->total += length;
#ifdef ID_HEAP_DEBUG
    msg_debug("added range base %lx, length %lx\n", base, length);
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
    u64 bit_offset = 0;
    u64 max_start = (r->b->maxbits - U64_FROM_BIT(order)) & ~MASK(order);
    if ((i->flags & ID_HEAP_FLAG_RANDOMIZE))
        bit_offset = random_u64() % max_start;

    u64 bit = bitmap_alloc_with_offset(r->b, order, bit_offset);
    u64 alloc_bits = 1ull << order;
    if (bit == INVALID_PHYSICAL)
	return bit;

    u64 offset = bit << page_order(i);
    i->h.allocated += alloc_bits;
#ifdef ID_HEAP_DEBUG
    msg_debug("heap %p, size %ld: got offset (%ld << %ld = %lx)\t>%lx\n",
	      i, alloc_bits, bit, page_order(i), offset, r->base + offset);
#endif
    return r->base + offset;
}

static u64 id_alloc(heap h, bytes count)
{
    id_heap i = (id_heap)h;
    if (count == 0)
	return INVALID_PHYSICAL;
    int order = find_page_order(i, count);

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
    int order = find_page_order(i, count);

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
    msg_err("heap %p, offset %lx, count %d: %s; leaking\n", h, a, count, s);
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

heap allocate_id_heap(heap h, bytes pagesize)
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
    i->total = 0;
    i->meta = h;
    i->parent = 0;
    i->ranges = allocate_vector(h, 1);
    if (i->ranges == INVALID_ADDRESS) {
	deallocate(h, i, sizeof(struct id_heap));
	return INVALID_ADDRESS;
    }
    i->flags = 0;
    return (heap)i;
}

/* external version */
boolean id_heap_add_range(heap h, u64 base, u64 length)
{
    return id_add_range((id_heap)h, base, length) != INVALID_ADDRESS;
}

boolean id_heap_reserve(heap h, u64 base, u64 length)
{
    id_heap i = (id_heap)h;
    id_range r;
    u64 end = base + length - 1;
    vector_foreach(i->ranges, r) {
        u64 r_end = r->base + r->length - 1;
        if (base >= r->base && end <= r_end) {
            u64 start = (base - r->base) / page_size(i);
            return bitmap_reserve(r->b, start,
                                  pad(length, page_size(i)) / page_size(i));
        }
    }
    return false;
}

u64 id_heap_total(heap h)
{
    id_heap i = (id_heap)h;
    return i->total;
}

void id_heap_set_randomize(heap h, boolean randomize)
{
    id_heap i = (id_heap)h;
    i->flags = randomize ? i->flags | ID_HEAP_FLAG_RANDOMIZE : i->flags & ~ID_HEAP_FLAG_RANDOMIZE;
}

heap create_id_heap(heap h, u64 base, u64 length, bytes pagesize)
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

heap create_id_heap_backed(heap h, heap parent, bytes pagesize)
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
