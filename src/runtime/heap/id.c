#include <runtime.h>

typedef struct id_range {
    struct rmnode n;
    bitmap b;
    u64 next_bit;               /* for next-fit search */
} *id_range;

#define ID_HEAP_FLAG_RANDOMIZE  1

typedef struct id_heap {
    struct heap h;
    u64 page_order;
    u64 total;
    u64 flags;
    heap meta;
    heap parent;
    rangemap ranges;
} *id_heap;

#define page_size(i) (i->h.pagesize)
#define page_order(i) (i->page_order)
#define page_mask(i) (page_size(i) - 1)

static inline int pages_from_bytes(id_heap i, bytes alloc_size)
{
    return pad(alloc_size, page_size(i)) >> page_order(i);
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
    id_range ir = allocate(i->meta, sizeof(struct id_range));
    ir->n.r = irange(base, base + length);
    if (ir == INVALID_ADDRESS)
	return ir;
    if (!rangemap_insert(i->ranges, &ir->n)) {
        msg_err("%s: range insertion failure; conflict with range %R\n", __func__, ir->n.r);
        goto fail;
    }
    u64 bits = length >> page_order(i);
    ir->b = allocate_bitmap(i->meta, bits);
    if (ir->b == INVALID_ADDRESS) {
        msg_err("%s: failed to allocate bitmap for range %R\n", __func__, ir->n.r);
        goto fail;
    }
    ir->next_bit = 0;
    i->total += length;
#ifdef ID_HEAP_DEBUG
    msg_debug("added range base %lx, length %lx\n", base, length);
#endif
    return ir;
  fail:
    deallocate(i->meta, ir, sizeof(struct id_range));
    return INVALID_ADDRESS;
}

static id_range id_get_backed_page(id_heap i)
{
    u64 length = i->parent->pagesize;
    u64 base = allocate_u64(i->parent, length);
    if (base == INVALID_PHYSICAL)
	return INVALID_ADDRESS;
    return id_add_range(i, base, length);
}

static u64 id_alloc_from_range(id_heap i, id_range r, u64 pages)
{
    u64 bit_offset;
    u64 pages_rounded = U64_FROM_BIT(find_order(pages));
    u64 max_start = r->b->maxbits - pages_rounded;
    if ((i->flags & ID_HEAP_FLAG_RANDOMIZE))
        bit_offset = random_u64() % max_start;
    else
        bit_offset = r->next_bit;

    u64 bit = bitmap_alloc_with_offset(r->b, pages, bit_offset);
    if (bit == INVALID_PHYSICAL)
	return bit;
    r->next_bit = bit;

    u64 offset = bit << page_order(i);
    i->h.allocated += pages << page_order(i);
#ifdef ID_HEAP_DEBUG
    msg_debug("heap %p, pages %ld: got offset (%ld << %ld = %lx)\t>%lx\n",
	      i, pages, bit, page_order(i), offset, r->n.r.start + offset);
#endif
    return r->n.r.start + offset;
}

static u64 id_alloc(heap h, bytes count)
{
    id_heap i = (id_heap)h;
    if (count == 0)
	return INVALID_PHYSICAL;
    u64 pages = pages_from_bytes(i, count);

    id_range r = (id_range)rangemap_first_node(i->ranges);
    while (r != INVALID_ADDRESS) {
	u64 a = id_alloc_from_range(i, r, pages);
	if (a != INVALID_PHYSICAL)
	    return a;
        r = (id_range)rangemap_next_node(i->ranges, (rmnode)r);
    }

    /* All parent allocations are the same size, so if it doesn't fit
       the next one, fail. */
    if (i->parent && (r = id_get_backed_page(i)) != INVALID_ADDRESS)
	return id_alloc_from_range(i, r, pages);

    return INVALID_PHYSICAL;
}

static CLOSURE_2_1(dealloc_from_range, void, id_heap, range, rmnode);
static void dealloc_from_range(id_heap i, range q, rmnode n)
{
    range ri = range_intersection(q, n->r);
    id_range r = (id_range)n;

    int bit = (ri.start - n->r.start) >> page_order(i);
    u64 pages = pages_from_bytes(i, range_span(ri));
    if (!bitmap_dealloc(r->b, bit, pages)) {
        msg_err("heap %p: bitmap dealloc for range %R failed; leaking\n", i, q);
        return;
    }

    if (bit < r->next_bit)
        r->next_bit = bit;

    u64 deallocated = pages << page_order(i);
    assert(i->h.allocated >= deallocated);
    i->h.allocated -= deallocated;
}

static void id_dealloc(heap h, u64 a, bytes count)
{
    id_heap i = (id_heap)h;

    if (count == 0)
	return;

    range q = irange(a, a + count);
    if ((a & page_mask(i)) != 0 || (count & page_mask(i)) != 0) {
        msg_err("heap %p: range %R not page-aligned; leaking\n", h, q);
        return;
    }

    rmnode_handler nh = closure(transient, dealloc_from_range, i, q);
    if (!rangemap_range_lookup(i->ranges, q, nh))
        msg_err("heap %p: no match for range %R\n", h, q);
}

static void id_destroy(heap h)
{
    id_heap i = (id_heap)h;
    id_range r = (id_range)rangemap_first_node(i->ranges);
    while (r != INVALID_ADDRESS) {
	deallocate_bitmap(r->b);
        r = (id_range)rangemap_next_node(i->ranges, (rmnode)r);
    }
    deallocate_rangemap(i->ranges);
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
    i->ranges = allocate_rangemap(h);
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

static CLOSURE_3_1(reserve_range, void, id_heap, range, boolean *, rmnode);
static void reserve_range(id_heap i, range q, boolean * fail, rmnode n)
{
    range ri = range_intersection(q, n->r);
    id_range r = (id_range)n;

    int bit = (ri.start - n->r.start) >> page_order(i);
    if (!bitmap_range_check_and_set(r->b, bit, pages_from_bytes(i, range_span(ri)), false, true))
        *fail = true;
}

boolean id_heap_reserve(heap h, u64 base, u64 length)
{
    id_heap i = (id_heap)h;
    base &= ~page_mask(i);
    length = pad(length, page_mask(i));

    range q = irange(base, base + length);
    boolean fail = false;
    rmnode_handler nh = closure(transient, reserve_range, i, q, &fail);

    boolean result = rangemap_range_lookup(i->ranges, q, nh);
    return result && !fail;
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
