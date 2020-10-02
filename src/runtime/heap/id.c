#ifdef KERNEL
#include <kernel.h>
#else
#include <runtime.h>
#endif

//#define ID_HEAP_DEBUG
#ifdef ID_HEAP_DEBUG
#define id_debug(x, ...) do {rprintf("%s: " x, __func__, ##__VA_ARGS__);} while(0)
#else
#define id_debug(x, ...)
#endif

typedef struct id_range {
    struct rmnode n;            /* range in pages */
    bitmap b;
    u64 next_bit;               /* for next-fit search */
} *id_range;

#define ID_HEAP_FLAG_RANDOMIZE  1

#define page_size(i) (i->h.pagesize)
#define page_order(i) (i->page_order)
#define page_mask(i) (page_size(i) - 1)

static inline int pages_from_bytes(id_heap i, bytes alloc_size)
{
    return pad(alloc_size, page_size(i)) >> page_order(i);
}

static id_range id_add_range(id_heap i, u64 base, u64 length)
{
    id_debug("base 0x%lx, end 0x%lx\n", base, base + length);
    /* -1 = unlimited; make maximum possible range */
    if (length == infinity) {
	length -= base;
	/* bitmap will round up to next 64 page boundary, don't wrap */
	length &= ~((1ull << (page_order(i) + 6)) - 1);
    }

    /* assert only page-sized and non-zero */
    assert(length >= page_size(i));
    assert((base & page_mask(i)) == 0);
    assert((length & page_mask(i)) == 0);

    /* check that this won't overlap with an existing range */
    u64 page_start = base >> page_order(i);
    u64 pages = length >> page_order(i);
    id_range ir = allocate(i->meta, sizeof(struct id_range));
    ir->n.r = irange(page_start, page_start + pages);
    id_debug("page range %R\n", ir->n.r);
    if (ir == INVALID_ADDRESS)
	return ir;
    if (!rangemap_insert(i->ranges, &ir->n)) {
        msg_err("%s: range insertion failure; conflict with range %R\n", __func__, ir->n.r);
        goto fail;
    }
    ir->b = allocate_bitmap(i->meta, i->map, pages);
    if (ir->b == INVALID_ADDRESS) {
        msg_err("%s: failed to allocate bitmap for range %R\n", __func__, ir->n.r);
        goto fail;
    }
    ir->next_bit = 0;
    i->total += length;
    id_debug("added range base 0x%lx, end 0x%lx (length 0x%lx)\n", base, base + length, length);
    return ir;
  fail:
    deallocate(i->meta, ir, sizeof(struct id_range));
    return INVALID_ADDRESS;
}

static id_range id_get_backed_page(id_heap i, bytes count)
{
    u64 parent_pages = ((count - 1) / i->parent->pagesize) + 1;
    u64 length = parent_pages * i->parent->pagesize;
    u64 base = allocate_u64(i->parent, length);
    id_debug("length 0x%lx, base 0x%lx\n", length, base);
    if (base == INVALID_PHYSICAL)
	return INVALID_ADDRESS;
    return id_add_range(i, base, length);
}

#define WHOLE_RANGE irange(0, infinity)

static u64 id_alloc_from_range(id_heap i, id_range r, u64 pages, range subrange)
{
    id_debug("id range %R, pages %ld, subrange %R\n", r->n.r, pages, subrange);
    u64 pages_rounded = U64_FROM_BIT(find_order(pages)); /* maintain 2^n alignment */

    /* find intersection, align start and end to 2^n and subtract range offset */
    range ri = range_intersection(r->n.r, subrange);
    id_debug("intersection %R, pages_rounded %ld\n", ri, pages_rounded);
    if (range_empty(ri))
        return INVALID_PHYSICAL;

    /* align search start (but not end, for pages may fit in a
       non-power-of-2 remainder at the end of the range) and remove
       id_range offset */
    ri.start = pad(ri.start, pages_rounded) - r->n.r.start;
    ri.end -= r->n.r.start;
    id_debug("after adjust %R\n", ri);
    if (!range_valid(ri) || range_span(ri) < pages) {
        id_debug("range invalid %d, range_span(ri) %ld, pages %ld\n",
                 range_valid(ri), range_span(ri), pages);
        return INVALID_PHYSICAL;
    }

    /* check for randomization, else check for next fit */
    u64 max_start = range_span(ri) > pages_rounded ?
        (range_span(ri) & ~(pages_rounded - 1)) - pages_rounded : 0;
    u64 start_bit = ri.start;
    if ((i->flags & ID_HEAP_FLAG_RANDOMIZE) && max_start > 0)
        start_bit += random_u64() % max_start;
    else if (point_in_range(ri, r->next_bit))
        start_bit = r->next_bit;

    id_debug("start_bit 0x%lx, end 0x%lx\n", start_bit, ri.end);
    /* search beginning at start_bit, wrapping around if needed */
    u64 bit = bitmap_alloc_within_range(r->b, pages, start_bit, ri.end);
    if (bit == INVALID_PHYSICAL && start_bit > ri.start)
	bit = bitmap_alloc_within_range(r->b, pages, ri.start, start_bit);
    if (bit == INVALID_PHYSICAL)
        return bit;

    r->next_bit = bit;
    i->allocated += pages << page_order(i);
    u64 result = (r->n.r.start + bit) << page_order(i);
    id_debug("allocated bit %ld, range page start %ld, returning 0x%lx\n",
             bit, r->n.r.start, result);
    return result;
}

static inline u64 id_alloc(heap h, bytes count)
{
    id_heap i = (id_heap)h;
    if (count == 0)
	return INVALID_PHYSICAL;
    u64 pages = pages_from_bytes(i, count);

    id_range r = (id_range)rangemap_first_node(i->ranges);
    while (r != INVALID_ADDRESS) {
	u64 a = id_alloc_from_range(i, r, pages, WHOLE_RANGE);
	if (a != INVALID_PHYSICAL)
	    return a;
        r = (id_range)rangemap_next_node(i->ranges, (rmnode)r);
    }

    /* All parent allocations are the same size, so if it doesn't fit
       the next one, fail. */
    if (i->parent && (r = id_get_backed_page(i, count)) != INVALID_ADDRESS)
	return id_alloc_from_range(i, r, pages, WHOLE_RANGE);

    return INVALID_PHYSICAL;
}

closure_function(2, 1, void, dealloc_from_range,
                 id_heap, i, range, q,
                 rmnode, n)
{
    id_heap i = bound(i);
    range q = bound(q);
    range ri = range_intersection(q, n->r);
    id_range r = (id_range)n;

    int bit = ri.start - n->r.start;
    u64 pages = range_span(ri);
    if (!bitmap_dealloc(r->b, bit, pages)) {
        msg_err("heap %p: bitmap dealloc for range %R failed; leaking\n", i, q);
        return;
    }

    if (bit < r->next_bit)
        r->next_bit = bit;

    u64 deallocated = pages << page_order(i);
    assert(i->allocated >= deallocated);
    i->allocated -= deallocated;
}

static inline void id_dealloc(heap h, u64 a, bytes count)
{
    id_heap i = (id_heap)h;

    if (count == 0)
	return;

    if ((a & page_mask(i)) != 0 || (count & page_mask(i)) != 0) {
        msg_err("heap %p: a 0x%lx, count 0x%lx not page-aligned; leaking\n", h, a, count);
        return;
    }

    range q = irange(a >> page_order(i), (a + count) >> page_order(i));
    rmnode_handler nh = stack_closure(dealloc_from_range, i, q);
    if (!rangemap_range_lookup(i->ranges, q, nh))
        msg_err("heap %p: no match for range %R\n", h, q);
}

closure_function(1, 1, void, destruct_id_range,
                 id_heap, i,
                 rmnode, n)
{
    id_range r = (id_range)n;
    deallocate_bitmap(r->b);
    deallocate(bound(i)->meta, r, sizeof(struct id_range));
}

static void id_destroy(heap h)
{
    id_heap i = (id_heap)h;
    deallocate_rangemap(i->ranges, stack_closure(destruct_id_range, i));
    deallocate(i->meta, i, sizeof(struct id_heap));
}

/* external version */
static boolean add_range(id_heap i, u64 base, u64 length)
{
    return id_add_range(i, base, length) != INVALID_ADDRESS;
}

closure_function(4, 1, void, set_intersection,
                 range, q, boolean *, fail, boolean, validate, boolean, allocate,
                 rmnode, n)
{
    range ri = range_intersection(bound(q), n->r);
    id_range r = (id_range)n;

    int bit = ri.start - n->r.start;
    if (!bitmap_range_check_and_set(r->b, bit, range_span(ri), bound(validate), bound(allocate)))
        *bound(fail) = true;
}

static u64 id_allocated(heap h)
{
    return ((id_heap)h)->allocated;
}

static u64 id_total(heap h)
{
    return ((id_heap)h)->total;
}

static inline boolean set_area(id_heap i, u64 base, u64 length, boolean validate, boolean allocate)
{
    base &= ~page_mask(i);
    length = pad(length, page_size(i));

    range q = irange(base >> page_order(i), (base + length) >> page_order(i));
    boolean fail = false;
    rmnode_handler nh = stack_closure(set_intersection, q, &fail, validate, allocate);
    boolean result = rangemap_range_lookup(i->ranges, q, nh);
    return result && !fail;
}

static inline void set_randomize(id_heap i, boolean randomize)
{
    i->flags = randomize ? i->flags | ID_HEAP_FLAG_RANDOMIZE : i->flags & ~ID_HEAP_FLAG_RANDOMIZE;
}

static inline u64 alloc_subrange(id_heap i, bytes count, u64 start, u64 end)
{
    /* convert to pages */
    range subrange = irange(pad(start, page_size(i)) >> page_order(i),
                            end == infinity ? infinity : end >> page_order(i));
    id_debug("heap %p, count 0x%lx, start 0x%lx, end 0x%lx, page range %R\n",
             i, count, start, end, subrange);
    if (count == 0 || !range_valid(subrange) || range_span(subrange) == 0 ||
        subrange.start == infinity)
        return INVALID_PHYSICAL;

    u64 pages = pages_from_bytes(i, count);
    if (range_span(subrange) < pages)
        return INVALID_PHYSICAL;

    id_range r = (id_range)rangemap_first_node(i->ranges);
    while (r != INVALID_ADDRESS) {
        u64 a = id_alloc_from_range(i, r, pages, subrange);
        if (a != INVALID_PHYSICAL) {
            return a;
        }
        r = (id_range)rangemap_next_node(i->ranges, (rmnode)r);
    }
    return INVALID_PHYSICAL;
}

/* Provides a hint as to what id should be allocated next. */
static inline void set_next(id_heap i, u64 next)
{
    rangemap_foreach(i->ranges, n) {
        id_range r = (id_range)n;
        if (point_in_range(r->n.r, next))
            r->next_bit = next;
        else if (r->n.r.start > next)
            r->next_bit = 0;
    }
}

#ifdef KERNEL
/* locking variants */

static u64 id_alloc_locking(heap h, bytes count)
{
    u64 flags = spin_lock_irq(&((id_heap)h)->lock);
    u64 a = id_alloc(h, count);
    spin_unlock_irq(&((id_heap)h)->lock, flags);
    return a;
}

static void id_dealloc_locking(heap h, u64 a, bytes count)
{
    u64 flags = spin_lock_irq(&((id_heap)h)->lock);
    id_dealloc(h, a, count);
    spin_unlock_irq(&((id_heap)h)->lock, flags);
}

static boolean add_range_locking(id_heap i, u64 base, u64 length)
{
    u64 flags = spin_lock_irq(&i->lock);
    boolean r = add_range(i, base, length);
    spin_unlock_irq(&i->lock, flags);
    return r;
}

static boolean set_area_locking(id_heap i, u64 base, u64 length, boolean validate, boolean allocate)
{
    u64 flags = spin_lock_irq(&i->lock);
    boolean r = set_area(i, base, length, validate, allocate);
    spin_unlock_irq(&i->lock, flags);
    return r;
}

static void set_randomize_locking(id_heap i, boolean randomize)
{
    u64 flags = spin_lock_irq(&i->lock);
    set_randomize(i, randomize);
    spin_unlock_irq(&i->lock, flags);
}

static u64 alloc_subrange_locking(id_heap i, bytes count, u64 start, u64 end)
{
    u64 flags = spin_lock_irq(&i->lock);
    u64 a = alloc_subrange(i, count, start, end);
    spin_unlock_irq(&i->lock, flags);
    return a;
}

static void set_next_locking(id_heap i, u64 next)
{
    u64 flags = spin_lock_irq(&i->lock);
    set_next(i, next);
    spin_unlock_irq(&i->lock, flags);
}
#endif

id_heap allocate_id_heap(heap meta, heap map, bytes pagesize, boolean locking)
{
    assert((pagesize & (pagesize-1)) == 0); /* pagesize is power of 2 */

    id_heap i = allocate(meta, sizeof(struct id_heap));
    if (i == INVALID_ADDRESS)
	return INVALID_ADDRESS;
    i->h.pagesize = pagesize;
    i->h.destroy = id_destroy;
    i->h.allocated = id_allocated;
    i->h.total = id_total;

#ifdef KERNEL
    if (locking) {
        spin_lock_init(&i->lock);
        i->h.alloc = id_alloc_locking;
        i->h.dealloc = id_dealloc_locking;
        i->add_range = add_range_locking;
        i->set_area = set_area_locking;
        i->set_randomize = set_randomize_locking;
        i->alloc_subrange = alloc_subrange_locking;
        i->set_next = set_next_locking;
    } else
#endif
    {
        i->h.alloc = id_alloc;
        i->h.dealloc = id_dealloc;
        i->add_range = add_range;
        i->set_area = set_area;
        i->set_randomize = set_randomize;
        i->alloc_subrange = alloc_subrange;
        i->set_next = set_next;
    }
    i->page_order = msb(pagesize);
    i->allocated = 0;
    i->total = 0;
    i->flags = 0;
    i->meta = meta;
    i->map = map;
    i->parent = 0;
    i->ranges = allocate_rangemap(meta);
    if (i->ranges == INVALID_ADDRESS) {
	deallocate(meta, i, sizeof(struct id_heap));
	return INVALID_ADDRESS;
    }
    return i;
}

id_heap create_id_heap(heap meta, heap map, u64 base, u64 length, bytes pagesize, boolean locking)
{
    id_heap i = allocate_id_heap(meta, map, pagesize, locking);
    if (i == INVALID_ADDRESS)
	return INVALID_ADDRESS;

    id_debug("heap %p, pagesize %d\n", i, pagesize);

    if (id_add_range(i, base, length) == INVALID_ADDRESS) {
	id_destroy((heap)i);
	return INVALID_ADDRESS;
    }
    return i;
}

id_heap create_id_heap_backed(heap meta, heap map, heap parent, bytes pagesize, boolean locking)
{
    id_heap i = allocate_id_heap(meta, map, pagesize, locking);
    if (i == INVALID_ADDRESS)
	return INVALID_ADDRESS;
    i->parent = parent;

    id_debug("heap %p, parent %p, pagesize %d\n", i, parent, pagesize);

    /* get initial address range from parent */
    if (id_get_backed_page(i, 1) == INVALID_ADDRESS) {
	id_destroy((heap)i);
	return INVALID_ADDRESS;
    }
    return i;
}
