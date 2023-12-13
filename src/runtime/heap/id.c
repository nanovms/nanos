#ifdef KERNEL
#include <kernel.h>
#else
#include <runtime.h>
#endif
#include <management.h>

//#define ID_HEAP_DEBUG
#ifdef ID_HEAP_DEBUG
#define id_debug(x, ...) do {rprintf("%s: " x, __func__, ##__VA_ARGS__);} while(0)
#else
#define id_debug(x, ...)
#endif

/* The location for next-fit search is stored for allocation size values from pagesize to
 * (pagesize << (NEXT_BIT_COUNT - 1)). */
#define NEXT_BIT_COUNT  10

typedef struct id_range {
    struct rmnode n;            /* range in pages */
    bitmap b;
    u64 bitmap_start;
    u64 next_bit[NEXT_BIT_COUNT];   /* for next-fit search */
} *id_range;

#define ID_HEAP_FLAG_RANDOMIZE  1

#define page_size(i) (i->h.pagesize)
#define page_order(i) (i->page_order)
#define page_mask(i) (page_size(i) - 1)

#define get_next_bit(ir, page_order)    ((ir)->next_bit[MIN(page_order, NEXT_BIT_COUNT - 1)])

#define set_next_bit(ir, page_order, bit)   do {    \
    if (page_order < NEXT_BIT_COUNT)                \
        (ir)->next_bit[page_order] = bit;           \
} while (0)

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
	length &= ~((1ull << (page_order(i) + BITMAP_WORDLEN_LOG)) - 1);
    }

    /* assert only page-sized and non-zero */
    assert(length >= page_size(i));
    assert((base & page_mask(i)) == 0);
    assert((length & page_mask(i)) == 0);

    /* check that this won't overlap with an existing range */
    u64 page_start = base >> page_order(i);
    u64 pages = length >> page_order(i);
    id_range ir = allocate(i->meta, sizeof(struct id_range));
    ir->n.r = irangel(page_start, pages);
    id_debug("page range %R\n", ir->n.r);
    if (ir == INVALID_ADDRESS)
	return ir;
    if (!rangemap_insert(i->ranges, &ir->n)) {
        msg_err("%s: range insertion failure; conflict with range %R\n", __func__, ir->n.r);
        goto fail;
    }

    /* To optimize performance of bitmap allocations, make the bitmap range start at a
     * BITMAP_WORDLEN-aligned value, so that the start argument to bitmap_alloc_within_range() is
     * always aligned to BITMAP_WORDLEN for allocation size values greater than
     * (BITMAP_WORDLEN / 2). */
    u64 page_start_mask = page_start & BITMAP_WORDMASK;

    ir->b = allocate_bitmap(i->meta, i->map, pages + page_start_mask);
    if (ir->b == INVALID_ADDRESS) {
        msg_err("%s: failed to allocate bitmap for range %R\n", __func__, ir->n.r);
        goto fail;
    }
    if (page_start_mask)
        /* Mark the initial bits (which are not part of the range supplied to this function) as
         * allocated, to prevent the bitmap from returning these bits during allocations. */
        bitmap_range_check_and_set(ir->b, 0, page_start_mask, false, true);
    ir->bitmap_start = page_start & ~BITMAP_WORDMASK;
    zero(ir->next_bit, sizeof(ir->next_bit));
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
    u64 page_order = find_order(pages);
    u64 pages_rounded = U64_FROM_BIT(page_order);   /* maintain 2^n alignment */

    /* find intersection, align start and end to 2^n and subtract range offset */
    range ri = range_intersection(r->n.r, subrange);
    id_debug("intersection %R, pages_rounded %ld\n", ri, pages_rounded);
    if (range_empty(ri))
        return INVALID_PHYSICAL;

    /* align search start (but not end, for pages may fit in a
       non-power-of-2 remainder at the end of the range) and remove
       id_range offset */
    ri.start = pad(ri.start, pages_rounded) - r->bitmap_start;
    ri.end -= r->bitmap_start;
    id_debug("after adjust %R\n", ri);
    if (!range_valid(ri) || range_span(ri) < pages) {
        id_debug("range invalid %d, range_span(ri) %ld, pages %ld\n",
                 range_valid(ri), range_span(ri), pages);
        return INVALID_PHYSICAL;
    }

    /* check for randomization, else check for next fit */
    u64 span = range_span(ri) & ~(pages_rounded - 1);
    u64 margin = span > pages_rounded ? span - pages_rounded : 0;
    u64 start_bit = ri.start;
    if ((i->flags & ID_HEAP_FLAG_RANDOMIZE) && margin > 0) {
        start_bit += random_u64() % margin;
    } else {
        u64 next_bit = get_next_bit(r, page_order);
        if (point_in_range(ri, next_bit))
            start_bit = MIN(next_bit, start_bit + margin);
    }

    id_debug("start_bit 0x%lx, end 0x%lx\n", start_bit, ri.end);
    /* search beginning at start_bit, wrapping around if needed */
    u64 bit = bitmap_alloc_within_range(r->b, pages, start_bit, ri.end);
    if (bit == INVALID_PHYSICAL && start_bit > ri.start)
	bit = bitmap_alloc_within_range(r->b, pages, ri.start, start_bit);
    if (bit == INVALID_PHYSICAL)
        return bit;

    set_next_bit(r, page_order, bit + pages_rounded);
    i->allocated += pages << page_order(i);
    u64 result = (r->bitmap_start + bit) << page_order(i);
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

closure_function(2, 1, boolean, dealloc_from_range,
                 id_heap, i, range, q,
                 rmnode, n)
{
    id_heap i = bound(i);
    range q = bound(q);
    range ri = range_intersection(q, n->r);
    id_range r = (id_range)n;

    int bit = ri.start - r->bitmap_start;
    u64 pages = range_span(ri);
    int order = find_order(pages);
    if (!bitmap_dealloc(r->b, bit, pages)) {
        msg_err("heap %p: bitmap dealloc for range %R failed; leaking\n", i, q);
        return false;
    }

    if (bit < get_next_bit(r, order))
        set_next_bit(r, order, bit);
    u64 deallocated = pages << page_order(i);
    assert(i->allocated >= deallocated);
    i->allocated -= deallocated;
    return true;
}

closure_function(2, 1, boolean, dealloc_gap,
                 id_heap, h, range, q,
                 range, r)
{
    msg_err("heap %p: gap %R found while deallocating %R\n", bound(h), r, bound(q));
    return false;
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

    range q = range_rshift(irangel(a, count), page_order(i));
    rmnode_handler nh = stack_closure(dealloc_from_range, i, q);
    range_handler rh = stack_closure(dealloc_gap, i, q);
    if (rangemap_range_lookup_with_gaps(i->ranges, q, nh, rh) == RM_ABORT)
        msg_err("failed, ra %p\n", __builtin_return_address(0));
}

closure_function(1, 1, boolean, destruct_id_range,
                 id_heap, i,
                 rmnode, n)
{
    id_range r = (id_range)n;
    deallocate_bitmap(r->b);
    deallocate(bound(i)->meta, r, sizeof(struct id_range));
    return true;
}

static inline bytes id_size(void)
{
    return sizeof(struct id_heap)
#ifdef KERNEL
        + sizeof(struct spinlock)
#endif
        ;
}

static void id_destroy(heap h)
{
    id_heap i = (id_heap)h;
    deallocate_rangemap(i->ranges, stack_closure(destruct_id_range, i));
    deallocate(i->meta, i, id_size());
}

/* external version */
static boolean add_range(id_heap i, u64 base, u64 length)
{
    return id_add_range(i, base, length) != INVALID_ADDRESS;
}

closure_function(3, 1, boolean, set_intersection,
                 range, q, boolean, validate, boolean, allocate,
                 rmnode, n)
{
    range ri = range_intersection(bound(q), n->r);
    id_range r = (id_range)n;
    int bit = ri.start - r->bitmap_start;
    if (!bitmap_range_check_and_set(r->b, bit, range_span(ri), bound(validate), bound(allocate)))
        return false;
    return true;
}

static u64 id_allocated(heap h)
{
    return ((id_heap)h)->allocated;
}

static u64 id_total(heap h)
{
    return ((id_heap)h)->total;
}

closure_function(2, 1, boolean, set_gap,
                 id_heap, i, range, q,
                 range, r)
{
    /* really no reason to ever set across ranges, so we should know if it happens... */
    msg_err("heap: %p, gap %R found while setting %R\n", bound(i), r, bound(q));
    return false;
}

static inline boolean set_area(id_heap i, u64 base, u64 length, boolean validate, boolean allocate)
{
    base &= ~page_mask(i);
    length = pad(length, page_size(i));

    range q = range_rshift(irangel(base, length), page_order(i));
    rmnode_handler nh = stack_closure(set_intersection, q, validate, allocate);
    range_handler rh = stack_closure(set_gap, i, q);
    int result = rangemap_range_lookup_with_gaps(i->ranges, q, nh, rh);
    if (validate && result == RM_MATCH) {
        if (allocate) {
            i->allocated += length;
        } else {
            assert(i->allocated >= length);
            i->allocated -= length;
        }
    }
    return result == RM_MATCH;
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
static inline void set_next(id_heap i, bytes count, u64 next)
{
    u64 order = find_order(pages_from_bytes(i, count));
    rangemap_foreach(i->ranges, n) {
        id_range r = (id_range)n;
        if (point_in_range(r->n.r, next))
            set_next_bit(r, order, next - r->bitmap_start);
        else if (r->n.r.start > next)
            set_next_bit(r, order, 0);
    }
}

#ifdef KERNEL
/* locking variants */

/* spinlock lies just after invariants */
#define id_lock(h) ((spinlock)(((id_heap)h) + 1))

static u64 id_alloc_locking(heap h, bytes count)
{
    u64 flags = spin_lock_irq(id_lock(h));
    u64 a = id_alloc(h, count);
    spin_unlock_irq(id_lock(h), flags);
    return a;
}

static void id_dealloc_locking(heap h, u64 a, bytes count)
{
    u64 flags = spin_lock_irq(id_lock(h));
    id_dealloc(h, a, count);
    spin_unlock_irq(id_lock(h), flags);
}

static boolean add_range_locking(id_heap i, u64 base, u64 length)
{
    u64 flags = spin_lock_irq(id_lock(i));
    boolean r = add_range(i, base, length);
    spin_unlock_irq(id_lock(i), flags);
    return r;
}

static boolean set_area_locking(id_heap i, u64 base, u64 length, boolean validate, boolean allocate)
{
    u64 flags = spin_lock_irq(id_lock(i));
    boolean r = set_area(i, base, length, validate, allocate);
    spin_unlock_irq(id_lock(i), flags);
    return r;
}

static void set_randomize_locking(id_heap i, boolean randomize)
{
    u64 flags = spin_lock_irq(id_lock(i));
    set_randomize(i, randomize);
    spin_unlock_irq(id_lock(i), flags);
}

static u64 alloc_subrange_locking(id_heap i, bytes count, u64 start, u64 end)
{
    u64 flags = spin_lock_irq(id_lock(i));
    u64 a = alloc_subrange(i, count, start, end);
    spin_unlock_irq(id_lock(i), flags);
    return a;
}

static void set_next_locking(id_heap i, bytes count, u64 next)
{
    u64 flags = spin_lock_irq(id_lock(i));
    set_next(i, count, next);
    spin_unlock_irq(id_lock(i), flags);
}

closure_function(2, 0, value, id_get_allocated,
                 id_heap, i, value, v)
{
    return value_rewrite_u64(bound(v), bound(i)->allocated);
}

closure_function(2, 0, value, id_get_total,
                 id_heap, i, value, v)
{
    return value_rewrite_u64(bound(v), bound(i)->total);
}

closure_function(2, 0, value, id_get_free,
                 id_heap, i, value, v)
{
    return value_rewrite_u64(bound(v), bound(i)->total - bound(i)->allocated);
}

#define register_stat(i, n, t, name)                                    \
    v = value_from_u64(0);                                              \
    s = sym(name);                                                      \
    set(t, s, v);                                                       \
    tuple_notifier_register_get_notify(n, s, closure(i->meta, id_get_ ##name, i, v));

static value id_management(heap h)
{
    id_heap i = (id_heap)h;
    if (i->mgmt)
        return i->mgmt;
    value v;
    symbol s;
    tuple t = timm("type", "id", "pagesize", "%d", i->h.pagesize);
    assert(t != INVALID_ADDRESS);
    tuple_notifier n = tuple_notifier_wrap(t);
    assert(n != INVALID_ADDRESS);
    register_stat(i, n, t, allocated);
    register_stat(i, n, t, total);
    register_stat(i, n, t, free);
    i->mgmt = (tuple)n;
    return n;
}

#endif /* KERNEL */

closure_function(2, 1, boolean, node_foreach_handler,
                 range_handler, rh, int, order,
                 rmnode, n)
{
    apply(bound(rh), range_lshift(n->r, bound(order)));
    return true;
}

boolean id_heap_range_foreach(id_heap i, range_handler rh)
{
    return (rangemap_range_lookup(i->ranges, (range){0, infinity},
                                  stack_closure(node_foreach_handler, rh, page_order(i))) ==
            RM_MATCH);
}

closure_function(1, 1, boolean, prealloc_foreach_handler,
                 id_heap, i,
                 range, r)
{
    return set_area(bound(i), r.start, range_span(r), false, false);
}

/* Pre-allocate all internal data structures so that no future allocations will be requested from
 * the meta or map heaps when operating the id heap. */
boolean id_heap_prealloc(id_heap i)
{
    return id_heap_range_foreach(i, stack_closure(prealloc_foreach_handler, i));
}

#ifdef KERNEL
id_heap clone_id_heap(id_heap source)
{
    heap h = source->meta;
    id_heap i = allocate(h, id_size());
    if (i == INVALID_ADDRESS)
        return INVALID_ADDRESS;
    boolean locking = source->h.alloc == id_alloc_locking;
    runtime_memcpy(i, source, sizeof(struct id_heap));
    if (locking)
        spin_lock_init(id_lock(i));
    i->ranges = allocate_rangemap(h);
    if (i->ranges == INVALID_ADDRESS)
        goto fail_dealloc;
    rangemap_foreach(source->ranges, n) {
        id_range r = struct_from_field(n, id_range, n);
        id_range s = allocate(h, sizeof(struct id_range));
        if (s == INVALID_ADDRESS)
            goto fail_dealloc_ranges;
        s->b = bitmap_clone(r->b);
        if (s->b == INVALID_ADDRESS)
            goto fail_dealloc_ranges;
        runtime_memcpy(s->next_bit, r->next_bit, sizeof(r->next_bit));
        s->n.r = r->n.r;
        assert(rangemap_insert(i->ranges, &s->n));
    }
    i->mgmt = 0;                /* regenerate */
    return i;
  fail_dealloc_ranges:
    rangemap_foreach(i->ranges, n) {
        id_range r = struct_from_field(n, id_range, n);
        rangemap_remove_node(i->ranges, n);
        deallocate_bitmap(r->b);
        deallocate(h, r, sizeof(*r));
    }
  fail_dealloc:
    deallocate(h, i, id_size());
    return INVALID_ADDRESS;
}
#endif

id_heap allocate_id_heap(heap meta, heap map, bytes pagesize, boolean locking)
{
    assert((pagesize & (pagesize-1)) == 0); /* pagesize is power of 2 */

    id_heap i = allocate(meta, id_size());
    if (i == INVALID_ADDRESS)
	return INVALID_ADDRESS;
    i->h.pagesize = pagesize;
    i->h.destroy = id_destroy;
    i->h.allocated = id_allocated;
    i->h.total = id_total;
    i->mgmt = 0;

#ifdef KERNEL
    i->h.management = id_management;
    if (locking) {
        spin_lock_init(id_lock(i));
        i->h.alloc = id_alloc_locking;
        i->h.dealloc = id_dealloc_locking;
        i->add_range = add_range_locking;
        i->set_area = set_area_locking;
        i->set_randomize = set_randomize_locking;
        i->alloc_subrange = alloc_subrange_locking;
        i->set_next = set_next_locking;
    } else
#else
    i->h.management = 0;
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
        deallocate(meta, i, id_size());
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
