/* multi-cache heap

   This heap multiplexes allocations across a set of objcaches of
   varying sizes. Allocations are made from the cache of the smallest
   size greater than or equal to the alloc size. Allocations of sizes
   greater than the largest cache size are served from the parent heap.

   To facilitate vendor code in the kernel that requires a malloc /
   free interface, deallocations may be made with a size of -1ull,
   provided that allocations are *only* served from one of the cache
   child heaps and not the parent. malloc/calloc functions exposed to
   such code should assert that the requested size does not exceed the
   maximum size passed to allocate_mcache (1ull << max_order).
*/

//#define MCACHE_DEBUG

#include <runtime.h>
#include <management.h>

typedef struct mcache {
    struct heap h;
    heap parent;
    heap meta;
    vector caches;
    u64 pagesize;
    u64 allocated;
    u64 parent_threshold;
    tuple mgmt;
    boolean malloc_style;   /* if true, deallocation requests are made without a size argument */
    table fallbacks;
} *mcache;

/* Mix each set of address bits between PAGELOG and 23 for a more even
   distribution among the four (default) buckets in the fallback table. */
static key fallback_key(void *p)
{
    u64 a = u64_from_pointer(p);
    return ((a >> 12) ^ (a >> 14)) ^ ((a >> 16) ^ (a >> 18)) ^
        ((a >> 20) ^ (a >> 22));
}

u64 mcache_alloc(heap h, bytes b)
{
    mcache m = (mcache)h;
    heap o;
#ifdef MCACHE_DEBUG
    rputs("mcache_alloc:   heap ");
    print_u64(u64_from_pointer(h));
    rputs(", size ");
    print_u64(b);
    rputs(": ");
#endif
    if (b > m->parent_threshold) {
        if (m->malloc_style && !m->fallbacks) {
            m->fallbacks = allocate_table(m->meta, fallback_key, pointer_equal);
            if (m->fallbacks == INVALID_ADDRESS) {
                rputs("mcache_alloc: failed to allocate fallbacks table\n");
                m->fallbacks = 0;
                return INVALID_PHYSICAL;
            }
        }
        u64 size = pad(b, m->parent->pagesize);
        u64 a = allocate_u64(m->parent, size);
        if (a != INVALID_PHYSICAL) {
            m->allocated += size;
            if (m->fallbacks)
                table_set(m->fallbacks, pointer_from_u64(a), pointer_from_u64(b));
        }
#ifdef MCACHE_DEBUG
        rputs("fallback to parent, size ");
        print_u64(b);
        rputs(", padded to ");
        print_u64(size);
        rputs(", addr ");
        print_u64(a);
        rputs("\n");
#endif
        return a;
    }

    /* Could become a binary search if search set is large... */
    vector_foreach(m->caches, o) {
	if (o && b <= o->pagesize) {
#ifdef MCACHE_DEBUG
	    rputs("match cache ");
	    print_u64(u64_from_pointer(o));
	    rputs(" obj size ");
	    print_u64(o->pagesize);
	    rputs(", pre validate...");
	    if (objcache_validate((heap)o))
		rputs("pass, alloc ");
	    else
		halt("failed!\n");
#endif
	    u64 a = allocate_u64(o, o->pagesize);
	    if (a != INVALID_PHYSICAL)
		m->allocated += o->pagesize;
#ifdef MCACHE_DEBUG
	    print_u64(a);
	    rputs(", post validate...");
	    if (objcache_validate((heap)o))
		rputs("pass\n");
	    else
		halt("failed!\n");
#endif
	    return a;
	}
    }
#ifdef MCACHE_DEBUG
    rputs("no matching cache; fail\n");
#endif
    return INVALID_PHYSICAL;
}

void mcache_dealloc(heap h, u64 a, bytes b)
{
#ifdef MCACHE_DEBUG
    rputs("mcache_dealloc: heap ");
    print_u64(u64_from_pointer(h));
    rputs(", addr ");
    print_u64(a);
    rputs(", size ");
    print_u64(b);
#endif

    mcache m = (mcache)h;
    u64 size = 0;

    if (b != -1ull && b > m->parent_threshold)
        size = pad(b, m->parent->pagesize);

    /* The fallback table tracks allocations that fall back to the parent
       heap. This allows use of a "malloc-style" interface to the mcache in
       which the allocation size is not specified on a deallocate. The cost of
       this is a table insertion when making a fallback allocation and a table
       lookup/removal when deallocating a fallback allocation of a known size,
       or on any deallocation (free) of an unknown size. */
    if (b == -1ull && m->fallbacks) {
        size = u64_from_pointer(table_remove(m->fallbacks, pointer_from_u64(a)));
        if (size > 0)
            size = pad(size, m->parent->pagesize);
    }

    if (size) {
#ifdef MCACHE_DEBUG
        rputs("dealloc size ");
        print_u64(b);
        rputs(", pagesize ");
        print_u64(m->parent->pagesize);
        rputs(", parent alloc size ");
        print_u64(size);
        rputs("\n");
#endif
        assert(m->allocated >= size);
        m->allocated -= size;
        deallocate_u64(m->parent, a, size);
        return;
    }

    heap o = objcache_from_object(a, m->pagesize);
    if (o == INVALID_ADDRESS) {
	rputs(", mcache ");
	print_u64(u64_from_pointer(m));
	rputs(": can't find cache for object ");
	print_u64(u64_from_pointer(a));
	rputs(", size ");
	print_u64(b);
	rputs("; leaking\n");
	return;
    }

    /* We don't really need the size, but if we're given a valid one,
       make some attempt to verify it. */
    if (b != -1ull && b > o->pagesize) {
	rputs("mcache ");
	print_u64(u64_from_pointer(m));
	rputs(": dealloc size (");
	print_u64(b);
	rputs(") exceeds found cache size (");
	print_u64(o->pagesize);
	rputs("); leaking\n");
	return;
    }

#ifdef MCACHE_DEBUG
    rputs(", pre validate...");
    if (objcache_validate((heap)o))
	rputs("pass");
    else
	halt("fail!\n");
#endif

    assert(m->allocated >= o->pagesize);
    m->allocated -= o->pagesize;
    deallocate(o, a, o->pagesize);
#ifdef MCACHE_DEBUG
    rputs(", post validate...");
    if (objcache_validate((heap)o))
	rputs("pass\n");
    else
	halt("fail!\n");
#endif
}

void destroy_mcache(heap h)
{
#ifdef MCACHE_DEBUG
    rputs("destroy_mcache: heap at ");
    print_u64(u64_from_pointer(h));
    rputs("\n");
#endif
    mcache m = (mcache)h;
    heap o;
    vector_foreach(m->caches, o) {
	if (o)
	    o->destroy(o);
    }
    if (m->fallbacks) {
        table_foreach(m->fallbacks, p, size) {
#ifdef MCACHE_DEBUG
            rputs("   dealloc fallback @ ");
            print_u64(u64_from_pointer(p));
            rputs(", size ");
            print_u64(u64_from_pointer(size));
            rputs("\n");
#endif
            deallocate(m->parent, p, pad(u64_from_pointer(size), m->parent->pagesize));
        }
        deallocate_table(m->fallbacks);
    }
    deallocate(m->meta, m, sizeof(struct mcache));
}

static u64 mcache_allocated(heap h)
{
    return ((mcache)h)->allocated;
}

static u64 mcache_total(heap h)
{
    u64 sum = 0;
    heap o;
    vector_foreach(((mcache)h)->caches, o) {
        if (o)
            sum += heap_total(o);
    }
    return sum;
}

closure_function(2, 0, value, mcache_get_allocated,
                 mcache, m, value, v)
{
    return value_rewrite_u64(bound(v), mcache_allocated((heap)bound(m)));
}

closure_function(2, 0, value, mcache_get_total,
                 mcache, m, value, v)
{
    return value_rewrite_u64(bound(v), mcache_total((heap)bound(m)));
}

closure_function(2, 0, value, mcache_get_free,
                 mcache, m, value, v)
{
    heap h = (heap)bound(m);
    return value_rewrite_u64(bound(v), mcache_total(h) - mcache_allocated(h));
}

#define register_stat(m, n, t, name)                                    \
    v = value_from_u64(0);                                              \
    s = sym(name);                                                      \
    set(t, s, v);                                                       \
    tuple_notifier_register_get_notify(n, s, closure(m->meta, mcache_get_ ##name, m, v));

static value mcache_management(heap h)
{
    mcache m = (mcache)h;
    if (m->mgmt)
        return m->mgmt;
    value v;
    symbol s;
    tuple t = timm("type", "mcache", "pagesize", "%d", m->h.pagesize);
    assert(t != INVALID_ADDRESS);
    tuple_notifier n = tuple_notifier_wrap(t, false);
    assert(n != INVALID_ADDRESS);
    register_stat(m, n, t, allocated);
    register_stat(m, n, t, total);
    register_stat(m, n, t, free);
    tuple c = allocate_tuple();
    assert(c != INVALID_ADDRESS);
    heap o;
    vector_foreach(m->caches, o) {
        if (o)
            set(c, intern_u64(o->pagesize), heap_management(o));
    }
    set(t, sym(caches), c);
    m->mgmt = (tuple)n;
    return n;
}

heap allocate_mcache(heap meta, heap parent, int min_order, int max_order, bytes pagesize,
                     boolean malloc_style)
{
    if (pagesize < parent->pagesize ||
	((pagesize - 1) & pagesize)) {
	msg_err("pagesize (%d) must be a power-of-2 >= parent pagesize (%d)\n",
		pagesize, parent->pagesize);
	return INVALID_ADDRESS;
    }

    if (U64_FROM_BIT(max_order) >= pagesize) {
	msg_err("max obj size (%d) must be less than pagesize %d\n", U64_FROM_BIT(max_order), pagesize);
	return INVALID_ADDRESS;
    }

    if (min_order > max_order) {
	msg_err("min_order (%d) cannot exceed max_order (%d)\n", min_order, max_order);
	return INVALID_ADDRESS;
    }

    mcache m = allocate(meta, sizeof(struct mcache));
    if (m == INVALID_ADDRESS)
	return INVALID_ADDRESS;

#ifdef MCACHE_DEBUG
    rputs("allocate_mcache: heap at ");
    print_u64(u64_from_pointer(m));
    rputs("\n");
#endif

    m->h.alloc = mcache_alloc;
    m->h.dealloc = mcache_dealloc;
    m->h.destroy = destroy_mcache;
    m->h.pagesize = U64_FROM_BIT(min_order); /* default to smallest obj size */
    m->h.allocated = mcache_allocated;
    m->h.total = mcache_total;
    m->h.management = mcache_management;
    m->meta = meta;
    m->parent = parent;
    m->caches = allocate_vector(meta, 1);
    m->pagesize = pagesize;
    m->allocated = 0;
    m->parent_threshold = U64_FROM_BIT(max_order);
    m->mgmt = 0;
    m->malloc_style = malloc_style;
    m->fallbacks = 0;

    for(int i = 0, order = min_order; order <= max_order; i++, order++) {
	u64 obj_size = U64_FROM_BIT(order);
#if defined(MEMDEBUG_MCACHE) || defined(MEMDEBUG_ALL)
	heap h = mem_debug_objcache(meta, parent, obj_size, pagesize);
#else
	caching_heap h = allocate_objcache(meta, parent, obj_size, pagesize, false);
#endif
#ifdef MCACHE_DEBUG
	rputs(" - cache size ");
	print_u64(obj_size);
	rputs(": ");
	print_u64(u64_from_pointer(h));
	rputs("\n");
#endif
	if (h == INVALID_ADDRESS) {
	    rputs("allocate_mcache: failed to allocate objcache of size ");
	    print_u64(obj_size);
	    rputs("\n");
	    destroy_mcache((heap)m);
	    return INVALID_ADDRESS;
	}
	assert(vector_set(m->caches, i, h));
    }
    return (heap)m;
}
