/* multi-cache heap

   This is essentially a wrapper heap for a set of caches of varying
   object sizes. Object sizes are specified on heap creation. Allocations
   are made from the cache of the smallest object size equal to or greater
   than the alloc size.
*/

//#define MCACHE_DEBUG

#include <runtime.h>

typedef struct mcache {
    struct heap h;
    heap parent;
    heap meta;
    vector caches;
    u64 pagesize;
    u64 allocated;
} *mcache;

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
    heap o = objcache_from_object(a, m->pagesize);
    if (o == INVALID_ADDRESS) {
	rputs("mcache ");
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
    deallocate(m->meta, m, sizeof(struct mcache));
}

static u64 mcache_allocated(heap h)
{
    return ((mcache)h)->allocated;
}

heap allocate_mcache(heap meta, heap parent, int min_order, int max_order, bytes pagesize)
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
    m->h.total = 0;
    m->meta = meta;
    m->parent = parent;
    m->caches = allocate_vector(meta, 1);
    m->pagesize = pagesize;
    m->allocated = 0;

    for(int i=0, order = min_order; order <= max_order; i++, order++) {
	u64 obj_size = U64_FROM_BIT(order);
	heap h = allocate_objcache(meta, parent, obj_size, pagesize);
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
	vector_set(m->caches, i, h);
    }
    return (heap)m;
}
