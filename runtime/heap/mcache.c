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
} *mcache;

u64 mcache_alloc(heap h, bytes b)
{
    mcache m = (mcache)h;
    heap o;
#ifdef MCACHE_DEBUG
    console("mcache_alloc:   heap ");
    print_u64(u64_from_pointer(h));
    console(", size ");
    print_u64(b);
    console(": ");
#endif
    /* Could become a binary search if search set is large... */
    vector_foreach(m->caches, o) {
	if (o && b <= o->pagesize) {
	    u64 a = allocate_u64(o, o->pagesize);
	    if (a != INVALID_PHYSICAL)
		h->allocated += o->pagesize;
#ifdef MCACHE_DEBUG
	    console("obj size ");
	    print_u64(o->pagesize);
	    console(", addr ");
	    print_u64(a);
	    console("\n");
#endif
	    return a;
	}
    }
#ifdef MCACHE_DEBUG
    console("no matching cache; fail\n");
#endif
    return INVALID_PHYSICAL;
}

void mcache_dealloc(heap h, u64 a, bytes b)
{
#ifdef MCACHE_DEBUG
    console("mcache_dealloc: heap ");
    print_u64(u64_from_pointer(h));
    console(", addr ");
    print_u64(a);
    console(", size ");
    print_u64(b);
    console("\n");
#endif
    mcache m = (mcache)h;
    heap o = objcache_from_object(a, m->parent->pagesize);
    if (o == INVALID_ADDRESS) {
	msg_err("mcache %p: can't find cache for object %P, size %d; leaking\n",
		m, a, b);
	return;
    }

    /* We don't really need the size, but if we're given a valid one,
       make some attempt to verify it. */
    if (b != -1ull && b > o->pagesize) {
	msg_err("dealloc size (%d) exceeds found cache size (%d); leaking\n",
		b, o->pagesize);
	return;
    }
    assert(h->allocated >= o->pagesize);
    h->allocated -= o->pagesize;
    deallocate(o, a, o->pagesize);
}

void destroy_mcache(heap h)
{
    mcache m = (mcache)h;
    heap o;
    vector_foreach(m->caches, o) {
	if (o)
	    o->destroy(o);
    }
    deallocate(m->meta, m, sizeof(struct mcache));
}

heap allocate_mcache(heap meta, heap parent, bytes * sizes)
{
    mcache m = allocate(meta, sizeof(struct mcache));
    if (m == INVALID_ADDRESS)
	return INVALID_ADDRESS;

#ifdef MCACHE_DEBUG
    console("allocate_mcache: heap at ");
    print_u64(u64_from_pointer(m));
    console("\n");
#endif

    m->h.alloc = mcache_alloc;
    m->h.dealloc = mcache_dealloc;
    m->h.destroy = destroy_mcache;
    m->h.pagesize = 0; 		/* XXX not clear what the meaning is here */
    m->h.allocated = 0;
    m->meta = meta;
    m->parent = parent;
    m->caches = allocate_vector(meta, 1);

    /* XXX sort sizes */
    for(int i=0; sizes[i] != -1ull; i++) {
	heap h = allocate_objcache(meta, parent, sizes[i]);
#ifdef MCACHE_DEBUG
	console(" - cache size ");
	print_u64(sizes[i]);
	console(": ");
	print_u64(u64_from_pointer(h));
	console("\n");
#endif
	if (h == INVALID_ADDRESS)
	    goto alloc_fail;
	vector_set(m->caches, i, h);
    }

    return (heap)m;
  alloc_fail:
    msg_err("failed to allocate caches\n");
    destroy_mcache((heap)m);
    return INVALID_ADDRESS;
}
