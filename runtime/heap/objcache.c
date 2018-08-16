/* object cache heap

   This allocates pages of objects at a time, recycling objects in a
   per-page free list. This can later expand into being a true
   slab-like object cache with object constructors, etc.

   issues / todo:

   - Do we bother with locking or leave it up to the caller to
     correctly synchronize accesses to the objcache instance?

     - Per-page locks may reduce contention.

   - See notes in allocate_objcache() with regard to supporting
     multi-page parent head allocations.

   - Round up cache occupancy and put in tuple space.

*/

#include <runtime.h>

#define FOOTER_MAGIC	(u16)(0xcafe)
typedef struct footer {
    u16 magic;			/* try to detect corruption by overruns */
    u16 free;			/* next free (recycled) object in page */
    u16 head;			/* next uninitialized object in page */
    u16 avail;			/* # of free and uninit. objects in page */
    struct list list;		/* full list if avail == 0, free otherwise */
} *footer;

typedef struct objcache {
    struct heap h;
    heap parent;
    struct list free;		/* pages with available objects */
    struct list full;		/* fully-occupied pages */
    u64 objs_per_page;		/* objects per page */
    u64 total_objs;		/* total objects in cache */
    u64 alloced_objs;		/* total cache occupancy (of total_objs) */
} *objcache;

typedef u64 page;

#define object_size(o) (o->h.pagesize)
#define page_size(o) (o->parent->pagesize)
#define next_free_from_obj(o) (*(u16*)pointer_from_u64(o))
#define is_valid_index(i) ((i) != (u16)-1)
#define invalid_index (-1)

static inline page page_from_obj(objcache o, u64 a)
{
    return ~(page_size(o) - 1) & a;
}

static inline page page_from_footer(objcache o, footer f)
{
    return page_from_obj(o, u64_from_pointer(f));
}

static inline footer footer_from_page(objcache o, page p)
{
    /* XXX assert low order bits of p are clear */
    return (footer)(p + page_size(o) - sizeof(struct footer));
}

static inline u64 obj_from_index(objcache o, page p, u16 i)
{
    return (p + i * object_size(o));
}

static inline u16 index_from_obj(objcache o, page p, u64 obj)
{
    assert(obj >= p);
    assert(obj < p + o->parent->pagesize);
    u64 offset = obj - p;
    assert(offset % object_size(o) == 0); /* insure obj lands on object boundary */
    return (u16)offset / object_size(o);
}

#define footer_from_list(l)						\
    ((footer)pointer_from_u64((u64_from_pointer(l) -			\
			       offsetof(footer, list))))

#define foreach_page_footer(l, f)				\
    for (f = footer_from_list((l)->next); &f->list != (l);	\
	 f = footer_from_list(f->list.next))

static footer objcache_addpage(objcache o)
{
    page p = allocate_u64(o->parent, o->h.pagesize);
    if (p == INVALID_PHYSICAL) {
	msg_err("unable to allocate page\n");
	return 0;
    }

    msg_debug("heap %p, got page %P\n", o, p);
    assert ((p & (page_size(o) - 1)) == 0);

    footer f = footer_from_page(o, p);
    f->free = invalid_index;
    f->head = 0;
    f->avail = o->objs_per_page;
    f->magic = FOOTER_MAGIC;

    list_insert_after(&o->free, &f->list);
    o->total_objs += o->objs_per_page;

    return f;
}

static void objcache_deallocate(heap h, u64 x, bytes size)
{
    objcache o = (objcache)h;
    page p = page_from_obj(o, x);
    footer f = footer_from_page(o, p);

    msg_debug("*** heap %p: objsize %d, per page %d, total %d, alloced %d\n",
	      h, object_size(o), o->objs_per_page, o->total_objs,
	      o->alloced_objs);
    msg_debug(" -  obj %P, page %p, footer: free %d, head %d, avail %d\n",
	      x, p, f->free, f->head, f->avail);

    if (f->magic != FOOTER_MAGIC) {
	halt("heap %p, object %P, size %d: bad magic!\n", h, x, size);
    }

    if (f->avail == 0) {
	assert(!is_valid_index(f->free));
	/* Move from full to free list */
	list_delete(&f->list);
	list_insert_after(&o->free, &f->list);
    }

    next_free_from_obj(x) = f->free;
    f->free = index_from_obj(o, p, x);
    f->avail++;
    assert(f->avail <= o->objs_per_page);

    assert(o->alloced_objs > 0);
    o->alloced_objs--;
}

static u64 objcache_allocate(heap h, bytes size)
{
    objcache o = (objcache)h;
    if (size != object_size(o)) {
	msg_err("on heap %p: alloc size (%d) doesn't match object size "
		"(%d)\n", h, size, object_size(o));
	return INVALID_PHYSICAL;
    }

    msg_debug("*** heap %p: objsize %d, per page %d, total %d, alloced %d\n",
	      h, object_size(o), o->objs_per_page, o->total_objs,
	      o->alloced_objs);
    
    footer f;
    struct list * next_free = list_get_next(&o->free);

    if (next_free) {
	f = footer_from_list(next_free);
    } else {
	msg_debug("empty; calling objcache_addpage()\n", o->free);

	if (!(f = objcache_addpage(o)))
	    return INVALID_PHYSICAL;
    }

    page p = page_from_footer(o, f);
    u64 obj;
	
    if (f->magic != FOOTER_MAGIC) {
	msg_err("heap %p, page %P, size %d: bad magic!\n", h, p, size);
	return INVALID_PHYSICAL;
    }

    msg_debug("allocating from page %P\n", p);
    
    /* first check page's free list */
    if (is_valid_index(f->free)) {
	msg_debug("f->free %d\n", f->free);
	obj = obj_from_index(o, p, f->free);
	f->free = next_free_from_obj(obj);
    } else {
	/* we must have an uninitialized object */
	assert(is_valid_index(f->head));
	assert(f->head < o->objs_per_page);

	msg_debug("f->head %d\n", f->head);
	
	obj = obj_from_index(o, p, f->head);
	f->head++;
    }

    assert(f->avail > 0);
    if(!--f->avail) {
	/* move from free to full list */
	list_delete(&f->list);
	list_insert_before(&o->full, &f->list);
    }
    
    assert(o->alloced_objs <= o->total_objs);
    o->alloced_objs++;
    
    msg_debug("returning obj %P\n", obj);
    
    return obj;
}

static void objcache_destroy(heap h)
{
    objcache o = (objcache)h;
    
    /* Check and report if there are unreturned objects, but proceed
       to release pages to parent heap anyway. */

    if (o->alloced_objs > 0) {
	msg_debug("%d objects still allocated in objcache %p; releasing "
		  "pages anyway\n", o->alloced_objs, o);
    }

    footer f;

    foreach_page_footer(&o->free, f) {
	page p = page_from_footer(o, f);
	deallocate_u64(o->parent, p, page_size(o));
    }
    
    foreach_page_footer(&o->full, f) {
	page p = page_from_footer(o, f);
	deallocate_u64(o->parent, p, page_size(o));
    }
}

/* Sanity-checks the object cache, returning true if no discrepancies
   are found. */
boolean objcache_validate(heap h)
{
    objcache o = (objcache)h;

    /* walk pages, checking:
       - reserved magic isn't clobbered
       - f->avail is nonzero and matches tally of free and uninit objs
       - full pages are indeed full
       - total_objs = page tally * objs_per_page
       - alloced_objs matches total objs_per_page minus f->avails
    */

    footer f;

    u64 total_pages = 0;
    u64 total_avail = 0;

    /* check free list */
    foreach_page_footer(&o->free, f) {
	page p = page_from_footer(o, f);
	if (f->magic != FOOTER_MAGIC) {
	    msg_err("page %P has wrong magic\n", p);
	    return false;
	}

	if (f->avail == 0) {
	    msg_err("page %P on free list but has 0 avail\n", p);
	    return false;
	}

	if (!is_valid_index(f->free) && f->head == o->objs_per_page) {
	    msg_err("page %P on free list but object freelist empty "
		    "and no uninitialized objects\n", p);
	    return false;
	}

	/* walk the chain of free objects and tally */
	int free_tally = 0;

	if (is_valid_index(f->free)) {
	    u16 next = f->free;

	    do {
		/* validate index */
		if (next >= o->objs_per_page) {
		    msg_err("page %P on free list has invalid object index "
			    "%d, objs_per_page %d\n", next, o->objs_per_page);
		    return false;
		}
		u64 obj = obj_from_index(o, p, next);
		free_tally++;
		next = next_free_from_obj(obj);
	    } while(is_valid_index(next));
	}

	if (f->head > o->objs_per_page) {
	    msg_err("page %P on free list has f->head = %d > objs_per_page = "
		    "%d\n", p, f->head, o->objs_per_page);
	    return false;
	}
	
	int uninit_count = o->objs_per_page - f->head;
	if (free_tally + uninit_count != f->avail) {
	    msg_err("page %P free (%d) and uninit (%d) counts do not equal "
		    "f->avail (%d)\n", p, free_tally, uninit_count, f->avail);
	    return false;
	}

	msg_debug("free page %P has %d free and %d uninit (%d avail)\n",
		  p, free_tally, uninit_count, f->avail);
		  
	total_avail += f->avail;
	total_pages++;
    }

    /* check full list */
    foreach_page_footer(&o->full, f) {
	page p = page_from_footer(o, f);
	if (f->magic != FOOTER_MAGIC) {
	    msg_err("page %P has wrong magic\n", p);
	    return false;
	}

	if (f->avail != 0) {
	    msg_err("page %P on full list but has non-zero avail (%d)\n",
		    p, f->avail);
	    return false;
	}

	if (is_valid_index(f->free)) {
	    msg_err("page %P on full list but object freelist non-empty "
		    "(%d)\n", p, f->free);
	    return false;
	}

	if (f->head < o->objs_per_page) {
	    msg_err("page %P on full list but uninitialized objects remain "
		    "(%d)\n", o->objs_per_page - f->head);
	    return false;
	}

	total_pages++;
    }

    /* validate counts */
    if (total_pages * o->objs_per_page != o->total_objs) {
	msg_err("total_objs (%d) doesn't match tallied pages (%d) * "
		"objs_per_page (%d)\n", o->total_objs, total_pages,
		o->objs_per_page);
	return false;
    }

    if (o->total_objs - total_avail != o->alloced_objs) {
	msg_err("total_objs (%d) - tallied available objs (%d) doesn't match "
		"o->alloced_objs (%d)\n", o->total_objs, total_avail,
		o->alloced_objs);
	return false;
    }
    
    return true;
}

heap allocate_objcache(heap meta, heap parent, bytes objsize)
{
    u64 objs_per_page;

    if (objsize < sizeof(u16)) {
	msg_err("object size must be > %d\n", sizeof(u64));
	return INVALID_ADDRESS;
    }
    
    objs_per_page = (parent->pagesize - sizeof(struct footer)) / objsize;
    
    msg_debug("allocate_objcache(): meta %p, parent %p, objsize %d, "
		   "parent pagesize %d, obj per page %d\n",
		   meta, parent, objsize, parent->pagesize, objs_per_page);
    
    if (objs_per_page == 0) {
	/* If we wish to expand the objcache to support multiple-page
	   allocations, we have the following options:

	   1) Use an rtrie lookup on object addresses to find the
	      allocation footer (or, better yet, store this
	      per-allocation meta in the rtrie itself). This will add
	      some cycles to each deallocation for the rtrie lookup.

	   2) Make parent heap allocations with an alignment parameter
	      equal to the allocation size. This requires any given
	      objcache instance to have constant, 2^n-sized parent
	      allocations where n > page order. The footer can then be
	      found in the usual way by masking off the lowest 2^n - 1
	      bits and adding in the footer offset.

	   There is always the option of multiplexing the
	   (de)allocation routines to use whatever strategy best fits
	   the page-to-object size ratio.
	*/

	msg_err("page size %d cannot accomodate object size %d\n",
		     parent->pagesize, objsize);
	return INVALID_ADDRESS;
    }

    if (objs_per_page >= (1 << 16)) {
	objs_per_page = (1 << 16) - 1;
	msg_err("too many objects per page (pagesize %d, objsize %d); "
		"limiting to %d\n", parent->pagesize, objsize, objs_per_page);
    }
    
    objcache o = allocate(meta, sizeof(struct objcache));
    o->h.alloc = objcache_allocate;
    o->h.dealloc = objcache_deallocate;
    o->h.destroy = objcache_destroy;
    object_size(o) = objsize;	/* o->h.pagesize */
    o->parent = parent;

    list_init(&o->free);
    list_init(&o->full);

    o->objs_per_page = objs_per_page;
    o->total_objs = 0;
    o->alloced_objs = 0;

    if (!objcache_addpage(o)) {
	msg_err("failed to add initial page to objcache %p\n", o);
	deallocate(meta, o, sizeof(struct objcache));
	return INVALID_ADDRESS;
    }

    return (heap)o;
}
