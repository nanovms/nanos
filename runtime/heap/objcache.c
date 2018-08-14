/* like freelist, but operating on a page's worth of objects at time

   later this can expand into being a true slab-like object cache with
   instantiators, cache aliasing protection, etc.

   issues / todo:

   - Do we bother with locking or leave it up to the caller to
     correctly synchronize accesses to the objcache instance?

   - See notes in allocate_objcache() with regard to supporting
     multi-page parent head allocations.

   - Round up cache occupancy and put in tuple space

*/

#include <runtime.h>

#define msg_err(fmt, ...) rprintf("%s error: " fmt, __func__, \
				  ##__VA_ARGS__);

#if 1
#define msg_debug(fmt, ...) rprintf("%s debug: " fmt, __func__, \
				    ##__VA_ARGS__);
#else
#define msg_debug(fmt, ...)
#endif

struct pagelist {
    struct pagelist * prev;
    struct pagelist * next;
};

#define FOOTER_RESERVED_MAGIC	(u16)(0xcafe)
typedef struct footer {
    struct pagelist list;	/* full list if avail == 0, free otherwise */
    u16 free;			/* next free (recycled) object in page */
    u16 head;			/* next uninitialized object in page */
    u16 avail;			/* # of free and uninit. objects in page */
    u16 reserved;		/* unused */
} *footer;

typedef struct objcache {
    struct heap h;
    heap parent;
    struct pagelist free;	/* pages with available objects */
    struct pagelist full;	/* fully-occupied pages */
    u64 page_objs;		/* objects per page */
    u64 total_objs;		/* total objects in cache */
    u64 alloced_objs;		/* total cache occupancy (of total_objs) */
} *objcache;

typedef u64 page;

#define object_size(o) (o->h.pagesize)
#define page_size(o) (o->parent->pagesize)
#define next_free_from_obj(o) (*(u64*)pointer_from_u64(o))
#define is_valid_index(i) ((i) != -1)
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

/* maybe move the list stuff to a generic header */
static inline void list_init(struct pagelist * head)
{
    head->prev = head->next = head;
}

static inline boolean list_empty(struct pagelist * head)
{
    assert((head->next == head) ^ (head->prev == head) == 0);
    return (head->next == head);
}

static inline struct pagelist * list_get_next(struct pagelist * head)
{
    return head->next == head ? 0 : head->next;
}

static inline void list_delete(struct pagelist * p)
{
    assert(p->prev && p->next);
    p->prev->next = p->next;
    p->next->prev = p->prev;
    p->prev = p->next = 0;	/* or poison magic */
}

static inline void list_insert_after(struct pagelist * pos,
				     struct pagelist * new)
{
    new->prev = pos;
    new->next = pos->next;
    pos->next->prev = new;
    pos->next = new;
}

static inline void list_insert_before(struct pagelist * pos,
				      struct pagelist * new)
{
    new->prev = pos->prev;
    new->next = pos;
    pos->prev->next = new;
    pos->prev = new;
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

    footer f = footer_from_page(o, p);
    f->free = invalid_index;
    f->head = 0;
    f->avail = o->page_objs;
    f->reserved = FOOTER_RESERVED_MAGIC;

    list_insert_after(&o->free, &f->list);
    o->total_objs += o->page_objs;

    return f;
}

static void objcache_deallocate(heap h, u64 x, bytes size)
{
    objcache o = (objcache)h;
    page p = page_from_obj(o, x);
    footer f = footer_from_page(o, p);
    u64 lastfree;

    msg_debug("heap %p, ptr %P, size: %d\n", o, x, size);
    msg_debug(" - page %p, footer: free %d, head %d, avail %d\n",
		   p, f->free, f->head, f->avail);

    if (is_valid_index(f->free)) {
	lastfree = obj_from_index(o, p, f->free);
    } else {
	lastfree = 0;
	if (f->avail == 0) {
	    /* Move from full to free list */
	    list_delete(&f->list);
	    list_insert_after(&o->free, &f->list);
	}
    }

    next_free_from_obj(x) = lastfree;
    f->free = index_from_obj(o, p, x);
    f->avail++;

    assert(f->avail < o->page_objs);
}

static u64 objcache_allocate(heap h, bytes size)
{
    objcache o = (objcache)h;
    assert(size == object_size(o));

    footer f = (footer)list_get_next(&o->free);
    
    if (!f) {
	msg_debug("empty; calling objcache_addpage()\n", o->free);

	if (!(f = objcache_addpage(o)))
	    return INVALID_PHYSICAL;
    }

    page p = page_from_footer(o, f);
    u64 obj;
	
    /* first check page's free list */
    if (is_valid_index(f->free)) {
	obj = obj_from_index(o, p, f->free);
	u64 n = next_free_from_obj(obj);
	f->free = n ? index_from_obj(o, p, n) : invalid_index;
    } else {
	/* we must have an uninitialized object */
	assert(is_valid_index(f->head));
	assert(f->head < o->page_objs);

	obj = obj_from_index(o, p, f->head);
	f->head++;
    }

    assert(f->avail > 0);
    if(!--f->avail) {
	/* move from free to full list */
	list_delete(&f->list);
	list_insert_before(&o->full, &f->list);
    }
    
    assert(o->alloced_objs < o->total_objs);
    o->alloced_objs++;
    
    return obj;
}

static void objcache_destroy(heap h)
{
    objcache o = (objcache)h;
    
    /* Check and report if there are unreturned objects, but proceed
       to release pages to parent heap anyway. */

    if (o->alloced_objs > 0) {
	msg_err("%d objects still allocated in objcache %p; releasing "
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
       - total_objs = page tally * page_objs
       - alloced_objs matches total page_objs minus f->avails
    */

    footer f;

    u64 total_pages = 0;
    u64 total_avail = 0;

    /* check free list */
    foreach_page_footer(&o->free, f) {
	page p = page_from_footer(o, f);
	if (f->reserved != FOOTER_RESERVED_MAGIC) {
	    msg_err("page %P has wrong magic\n", p);
	    return false;
	}

	if (f->avail == 0) {
	    msg_err("page %P on free list but has 0 avail\n", p);
	    return false;
	}

	if (!is_valid_index(f->free)) {
	    msg_err("page %P on free list but object freelist empty\n", p);
	    return false;
	}

	/* walk the chain of free objects and tally */
	int free_tally = 1;
	u64 obj = obj_from_index(o, p, f->free);
	
	while (obj != 0) {
	    obj = next_free_from_obj(o);
	    free_tally++;
	}

	if (f->head >= o->page_objs) {
	    msg_err("page %P on free list has f->head = %d > page_objs = %d\n",
		    p, f->head, o->page_objs);
	    return false;
	}
	
	int uninit_count = o->page_objs - f->head;
	if (free_tally + uninit_count != f->avail) {
	    msg_err("page %P free (%d) and uninit (%d) counts do not equal "
		    "f->avail (%d)\n", p, free_tally, uninit_count, f->avail);
	    return false;
	}

	total_avail += f->avail;
	total_pages++;
    }

    /* check full list */
    foreach_page_footer(&o->full, f) {
	page p = page_from_footer(o, f);
	if (f->reserved != FOOTER_RESERVED_MAGIC) {
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

	if (f->head < o->page_objs) {
	    msg_err("page %P on full list but uninitialized objects remain "
		    "(%d)\n", o->page_objs - f->head);
	    return false;
	}

	total_pages++;
    }

    /* validate counts */
    if (total_pages * object_size(o) != o->total_objs) {
	msg_err("total_objs (%d) doesn't match tallied pages (%d) * "
		"objsize (%d)\n", o->total_objs, total_pages, object_size(o));
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
    u64 page_objs = (parent->pagesize - sizeof(struct footer)) / objsize;
    
    msg_debug("allocate_objcache(): meta %p, parent %p, objsize %d, "
		   "parent pagesize %d, obj per page %d\n",
		   meta, parent, objsize, parent->pagesize, page_objs);
    
    if (page_objs == 0) {
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

    if (page_objs >= (1 << 16)) {
	page_objs = (1 << 16) - 1;
	msg_err("too many objects per page (pagesize %d, objsize %d); "
		"limiting to %d\n", parent->pagesize, objsize, page_objs);
    }
    
    objcache o = allocate(meta, sizeof(struct objcache));
    o->h.alloc = objcache_allocate;
    o->h.dealloc = objcache_deallocate;
    o->h.destroy = objcache_destroy;
    object_size(o) = objsize;	/* o->h.pagesize */
    o->parent = parent;

    list_init(&o->free);
    list_init(&o->full);

    o->page_objs = page_objs;
    o->total_objs = 0;
    o->alloced_objs = 0;

    if (!objcache_addpage(o)) {
	msg_err("failed to add initial page to objcache %p\n", o);
	deallocate(meta, o, sizeof(struct objcache));
	return INVALID_ADDRESS;
    }

    return (heap)o;
}


#if 0

void objcache_tb(heap meta, heap parent)
{
    /* just a cursory test */
    int n = 1024;
    int size = 32;
    int opp = PAGESIZE / size;
    int i;
    heap h = allocate_objcache(meta, parent, size);
    vector objs = allocate_vector(meta, n);

    msg_debug("objs %p, heap %p\n", objs, h);
    
    if (h == INVALID_ADDRESS) {
	msg_err("tb: failed to allocate objcache heap\n");
	/* XXX free vector */
	return;
    }

    /* allocate a page's worth */
    i = opp - 1;
    do {
	void * p = allocate(h, size);
	if (p == INVALID_ADDRESS) {
	    msg_err("tb: failed to allocate object\n");
	}
	vector_set(objs, i, p);
    } while (i--);

    /* and return */
    i = opp - 1;
    do {
	void * p = vector_get(objs, i);
	msg_debug("dealloc %p\n", p);
	deallocate(h, p, size);
    } while (i--);

    /* re-allocate a page's worth */
    i = opp - 1;
    do {
	void * p = allocate(h, size);
	if (p == INVALID_ADDRESS) {
	    msg_err("tb: failed to allocate object\n");
	}
	vector_set(objs, i, p);
    } while (i--);

    /* and one more to trigger a new page */
    void * p = allocate(h, size);

    /* list pages */
    objpage op = ((objcache)h)->pages;
    do {
	msg_debug("page %p\n", op->page);
	op = op->next;
    } while (op);
}

#endif
