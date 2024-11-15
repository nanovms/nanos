/* object cache heap

   This allocates pages of objects at a time, recycling objects in a
   per-page free list. This can later expand into being a true
   slab-like object cache with object constructors, etc.

   issues / todo:

   - Per-page locks may reduce contention.

   - See notes in allocate_objcache() with regard to supporting
     multi-page parent head allocations.

   - Round up cache occupancy and put in tuple space.

*/

#ifdef KERNEL
#include <kernel.h>
#else
#include <runtime.h>
#endif
#include <management.h>

#define FOOTER_MAGIC    (u16)(0xcafe)

typedef struct objcache *objcache;
typedef struct footer {
    u16 magic;              /* try to detect corruption by overruns */
    u16 free;               /* next free (recycled) object in page */
    u16 head;               /* next uninitialized object in page */
    u16 avail;              /* # of free and uninit. objects in page */
    heap cache;             /* objcache to which this page belongs */
    struct list list;       /* full list if avail == 0, free otherwise */
} *footer;

typedef struct objcache {
    struct caching_heap ch;
    heap meta;
    heap parent;
    struct list free;       /* pages with available objects */
    struct list full;       /* fully-occupied pages */
    bytes pagesize;         /* allocation size for parent heap */
    u64 objs_per_page;      /* objects per page */
    u64 total_objs;         /* total objects in cache */
    u64 alloced_objs;       /* total cache occupancy (of total_objs) */
    heap wrapper_heap;      /* heap wrapper */
    boolean prealloc_only;  /* do not allocate beyond preallocated count */
    tuple mgmt;
#ifdef KERNEL
    struct spinlock lock;
#endif
} *objcache;

typedef u64 page;

#define object_size(o) (o->ch.h.pagesize)
#define page_size(o) (o->pagesize)
#define next_free_from_obj(obj) (*(u16*)pointer_from_u64(obj))
#define invalid_index ((u16)-1)
#define is_valid_index(i) (((u16)i) != invalid_index)

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
    assert(obj < p + page_size(o));
    u64 offset = obj - p;
    assert(offset % object_size(o) == 0); /* insure obj lands on object boundary */
    return (u16)(offset / object_size(o));
}

#define footer_from_list(l) struct_from_list(l, footer, list)

#define foreach_page_footer(l, f)				\
    for (footer __next, f = footer_from_list((l)->next);                        \
        __next = footer_from_list(f->list.next), &f->list != (l); f = __next)

static footer objcache_addpage(objcache o)
{
    page p = allocate_u64(o->parent, page_size(o));
    if (p == INVALID_PHYSICAL) {
        msg_warn("objcache: unable to allocate page");
        return 0;
    }

    msg_debug("heap %p, got page %lx\n", o, p);
    assert ((p & (page_size(o) - 1)) == 0);

    footer f = footer_from_page(o, p);
    f->magic = FOOTER_MAGIC;
    f->free = invalid_index;
    f->head = 0;
    f->avail = o->objs_per_page;
    f->cache = o->wrapper_heap ? o->wrapper_heap : (heap)o;
    list_insert_after(&o->free, &f->list);
    o->total_objs += o->objs_per_page;

    return f;
}

static void objcache_removepage(objcache o, footer f)
{
    list_delete(&f->list);
    deallocate_u64(o->parent, page_from_footer(o, f), page_size(o));
    o->total_objs -= o->objs_per_page;
}

static inline boolean validate_page(objcache o, footer f)
{
    if (f->magic != FOOTER_MAGIC) {
        msg_err("objcache %p, footer %p, bad magic! (%x)", o, f, f->magic);
        return false;
    }

    if (f->cache != (heap)o && (o->wrapper_heap && f->cache != o->wrapper_heap)) {
        msg_err("objcache %p, footer %p, f->cache mismatch (%p)", o, f, f->cache);
        return false;
    }

    return true;
}

static inline void objcache_deallocate(heap h, u64 x, bytes size)
{
    objcache o = (objcache)h;
    page p = page_from_obj(o, x);
    footer f = footer_from_page(o, p);

    if (size != object_size(o)) {
        msg_err("objcache %p: dealloc size (%d) doesn't match object size (%d); leaking",
            h, size, object_size(o));
        return;
    }

    msg_debug("*** heap %p: objsize %d, per page %ld, total %ld, alloced %ld\n",
              h, object_size(o), o->objs_per_page, o->total_objs, o->alloced_objs);
    msg_debug(" -  obj %lx, page %p, footer: free %d, head %d, avail %d\n",
              x, p, f->free, f->head, f->avail);

    if (!validate_page(o, f)) {
        msg_err("%s: leaking object", func_ss);
        return;
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

static inline u64 objcache_allocate(heap h, bytes size)
{
    objcache o = (objcache)h;
    if (size != object_size(o)) {
        msg_err("objcache %p: alloc size (%d) doesn't match object size (%d)",
            h, size, object_size(o));
        return INVALID_PHYSICAL;
    }

    msg_debug("*** heap %p: objsize %d, per page %ld, total %ld, alloced %ld\n",
              h, object_size(o), o->objs_per_page, o->total_objs, o->alloced_objs);

    footer f;
    struct list * next_free = list_get_next(&o->free);

    if (next_free) {
        f = footer_from_list(next_free);
    } else {
        if (o->prealloc_only || !(f = objcache_addpage(o)))
            return INVALID_PHYSICAL;
    }

    if (!validate_page(o, f)) {
        msg_err("%s failed", func_ss);
        return INVALID_PHYSICAL;
    }

    page p = page_from_footer(o, f);

    msg_debug("allocating from page %lx\n", p);

    /* first check page's free list */
    u64 obj;
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
    msg_debug("returning obj %lx\n", obj);
    return obj;
}

static void objcache_destroy(heap h)
{
    objcache o = (objcache)h;

    /* Check and report if there are unreturned objects, but proceed
       to release pages to parent heap anyway. */
    if (o->alloced_objs > 0) {
	msg_debug("%ld objects still allocated in objcache %p; releasing pages anyway\n",
	    o->alloced_objs, o);
    }

    foreach_page_footer(&o->free, f)
        deallocate_u64(o->parent, page_from_footer(o, f), page_size(o));
    foreach_page_footer(&o->full, f)
        deallocate_u64(o->parent, page_from_footer(o, f), page_size(o));
    deallocate(o->meta, o, sizeof(struct objcache));
}

static u64 objcache_allocated(heap h)
{
    objcache o = (objcache)h;
    return o->alloced_objs * object_size(o);
}

static u64 objcache_total(heap h)
{
    objcache o = (objcache)h;
    return o->total_objs * object_size(o);
}

heap objcache_from_object(u64 obj, bytes parent_pagesize)
{
    footer f = pointer_from_u64((obj & ~((u64) parent_pagesize - 1)) +
                    (parent_pagesize - sizeof(struct footer)));
    if (f->magic != FOOTER_MAGIC)
        return INVALID_ADDRESS;
    return (heap)f->cache;
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

    u64 total_pages = 0;
    u64 total_avail = 0;

    /* check free list */
    foreach_page_footer(&o->free, f) {
        page p = page_from_footer(o, f);

        if (!validate_page(o, f)) {
            msg_err("%s failed on page %lx on free list", func_ss, p);
            return false;
        }

        if (f->avail == 0) {
            msg_err("%s error: page %lx on free list but has 0 avail", func_ss, p);
            return false;
        }

        if (!is_valid_index(f->free) && f->head == o->objs_per_page) {
            msg_err("%s error: page %lx on free list but object freelist empty "
                    "and no uninitialized objects", func_ss, p);
            return false;
        }

        /* walk the chain of free objects and tally */
        int free_tally = 0;

        if (is_valid_index(f->free)) {
            u16 next = f->free;

            do {
                /* validate index */
                if (next >= o->objs_per_page) {
                    msg_err("%s error: page %lx on free list has invalid object index %d, "
                            "objs_per_page %ld", func_ss, p, next, o->objs_per_page);
                    return false;
                }
                u64 obj = obj_from_index(o, p, next);
                free_tally++;
                next = next_free_from_obj(obj);
            } while(is_valid_index(next) && free_tally <= invalid_index);

            if (free_tally > invalid_index) {
                msg_err("%s error: page %lx on free list overflow while walking free list; "
                        "corrupt from possible loop, free_tally %d", func_ss, p, free_tally);
                return false;
            }
        }

        if (f->head > o->objs_per_page) {
            msg_err("%s error: page %lx on free list has f->head = %d > objs_per_page = %ld",
                    func_ss, p, f->head, o->objs_per_page);
            return false;
        }

        int uninit_count = o->objs_per_page - f->head;
        if (free_tally + uninit_count != f->avail) {
            msg_err("%s error: page %lx free (%d) and uninit (%d) counts do not equal f->avail "
                    "(%d)", func_ss, p, free_tally, uninit_count, f->avail);
            return false;
        }

        msg_debug("free page %lx has %d free and %d uninit (%d avail)\n",
                  p, free_tally, uninit_count, f->avail);

        total_avail += f->avail;
        total_pages++;
    }

    /* check full list */
    foreach_page_footer(&o->full, f) {
        page p = page_from_footer(o, f);

        if (!validate_page(o, f)) {
            msg_err("%s failed on page %lx on full list", func_ss, p);
            return false;
        }

        if (f->avail != 0) {
            msg_err("%s error: page %lx on full list but has non-zero avail (%d)",
                    func_ss, p, f->avail);
            return false;
        }

        if (is_valid_index(f->free)) {
            msg_err("%s error: page %lx on full list but object freelist non-empty (%d)",
                    func_ss, p, f->free);
            return false;
        }

        if (f->head < o->objs_per_page) {
            msg_err("%s error: page %lx on full list but uninitialized objects remain (%ld)",
                    func_ss, p, o->objs_per_page - f->head);
            return false;
        }

        total_pages++;
    }

    /* validate counts */
    if (total_pages * o->objs_per_page != o->total_objs) {
        msg_err("%s error: total_objs (%ld) doesn't match tallied pages (%ld) * objs_per_page "
                "(%ld)", func_ss, o->total_objs, total_pages, o->objs_per_page);
        return false;
    }

    if (o->total_objs - total_avail != o->alloced_objs) {
        msg_err("%s error: total_objs (%ld) - tallied available objs (%ld) doesn't match "
                "o->alloced_objs (%ld)", func_ss, o->total_objs, total_avail, o->alloced_objs);
        return false;
    }

    return true;
}

closure_function(2, 0, value, objcache_get_allocated,
                 objcache, o, value, v)
{
    return value_rewrite_u64(bound(v), objcache_allocated((heap)bound(o)));
}

closure_function(2, 0, value, objcache_get_total,
                 objcache, o, value, v)
{
    return value_rewrite_u64(bound(v), objcache_total((heap)bound(o)));
}

closure_function(2, 0, value, objcache_get_free,
                 objcache, o, value, v)
{
    heap h = (heap)bound(o);
    return value_rewrite_u64(bound(v), objcache_total(h) - objcache_allocated(h));
}

#define register_stat(o, n, t, name)                                    \
    v = value_from_u64(0);                                              \
    s = sym(name);                                                      \
    set(t, s, v);                                                       \
    tuple_notifier_register_get_notify(n, s, closure(o->meta, objcache_get_ ##name, o, v));

static value objcache_management(heap h)
{
    objcache o = (objcache)h;
    if (o->mgmt)
        return o->mgmt;
    value v;
    symbol s;
    tuple t = timm("type", "objcache");
    t = timm_append(t, "pagesize", "%d", object_size(o));
    tuple_notifier n = tuple_notifier_wrap(t, false);
    assert(n != INVALID_ADDRESS);
    register_stat(o, n, t, allocated);
    register_stat(o, n, t, total);
    register_stat(o, n, t, free);
    o->mgmt = (tuple)n;
    return n;
}

static inline bytes objcache_drain(struct caching_heap *ch, bytes size, bytes retain)
{
    objcache o = (objcache)ch;
    bytes retained = 0;
    bytes drained = 0;
    /* First pass: compute the amount of retained memory, and drain memory only if the amount
     * computed so far is higher than `retain`. */
    foreach_page_footer(&o->free, f) {
        if ((retained >= retain) && (f->avail == o->objs_per_page)) {
            objcache_removepage(o, f);
            drained += page_size(o);
            if (drained >= size)
                return drained;
        } else {
            retained += f->avail * object_size(o);
        }
    }
    /* Second pass: drain additional memory unless it would bring the total amount of retained
     * memory below `retain`. */
    foreach_page_footer(&o->free, f) {
        if (retained < retain + page_size(o))
            break;
        if (f->avail == o->objs_per_page) {
            objcache_removepage(o, f);
            drained += page_size(o);
            if (drained >= size)
                break;
            retained -= page_size(o);
        }
    }
    return drained;
}

#ifdef KERNEL

#define objcache_lock(h) (&((objcache)(h))->lock)

static u64 objcache_alloc_locking(heap h, bytes size)
{
    u64 flags = spin_lock_irq(objcache_lock(h));
    u64 a = objcache_allocate(h, size);
    spin_unlock_irq(objcache_lock(h), flags);
    return a;
}

static void objcache_dealloc_locking(heap h, u64 x, bytes size)
{
    u64 flags = spin_lock_irq(objcache_lock(h));
    objcache_deallocate(h, x, size);
    spin_unlock_irq(objcache_lock(h), flags);
}

static bytes objcache_drain_locking(struct caching_heap *ch, bytes size, bytes retain)
{
    u64 flags = spin_lock_irq(objcache_lock(ch));
    u64 drained = objcache_drain(ch, size, retain);
    spin_unlock_irq(objcache_lock(ch), flags);
    return drained;
}

#endif

/* If the parent heap gives allocations that are aligned to size, the
   caller may choose a power-of-2 pagesize that is larger than the
   parent pagesize. Otherwise, pagesize must be equal to parent
   pagesize. */
caching_heap allocate_objcache(heap meta, heap parent, bytes objsize, bytes pagesize, boolean locking)
{
    u64 objs_per_page;

    if (objsize < sizeof(u16)) {
        msg_err("objcache object size must be > %d", sizeof(u16));
        return INVALID_ADDRESS;
    }

    if (pagesize < parent->pagesize ||
        ((pagesize - 1) & pagesize)) {
        msg_err("objcache pagesize (%d) must be a power-of-2 >= parent pagesize (%d)",
            pagesize, parent->pagesize);
        return INVALID_ADDRESS;
    }

    objs_per_page = (pagesize - sizeof(struct footer)) / objsize;

    msg_debug("allocate_objcache(): meta %p, parent %p, objsize %d, "
               "pagesize %d, obj per page %ld\n",
               meta, parent, objsize, pagesize, objs_per_page);

    if (objs_per_page == 0) {
        msg_err("objcache page size %d cannot accommodate object size %d",
                pagesize, objsize);
        return INVALID_ADDRESS;
    }

    if (objs_per_page >= U64_FROM_BIT(16)) {
        objs_per_page = U64_FROM_BIT(16) - 1;
        msg_warn("objcache: too many objects per page (pagesize %d, objsize %d); "
            "limiting to %ld", pagesize, objsize, objs_per_page);
    }

    objcache o = allocate(meta, sizeof(struct objcache));
    assert(o != INVALID_ADDRESS);
#ifdef KERNEL
    if (locking) {
        spin_lock_init(objcache_lock(o));
        o->ch.h.alloc = objcache_alloc_locking;
        o->ch.h.dealloc = objcache_dealloc_locking;
        o->ch.drain = objcache_drain_locking;
    } else
#endif
    {
        o->ch.h.alloc = objcache_allocate;
        o->ch.h.dealloc = objcache_deallocate;
        o->ch.drain = objcache_drain;
    }
    o->ch.h.destroy = objcache_destroy;
    o->ch.h.allocated = objcache_allocated;
    o->ch.h.total = objcache_total;
    o->ch.h.pagesize = objsize;
    o->ch.h.management = objcache_management;
    o->meta = meta;
    o->parent = parent;

    list_init(&o->free);
    list_init(&o->full);

    o->pagesize = pagesize;
    o->objs_per_page = objs_per_page;
    o->total_objs = 0;
    o->alloced_objs = 0;
    o->wrapper_heap = 0;
    o->mgmt = 0;
    o->prealloc_only = false;

    return (caching_heap)o;
}

caching_heap allocate_wrapped_objcache(heap meta, heap parent, bytes objsize, bytes pagesize, heap wrapper)
{
    objcache o = (objcache)allocate_objcache(meta, parent, objsize, pagesize, false);
    if (o == INVALID_ADDRESS)
        return INVALID_ADDRESS;
    o->wrapper_heap = wrapper;
    return (caching_heap)o;
}

caching_heap allocate_objcache_preallocated(heap meta, heap parent, bytes objsize, bytes pagesize, u64 prealloc_count, boolean prealloc_only)
{
    objcache o = (objcache)allocate_objcache(meta, parent, objsize, pagesize, false);
    if (o == INVALID_ADDRESS)
        return INVALID_ADDRESS;
    u64 npages = prealloc_count / o->objs_per_page + (prealloc_count % o->objs_per_page ? 1 : 0);
    for (u64 i = 0; i < npages; i++) {
        footer f = objcache_addpage(o);
        assert(f != INVALID_ADDRESS);
    }
    o->prealloc_only = prealloc_only;
    return (caching_heap)o;
}

