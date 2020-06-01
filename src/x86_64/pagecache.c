#include <kernel.h>
#include <page.h>
#include <pagecache.h>

//#define PAGECACHE_DEBUG
#if defined(PAGECACHE_DEBUG)
#define pagecache_debug(x, ...) do {rprintf("PGC: " x, ##__VA_ARGS__);} while(0)
#else
#define pagecache_debug(x, ...)
#endif

#define MAX_PAGE_COMPLETION_VECS 128

static inline u64 pagecache_pagesize(pagecache pc)
{
    return U64_FROM_BIT(pc->page_order);
}

static inline u64 pagecache_blocksize(pagecache pc)
{
    return U64_FROM_BIT(pc->block_order);
}

static int page_state(pagecache_page pp)
{
    return pp->state_phys >> PAGECACHE_PAGESTATE_SHIFT;
}

static inline void pagelist_enqueue(pagelist pl, pagecache_page pp)
{
    list_insert_before(&pl->l, &pp->l);
    pl->pages++;
}

static inline void pagelist_remove(pagelist pl, pagecache_page pp)
{
    list_delete(&pp->l);
    pl->pages--;
}

static inline void pagelist_move(pagelist dest, pagelist src, pagecache_page pp)
{
    pagelist_remove(src, pp);
    pagelist_enqueue(dest, pp);
}

static inline void pagelist_touch(pagelist pl, pagecache_page pp)
{
    list_delete(&pp->l);
    list_insert_before(&pl->l, &pp->l);
}

static inline void change_page_state_locked(pagecache pc, pagecache_page pp, int state)
{
    int old_state = page_state(pp);
    switch (state) {
#if 0
    /* Temporarily disabling use of free until we have a scheme to
       keep and act on "refault" data */
    case PAGECACHE_PAGESTATE_FREE:
        assert(old_state == PAGECACHE_PAGESTATE_EVICTED);
        pagelist_enqueue(&pc->free, pp);
        break;
#endif
    case PAGECACHE_PAGESTATE_EVICTED:
        if (old_state == PAGECACHE_PAGESTATE_NEW) {
            pagelist_remove(&pc->new, pp);
        } else {
            assert(old_state == PAGECACHE_PAGESTATE_ACTIVE);
            pagelist_remove(&pc->active, pp);
        }
        /* caller must do release following state change to evicted */
        break;
    case PAGECACHE_PAGESTATE_ALLOC:
        assert(old_state == PAGECACHE_PAGESTATE_FREE);
        pagelist_remove(&pc->free, pp);
        break;
    case PAGECACHE_PAGESTATE_READING:
        assert(old_state == PAGECACHE_PAGESTATE_ALLOC);
        break;
    case PAGECACHE_PAGESTATE_WRITING:
        if (old_state == PAGECACHE_PAGESTATE_NEW) {
            pagelist_move(&pc->writing, &pc->new, pp);
        } else if (old_state == PAGECACHE_PAGESTATE_ACTIVE) {
            pagelist_move(&pc->writing, &pc->active, pp);
        } else if (old_state == PAGECACHE_PAGESTATE_WRITING) {
            /* write already pending, move to tail of queue */
            pagelist_touch(&pc->writing, pp);
        } else {
            assert(old_state == PAGECACHE_PAGESTATE_ALLOC);
            pagelist_enqueue(&pc->writing, pp);
        }
        break;
    case PAGECACHE_PAGESTATE_NEW:
        if (old_state == PAGECACHE_PAGESTATE_ACTIVE) {
            pagelist_move(&pc->new, &pc->active, pp);
        } else if (old_state == PAGECACHE_PAGESTATE_WRITING) {
            pagelist_move(&pc->new, &pc->writing, pp);
        } else {
            assert(old_state == PAGECACHE_PAGESTATE_READING);
            pagelist_enqueue(&pc->new, pp);
        }
        break;
    case PAGECACHE_PAGESTATE_ACTIVE:
        assert(old_state == PAGECACHE_PAGESTATE_NEW);
        pagelist_move(&pc->active, &pc->new, pp);
        break;
    default:
        halt("%s: bad state %d, old %d\n", __func__, state, old_state);
    }

    pp->state_phys = (pp->state_phys & MASK(PAGECACHE_PAGESTATE_SHIFT)) |
        ((u64)state << PAGECACHE_PAGESTATE_SHIFT);
}

closure_function(1, 0, void, pagecache_service_completions,
                 pagecache, pc)
{
    /* we don't need the pagecache lock here; flag reset is atomic and dequeue is safe */
    bound(pc)->service_enqueued = false;
    vector v;
    while ((v = dequeue(bound(pc)->completion_vecs)) != INVALID_ADDRESS) {
        status_handler sh;
        status s = vector_pop(v);
        vector_foreach(v, sh) {
            assert(sh);
            apply(sh, s);
        }
        deallocate_vector(v);
    }
}

static void pagecache_page_queue_completions_locked(pagecache pc, pagecache_page pp, status s)
{
    if (pp->completions && vector_length(pp->completions) > 0) {
        vector_push(pp->completions, s);
        assert(enqueue(pc->completion_vecs, pp->completions));
        pp->completions = 0;
        if (!pc->service_enqueued) {
            pc->service_enqueued = true;
            assert(enqueue(runqueue, pc->service_completions));
        }
    }
}

closure_function(2, 1, void, pagecache_read_page_complete,
                 pagecache, pc, pagecache_page, pp,
                 status, s)
{
    pagecache pc = bound(pc);
    pagecache_page pp = bound(pp);
    pagecache_debug("%s: pc %p, pp %p, status %v\n", __func__, pc, bound(pp), s);
    assert(page_state(pp) == PAGECACHE_PAGESTATE_READING);

    if (!is_ok(s)) {
        /* TODO need policy for capturing/reporting I/O errors... */
        msg_err("error reading page 0x%lx: %v\n", pp->offset << pc->page_order, s);
    }
    spin_lock(&pc->state_lock);
    change_page_state_locked(bound(pc), pp, PAGECACHE_PAGESTATE_NEW);
    pagecache_page_queue_completions_locked(pc, pp, s);
    spin_unlock(&pc->state_lock);
    closure_finish();
}

/* As we're not doing backed mappings yet, we don't yet have soft
   faults wired up; new -> active transitions occur as a result of sg
   reads from fs.
*/
static boolean pagecache_page_touch_if_filled(pagecache pc, pagecache_page pp)
{
    spin_lock(&pc->state_lock);
    int state = page_state(pp);
    if (state == PAGECACHE_PAGESTATE_READING ||
        state == PAGECACHE_PAGESTATE_ALLOC) {
        spin_unlock(&pc->state_lock);
        return false;
    }

    /* move to bottom of active list */
    if (state == PAGECACHE_PAGESTATE_ACTIVE) {
        list_delete(&pp->l);
        list_insert_before(&pc->active.l, &pp->l);
    } else if (state == PAGECACHE_PAGESTATE_NEW) {
        /* cache hit -> active */
        change_page_state_locked(pc, pp, PAGECACHE_PAGESTATE_ACTIVE);
    } else {
        assert(state == PAGECACHE_PAGESTATE_WRITING ||
               state == PAGECACHE_PAGESTATE_DIRTY);
    }
    spin_unlock(&pc->state_lock);
    return true;
}

static void enqueue_page_completion_statelocked(pagecache pc, pagecache_page pp, status_handler sh)
{
    /* completions may have been consumed on service */
    if (!pp->completions)
        pp->completions = allocate_vector(pc->h, 4);
    vector_push(pp->completions, sh);
}

static inline range byte_range_from_pagecache_page(pagecache pc, pagecache_page pp)
{
    return range_lshift(irange(pp->offset, pp->offset + 1), pc->page_order);
}

static void pagecache_page_fill(pagecache pc, pagecache_page pp, status_handler sh)
{
    spin_lock(&pc->state_lock);
    enqueue_page_completion_statelocked(pc, pp, sh);
    if (page_state(pp) != PAGECACHE_PAGESTATE_ALLOC) {
        spin_unlock(&pc->state_lock);
        return;
    }
    change_page_state_locked(pc, pp, PAGECACHE_PAGESTATE_READING);
    spin_unlock(&pc->state_lock);

    /* zero pad anything extending past end of backing storage */
    range r = byte_range_from_pagecache_page(pc, pp);
    if (r.end > pc->length) {
        zero(pp->kvirt + (pc->length - r.start), r.end - pc->length);
        r.end = pc->length;
    }

    /* issue block reads */
    range blocks = range_rshift(r, pc->block_order);
    pagecache_debug("%s: pc %p, pp %p, blocks %R, reading...\n", __func__, pc, pp, blocks);
    apply(pc->block_read, pp->kvirt, blocks,
          closure(pc->h, pagecache_read_page_complete, pc, pp));
}

static u64 evict_from_list_locked(pagecache pc, struct pagelist *pl, u64 pages)
{
    u64 evicted = 0;
    list_foreach(&pl->l, l) {
        if (evicted >= pages)
            break;

        pagecache_page pp = struct_from_list(l, pagecache_page, l);
        pagecache_debug("%s: list %s, release pp %R, state %d, count %ld\n", __func__,
                        pl == &pc->new ? "new" : "active", byte_range_from_pagecache_page(pc, pp),
                        page_state(pp), pp->refcount.c);
        change_page_state_locked(pc, pp, PAGECACHE_PAGESTATE_EVICTED);
        rbtree_remove_node(&pc->pages, &pp->node);
        refcount_release(&pp->refcount); /* eviction, as far as cache is concerned */
        evicted++;
    }
    return evicted;
}

static void balance_page_lists_locked(pagecache pc)
{
    /* balance active and new lists */
    s64 dp = ((s64)pc->active.pages - (s64)pc->new.pages) / 2;
    pagecache_debug("%s: active %ld, new %ld, dp %ld\n", __func__, pc->active.pages, pc->new.pages, dp);
    list_foreach(&pc->active.l, l) {
        if (dp <= 0)
            break;
        pagecache_page pp = struct_from_list(l, pagecache_page, l);
        /* We don't presently have a notion of "time" in the cache, so
           just cull unreferenced buffers in LRU fashion until active
           pages are equivalent to new...loosely inspired by linux
           approach. */
        if (pp->refcount.c == 1) {
            pagecache_debug("   pp %R -> new\n", byte_range_from_pagecache_page(pc, pp));
            change_page_state_locked(pc, pp, PAGECACHE_PAGESTATE_NEW);
            dp--;
        }
    }
}

closure_function(2, 0, void, pagecache_page_release,
                 pagecache, pc, pagecache_page, pp)
{
    pagecache_page pp = bound(pp);
    /* remove from existing list depending on state */
    int state = page_state(pp);
    if (state != PAGECACHE_PAGESTATE_EVICTED)
        halt("%s: pc %p, pp %p, invalid state %d\n", __func__, bound(pc), pp, page_state(pp));

    pagecache pc = bound(pc);
    deallocate(pc->backed, pp->kvirt, pagecache_pagesize(pc));
    u64 pre = fetch_and_add(&pc->total_pages, -1);
    assert(pre > 0);
    pagecache_debug("%s: total pages now %ld\n", __func__, pre - 1);
    closure_finish();
}

static pagecache_page allocate_pagecache_page(pagecache pc, u64 offset)
{
    /* allocate - later we can look at blocks of pages at a time */
    u64 pagesize = U64_FROM_BIT(pc->page_order);
    void *p = allocate(pc->backed, pagesize);
    if (p == INVALID_ADDRESS)
        return INVALID_ADDRESS;

    pagecache_page pp = allocate(pc->h, sizeof(struct pagecache_page));
    if (pp == INVALID_ADDRESS)
        goto fail_dealloc_backed;

    pp->l.next = pp->l.prev = 0;
    init_rbnode(&pp->node);
    pp->state_phys = ((u64)PAGECACHE_PAGESTATE_ALLOC << PAGECACHE_PAGESTATE_SHIFT) |
        (physical_from_virtual(p) >> pc->page_order);
    pp->write_merge = 0;        /* allocated on demand */
    pp->completions = 0;
    init_refcount(&pp->refcount, 1, closure(pc->h, pagecache_page_release, pc, pp));
    pp->kvirt = p;
    pp->offset = offset;
    assert(rbtree_insert_node(&pc->pages, &pp->node));
    fetch_and_add(&pc->total_pages, 1); /* decrement happens without cache lock */
    return pp;
  fail_dealloc_backed:
    deallocate(pc->backed, p, pagesize);
    return INVALID_ADDRESS;
}

static void pagecache_read_page_internal(pagecache pc, pagecache_page pp,
                                         sg_list sg, range q, merge m)
{
    range r = byte_range_from_pagecache_page(pc, pp);
    pagecache_debug("%s: pc %p, sg %p, q %R, m %p, r %R, pp %p, refcount %d, state %d\n",
                    __func__, pc, sg, q, m, r, pp, pp->refcount.c, page_state(pp));

    range i = range_intersection(q, r);
    bytes length = range_span(i);
    bytes offset = i.start - r.start;
    sg_buf sgb = sg_list_tail_add(sg, length);

    sgb->buf = pp->kvirt + offset;
    sgb->length = length;
    sgb->refcount = &pp->refcount;
    refcount_reserve(&pp->refcount); /* reference for being on sg list */

    if (!pagecache_page_touch_if_filled(pc, pp)) {
        pagecache_page_fill(pc, pp, apply_merge(m));
    }
}

static boolean pagecache_read_internal(pagecache pc, sg_list sg, range q, status_handler complete)
{
    pagecache_debug("%s: pc %p, sg %p, q %R, completion %p\n", __func__, pc, sg, q, complete);
    assert(range_span(q) > 0);
    merge m = allocate_merge(pc->h, complete);
    status_handler sh = apply_merge(m);

    /* fill gaps and initiate reads */
    spin_lock(&pc->pages_lock);
    struct pagecache_page k;
    k.offset = q.start >> pc->page_order;
    u64 end = (q.end + MASK(pc->page_order)) >> pc->page_order;
    pagecache_page pp = (pagecache_page)rbtree_lookup(&pc->pages, &k.node);
    for (u64 i = k.offset; i < end; i++) {
        if (pp == INVALID_ADDRESS || pp->offset > i) {
            pp = allocate_pagecache_page(pc, i);
            if (pp == INVALID_ADDRESS) {
                spin_unlock(&pc->pages_lock);
                apply(apply_merge(m), timm("result", "failed to allocate pagecache_page"));
                return false;
            }
        }
        pagecache_read_page_internal(pc, pp, sg, q, m);
        pp = (pagecache_page)rbnode_get_next((rbnode)pp);
    }
    spin_unlock(&pc->pages_lock);

    /* finished issuing requests */
    apply(sh, STATUS_OK);
    return true;
}

closure_function(1, 3, void, pagecache_read_sg,
                 pagecache, pc,
                 sg_list, sg, range, q, status_handler, sh)
{
    pagecache_read_internal(bound(pc), sg, q, sh);
}

/* TODO for pagecache writing:

   future:
   - use the block mapper to convert between byte offset and block numbers
     - this paves the way for per-fsfile cache, bypassing tfs extent lookup
   - implement write-back
*/

closure_function(2, 1, void, pagecache_write_page_merge_complete,
                 pagecache, pc, pagecache_page, pp,
                 status, s)
{
    pagecache pc = bound(pc);
    pagecache_page pp = bound(pp);
    spin_lock(&pc->state_lock);
    change_page_state_locked(pc, pp, PAGECACHE_PAGESTATE_NEW);
    pagecache_page_queue_completions_locked(pc, pp, s);
    pp->write_merge = 0;
    spin_unlock(&pc->state_lock);
    closure_finish();
}

static void pagecache_write_page_internal(pagecache pc, pagecache_page pp,
                                          void *buf, range q, status_handler sh)
{
    range r = byte_range_from_pagecache_page(pc, pp);
    range i = range_intersection(q, r);
    u64 len = range_span(i);
    u64 page_offset = i.start - r.start;
    void *dest = pp->kvirt + page_offset;
    void *src = buf + (i.start - q.start);
    pagecache_debug("%s: pc %p, pp %p, refcount %d, state %d, src %p, i %R, offset %d, len %d\n",
                    __func__, pc, pp, pp->refcount.c, page_state(pp), src, i, page_offset, len);

    spin_lock(&pc->state_lock);
    change_page_state_locked(pc, pp, PAGECACHE_PAGESTATE_WRITING);

    /* write to cache buffer and commit to storage */
    pagecache_debug("   copy %p <- %p %d bytes\n", dest, src, len);
    assert(r.start + len <= pc->length);
    runtime_memcpy(dest, src, len);
    range blocks = range_rshift(i, pc->block_order);
    pagecache_debug("   write %p to block range %R\n", dest, blocks);
    if (!pp->write_merge) {
        /* TODO make inline merge to eliminate alloc? */
        pp->write_merge = allocate_merge(pc->h, closure(pc->h, pagecache_write_page_merge_complete,
                                                        pc, pp));
        assert(pp->write_merge != INVALID_ADDRESS);
        assert(!pp->completions || vector_length(pp->completions) == 0);
    }
    spin_unlock(&pc->state_lock);
    apply(pc->block_write, dest, blocks, apply_merge(pp->write_merge));

    /* TODO check to see if an error was posted already... */
    apply(sh, STATUS_OK);
}

closure_function(5, 1, void, pagecache_write_io_check_complete,
                 pagecache, pc, pagecache_page, pp, void *, buf, range, q, status_handler, sh,
                 status, s)
{
    if (!is_ok(s)) {
        apply(bound(sh), s);
    } else {
        pagecache_write_page_internal(bound(pc), bound(pp), bound(buf), bound(q), bound(sh));
    }
    closure_finish();
}

static void pagecache_write_page_io_check(pagecache pc, pagecache_page pp,
                                          void *buf, range q, status_handler sh)
{
    spin_lock(&pc->state_lock);
    int state = page_state(pp);
    assert(state != PAGECACHE_PAGESTATE_ALLOC);
    if (state == PAGECACHE_PAGESTATE_READING) {
        enqueue_page_completion_statelocked(pc, pp,
                                            closure(pc->h, pagecache_write_io_check_complete,
                                                    pc, pp, buf, q, sh));
        spin_unlock(&pc->state_lock);
    } else {
        spin_unlock(&pc->state_lock);
        pagecache_write_page_internal(pc, pp, buf, q, sh);
    }
}

closure_function(5, 1, void, pagecache_write_page_filled,
                 pagecache, pc, pagecache_page, pp, void *, buf, range, q, status_handler, sh,
                 status, s)
{
    pagecache_debug("%s: page %R, status %v\n", __func__, bound(pp)->node.r, s);
    if (!is_ok(s)) {
        apply(bound(sh), timm_up(s, "result", "%s: fill failed", __func__));
    } else {
        pagecache_write_page_io_check(bound(pc), bound(pp), bound(buf), bound(q), bound(sh));
    }
    closure_finish();
}

closure_function(1, 3, void, pagecache_write,
                 pagecache, pc,
                 void *, buf, range, blocks, status_handler, completion)
{
    pagecache pc = bound(pc);
    pagecache_debug("%s: buf %p, sg %p, blocks %R, completion %p\n", __func__, pc, buf, blocks, completion);
    range q = range_lshift(blocks, pc->block_order);
    merge m = allocate_merge(pc->h, completion);
    status_handler sh = apply_merge(m);

    /* fill gaps and initiate writes (and prerequisite reads) */
    spin_lock(&pc->pages_lock);
    struct pagecache_page k;
    k.offset = q.start >> pc->page_order;
    u64 end = (q.end + MASK(pc->page_order)) >> pc->page_order;
    pagecache_page pp = (pagecache_page)rbtree_lookup(&pc->pages, &k.node);
    for (u64 i = k.offset; i < end; i++) {
        if (pp == INVALID_ADDRESS || pp->offset > i) {
            pp = allocate_pagecache_page(pc, i);
            if (pp == INVALID_ADDRESS) {
                apply(apply_merge(m), timm("result", "failed to allocate pagecache_page"));
                spin_unlock(&pc->pages_lock);
                return;
            }

            /* if this write covers the entire page, don't bother trying to fill it first */
            range r = byte_range_from_pagecache_page(pc, pp);
            range i = range_intersection(r, q);
            if (i.start == r.start && i.end == MIN(r.end, pc->length)) {
                pagecache_write_page_internal(pc, pp, buf, q, apply_merge(m));
            } else {
                pagecache_page_fill(pc, pp, closure(pc->h, pagecache_write_page_filled,
                                                    pc, pp, buf, q, apply_merge(m)));
            }
        } else {
            pagecache_write_page_io_check(pc, pp, buf, q, apply_merge(m));
        }
        pp = (pagecache_page)rbnode_get_next((rbnode)pp);
    }
    spin_unlock(&pc->pages_lock);
    apply(sh, STATUS_OK);
}

static inline void page_list_init(struct pagelist *pl)
{
    list_init(&pl->l);
    pl->pages = 0;
}

/* evict pages from new and active lists, then rebalance */
static u64 evict_pages_locked(pagecache pc, u64 pages)
{
    u64 evicted = evict_from_list_locked(pc, &pc->new, pages);
    if (evicted < pages) {
        /* To fill the requested pages evictions, we are more
           aggressive here, evicting even in-use pages (rc > 1) in the
           active list. */
        evicted += evict_from_list_locked(pc, &pc->active, pages - evicted);
    }
    balance_page_lists_locked(pc);
    return evicted;
}

u64 pagecache_drain(pagecache pc, u64 drain_bytes)
{
    u64 pages = pad(drain_bytes, pagecache_pagesize(pc)) >> pc->page_order;

    /* We could avoid taking both locks here if we keep drained page
       objects around (which incidentally could be useful to keep
       refault data). */
    spin_lock(&pc->pages_lock);
    spin_lock(&pc->state_lock);
    u64 evicted = evict_pages_locked(pc, pages);
    spin_unlock(&pc->state_lock);
    spin_unlock(&pc->pages_lock);
    return evicted << pc->page_order;
}

closure_function(1, 1, void, pagecache_sync,
                 pagecache, pc,
                 status_handler, complete)
{
    pagecache pc = bound(pc);
    assert(complete);

    pagecache_page pp = 0;
    /* If writes are pending, tack completion onto the mostly recently written page. */
    spin_lock(&pc->state_lock);
    if (!list_empty(&pc->writing.l)) {
        list l = pc->writing.l.prev;
        pp = struct_from_list(l, pagecache_page, l);
        enqueue_page_completion_statelocked(pc, pp, complete);
        spin_unlock(&pc->state_lock);
        return;
    }
    spin_unlock(&pc->state_lock);
    apply(complete, STATUS_OK);
}

closure_function(1, 1, boolean, pagecache_page_print_key,
                 pagecache, pc,
                 rbnode, n)
{
    rprintf(" 0x%lx", ((pagecache_page)n)->offset << pagecache_blocksize(bound(pc)));
    return true;
}

closure_function(0, 2, int, pagecache_page_compare,
                 rbnode, a, rbnode, b)
{
    u64 oa = ((pagecache_page)a)->offset;
    u64 ob = ((pagecache_page)b)->offset;
    return oa == ob ? 0 : (oa < ob ? -1 : 1);
}

pagecache allocate_pagecache(heap general, heap backed,
                             u64 length, u64 pagesize, u64 block_size,
                             block_mapper mapper, block_io read, block_io write)
{
    pagecache pc = allocate(general, sizeof(struct pagecache));
    if (pc == INVALID_ADDRESS)
        return pc;

    pc->total_pages = 0;
    if (length & (block_size - 1)) {
        msg_err("length (0x%lx) must be multiple of block size (%d)\n", length, block_size);
        return INVALID_ADDRESS;
    }
    pc->length = length;
    pc->page_order = find_order(pagesize);
    assert(pagesize == U64_FROM_BIT(pc->page_order));
    pc->block_order = find_order(block_size);
    assert(block_size == U64_FROM_BIT(pc->block_order));
    pc->h = general;
    pc->backed = backed;

    spin_lock_init(&pc->pages_lock);
    init_rbtree(&pc->pages, closure(general, pagecache_page_compare),
                closure(general, pagecache_page_print_key, pc));
    spin_lock_init(&pc->state_lock);
    page_list_init(&pc->free);
    page_list_init(&pc->new);
    page_list_init(&pc->active);
    page_list_init(&pc->writing);
    page_list_init(&pc->dirty);

    pc->mapper = mapper;
    pc->block_read = read;
    pc->block_write = write;
    pc->sg_read = closure(general, pagecache_read_sg, pc);
    pc->write = closure(general, pagecache_write, pc);
    pc->sync = closure(general, pagecache_sync, pc);

    pc->completion_vecs = allocate_queue(general, MAX_PAGE_COMPLETION_VECS);
    assert(pc->completion_vecs != INVALID_ADDRESS);
    pc->service_completions = closure(general, pagecache_service_completions, pc);
    pc->service_enqueued = false;
    return pc;
}
