/* TODO:
   - keep refault stats
   - interface to physical free page list / shootdown epochs

   - would be nice to propagate a priority alone with requests to
     pagecache - which in turn would be passed to page I/O - so that
     page fault fills can go to head of request queue
*/

/* don't care for this ... but we're used in both kernel and other contexts ... maybe split up */
#ifdef KERNEL
#include <kernel.h>
#else
#include <runtime.h>
typedef void *nanos_thread;
#define get_current_thread()    0
#define set_current_thread(t)
#endif

#include <pagecache.h>
#include <pagecache_internal.h>

#if defined(PAGECACHE_DEBUG)
#ifdef KERNEL
#define pagecache_debug(x, ...) do {tprintf(sym(pagecache), 0, x, ##__VA_ARGS__);} while(0)
#else
#define pagecache_debug(x, ...) do {rprintf("PGC: " x, ##__VA_ARGS__);} while(0)
#endif
#else
#define pagecache_debug(x, ...)
#endif

#ifdef BOOT
#define PAGECACHE_READ_ONLY
#endif

/* TODO: Seems like this ought not to be so large ... but we're
   queueing a ton with the polled ATA driver. There's only one queue globally anyhow. */
#define MAX_PAGE_COMPLETION_VECS 16384

BSS_RO_AFTER_INIT static pagecache global_pagecache;

static inline u64 cache_pagesize(pagecache pc)
{
    return U64_FROM_BIT(pc->page_order);
}

static inline int page_state(pagecache_page pp)
{
    return pp->state_offset >> PAGECACHE_PAGESTATE_SHIFT;
}

static inline u64 page_offset(pagecache_page pp)
{
    return pp->state_offset & MASK(PAGECACHE_PAGESTATE_SHIFT);
}

static inline range byte_range_from_page(pagecache pc, pagecache_page pp)
{
    return range_lshift(irangel(page_offset(pp), 1), pc->page_order);
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

#ifdef KERNEL
static inline void pagecache_lock_state(pagecache pc)
{
    spin_lock(&pc->state_lock);
}

static inline void pagecache_unlock_state(pagecache pc)
{
    spin_unlock(&pc->state_lock);
}

static inline void pagecache_lock_volume(pagecache_volume pv)
{
    spin_lock(&pv->lock);
}

static inline void pagecache_unlock_volume(pagecache_volume pv)
{
    spin_unlock(&pv->lock);
}

/* TODO revisit node locking */
static inline void pagecache_lock_node(pagecache_node pn)
{
    spin_lock(&pn->pages_lock);
}

static inline void pagecache_unlock_node(pagecache_node pn)
{
    spin_unlock(&pn->pages_lock);
}

#else
#define pagecache_lock_state(pc)
#define pagecache_unlock_state(pc)
#define pagecache_lock_volume(pv)
#define pagecache_unlock_volume(pv)
#define pagecache_lock_node(pn)
#define pagecache_unlock_node(pn)
#endif

static inline void change_page_state_locked(pagecache pc, pagecache_page pp, int state)
{
    int old_state = page_state(pp);
    switch (state) {
    case PAGECACHE_PAGESTATE_FREE:
        if (old_state == PAGECACHE_PAGESTATE_NEW) {
            pagelist_move(&pc->free, &pc->new, pp);
        } else {
            assert(old_state == PAGECACHE_PAGESTATE_ACTIVE);
            pagelist_move(&pc->free, &pc->active, pp);
        }
        break;
    case PAGECACHE_PAGESTATE_ALLOC:
        if (old_state == PAGECACHE_PAGESTATE_FREE)
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
            pagelist_enqueue(&pc->writing, pp);
        }
        if (old_state != PAGECACHE_PAGESTATE_WRITING &&
                old_state != PAGECACHE_PAGESTATE_DIRTY)
            refcount_reserve(&pp->node->refcount);
        break;
    case PAGECACHE_PAGESTATE_NEW:
        if (old_state == PAGECACHE_PAGESTATE_ACTIVE) {
            pagelist_move(&pc->new, &pc->active, pp);
        } else if (old_state == PAGECACHE_PAGESTATE_WRITING) {
            pagelist_move(&pc->new, &pc->writing, pp);
            refcount_release(&pp->node->refcount);
        } else {
            assert(old_state == PAGECACHE_PAGESTATE_READING);
            pagelist_enqueue(&pc->new, pp);
        }
        break;
    case PAGECACHE_PAGESTATE_ACTIVE:
        assert(old_state == PAGECACHE_PAGESTATE_NEW);
        pagelist_move(&pc->active, &pc->new, pp);
        break;
    case PAGECACHE_PAGESTATE_DIRTY:
        if (old_state == PAGECACHE_PAGESTATE_NEW) {
            pagelist_remove(&pc->new, pp);
        } else if (old_state == PAGECACHE_PAGESTATE_ACTIVE) {
            pagelist_remove(&pc->active, pp);
        } else {
            assert(old_state == PAGECACHE_PAGESTATE_WRITING);
            pagelist_remove(&pc->writing, pp);
        }
        if (old_state != PAGECACHE_PAGESTATE_WRITING)
            refcount_reserve(&pp->node->refcount);
        break;
    default:
        halt("%s: bad state %d, old %d\n", __func__, state, old_state);
    }

    pp->state_offset = (pp->state_offset & MASK(PAGECACHE_PAGESTATE_SHIFT)) |
        ((u64)state << PAGECACHE_PAGESTATE_SHIFT);
}

static void pagecache_page_queue_completions_locked(pagecache pc, pagecache_page pp, status s)
{
    list_foreach(&pp->bh_completions, l) {
        page_completion c = struct_from_list(l, page_completion, l);
        assert(c->sh != INVALID_ADDRESS && c->sh != 0);
#ifdef KERNEL
        async_apply_status_handler(c->sh, s);
#else
        apply(c->sh, s);
#endif
        list_delete(l);
        deallocate(pc->completions, c, sizeof(*c));
    }
}

static void enqueue_page_completion_statelocked(pagecache pc, pagecache_page pp, status_handler sh)
{
    page_completion c = allocate(pc->completions, sizeof(*c));
    assert(c != INVALID_ADDRESS);

    c->sh = sh;
    list l = &pp->bh_completions;
    list_push_back(l, &c->l);
}

static boolean realloc_pagelocked(pagecache pc, pagecache_page pp)
{
    pagecache_debug("%s: pc %p pp %p refcount %d state %d\n", __func__, pc, pp, pp->refcount.c, page_state(pp));
    pp->kvirt = allocate(pc->contiguous, U64_FROM_BIT(pc->page_order));
    if (pp->kvirt == INVALID_ADDRESS) {
        return false;
    }
    assert(pp->refcount.c == 0);
    refcount_reserve(&pp->refcount);
    pp->write_count = 0;
    #ifdef KERNEL
    pp->phys = physical_from_virtual(pp->kvirt);
    #endif
    fetch_and_add(&pc->total_pages, 1);
    change_page_state_locked(pc, pp, PAGECACHE_PAGESTATE_ALLOC);
    pp->evicted = false;
    return true;
}

static void pagecache_add_sgb(pagecache pc, pagecache_page pp, sg_list sg)
{
    sg_buf sgb = sg_list_tail_add(sg, cache_pagesize(pc));
    sgb->buf = pp->kvirt;
    sgb->size = cache_pagesize(pc);
    sgb->offset = 0;
    sgb->refcount = &pp->refcount;
    refcount_reserve(sgb->refcount);
}

/* Returns true if the page is already cached (or is being fetched from disk), false if a disk read
 * needs to be requested to fetch the page (or re-allocation of a freed page failed). */
static boolean touch_page_locked(pagecache_node pn, pagecache_page pp, merge m)
{
    pagecache_volume pv = pn->pv;
    pagecache pc = pv->pc;

    pagecache_debug("%s: pn %p, pp %p, m %p, state %d\n", __func__, pn, pp, m, page_state(pp));
    switch (page_state(pp)) {
    case PAGECACHE_PAGESTATE_READING:
        enqueue_page_completion_statelocked(pc, pp, apply_merge(m));
        break;
    case PAGECACHE_PAGESTATE_FREE:
        if (!realloc_pagelocked(pc, pp))
            return false;
        /* no break */
    case PAGECACHE_PAGESTATE_ALLOC:
        change_page_state_locked(pc, pp, PAGECACHE_PAGESTATE_READING);
        return false;
    case PAGECACHE_PAGESTATE_ACTIVE:
        /* move to bottom of active list */
        list_delete(&pp->l);
        list_insert_before(&pc->active.l, &pp->l);
        break;
    case PAGECACHE_PAGESTATE_NEW:
        /* cache hit -> active */
        change_page_state_locked(pc, pp, PAGECACHE_PAGESTATE_ACTIVE);
        break;
    }
    return true;
}

#ifndef PAGECACHE_READ_ONLY

closure_function(3, 1, void, pagecache_read_page_complete,
                 pagecache, pc, pagecache_page, pp, sg_list, sg,
                 status, s)
{
    pagecache pc = bound(pc);
    pagecache_page pp = bound(pp);
    assert(page_state(pp) == PAGECACHE_PAGESTATE_READING);

    if (!is_ok(s)) {
        /* TODO need policy for capturing/reporting I/O errors... */
        msg_err("error reading page 0x%lx: %v\n", page_offset(pp) << pc->page_order, s);
    }
    pagecache_lock_state(pc);
    change_page_state_locked(bound(pc), pp, PAGECACHE_PAGESTATE_NEW);
    pagecache_page_queue_completions_locked(pc, pp, s);
    pagecache_unlock_state(pc);
    sg_list_release(bound(sg));
    deallocate_sg_list(bound(sg));
    closure_finish();
}

static boolean touch_or_fill_page_nodelocked(pagecache_node pn, pagecache_page pp, merge m)
{
    pagecache_volume pv = pn->pv;
    pagecache pc = pv->pc;

    pagecache_lock_state(pc);
    pagecache_debug("%s: pn %p, pp %p, m %p, state %d\n", __func__, pn, pp, m, page_state(pp));
    switch (page_state(pp)) {
    case PAGECACHE_PAGESTATE_READING:
        if (m) {
            enqueue_page_completion_statelocked(pc, pp, apply_merge(m));
        }
        pagecache_unlock_state(pc);
        return false;
    case PAGECACHE_PAGESTATE_FREE:
        if (!realloc_pagelocked(pc, pp))
            return false;
        /* fall through */
    case PAGECACHE_PAGESTATE_ALLOC:
        if (m) {
            enqueue_page_completion_statelocked(pc, pp, apply_merge(m));
            change_page_state_locked(pc, pp, PAGECACHE_PAGESTATE_READING);
        }
        pagecache_unlock_state(pc);

        if (m) {
            /* issue page reads */
            range r = byte_range_from_page(pc, pp);
            pagecache_debug("   pc %p, pp %p, r %R, reading...\n", pc, pp, r);
            sg_list sg = allocate_sg_list();
            assert(sg != INVALID_ADDRESS);
            pagecache_add_sgb(pc, pp, sg);
            apply(pn->fs_read, sg, r,
                  closure(pc->h, pagecache_read_page_complete, pc, pp, sg));
        }
        return false;
    case PAGECACHE_PAGESTATE_ACTIVE:
        /* move to bottom of active list */
        list_delete(&pp->l);
        list_insert_before(&pc->active.l, &pp->l);
        break;
    case PAGECACHE_PAGESTATE_NEW:
        /* cache hit -> active */
        change_page_state_locked(pc, pp, PAGECACHE_PAGESTATE_ACTIVE);
        break;
    case PAGECACHE_PAGESTATE_WRITING:
    case PAGECACHE_PAGESTATE_DIRTY:
        break;
    default:
        halt("%s: invalid state %d\n", __func__, page_state(pp));
    }
    pagecache_unlock_state(pc);
    return true;
}

#endif

define_closure_function(2, 0, void, pagecache_page_free,
                        pagecache, pc, pagecache_page, pp)
{
    pagecache_page pp = bound(pp);
    pagecache_debug("%s: pp %p state %d\n", __func__, pp, page_state(pp));
    assert(pp->write_count == 0);
    assert(pp->refcount.c == 0);

    pagecache pc = bound(pc);
    pagecache_lock_state(pc);
    change_page_state_locked(pc, pp, PAGECACHE_PAGESTATE_FREE);
    pagecache_unlock_state(pc);
    deallocate(pc->contiguous, pp->kvirt, cache_pagesize(pc));
    pp->kvirt = INVALID_ADDRESS;
    pp->phys = INVALID_PHYSICAL;
    u64 pre = fetch_and_add(&pc->total_pages, -1);
    assert(pre > 0);
    pagecache_debug("%s: total pages now %ld\n", __func__, pre - 1);
}

static pagecache_page allocate_page_nodelocked(pagecache_node pn, u64 offset)
{
    /* allocate - later we can look at blocks of pages at a time */
    pagecache pc = pn->pv->pc;
    u64 pagesize = U64_FROM_BIT(pc->page_order);
    void *p = allocate(pc->contiguous, pagesize);
    if (p == INVALID_ADDRESS)
        return INVALID_ADDRESS;

    pagecache_page pp = allocate(pc->h, sizeof(struct pagecache_page));
    if (pp == INVALID_ADDRESS)
        goto fail_dealloc_contiguous;

    init_rbnode(&pp->rbnode);
    init_refcount(&pp->refcount, 1, init_closure(&pp->free, pagecache_page_free, pc, pp));
    assert((offset >> PAGECACHE_PAGESTATE_SHIFT) == 0);
    pp->state_offset = ((u64)PAGECACHE_PAGESTATE_ALLOC << PAGECACHE_PAGESTATE_SHIFT) | offset;
    pp->write_count = 0;
    pp->kvirt = p;
    pp->node = pn;
    pp->l.next = pp->l.prev = 0;
    pp->evicted = false;
#ifdef KERNEL
    pp->phys = physical_from_virtual(p);
#endif
    list_init(&pp->bh_completions);
    assert(rbtree_insert_node(&pn->pages, &pp->rbnode));
    fetch_and_add(&pc->total_pages, 1); /* decrement happens without cache lock */
    return pp;
  fail_dealloc_contiguous:
    deallocate(pc->contiguous, p, pagesize);
    return INVALID_ADDRESS;
}

#ifndef PAGECACHE_READ_ONLY
static u64 evict_from_list_locked(pagecache pc, struct pagelist *pl, vector evictlist, u64 pages)
{
    u64 evicted = 0;
    list_foreach(&pl->l, l) {
        if (evicted >= pages)
            break;

        pagecache_page pp = struct_from_list(l, pagecache_page, l);
        if (pp->evicted)
            continue;
        assert(pp->refcount.c != 0);
        pagecache_debug("%s: list %s, release pp %p - %R, state %d, count %ld\n", __func__,
                        pl == &pc->new ? "new" : "active", pp, byte_range_from_page(pc, pp),
                        page_state(pp), pp->refcount.c);
        pp->evicted = true;
        vector_push(evictlist, pp);
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
            pagecache_debug("   pp %R -> new\n", byte_range_from_page(pc, pp));
            change_page_state_locked(pc, pp, PAGECACHE_PAGESTATE_NEW);
            dp--;
        }
    }
}

static pagecache_page page_lookup_nodelocked(pagecache_node pn, u64 n)
{
    struct pagecache_page k;
    k.state_offset = n;
    return (pagecache_page)rbtree_lookup(&pn->pages, &k.rbnode);
}

static pagecache_page page_lookup_or_alloc_nodelocked(pagecache_node pn, u64 n)
{
    pagecache_page pp = page_lookup_nodelocked(pn, n);
    if (pp == INVALID_ADDRESS) {
        pp = allocate_page_nodelocked(pn, n);
    } else if (page_state(pp) == PAGECACHE_PAGESTATE_FREE) {
        pagecache pc = pn->pv->pc;
        pagecache_lock_state(pc);
        realloc_pagelocked(pc, pp);
        pagecache_unlock_state(pc);
    }
    return pp;
}

static pagecache_page touch_or_fill_page_by_num_nodelocked(pagecache_node pn, u64 n, merge m)
{
    pagecache_page pp = page_lookup_or_alloc_nodelocked(pn, n);
    if (pp == INVALID_ADDRESS)
        apply(apply_merge(m), timm("result", "failed to allocate pagecache_page"));
    else
        touch_or_fill_page_nodelocked(pn, pp, m);
    return pp;
}

/* called with node locked */
static boolean pagecache_set_dirty(pagecache_node pn, range r)
{
    if (!rangemap_insert_range(&pn->dirty, r))
        return false;
    pagecache_debug("node %p, added dirty range %R\n", pn, r);
    pagecache_volume pv = pn->pv;
    pagecache_lock_volume(pv);
    if (!list_inserted(&pn->l))
        list_insert_before(&pv->dirty_nodes, &pn->l);
    pagecache_unlock_volume(pv);
    return true;
}

closure_function(5, 1, void, pagecache_write_sg_finish,
                 pagecache_node, pn, range, q, sg_list, sg, status_handler, completion, context, saved_ctx,
                 status, s)
{
    pagecache_node pn = bound(pn);
    pagecache pc = pn->pv->pc;
    range q = bound(q);
    int page_order = pc->page_order;
    int block_order = pn->pv->block_order;
    u64 pi = q.start >> page_order;
    u64 end = (q.end + MASK(pc->page_order)) >> page_order;
    sg_list sg = bound(sg);
    status_handler completion = bound(completion);

    pagecache_debug("%s: pn %p, q %R, sg %p, status %v\n", __func__, pn, q, sg, s);
    if (!is_ok(s))
        goto exit;

    pagecache_lock_node(pn);
    pagecache_page pp = page_lookup_nodelocked(pn, pi);

    /* copy data to the page cache */
    u64 offset = q.start & MASK(page_order);
    range r = irange(q.start & ~MASK(block_order), q.end);
#ifdef KERNEL
    context saved_ctx = bound(saved_ctx);
    if (saved_ctx)
        use_fault_handler(saved_ctx->fault_handler);
#endif
    do {
        assert(pp != INVALID_ADDRESS && page_offset(pp) == pi);
        u64 copy_len = MIN(q.end - (pi << page_order), cache_pagesize(pc)) - offset;
        if (sg) {
            u64 res = sg_copy_to_buf(pp->kvirt + offset, sg, copy_len);
            assert(res == copy_len);
        } else {
            zero(pp->kvirt + offset, copy_len);
        }
        pagecache_lock_state(pc);
        assert(page_state(pp) != PAGECACHE_PAGESTATE_READING);
        if (page_state(pp) != PAGECACHE_PAGESTATE_DIRTY)
            change_page_state_locked(pc, pp, PAGECACHE_PAGESTATE_DIRTY);
        pagecache_unlock_state(pc);
        offset = 0;
        pi++;
        pp = (pagecache_page)rbnode_get_next((rbnode)pp);
    } while (pi < end);
    if (!pagecache_set_dirty(pn, r))
        s = timm("result", "failed to add dirty range");
    pagecache_unlock_node(pn);
#ifdef KERNEL
    if (saved_ctx)
        clear_fault_handler();
#endif
  exit:
    closure_finish();
#ifdef KERNEL
    async_apply_status_handler(completion, s);
#else
    apply(completion, s);
#endif
}

closure_function(1, 3, void, pagecache_write_sg,
                 pagecache_node, pn,
                 sg_list, sg, range, q, status_handler, completion)
{
    pagecache_node pn = bound(pn);
    pagecache_volume pv = pn->pv;
    pagecache pc = pv->pc;
    pagecache_debug("%s: node %p, q %R, sg %p, completion %F, from %p\n", __func__,
                    pn, q, sg, completion, __builtin_return_address(0));
    if (!is_ok(pv->write_error)) {
        /* From a previous (asynchronous) write failure */
        pagecache_debug("   pending write error %v\n", __func__, pv->write_error);
        apply(completion, pv->write_error);
        return;
    }

    if (range_span(q) == 0) {
        apply(completion, STATUS_OK);
        return;
    }

    /* extend node length if writing past current end */
    if (q.end > pn->length)
        pn->length = q.end;

    u64 start_offset = q.start & MASK(pc->page_order);
    u64 end_offset = q.end & MASK(pc->page_order);
    range r = range_rshift(q, pc->page_order);
    pagecache_lock_node(pn);
    /* attempt to reserve disk space for the write */
    if (pn->fs_reserve && sg) {
        status ss;
        if ((ss = apply(pn->fs_reserve, q)) != STATUS_OK) {
            pagecache_unlock_node(pn);
            apply(completion, ss);
            return;
        }
    }

    context ctx;
#ifdef KERNEL
    ctx = get_current_context(current_cpu());
    if (!is_syscall_context(ctx))
        ctx = 0;
#else
    ctx = 0;
#endif

    /* prepare pages for writing */
    merge m = allocate_merge(pc->h, closure(pc->h, pagecache_write_sg_finish, pn, q, sg,
                                            completion, ctx));
    status_handler sh = apply_merge(m);

    /* initiate reads for rmw start and/or end */
    if (start_offset != 0) {
        pagecache_page pp = touch_or_fill_page_by_num_nodelocked(pn, q.start >> pc->page_order, m);
        if (pp != INVALID_ADDRESS)
            refcount_reserve(&pp->refcount);
        r.start++;
    }
    if (end_offset != 0) {
        if ((q.end < pn->length) && /* tail rmw */
                !((q.start & ~MASK(pc->page_order)) ==
                  (q.end & ~MASK(pc->page_order)) && start_offset != 0) /* no double fill */) {
            pagecache_page pp = touch_or_fill_page_by_num_nodelocked(pn, q.end >> pc->page_order, m);
            if (pp != INVALID_ADDRESS)
                refcount_reserve(&pp->refcount);
        } else {
            r.end++;
        }
    }

    /* prepare whole pages, blocking for any pending reads */
    for (u64 pi = r.start; pi < r.end; pi++) {
        pagecache_page pp = page_lookup_nodelocked(pn, pi);
        if (pp == INVALID_ADDRESS) {
            pp = allocate_page_nodelocked(pn, pi);
            if (pp == INVALID_ADDRESS) {
                pagecache_unlock_node(pn);
                const char *err = "failed to allocate pagecache_page";
                apply(sh, timm("result", err)); /* close out merge, record write error */
                apply(completion, timm("result", err));
                return;
            }

            /* set to writing state to begin queueing dependent operations */
            change_page_state_locked(pc, pp, PAGECACHE_PAGESTATE_WRITING);

            /* When writing a new page at the end of a node whose length is not page-aligned, zero
               the remaining portion of the page. The filesystem will depend on this to properly
               implement file holes. */
            range i = range_intersection(byte_range_from_page(pc, pp), q);
            u64 page_offset = i.end & MASK(pc->page_order);
            if (page_offset) {
                u64 len = U64_FROM_BIT(pc->page_order) - page_offset;
                pagecache_debug("   zero unaligned end, i %R, page offset 0x%lx, len 0x%lx\n",
                                i, page_offset, len);
                assert(i.end == pn->length);
                zero(pp->kvirt + page_offset, len);
            }
        }
        pagecache_lock_state(pc);
        if (page_state(pp) == PAGECACHE_PAGESTATE_FREE)
            realloc_pagelocked(pc, pp);
        refcount_reserve(&pp->refcount);
        if (page_state(pp) == PAGECACHE_PAGESTATE_READING)
            enqueue_page_completion_statelocked(pc, pp, apply_merge(m));
        pagecache_unlock_state(pc);
    }
    pagecache_unlock_node(pn);
    apply(sh, STATUS_OK);
}

/* evict pages from new and active lists, then rebalance */
static u64 evict_pages_locked(pagecache pc, u64 pages, vector evictlist)
{
    u64 evicted = evict_from_list_locked(pc, &pc->new, evictlist, pages);
    if (evicted < pages) {
        /* To fill the requested pages evictions, we are more
           aggressive here, evicting even in-use pages (rc > 1) in the
           active list. */
        evicted += evict_from_list_locked(pc, &pc->active, evictlist, pages - evicted);
    }
    return evicted;
}

#define DRAIN_ITER_MAX   128

u64 pagecache_drain(u64 drain_bytes)
{
    pagecache_page pp;
    pagecache pc = global_pagecache;
    u64 pages = pad(drain_bytes, cache_pagesize(pc)) >> pc->page_order;
    vector v;
    u64 evicted = 0;

    if ((v = allocate_vector(pc->h, DRAIN_ITER_MAX)) == INVALID_ADDRESS)
        return 0;
    while (evicted < pages) {
        pagecache_lock_state(pc);
        u64 n = evict_pages_locked(pc, MIN(pages - evicted, DRAIN_ITER_MAX), v);
        pagecache_unlock_state(pc);
        if (n == 0)
            break;
        evicted += n;
        while ((pp = vector_pop(v)))
            refcount_release(&pp->refcount);
    }
    deallocate_vector(v);

    pagecache_lock_state(pc);
    balance_page_lists_locked(pc);
    pagecache_unlock_state(pc);
    return evicted << pc->page_order;
}

/* TODO could encode completion to indicate completion on transition
   to new rather than writing - otherwise we're completing on storage
   request issuance, not completion - just for sync use */
static void pagecache_finish_pending_writes(pagecache pc, pagecache_volume pv, pagecache_node pn,
                                            status_handler complete)
{
    pagecache_page pp = 0;
    /* If writes are pending, tack completion onto the mostly recently written page. */
    pagecache_lock_state(pc);
    list_foreach_reverse(&pc->writing.l, l) {
        pp = struct_from_list(l, pagecache_page, l);
        if ((!pn || pp->node == pn) && (!pv || pp->node->pv == pv)) {
            enqueue_page_completion_statelocked(pc, pp, complete);
            pagecache_unlock_state(pc);
            return;
        }
    }
    pagecache_unlock_state(pc);
    apply(complete, STATUS_OK);
}

#ifdef KERNEL
static void pagecache_scan_shared_mappings(pagecache pc);
static void pagecache_scan_node(pagecache_node pn);
#else
static void pagecache_scan_shared_mappings(pagecache pc) {}
static void pagecache_scan_node(pagecache_node pn) {}
#endif

closure_function(4, 1, void, pagecache_commit_complete,
                 pagecache, pc, pagecache_page, first_page, u64, page_count, sg_list, sg,
                 status, s)
{
    pagecache pc = bound(pc);
    pagecache_page pp = bound(first_page);
    sg_list sg = bound(sg);
    pagecache_debug("%s: pp %p, s %v\n", __func__, pp, s);
    if (!is_ok(s)) {
        pagecache_debug("%s: write_error now %v\n", __func__, s);
        pp->node->pv->write_error = s;
        sg_list_release(sg);
    }
    u64 page_count = bound(page_count);
    pagecache_lock_state(pc);
    do {
        assert(pp->write_count > 0);
        if (pp->write_count-- == 1) {
            if (page_state(pp) != PAGECACHE_PAGESTATE_DIRTY)
                change_page_state_locked(pc, pp,
                                         is_ok(s) ? PAGECACHE_PAGESTATE_NEW :
                                                    PAGECACHE_PAGESTATE_DIRTY);
            pagecache_page_queue_completions_locked(pc, pp, s);
        }
        pp = (pagecache_page)rbnode_get_next((rbnode)pp);
    } while (--page_count > 0);
    pagecache_unlock_state(pc);
    deallocate_sg_list(sg);
    closure_finish();
}

static void pagecache_commit_dirty_node(pagecache_node pn)
{
    pagecache_debug("committing dirty node %p\n", pn);
    pagecache_volume pv = pn->pv;
    pagecache pc = pv->pc;
    pagecache_lock_node(pn);
    int cc=0;
    rangemap_foreach(&pn->dirty, n) {
        sg_list sg = allocate_sg_list();
        if (sg == INVALID_ADDRESS)
            goto unlock_node;
        pagecache_debug("  range %R\n", n->r);
        u64 start = n->r.start;
        pagecache_page first_page = page_lookup_nodelocked(pn, start >> pc->page_order);
        u64 page_count = 0;
        pagecache_page pp = first_page;
        do {
            u64 page_offset = start & MASK(pc->page_order);
            u64 len = pad(MIN(cache_pagesize(pc) - page_offset, n->r.end - start),
                          U64_FROM_BIT(pv->block_order));
            sg_buf sgb = sg_list_tail_add(sg, len);
            sgb->buf = pp->kvirt + page_offset;
            sgb->offset = 0;
            sgb->size = len;
            sgb->refcount = &pp->refcount;
            refcount_reserve(&pp->refcount);
            pagecache_lock_state(pc);
            change_page_state_locked(pc, pp, PAGECACHE_PAGESTATE_WRITING);
            pp->write_count++;
            pagecache_unlock_state(pc);
            page_count++;
            start += len;
            pp = (pagecache_page)rbnode_get_next((rbnode)pp);
        } while (start < n->r.end);
        apply(pn->fs_write, sg, n->r,
              closure(pc->h, pagecache_commit_complete, pc, first_page, page_count, sg));
        cc++;
        rangemap_remove_range(&pn->dirty, n);
    }
    pagecache_lock_volume(pv);
    if (list_inserted(&pn->l))
        list_delete(&pn->l);
    pagecache_unlock_volume(pv);
unlock_node:
    pagecache_unlock_node(pn);
}

static void pagecache_commit_dirty_pages(pagecache pc)
{
    pagecache_debug("%s\n", __func__);

    list_foreach(&pc->volumes, l) {
        pagecache_volume pv = struct_from_list(l, pagecache_volume, l);
        pagecache_node pn = 0;
        do {
            pagecache_lock_volume(pv);
            list l = list_get_next(&pv->dirty_nodes);
            pagecache_unlock_volume(pv);
            if (l) {
                pn = struct_from_list(l, pagecache_node, l);
                pagecache_commit_dirty_node(pn);
            } else {
                pn = 0;
            }
        } while (pn);
    }
}

static void pagecache_scan(pagecache pc)
{
    pagecache_scan_shared_mappings(pc);
    pagecache_commit_dirty_pages(pc);
}

void pagecache_sync_volume(pagecache_volume pv, status_handler complete)
{
    pagecache_debug("%s: pv %p, complete %p (%F)\n", __func__, pv, complete, complete);
    pagecache_scan(pv->pc);         /* commit dirty pages */
    pagecache_finish_pending_writes(pv->pc, pv, 0, complete);
}

/* not quite sync; the caller takes care of committing dirty pages */
void pagecache_node_finish_pending_writes(pagecache_node pn, status_handler complete)
{
    pagecache_debug("%s: pn %p, complete %p (%F)\n", __func__, pn, complete, complete);
    pagecache_finish_pending_writes(pn->pv->pc, 0, pn, complete);
}

void pagecache_sync_node(pagecache_node pn, status_handler complete)
{
    pagecache_debug("%s: pn %p, complete %p (%F)\n", __func__, pn, complete, complete);
    pagecache_scan_node(pn);
    pagecache_commit_dirty_node(pn);
    pagecache_finish_pending_writes(pn->pv->pc, 0, pn, complete);
}
#endif /* !PAGECACHE_READ_ONLY */

typedef closure_type(pp_handler, void, pagecache_page);

closure_function(5, 1, void, pagecache_node_fetch_complete,
                 pagecache, pc, pagecache_page, first_page, u64, page_count, sg_list, sg, status_handler, complete,
                 status, s)
{
    pagecache pc = bound(pc);
    pagecache_page pp = bound(first_page);
    u64 page_count = bound(page_count);
    sg_list sg = bound(sg);
    pagecache_debug("%s: page count %ld, status %v\n", __func__, page_count, s);
    pagecache_lock_state(pc);
    while (page_count-- > 0) {
        change_page_state_locked(pc, pp,
            is_ok(s) ? PAGECACHE_PAGESTATE_NEW : PAGECACHE_PAGESTATE_ALLOC);
        pagecache_page_queue_completions_locked(pc, pp, s);
        pp = (pagecache_page)rbnode_get_next((rbnode)pp);
    }
    pagecache_unlock_state(pc);
    sg_list_release(sg);
    deallocate_sg_list(sg);
    apply(bound(complete), s);
    closure_finish();
}

static boolean pagecache_node_fetch_sg(pagecache pc, pagecache_node pn, range r, sg_list sg,
                                       pagecache_page pp, merge m)
{
    status_handler fetch_sh = apply_merge(m);
    status_handler fetch_complete = closure(pc->h, pagecache_node_fetch_complete, pc,
        pp, range_span(r) >> pc->page_order, sg, fetch_sh);
    if (fetch_complete == INVALID_ADDRESS) {
        apply(fetch_sh, timm("result", "failed to allocate fetch completion"));
        return false;
    }
    pagecache_debug("fetching %R from node %p\n", r, pn);
    apply(pn->fs_read, sg, r, fetch_complete);
    return true;
}

static void pagecache_node_fetch_internal(pagecache_node pn, range q, pp_handler ph,
                                          status_handler completion)
{
    pagecache pc = pn->pv->pc;
    merge m = allocate_merge(pc->h, completion);
    status_handler sh = apply_merge(m);
    struct pagecache_page k;
    if (q.end > pn->length)
        q.end = pn->length;
    k.state_offset = q.start >> pc->page_order;
    u64 end = (q.end + MASK(pc->page_order)) >> pc->page_order;
    pagecache_lock_node(pn);
    pagecache_page pp = (pagecache_page)rbtree_lookup(&pn->pages, &k.rbnode);
    sg_list read_sg = 0;
    pagecache_page read_pp = 0;
    range read_r;
    pagecache_lock_state(pc);
    for (u64 pi = k.state_offset; pi < end; pi++) {
        if (pp == INVALID_ADDRESS || page_offset(pp) > pi) {
            pp = allocate_page_nodelocked(pn, pi);
            if (pp == INVALID_ADDRESS) {
                apply(apply_merge(m), timm("result", "failed to allocate pagecache_page"));
                break;
            }
        }
        if (ph)
            apply(ph, pp);
        if (touch_page_locked(pn, pp, m)) {
            /* This page does not need to be fetched: fetch pages accumulated so far in read_sg. */
            if (read_sg) {
                pagecache_unlock_state(pc);
                boolean success = pagecache_node_fetch_sg(pc, pn, read_r, read_sg, read_pp, m);
                pagecache_lock_state(pc);
                if (!success)
                    break;
                read_sg = 0;
            }
        } else {
            /* This page needs to be fetched: add it to read_sg. */
            if (page_state(pp) == PAGECACHE_PAGESTATE_FREE) {
                apply(apply_merge(m), timm("result", "failed to allocate page"));
                break;
            }
            if (!read_sg) {
                read_sg = allocate_sg_list();
                if (read_sg == INVALID_ADDRESS) {
                    apply(apply_merge(m), timm("result", "failed to allocate read SG list"));
                    read_sg = 0;
                    break;
                }
                read_pp = pp;
                read_r = range_lshift(irangel(page_offset(pp), 0), pc->page_order);
            }
            pagecache_add_sgb(pc, pp, read_sg);
            read_r.end += cache_pagesize(pc);
        }
        pp = (pagecache_page)rbnode_get_next((rbnode)pp);
    }
    pagecache_unlock_state(pc);
    pagecache_unlock_node(pn);
    if (read_sg && !pagecache_node_fetch_sg(pc, pn, read_r, read_sg, read_pp, m))
        deallocate_sg_list(read_sg);

    /* finished issuing requests */
    apply(sh, STATUS_OK);
}

closure_function(3, 1, void, pagecache_read_pp_handler,
                 pagecache, pc, range, q, sg_list, sg,
                 pagecache_page, pp)
{
    range r = byte_range_from_page(bound(pc), pp);
    range i = range_intersection(bound(q), r);
    u64 length = range_span(i);
    sg_buf sgb = sg_list_tail_add(bound(sg), length);
    sgb->buf = pp->kvirt + (i.start - r.start);
    sgb->size = length;
    sgb->offset = 0;
    sgb->refcount = &pp->refcount;
    refcount_reserve(&pp->refcount);
}

closure_function(1, 3, void, pagecache_read_sg,
                 pagecache_node, pn,
                 sg_list, sg, range, q, status_handler, completion)
{
    pagecache_node pn = bound(pn);
    pagecache pc = pn->pv->pc;
    pagecache_debug("%s: node %p, q %R, sg %p, completion %F\n", __func__, pn, q, sg, completion);
    q = range_intersection(q, irangel(0, pn->length));
    pagecache_node_fetch_internal(pn, q, stack_closure(pagecache_read_pp_handler, pc, q, sg),
                                  completion);
}


#ifdef KERNEL
closure_function(3, 3, boolean, pagecache_check_dirty_page,
                 pagecache, pc, pagecache_shared_map, sm, flush_entry, fe,
                 int, level, u64, vaddr, pteptr, entry)
{
    pagecache pc = bound(pc);
    pagecache_shared_map sm = bound(sm);
    pte old_entry = pte_from_pteptr(entry);
    if (pte_is_present(old_entry) &&
        pte_is_mapping(level, old_entry) &&
        pte_is_dirty(old_entry)) {
        range r = irangel(sm->node_offset + (vaddr - sm->n.r.start), cache_pagesize(pc));
        u64 pi = r.start >> pc->page_order;
        pagecache_debug("   dirty: vaddr 0x%lx, pi 0x%lx\n", vaddr, pi);
        pt_pte_clean(entry);
        page_invalidate(bound(fe), vaddr);
        pagecache_node pn = sm->pn;
        pagecache_lock_node(pn);
        pagecache_page pp = page_lookup_nodelocked(pn, pi);
        assert(pp != INVALID_ADDRESS);
        pagecache_lock_state(pc);
        if (page_state(pp) != PAGECACHE_PAGESTATE_DIRTY)
            change_page_state_locked(pc, pp, PAGECACHE_PAGESTATE_DIRTY);
        pagecache_unlock_state(pc);
        pagecache_set_dirty(pn, r);
        pagecache_unlock_node(pn);
    }
    return true;
}

static void pagecache_scan_shared_map(pagecache pc, pagecache_shared_map sm, flush_entry fe)
{
    traverse_ptes(sm->n.r.start, range_span(sm->n.r),
                  stack_closure(pagecache_check_dirty_page, pc, sm, fe));
}

static void pagecache_scan_shared_mappings(pagecache pc)
{
    pagecache_debug("%s\n", __func__);
    flush_entry fe = get_page_flush_entry();
    list_foreach(&pc->shared_maps, l) {
        pagecache_shared_map sm = struct_from_list(l, pagecache_shared_map, l);
        pagecache_debug("   shared map va %R, node_offset 0x%lx\n", sm->n.r, sm->node_offset);
        pagecache_scan_shared_map(pc, sm, fe);
    }
    page_invalidate_sync(fe, 0);
}

static void pagecache_scan_node(pagecache_node pn)
{
    pagecache_debug("%s\n", __func__);
    flush_entry fe = get_page_flush_entry();
    rangemap_foreach(pn->shared_maps, n) {
        pagecache_shared_map sm = (pagecache_shared_map)n;
        pagecache_debug("   shared map va %R, node_offset 0x%lx\n", n->r, sm->node_offset);
        pagecache_scan_shared_map(pn->pv->pc, sm, fe);
    }
    page_invalidate_sync(fe, 0);
}

define_closure_function(1, 2, void, pagecache_scan_timer,
                        pagecache, pc,
                        u64, expiry, u64, overruns)
{
    pagecache pc = bound(pc);
    if ((overruns != timer_disabled) && !pc->writeback_in_progress) {
        pagecache_scan(pc);
        pc->writeback_in_progress = true;
        pagecache_finish_pending_writes(pc, 0, 0, (status_handler)&pc->writeback_complete);
    }
}

define_closure_function(0, 1, void, pagecache_writeback_complete,
                        status, s)
{
    pagecache pc = struct_from_field(closure_self(), pagecache, writeback_complete);
    pc->writeback_in_progress = false;
}

void pagecache_node_add_shared_map(pagecache_node pn, range q /* bytes */, u64 node_offset)
{
    pagecache pc = pn->pv->pc;
    pagecache_shared_map sm = allocate(pc->h, sizeof(struct pagecache_shared_map));
    assert(sm != INVALID_ADDRESS);
    sm->n.r = q;
    sm->pn = pn;
    sm->node_offset = node_offset;
    pagecache_debug("%s: pn %p, q %R, node_offset 0x%lx\n", __func__, pn, q, node_offset);
    pagecache_lock_state(pc);
    list_insert_before(&pc->shared_maps, &sm->l);
    assert(rangemap_insert(pn->shared_maps, &sm->n));
    pagecache_unlock_state(pc);
}

closure_function(3, 1, boolean, close_shared_pages_intersection,
                 pagecache_node, pn, range, q, flush_entry, fe,
                 rmnode, n)
{
    pagecache_node pn = bound(pn);
    pagecache pc = pn->pv->pc;
    pagecache_shared_map sm = (pagecache_shared_map)n;
    range rn = n->r;
    range ri = range_intersection(bound(q), rn);
    boolean head = ri.start > rn.start;
    boolean tail = ri.end < rn.end;

    pagecache_debug("   intersection %R, head %d, tail %d\n", ri, head, tail);

    /* scan intersecting map regardless of editing */
    pagecache_scan_shared_map(pc, sm, bound(fe));

    if (!head && !tail) {
        rangemap_remove_node(pn->shared_maps, n);
        list_delete(&sm->l);
        deallocate(pc->h, sm, sizeof(struct pagecache_shared_map));
    } else if (head) {
        /* truncate map at start */
        assert(rangemap_reinsert(pn->shared_maps, n, irange(rn.start, ri.start)));

        if (tail) {
            /* create map at tail end */
            pagecache_node_add_shared_map(pn, irange(ri.end, rn.end),
                                          sm->node_offset + (ri.end - rn.start));
        }
    } else {
        /* tail only: move map start back */
        assert(rangemap_reinsert(pn->shared_maps, n, irange(ri.end, rn.end)));
        sm->node_offset += ri.end - rn.start;
    }
    return true;
}

void pagecache_node_close_shared_pages(pagecache_node pn, range q /* bytes */, flush_entry fe)
{
    pagecache_debug("%s: node %p, q %R\n", __func__, pn, q);
    rangemap_range_lookup(pn->shared_maps, q,
                          stack_closure(close_shared_pages_intersection, pn, q, fe));
}

closure_function(2, 1, boolean, scan_shared_pages_intersection,
                 pagecache, pc, flush_entry, fe,
                 rmnode, n)
{
    /* currently just scanning the whole map - it could be just a range,
       but with scan and sync timers imminent, does it really matter? */
    pagecache_shared_map sm = (pagecache_shared_map)n;
    pagecache_debug("   map %p\n", sm);
    pagecache_scan_shared_map(bound(pc), sm, bound(fe));
    return true;
}

void pagecache_node_scan_and_commit_shared_pages(pagecache_node pn, range q /* bytes */)
{
    pagecache_debug("%s: node %p, q %R\n", __func__, pn, q);
    flush_entry fe = get_page_flush_entry();
    rangemap_range_lookup(pn->shared_maps, q,
                          stack_closure(scan_shared_pages_intersection, pn->pv->pc, fe));
    pagecache_commit_dirty_node(pn);
    page_invalidate_sync(fe, 0);
}

boolean pagecache_node_do_page_cow(pagecache_node pn, u64 node_offset, u64 vaddr, pageflags flags)
{
    pagecache_debug("%s: node %p, node_offset 0x%lx, vaddr 0x%lx, flags 0x%lx\n",
                    __func__, pn, node_offset, vaddr, flags.w);
    pagecache pc = pn->pv->pc;
    u64 paddr = allocate_u64(pc->physical, PAGESIZE);
    if (paddr == INVALID_PHYSICAL)
        return false;
    pagecache_lock_node(pn);
    pagecache_page pp = page_lookup_nodelocked(pn, node_offset >> pc->page_order);
    assert(pp != INVALID_ADDRESS);
    assert(pageflags_is_writable(flags));
    assert(page_state(pp) != PAGECACHE_PAGESTATE_FREE);
    assert(pp->kvirt != INVALID_ADDRESS);
    assert(pp->refcount.c != 0);
    unmap(vaddr, cache_pagesize(pc));
    map(vaddr, paddr, cache_pagesize(pc), flags);
    runtime_memcpy(pointer_from_u64(vaddr), pp->kvirt, cache_pagesize(pc));
    pagecache_unlock_node(pn);
    refcount_release(&pp->refcount);
    return true;
}

void pagecache_node_fetch_pages(pagecache_node pn, range r)
{
    pagecache_debug("%s: node %p, r %R\n", __func__, pn, r);
    pagecache_node_fetch_internal(pn, r, 0, ignore_status);
}

static void map_page(pagecache pc, pagecache_page pp, u64 vaddr, pageflags flags, status_handler complete)
{
    assert(pp->refcount.c != 0);
    assert(pp->kvirt != INVALID_ADDRESS);
    map_with_complete(vaddr, pp->phys, cache_pagesize(pc), flags, complete);
}

closure_function(5, 1, void, map_page_finish,
                 pagecache, pc, pagecache_page, pp, u64, vaddr, pageflags, flags, status_handler, complete,
                 status, s)
{
    if (is_ok(s)) {
        map_page(bound(pc), bound(pp), bound(vaddr), bound(flags), bound(complete));
    } else {
        apply(bound(complete), s);
    }
    closure_finish();
}

/* not context restoring */
void pagecache_map_page(pagecache_node pn, u64 node_offset, u64 vaddr, pageflags flags,
                        status_handler complete)
{
    pagecache pc = pn->pv->pc;
    pagecache_lock_node(pn);
    u64 pi = node_offset >> pc->page_order;
    pagecache_page pp = page_lookup_or_alloc_nodelocked(pn, pi);
    pagecache_debug("%s: pn %p, node_offset 0x%lx, vaddr 0x%lx, flags 0x%lx, complete %F, pp %p\n",
                    __func__, pn, node_offset, vaddr, flags, complete, pp);
    if (pp == INVALID_ADDRESS) {
        pagecache_unlock_node(pn);
        apply(complete, timm("result", "%s: unable to allocate pagecache page", __func__));
        return;
    }
    merge m = allocate_merge(pc->h, closure(pc->h, map_page_finish,
                                            pc, pp, vaddr, flags, complete));
    status_handler k = apply_merge(m);
    touch_or_fill_page_nodelocked(pn, pp, m);
    refcount_reserve(&pp->refcount);
    pagecache_unlock_node(pn);
    apply(k, STATUS_OK);
}

/* no-alloc / no-fill path */
boolean pagecache_map_page_if_filled(pagecache_node pn, u64 node_offset, u64 vaddr, pageflags flags,
                                     status_handler complete)
{
    boolean mapped = false;
    pagecache_lock_node(pn);
    pagecache_page pp = page_lookup_nodelocked(pn, node_offset >> pn->pv->pc->page_order);
    pagecache_debug("%s: pn %p, node_offset 0x%lx, vaddr 0x%lx, flags 0x%lx, pp %p\n",
                    __func__, pn, node_offset, vaddr, flags.w, pp);
    if (pp == INVALID_ADDRESS)
        goto out;
    if (touch_or_fill_page_nodelocked(pn, pp, 0)) {
        mapped = true;
        map_page(pn->pv->pc, pp, vaddr, flags, complete);
    }
    refcount_reserve(&pp->refcount);
  out:
    pagecache_unlock_node(pn);
    return mapped;
}

closure_function(4, 3, boolean, pagecache_unmap_page_nodelocked,
                 pagecache_node, pn, u64, vaddr_base, u64, node_offset, flush_entry, fe,
                 int, level, u64, vaddr, pteptr, entry)
{
    pte old_entry = pte_from_pteptr(entry);
    if (pte_is_present(old_entry) &&
        pte_is_mapping(level, old_entry)) {
        u64 pi = (bound(node_offset) + (vaddr - bound(vaddr_base))) >> PAGELOG;
        pagecache_debug("   vaddr 0x%lx, pi 0x%lx\n", vaddr, pi);
        pte_set(entry, 0);
        page_invalidate(bound(fe), vaddr);
        pagecache_page pp = page_lookup_nodelocked(bound(pn), pi);
        assert(pp != INVALID_ADDRESS);
        u64 phys = page_from_pte(old_entry);
        if (phys == pp->phys) {
            /* shared or cow */
            assert(pp->refcount.c >= 1);
            refcount_release(&pp->refcount);
        } else {
            /* private copy: free physical page */
            pagecache pc = bound(pn)->pv->pc;
            deallocate_u64(pc->physical, phys, cache_pagesize(pc));
        }
    }
    return true;
}

void pagecache_node_unmap_pages(pagecache_node pn, range v /* bytes */, u64 node_offset)
{
    pagecache_debug("%s: pn %p, v %R, node_offset 0x%lx\n", __func__, pn, v, node_offset);
    flush_entry fe = get_page_flush_entry();
    pagecache_node_close_shared_pages(pn, v, fe);
    pagecache_lock_node(pn);
    traverse_ptes(v.start, range_span(v), stack_closure(pagecache_unmap_page_nodelocked, pn,
                                                        v.start, node_offset, fe));
    pagecache_unlock_node(pn);
    page_invalidate_sync(fe, 0);
}
#endif

define_closure_function(1, 1, boolean, pagecache_page_print_key,
                 pagecache, pc,
                 rbnode, n)
{
    rprintf(" 0x%lx", page_offset((pagecache_page)n) << cache_pagesize(bound(pc)));
    return true;
}

define_closure_function(0, 2, int, pagecache_page_compare,
                 rbnode, a, rbnode, b)
{
    u64 oa = page_offset((pagecache_page)a);
    u64 ob = page_offset((pagecache_page)b);
    return oa == ob ? 0 : (oa < ob ? -1 : 1);
}

void pagecache_set_node_length(pagecache_node pn, u64 length)
{
    pn->length = length;
}

u64 pagecache_get_node_length(pagecache_node pn)
{
    return pn->length;
}

closure_function(0, 1, boolean, pagecache_page_release,
                 rbnode, n)
{
    pagecache_page pp = struct_from_list(n, pagecache_page, rbnode);
    refcount_release(&pp->refcount);
    return true;
}

closure_function(0, 1, boolean, pagecache_node_assert,
                 rmnode, n)
{
    /* A pagecache node being deallocated must not have any shared maps. */
    assert(0);
    return false;
}

define_closure_function(1, 0, void, pagecache_node_free,
                        pagecache_node, pn)
{
    pagecache_node pn = bound(pn);
    if (pn->fs_read)
        deallocate_closure(pn->fs_read);
    deallocate_closure(pn->cache_read);
#ifndef PAGECACHE_READ_ONLY
    if (pn->fs_write)
        deallocate_closure(pn->fs_write);
    if (pn->fs_reserve)
        deallocate_closure(pn->fs_reserve);
    deallocate_closure(pn->cache_write);
#endif
    destruct_rbtree(&pn->pages, stack_closure(pagecache_page_release));
    deallocate_rangemap(pn->shared_maps, stack_closure(pagecache_node_assert));
    deallocate(pn->pv->pc->h, pn, sizeof(*pn));
}

define_closure_function(1, 0, void, pagecache_node_queue_free,
                        pagecache_node, pn)
{
    thunk t = (void *)&bound(pn)->free;
#ifdef KERNEL
    /* freeing the node must be deferred to avoid state lock reentrance */
    async_apply(t);
#else
    apply(t);
#endif
}

void pagecache_deallocate_node(pagecache_node pn)
{
    refcount_release(&pn->refcount);
}

sg_io pagecache_node_get_reader(pagecache_node pn)
{
    return pn->cache_read;
}

sg_io pagecache_node_get_writer(pagecache_node pn)
{
    return pn->cache_write;
}

pagecache_node pagecache_allocate_node(pagecache_volume pv, sg_io fs_read, sg_io fs_write, pagecache_node_reserve fs_reserve)
{
    heap h = pv->pc->h;
    pagecache_node pn = allocate(h, sizeof(struct pagecache_node));
    if (pn == INVALID_ADDRESS)
        return pn;
    pn->pv = pv;
    pn->shared_maps = allocate_rangemap(h);
    if (pn->shared_maps == INVALID_ADDRESS) {
        deallocate(h, pn, sizeof(struct pagecache_node));
        return INVALID_ADDRESS;
    }
#ifdef KERNEL
    spin_lock_init(&pn->pages_lock);
#endif
    list_init_member(&pn->l);
    init_rangemap(&pn->dirty, h);
    init_rbtree(&pn->pages, (rb_key_compare)&pv->pc->page_compare,
                (rbnode_handler)&pv->pc->page_print_key);
    pn->length = 0;
    pn->cache_read = closure(h, pagecache_read_sg, pn);
#ifndef PAGECACHE_READ_ONLY
    pn->cache_write = closure(h, pagecache_write_sg, pn);
#else
    pn->cache_write = 0;
#endif
    pn->fs_read = fs_read;
    pn->fs_write = fs_write;
    pn->fs_reserve = fs_reserve;
    init_closure(&pn->free, pagecache_node_free, pn);
    init_refcount(&pn->refcount, 1, init_closure(&pn->queue_free, pagecache_node_queue_free, pn));
    return pn;
}

void *pagecache_get_zero_page(void)
{
    return global_pagecache->zero_page;
}

int pagecache_get_page_order(void)
{
    return global_pagecache->page_order;
}

u64 pagecache_get_occupancy(void)
{
    return global_pagecache->total_pages << pagecache_get_page_order();
}

pagecache_volume pagecache_allocate_volume(u64 length, int block_order)
{
    pagecache pc = global_pagecache;
    pagecache_volume pv = allocate(pc->h, sizeof(struct pagecache_volume));
    if (pv == INVALID_ADDRESS)
        return pv;
    pv->pc = pc;
    list_insert_before(&pc->volumes, &pv->l);
    list_init(&pv->dirty_nodes);
#ifdef KERNEL
    spin_lock_init(&pv->lock);
    if (!timer_is_active(&pc->scan_timer)) {
        timestamp t = seconds(PAGECACHE_SCAN_PERIOD_SECONDS);
        register_timer(kernel_timers, &pc->scan_timer, CLOCK_ID_MONOTONIC, t, false, t,
                       (timer_handler)&pc->do_scan_timer);
    }
#endif
    pv->length = length;
    pv->block_order = block_order;
    pv->write_error = STATUS_OK;
    return pv;
}

void pagecache_dealloc_volume(pagecache_volume pv)
{
    list_delete(&pv->l);
    deallocate(pv->pc->h, pv, sizeof(*pv));
}

static inline void page_list_init(struct pagelist *pl)
{
    list_init(&pl->l);
    pl->pages = 0;
}

void init_pagecache(heap general, heap contiguous, heap physical, u64 pagesize)
{
    pagecache pc = allocate(general, sizeof(struct pagecache));
    assert (pc != INVALID_ADDRESS);

    pc->total_pages = 0;
    pc->page_order = find_order(pagesize);
    assert(pagesize == U64_FROM_BIT(pc->page_order));
    pc->h = general;
    pc->contiguous = contiguous;
    pc->physical = physical;
    pc->zero_page = allocate_zero(contiguous, pagesize);
    assert(pc->zero_page != INVALID_ADDRESS);

#ifdef KERNEL
    pc->completions =
        locking_heap_wrapper(general, allocate_objcache(general, contiguous,
                                                        sizeof(struct page_completion),
                                                        PAGESIZE));
    assert(pc->completions != INVALID_ADDRESS);
    spin_lock_init(&pc->state_lock);
#else
    pc->completions = general;
#endif
    page_list_init(&pc->free);
    page_list_init(&pc->new);
    page_list_init(&pc->active);
    page_list_init(&pc->writing);
    list_init(&pc->volumes);
    list_init(&pc->shared_maps);
    init_closure(&pc->page_compare, pagecache_page_compare);
    init_closure(&pc->page_print_key, pagecache_page_print_key, pc);

#ifdef KERNEL
    pc->writeback_in_progress = false;
    init_timer(&pc->scan_timer);
    init_closure(&pc->do_scan_timer, pagecache_scan_timer, pc);
    init_closure(&pc->writeback_complete, pagecache_writeback_complete);
#endif
    global_pagecache = pc;
}
