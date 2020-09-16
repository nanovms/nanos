/* TODO:
   - reinstate free list, keep refault counts
   - interface to physical free page list / shootdown epochs

   - would be nice to propagate a priority alone with requests to
     pagecache - which in turn would be passed to page I/O - so that
     page fault fills can go to head of request queue
*/

/* don't care for this ... but we're used in both kernel and other contexts ... maybe split up */
#ifdef KERNEL
#include <kernel.h>
#include <page.h>
#else
#include <runtime.h>
#endif

#include <pagecache.h>
#include <pagecache_internal.h>

//#define PAGECACHE_DEBUG
#if defined(PAGECACHE_DEBUG)
#define pagecache_debug(x, ...) do {rprintf("PGC: " x, ##__VA_ARGS__);} while(0)
#else
#define pagecache_debug(x, ...)
#endif

#ifdef BOOT
#define PAGECACHE_READ_ONLY
#endif

/* TODO: Seems like this ought not to be so large ... but we're
   queueing a ton with the polled ATA driver. There's only one queue globally anyhow. */
#define MAX_PAGE_COMPLETION_VECS 16384

static pagecache global_pagecache;

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
#define pagecache_lock_node(pn)
#define pagecache_unlock_node(pn)
#endif

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
        } else if (old_state == PAGECACHE_PAGESTATE_DIRTY) {
            pagelist_move(&pc->writing, &pc->dirty, pp);
        } else if (old_state == PAGECACHE_PAGESTATE_WRITING) {
            /* write already pending, move to tail of queue */
            pagelist_touch(&pc->writing, pp);
        } else {
            assert(old_state == PAGECACHE_PAGESTATE_ALLOC);
            pagelist_enqueue(&pc->writing, pp);
        }
        pp->write_count++;
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
    case PAGECACHE_PAGESTATE_DIRTY:
        if (old_state == PAGECACHE_PAGESTATE_NEW) {
            pagelist_move(&pc->dirty, &pc->new, pp);
        } else if (old_state == PAGECACHE_PAGESTATE_ACTIVE) {
            pagelist_move(&pc->dirty, &pc->active, pp);
        } else {
            assert(old_state == PAGECACHE_PAGESTATE_WRITING);
            pagelist_move(&pc->dirty, &pc->writing, pp);
        }
        break;
    default:
        halt("%s: bad state %d, old %d\n", __func__, state, old_state);
    }

    pp->state_offset = (pp->state_offset & MASK(PAGECACHE_PAGESTATE_SHIFT)) |
        ((u64)state << PAGECACHE_PAGESTATE_SHIFT);
}

#ifdef STAGE3
closure_function(1, 0, void, pagecache_service_completions,
                 pagecache, pc)
{
    /* we don't need the pagecache lock here; flag reset is atomic and dequeue is safe */
    assert(bound(pc)->service_enqueued);
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
#else
static void pagecache_page_queue_completions_locked(pagecache pc, pagecache_page pp, status s)
{
    if (pp->completions && vector_length(pp->completions) > 0) {
        vector v = pp->completions;
        pp->completions = 0;
        status_handler sh;
        vector_foreach(v, sh) {
            assert(sh);
            apply(sh, s);
        }
        deallocate_vector(v);
    }
}
#endif

closure_function(3, 1, void, pagecache_read_page_complete,
                 pagecache, pc, pagecache_page, pp, sg_list, sg,
                 status, s)
{
    pagecache pc = bound(pc);
    pagecache_page pp = bound(pp);
    pagecache_debug("%s: pc %p, pp %p, status %v\n", __func__, pc, bound(pp), s);
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

static void enqueue_page_completion_statelocked(pagecache pc, pagecache_page pp, status_handler sh)
{
    /* completions may have been consumed on service */
    if (!pp->completions)
        pp->completions = allocate_vector(pc->h, 4);
    vector_push(pp->completions, sh);
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
            refcount_reserve(&pp->refcount);
        }
        pagecache_unlock_state(pc);
        return false;
    case PAGECACHE_PAGESTATE_ALLOC:
        if (m) {
            enqueue_page_completion_statelocked(pc, pp, apply_merge(m));
            change_page_state_locked(pc, pp, PAGECACHE_PAGESTATE_READING);
            refcount_reserve(&pp->refcount);
        }
        pagecache_unlock_state(pc);

        if (m) {
            /* issue page reads */
            range r = byte_range_from_page(pc, pp);
            pagecache_debug("   pc %p, pp %p, r %R, reading...\n", pc, pp, r);
            sg_list sg = allocate_sg_list();
            assert(sg != INVALID_ADDRESS);
            sg_buf sgb = sg_list_tail_add(sg, cache_pagesize(pc));
            sgb->buf = pp->kvirt;
            sgb->size = cache_pagesize(pc);
            sgb->offset = 0;
            sgb->refcount = &pp->refcount;
            refcount_reserve(sgb->refcount);
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
    refcount_reserve(&pp->refcount);
    pagecache_unlock_state(pc);
    return true;
}

define_closure_function(2, 0, void, pagecache_page_free,
                        pagecache, pc, pagecache_page, pp)
{
    pagecache_page pp = bound(pp);
    /* remove from existing list depending on state */
    int state = page_state(pp);
    if (state != PAGECACHE_PAGESTATE_EVICTED)
        halt("%s: pc %p, pp %p, invalid state %d\n", __func__, bound(pc), pp, page_state(pp));

    pagecache pc = bound(pc);
    deallocate(pc->contiguous, pp->kvirt, cache_pagesize(pc));
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
#ifdef KERNEL
    pp->phys = physical_from_virtual(p);
#endif
    pp->completions = 0;
    assert(rbtree_insert_node(&pn->pages, &pp->rbnode));
    fetch_and_add(&pc->total_pages, 1); /* decrement happens without cache lock */
    return pp;
  fail_dealloc_contiguous:
    deallocate(pc->contiguous, p, pagesize);
    return INVALID_ADDRESS;
}

#ifndef PAGECACHE_READ_ONLY
static u64 evict_from_list_locked(pagecache pc, struct pagelist *pl, u64 pages)
{
    u64 evicted = 0;
    list_foreach(&pl->l, l) {
        if (evicted >= pages)
            break;

        pagecache_page pp = struct_from_list(l, pagecache_page, l);
        pagecache_debug("%s: list %s, release pp %R, state %d, count %ld\n", __func__,
                        pl == &pc->new ? "new" : "active", byte_range_from_page(pc, pp),
                        page_state(pp), pp->refcount.c);
        change_page_state_locked(pc, pp, PAGECACHE_PAGESTATE_EVICTED);
        rbtree_remove_node(&pp->node->pages, &pp->rbnode);
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
    }
    return pp;
}

static void touch_or_fill_page_by_num_nodelocked(pagecache_node pn, u64 n, merge m)
{
    pagecache_page pp = page_lookup_or_alloc_nodelocked(pn, n);
    if (pp == INVALID_ADDRESS)
        apply(apply_merge(m), timm("result", "failed to allocate pagecache_page"));
    else
        touch_or_fill_page_nodelocked(pn, pp, m);
}

closure_function(5, 1, void, pagecache_write_sg_finish,
                 pagecache_node, pn, range, q, sg_list, sg, status_handler, completion, boolean, complete,
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

    pagecache_debug("%s: pn %p, q %R, sg %p, complete %d, status %v\n", __func__, pn, q,
                    sg, bound(complete), s);

    pagecache_lock_node(pn);
    pagecache_page pp = page_lookup_nodelocked(pn, pi);
    if (bound(complete)) {
        /* TODO: We handle storage errors after the syscall write
           completion has been applied. This means that storage
           allocation and I/O errors aren't being propagated back to
           the syscalls that caused them and are therefore imprecise.
           For now, we take note of any write error and stash it in
           the volume to be returned on a subsequent call.

           As of now, we do not automatically clear a pending error
           condition after reporting. Some logic will need to be added
           to clear specific conditions and allow the application to
           recover from an error (e.g. test for and clear a pending
           FS_STATUS_NOSPACE after an extent has been deleted).

           This is clearly a stop-gap, meant to prevent endless,
           runaway writes on common conditions like storage
           exhaustion. */

        if (!is_ok(s)) {
            pagecache_debug("%s: write_error now %v\n", __func__, s);
            pn->pv->write_error = s;
        }

        do {
            assert(pp != INVALID_ADDRESS && page_offset(pp) == pi);
            pagecache_lock_state(pc);
            assert(pp->write_count > 0);
            if (pp->write_count-- == 1) {
                if (page_state(pp) != PAGECACHE_PAGESTATE_DIRTY)
                    change_page_state_locked(pc, pp, PAGECACHE_PAGESTATE_NEW);
                pagecache_page_queue_completions_locked(pc, pp, s);
            }
            pagecache_unlock_state(pc);
// TODO            refcount_release(&pp->refcount);
            pi++;
            pp = (pagecache_page)rbnode_get_next((rbnode)pp);
        } while (pi < end);
        pagecache_unlock_node(pn);
        closure_finish();
        return;
    }

    /* apply writes, allocating pages as needed */
    u64 offset = q.start & MASK(page_order);
    u64 block_offset = q.start & MASK(block_order);
    range r = irange(q.start & ~MASK(block_order), q.end);
    sg_list write_sg;
    if (sg) {
        write_sg = allocate_sg_list();
        if (write_sg == INVALID_ADDRESS) {
            pagecache_unlock_node(pn);
            apply(bound(completion), timm("result", "failed to allocate write sg"));
            closure_finish();
            return;
        }
    } else {
        write_sg = 0;
    }
    do {
        if (pp == INVALID_ADDRESS || page_offset(pp) > pi) {
            assert(offset == 0 && block_offset == 0); /* should never alloc for unaligned head */
            pp = allocate_page_nodelocked(pn, pi);
            if (pp == INVALID_ADDRESS) {
                pagecache_unlock_node(pn);
                apply(bound(completion), timm("result", "failed to allocate pagecache_page"));
                if (write_sg) {
                    sg_list_release(write_sg);
                    deallocate_sg_list(write_sg);
                }
                closure_finish();
                return;
            }

            /* When writing a new page at the end of a node whose length is not block-aligned, zero
               the remaining portion of the last block. The filesystem will depend on this to properly
               implement file holes. */
            range i = range_intersection(byte_range_from_page(pc, pp), q);
            u64 tail_offset = i.end & MASK(block_order);
            if (tail_offset) {
                u64 page_offset = i.end & MASK(page_order);
                u64 len = U64_FROM_BIT(block_order) - tail_offset;
                pagecache_debug("   zero unaligned end, i %R, page offset 0x%lx, len 0x%lx\n",
                                i, page_offset, len);
                assert(i.end == pn->length);
                zero(pp->kvirt + page_offset, len);
            }
        }
        u64 copy_len = MIN(q.end - (pi << page_order), cache_pagesize(pc)) - offset;
        u64 req_len = pad(copy_len + block_offset, U64_FROM_BIT(block_order));
        if (write_sg) {
            sg_buf sgb = sg_list_tail_add(write_sg, req_len);
            sgb->buf = pp->kvirt;
            sgb->offset = offset - block_offset;
            sgb->size = sgb->offset + req_len;
            sgb->refcount = &pp->refcount;
            refcount_reserve(sgb->refcount);
            u64 res = sg_copy_to_buf(pp->kvirt + offset, sg, copy_len);
            assert(res == copy_len);
        } else {
            zero(pp->kvirt + offset, copy_len);
        }
        pagecache_lock_state(pc);
        change_page_state_locked(pc, pp, PAGECACHE_PAGESTATE_WRITING);
        pagecache_unlock_state(pc);
        offset = 0;
        block_offset = 0;
        pi++;
        pp = (pagecache_page)rbnode_get_next((rbnode)pp);
    } while (pi < end);
    pagecache_unlock_node(pn);

    /* issue write */
    bound(complete) = true;
    pagecache_debug("   calling fs_write, range %R, sg %p\n", r, write_sg);
    apply(pn->fs_write, write_sg, r, (status_handler)closure_self());
    apply(bound(completion), STATUS_OK);
}

closure_function(1, 3, void, pagecache_write_sg,
                 pagecache_node, pn,
                 sg_list, sg, range, q, status_handler, completion)
{
    pagecache_node pn = bound(pn);
    pagecache_volume pv = pn->pv;
    pagecache pc = pv->pc;
    pagecache_debug("%s: node %p, q %R, sg %p, completion %F\n", __func__, pn, q, sg, completion);

    if (!is_ok(pv->write_error)) {
        /* From a previous (asynchronous) write failure - see comment
           in pagecache_write_sg_finish above */
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

    /* prepare pages for writing */
    merge m = allocate_merge(pc->h, closure(pc->h, pagecache_write_sg_finish, pn, q, sg, completion, false));
    status_handler sh = apply_merge(m);

    /* initiate reads for rmw start and/or end */
    u64 start_offset = q.start & MASK(pc->page_order);
    u64 end_offset = q.end & MASK(pc->page_order);
    range r = range_rshift(q, pc->page_order);
    pagecache_lock_node(pn);
    if (start_offset != 0) {
        touch_or_fill_page_by_num_nodelocked(pn, q.start >> pc->page_order, m);
        r.start++;
    }
    if (end_offset != 0 && (q.end < pn->length) && /* tail rmw */
        !((q.start & ~MASK(pc->page_order)) ==
          (q.end & ~MASK(pc->page_order)) && start_offset != 0) /* no double fill */) {
        touch_or_fill_page_by_num_nodelocked(pn, q.end >> pc->page_order, m);
    }

    /* scan whole pages, blocking for any pending reads */
    pagecache_page pp = page_lookup_nodelocked(pn, r.start);
    while (pp != INVALID_ADDRESS && page_offset(pp) < r.end) {
        refcount_reserve(&pp->refcount);
        pagecache_lock_state(pc);
        if (page_state(pp) == PAGECACHE_PAGESTATE_READING)
            enqueue_page_completion_statelocked(pc, pp, apply_merge(m));
        pagecache_unlock_state(pc);
        pp = (pagecache_page)rbnode_get_next((rbnode)pp);
    }
    pagecache_unlock_node(pn);
    apply(sh, STATUS_OK);
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

u64 pagecache_drain(u64 drain_bytes)
{
    pagecache pc = global_pagecache;
    u64 pages = pad(drain_bytes, cache_pagesize(pc)) >> pc->page_order;

    /* We could avoid taking both locks here if we keep drained page
       objects around (which incidentally could be useful to keep
       refault data). */

    // XXX TODO This is a race issue on SMP now ... the locking scheme here needs to be rehashed
//    spin_lock(&pc->pages_lock);
    pagecache_lock_state(pc);
    u64 evicted = evict_pages_locked(pc, pages);
    pagecache_unlock_state(pc);
//    spin_unlock(&pc->pages_lock);
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

#ifdef STAGE3
static void pagecache_scan(pagecache pc);
static void pagecache_scan_node(pagecache_node pn);
#else
static void pagecache_scan(pagecache pc) {}
static void pagecache_scan_node(pagecache_node pn) {}
#endif

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
    pagecache_finish_pending_writes(pn->pv->pc, 0, pn, complete);
}
#endif /* !PAGECACHE_READ_ONLY */

closure_function(1, 3, void, pagecache_read_sg,
                 pagecache_node, pn,
                 sg_list, sg, range, q, status_handler, completion)
{
    pagecache_node pn = bound(pn);
    pagecache pc = pn->pv->pc;
    pagecache_debug("%s: node %p, q %R, sg %p, completion %F\n", __func__, pn, q, sg, completion);

    merge m = allocate_merge(pc->h, completion);
    status_handler sh = apply_merge(m);
    struct pagecache_page k;
    if (q.end > pn->length)
        q.end = pn->length;
    k.state_offset = q.start >> pc->page_order;
    u64 end = (q.end + MASK(pc->page_order)) >> pc->page_order;
    pagecache_lock_node(pn);
    pagecache_page pp = (pagecache_page)rbtree_lookup(&pn->pages, &k.rbnode);
    for (u64 pi = k.state_offset; pi < end; pi++) {
        if (pp == INVALID_ADDRESS || page_offset(pp) > pi) {
            pp = allocate_page_nodelocked(pn, pi);
            if (pp == INVALID_ADDRESS) {
                pagecache_unlock_node(pn);
                apply(apply_merge(m), timm("result", "failed to allocate pagecache_page"));
                return;
            }
        }

        range r = byte_range_from_page(pc, pp);
        range i = range_intersection(q, r);
        u64 length = range_span(i);
        sg_buf sgb = sg_list_tail_add(sg, length);
        sgb->buf = pp->kvirt + (i.start - r.start);
        sgb->size = length;
        sgb->offset = 0;
        sgb->refcount = &pp->refcount;

        touch_or_fill_page_nodelocked(pn, pp, m);
        pp = (pagecache_page)rbnode_get_next((rbnode)pp);
    }
    pagecache_unlock_node(pn);

    /* finished issuing requests */
    apply(sh, STATUS_OK);
}


#ifdef STAGE3
/* x86 */
closure_function(2, 3, boolean, pagecache_check_dirty_page,
                 pagecache, pc, pagecache_shared_map, sm,
                 int, level, u64, vaddr, u64 *, entry)
{
    pagecache pc = bound(pc);
    pagecache_shared_map sm = bound(sm);
    u64 old_entry = *entry;
    if (pt_entry_is_present(old_entry) &&
        pt_entry_is_pte(level, old_entry) &&
        pt_entry_is_dirty(old_entry)) {
        u64 pi = (sm->node_offset + (vaddr - sm->n.r.start)) >> PAGELOG;
        pagecache_debug("   dirty: vaddr 0x%lx, pi 0x%lx\n", vaddr, pi);
        *entry = old_entry & ~PAGE_DIRTY;
        page_invalidate(vaddr, ignore);
        pagecache_page pp = page_lookup_nodelocked(sm->pn, pi);
        assert(pp != INVALID_ADDRESS);
        pagecache_lock_state(pc);
        if (page_state(pp) != PAGECACHE_PAGESTATE_DIRTY)
            change_page_state_locked(pc, pp, PAGECACHE_PAGESTATE_DIRTY);
        pagecache_unlock_state(pc);
    }
    return true;
}

static void pagecache_scan_shared_map(pagecache pc, pagecache_shared_map sm)
{
    traverse_ptes(sm->n.r.start, range_span(sm->n.r),
                  stack_closure(pagecache_check_dirty_page, pc, sm));
}

static void pagecache_scan_shared_mappings(pagecache pc)
{
    pagecache_debug("%s\n", __func__);
    list_foreach(&pc->shared_maps, l) {
        pagecache_shared_map sm = struct_from_list(l, pagecache_shared_map, l);
        pagecache_debug("   shared map va %R, node_offset 0x%lx\n", sm->n.r, sm->node_offset);
        pagecache_scan_shared_map(pc, sm);
    }
}

static void pagecache_scan_node(pagecache_node pn)
{
    pagecache_debug("%s\n", __func__);
    rangemap_foreach(pn->shared_maps, n) {
        pagecache_shared_map sm = (pagecache_shared_map)n;
        pagecache_debug("   shared map va %R, node_offset 0x%lx\n", n->r, sm->node_offset);
        pagecache_scan_shared_map(pn->pv->pc, sm);
    }
}

closure_function(2, 1, void, pagecache_commit_complete,
                 pagecache, pc, pagecache_page, pp,
                 status, s)
{
    pagecache pc = bound(pc);
    pagecache_page pp = bound(pp);
    pagecache_debug("%s: pp %p, s %v\n", __func__, pp, s);
    if (!is_ok(s)) {
        pagecache_debug("%s: write_error now %v\n", __func__, s);
        pp->node->pv->write_error = s;
    }
    pagecache_lock_state(pc);
    assert(pp->write_count > 0);
    if (pp->write_count-- == 1) {
        if (page_state(pp) != PAGECACHE_PAGESTATE_DIRTY)
            change_page_state_locked(pc, pp, PAGECACHE_PAGESTATE_NEW);
        pagecache_page_queue_completions_locked(pc, pp, s);
    }
    pagecache_unlock_state(pc);
    closure_finish();
}

void pagecache_commit_dirty_pages(pagecache pc)
{
    pagecache_debug("%s\n", __func__);
    pagecache_lock_state(pc);

    /* It might be more efficient to move these to a temporary list,
       issue writes and then resolve on merge completion... */
    list_foreach(&pc->dirty.l, l) {
        pagecache_page pp = struct_from_list(l, pagecache_page, l);
        sg_list sg = allocate_sg_list();
        assert(sg != INVALID_ADDRESS);
        sg_buf sgb = sg_list_tail_add(sg, cache_pagesize(pc));
        sgb->buf = pp->kvirt;
        sgb->offset = 0;
        sgb->size = cache_pagesize(pc);
        sgb->refcount = &pp->refcount;
        refcount_reserve(&pp->refcount);
        change_page_state_locked(pc, pp, PAGECACHE_PAGESTATE_WRITING);
        pagecache_unlock_state(pc);

        apply(pp->node->fs_write, sg,
              irangel(page_offset(pp) << pc->page_order, cache_pagesize(pc)),
              closure(pc->h, pagecache_commit_complete, pc, pp));

        pagecache_lock_state(pc);
    }
    pagecache_unlock_state(pc);
}

static void pagecache_scan(pagecache pc)
{
    if (pc->scan_in_progress)   /* unnecessary? */
        return;
    pc->scan_in_progress = true;
    pagecache_scan_shared_mappings(pc);
    pagecache_commit_dirty_pages(pc);
}

define_closure_function(1, 1, void, pagecache_scan_timer,
                        pagecache, pc,
                        u64, overruns /* ignored */)
{
    pagecache_scan(bound(pc));
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
    if (!pc->scan_timer) {
        timestamp t = seconds(PAGECACHE_SCAN_PERIOD_SECONDS);
        pc->scan_timer = register_timer(runloop_timers, CLOCK_ID_MONOTONIC, t, false, t,
                                        (timer_handler)&pc->do_scan_timer);
    }
    pagecache_unlock_state(pc);
}

closure_function(2, 1, void, close_shared_pages_intersection,
                 pagecache_node, pn, range, q,
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
    pagecache_scan_shared_map(pc, sm);

    if (!head && !tail) {
        rangemap_remove_node(pn->shared_maps, n);
        list_delete(&sm->l);
        deallocate(pc->h, sm, sizeof(struct pagecache_shared_map));
        if (list_empty(&pc->shared_maps)) {
            pagecache_debug("   disable scan timer\n");
            remove_timer(pc->scan_timer, 0);
            pc->scan_timer = 0;
        }
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
}

void pagecache_node_close_shared_pages(pagecache_node pn, range q /* bytes */)
{
    pagecache_debug("%s: node %p, q %R\n", __func__, pn, q);
    rangemap_range_lookup(pn->shared_maps, q,
                          stack_closure(close_shared_pages_intersection, pn, q));
}

closure_function(1, 1, void, scan_shared_pages_intersection,
                 pagecache, pc,
                 rmnode, n)
{
    /* currently just scanning the whole map - it could be just a range,
       but with scan and sync timers imminent, does it really matter? */
    pagecache_shared_map sm = (pagecache_shared_map)n;
    pagecache_debug("   map %p\n", sm);
    pagecache_scan_shared_map(bound(pc), sm);
}

void pagecache_node_scan_and_commit_shared_pages(pagecache_node pn, range q /* bytes */)
{
    pagecache_debug("%s: node %p, q %R\n", __func__, pn, q);
    rangemap_range_lookup(pn->shared_maps, q,
                          stack_closure(scan_shared_pages_intersection, pn->pv->pc));
    pagecache_commit_dirty_pages(pn->pv->pc);
}

boolean pagecache_node_do_page_cow(pagecache_node pn, u64 node_offset, u64 vaddr, u64 flags)
{
    pagecache_debug("%s: node %p, node_offset 0x%lx, vaddr 0x%lx, flags 0x%lx\n",
                    __func__, pn, node_offset, vaddr, flags);
    pagecache pc = pn->pv->pc;
    u64 paddr = allocate_u64(pc->physical, PAGESIZE);
    if (paddr == INVALID_PHYSICAL)
        return false;
    pagecache_lock_node(pn);
    pagecache_page pp = page_lookup_nodelocked(pn, node_offset >> pc->page_order);
    assert(pp != INVALID_ADDRESS);
    /* just overwrite old pte */
    assert(flags & PAGE_WRITABLE);
    map(vaddr, paddr, cache_pagesize(pc), flags);
    runtime_memcpy(pointer_from_u64(vaddr), pp->kvirt, cache_pagesize(pc));
    pagecache_unlock_node(pn);
    refcount_release(&pp->refcount);
    return true;
}

void pagecache_node_fetch_pages(pagecache_node pn, range r)
{
    pagecache_debug("%s: node %p, r %R\n", __func__, pn, r);
    pagecache pc = pn->pv->pc;
    merge m = allocate_merge(pc->h, ignore_status);
    status_handler sh = apply_merge(m);
    if (r.end > pn->length)
        r.end = pn->length;
    struct pagecache_page k;
    k.state_offset = r.start >> pc->page_order;
    u64 end = (r.end + MASK(pc->page_order)) >> pc->page_order;
    pagecache_lock_node(pn);
    pagecache_page pp = (pagecache_page)rbtree_lookup(&pn->pages, &k.rbnode);
    for (u64 pi = k.state_offset; pi < end; pi++) {
        if (pp == INVALID_ADDRESS || page_offset(pp) > pi) {
            pagecache_debug(" allocating page at index %ld\n", pi);
            pp = allocate_page_nodelocked(pn, pi);
            if (pp == INVALID_ADDRESS) {
                pagecache_debug(" cannot allocate page\n");
                break;
            }
        }
        touch_or_fill_page_nodelocked(pn, pp, m);
        pp = (pagecache_page)rbnode_get_next((rbnode)pp);
    }
    pagecache_unlock_node(pn);
    apply(sh, STATUS_OK);
}

static void map_page(pagecache pc, pagecache_page pp, u64 vaddr, u64 flags)
{
    map(vaddr, pp->phys, cache_pagesize(pc), flags);
}

closure_function(5, 1, void, map_page_finish,
                 pagecache, pc, pagecache_page, pp, u64, vaddr, u64, flags, status_handler, complete,
                 status, s)
{
    if (is_ok(s))
        map_page(bound(pc), bound(pp), bound(vaddr), bound(flags));
    apply(bound(complete), s);
    closure_finish();
}

void pagecache_map_page(pagecache_node pn, u64 node_offset, u64 vaddr, u64 flags,
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
    pagecache_unlock_node(pn);
    apply(k, STATUS_OK);
}

/* no-alloc / no-fill path, meant to be safe outside of kernel lock */
boolean pagecache_map_page_if_filled(pagecache_node pn, u64 node_offset, u64 vaddr, u64 flags)
{
    boolean mapped = false;
    pagecache_lock_node(pn);
    pagecache_page pp = page_lookup_nodelocked(pn, node_offset >> pn->pv->pc->page_order);
    pagecache_debug("%s: pn %p, node_offset 0x%lx, vaddr 0x%lx, flags 0x%lx, pp %p\n",
                    __func__, pn, node_offset, vaddr, flags, pp);
    if (pp == INVALID_ADDRESS)
        goto out;
    if (touch_or_fill_page_nodelocked(pn, pp, 0)) {
        mapped = true;
        map_page(pn->pv->pc, pp, vaddr, flags);
    }
  out:
    pagecache_unlock_node(pn);
    return mapped;
}

/* need to move these to x86-specific pc routines */
closure_function(3, 3, boolean, pagecache_unmap_page_nodelocked,
                 pagecache_node, pn, u64, vaddr_base, u64, node_offset,
                 int, level, u64, vaddr, u64 *, entry)
{
    u64 old_entry = *entry;
    if (pt_entry_is_present(old_entry) &&
        pt_entry_is_pte(level, old_entry)) {
        u64 pi = (bound(node_offset) + (vaddr - bound(vaddr_base))) >> PAGELOG;
        pagecache_debug("   vaddr 0x%lx, pi 0x%lx\n", vaddr, pi);
        *entry = 0;
        page_invalidate(vaddr, ignore);
        pagecache_page pp = page_lookup_nodelocked(bound(pn), pi);
        assert(pp != INVALID_ADDRESS);
        u64 phys = page_from_pte(old_entry);
        if (phys == pp->phys) {
            /* shared or cow */
            assert(pp->refcount.c > 1);
            refcount_release(&pp->refcount);
        } else {
            /* private copy */
            pagecache pc = bound(pn)->pv->pc;
            deallocate_u64(pc->physical, phys, cache_pagesize(pc));
        }
    }
    return true;
}

void pagecache_node_unmap_pages(pagecache_node pn, range v /* bytes */, u64 node_offset)
{
    pagecache_debug("%s: pn %p, v %R, node_offset 0x%lx\n", __func__, pn, v, node_offset);
    pagecache_node_close_shared_pages(pn, v);
    pagecache_lock_node(pn);
    traverse_ptes(v.start, range_span(v), stack_closure(pagecache_unmap_page_nodelocked, pn,
                                                        v.start, node_offset));
    pagecache_unlock_node(pn);
}
#endif

closure_function(1, 1, boolean, pagecache_page_print_key,
                 pagecache, pc,
                 rbnode, n)
{
    rprintf(" 0x%lx", page_offset((pagecache_page)n) << cache_pagesize(bound(pc)));
    return true;
}

closure_function(0, 2, int, pagecache_page_compare,
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

void pagecache_deallocate_node(pagecache_node pn)
{
    /* TODO: We probably need to add a refcount to the node with a
       reference for every page in the cache. This would need to:

       - prevent issuing of new operations
       - flush for node
       - drain all pages of this node from the cache
       - finally delete after the last refcount release

       For now, we're leaking nodes for files that get deleted and log
       extensions that get retired.
    */
}

sg_io pagecache_node_get_reader(pagecache_node pn)
{
    return pn->cache_read;
}

sg_io pagecache_node_get_writer(pagecache_node pn)
{
    return pn->cache_write;
}

pagecache_node pagecache_allocate_node(pagecache_volume pv, sg_io fs_read, sg_io fs_write)
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
    list_insert_before(&pv->nodes, &pn->l);
    init_rbtree(&pn->pages, closure(h, pagecache_page_compare),
                closure(h, pagecache_page_print_key, pv->pc));
    pn->length = 0;
    pn->cache_read = closure(h, pagecache_read_sg, pn);
#ifndef PAGECACHE_READ_ONLY
    pn->cache_write = closure(h, pagecache_write_sg, pn);
#else
    pn->cache_write = 0;
#endif
    pn->fs_read = fs_read;
    pn->fs_write = fs_write;
    return pn;
}

void *pagecache_get_zero_page(void)
{
    return global_pagecache->zero_page;
}

int pagecache_get_page_order()
{
    return global_pagecache->page_order;
}

pagecache_volume pagecache_allocate_volume(u64 length, int block_order)
{
    pagecache pc = global_pagecache;
    pagecache_volume pv = allocate(pc->h, sizeof(struct pagecache_volume));
    if (pv == INVALID_ADDRESS)
        return pv;
    pv->pc = pc;
    list_insert_before(&pc->volumes, &pv->l);
    list_init(&pv->nodes);
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
    if (pc->zero_page == INVALID_ADDRESS) {
        halt("failed to allocate zero page\n");
    }

#ifdef KERNEL
    spin_lock_init(&pc->state_lock);
#endif
    page_list_init(&pc->free);
    page_list_init(&pc->new);
    page_list_init(&pc->active);
    page_list_init(&pc->writing);
    page_list_init(&pc->dirty);
    list_init(&pc->volumes);
    list_init(&pc->shared_maps);

#ifdef STAGE3
    pc->completion_vecs = allocate_queue(general, MAX_PAGE_COMPLETION_VECS);
    assert(pc->completion_vecs != INVALID_ADDRESS);
    pc->service_completions = closure(general, pagecache_service_completions, pc);
    pc->service_enqueued = false;
    pc->scan_in_progress = false;
    pc->scan_timer = 0;
    init_closure(&pc->do_scan_timer, pagecache_scan_timer, pc);
#endif
    global_pagecache = pc;
}
