/* TODO:
   - keep refault stats
   - interface to physical free page list / shootdown epochs

   - would be nice to propagate a priority alone with requests to
     pagecache - which in turn would be passed to page I/O - so that
     page fault fills can go to head of request queue
*/

#include <kernel.h>
#include <dma.h>
#include <errno.h>
#include <pagecache.h>
#include <pagecache_internal.h>
#include <tfs.h>

#if defined(PAGECACHE_DEBUG)
#define pagecache_debug(x, ...) do {tprintf(sym(pagecache), 0, ss(x), ##__VA_ARGS__);} while(0)
#else
#define pagecache_debug(x, ...)
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

static inline void pagecache_lock(pagecache pc)
{
    spin_lock(&pc->global_lock);
}

static inline void pagecache_unlock(pagecache pc)
{
    spin_unlock(&pc->global_lock);
}

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

static inline boolean pagecache_trylock_node(pagecache_node pn)
{
    return spin_try(&pn->pages_lock);
}

static inline void pagecache_unlock_node(pagecache_node pn)
{
    spin_unlock(&pn->pages_lock);
}

closure_type(pp_handler, boolean, pagecache_page pp);

static inline void change_page_state_locked(pagecache pc, pagecache_page pp, int state)
{
    int old_state = page_state(pp);
    switch (state) {
    case PAGECACHE_PAGESTATE_FREE:
        if (old_state == PAGECACHE_PAGESTATE_NEW) {
            pagelist_move(&pc->free, &pc->new, pp);
        } else if (old_state == PAGECACHE_PAGESTATE_ACTIVE) {
            pagelist_move(&pc->free, &pc->active, pp);
        } else {
            assert(old_state == PAGECACHE_PAGESTATE_ALLOC);
            pagelist_enqueue(&pc->free, pp);
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
        } else if (old_state == PAGECACHE_PAGESTATE_WRITING) {
            pagelist_remove(&pc->writing, pp);
        }
        if (old_state != PAGECACHE_PAGESTATE_WRITING)
            refcount_reserve(&pp->node->refcount);
        break;
    default:
        halt("%s: bad state %d, old %d\n", func_ss, state, old_state);
    }

    pp->state_offset = (pp->state_offset & MASK(PAGECACHE_PAGESTATE_SHIFT)) |
        ((u64)state << PAGECACHE_PAGESTATE_SHIFT);
}

static void pagecache_page_queue_completions_locked(pagecache pc, pagecache_page pp, status s)
{
    list_foreach(&pp->bh_completions, l) {
        page_completion c = struct_from_list(l, page_completion, l);
        assert(c->sh != INVALID_ADDRESS && c->sh != 0);
        s = timm_clone(s);
        async_apply_status_handler(c->sh, s);
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
    pagecache_debug("%s: pc %p pp %p refcount %d state %d\n", func_ss, pc, pp, pp->refcount,
                    page_state(pp));
    pp->kvirt = allocate(pc->contiguous, U64_FROM_BIT(pc->page_order));
    if (pp->kvirt == INVALID_ADDRESS) {
        return false;
    }
    assert(pp->refcount++ == 0);
    pp->write_count = 0;
    pp->phys = physical_from_virtual(pp->kvirt);
    fetch_and_add(&pc->total_pages, 1);
    change_page_state_locked(pc, pp, PAGECACHE_PAGESTATE_ALLOC);
    pp->evicted = false;
    return true;
}

static sg_buf pagecache_add_sgb(pagecache_page pp, sg_list sg, u64 size)
{
    sg_buf sgb = sg_list_tail_add(sg, size);
    if (sgb != INVALID_ADDRESS) {
        sgb->buf = pp->kvirt;
        sgb->size = size;
        sgb->offset = 0;
        sgb->refcount = 0;
    }
    return sgb;
}

/* Returns true if the page is already cached (or is being fetched from disk), false if a disk read
 * needs to be requested to fetch the page (or re-allocation of a freed page failed). */
static boolean touch_page_locked(pagecache_node pn, pagecache_page pp, merge m)
{
    pagecache_volume pv = pn->pv;
    pagecache pc = pv->pc;

    pagecache_debug("%s: pn %p, pp %p, m %p, state %d\n", func_ss, pn, pp, m, page_state(pp));
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

closure_function(3, 1, void, pagecache_read_page_complete,
                 pagecache, pc, pagecache_page, pp, sg_list, sg,
                 status s)
{
    pagecache pc = bound(pc);
    pagecache_page pp = bound(pp);
    assert(page_state(pp) == PAGECACHE_PAGESTATE_READING);

    if (!is_ok(s)) {
        /* TODO need policy for capturing/reporting I/O errors... */
        msg_err("pagecache: error reading page 0x%lx: %v", page_offset(pp) << pc->page_order, s);
    }
    pagecache_lock_state(pc);
    change_page_state_locked(bound(pc), pp, PAGECACHE_PAGESTATE_NEW);
    pagecache_page_queue_completions_locked(pc, pp, s);
    pagecache_unlock_state(pc);
    timm_dealloc(s);
    sg_list_release(bound(sg));
    deallocate_sg_list(bound(sg));
    closure_finish();
}

/* The page refcount is incremented (unless the page is not filled and either a read request is not
 * ongoing, or the merge argument is null). */
static boolean touch_or_fill_page_nodelocked(pagecache_node pn, pagecache_page pp, merge m)
{
    pagecache_volume pv = pn->pv;
    pagecache pc = pv->pc;
    range r;

    pagecache_lock_state(pc);
    pagecache_debug("%s: pn %p, pp %p, m %p, state %d\n", func_ss, pn, pp, m, page_state(pp));
    switch (page_state(pp)) {
    case PAGECACHE_PAGESTATE_READING:
        if (m) {
            enqueue_page_completion_statelocked(pc, pp, apply_merge(m));
            pp->refcount++;
        }
        pagecache_unlock_state(pc);
        return false;
    case PAGECACHE_PAGESTATE_FREE:
        if (!realloc_pagelocked(pc, pp)) {
            if (m)
                apply(apply_merge(m), timm("result", "failed to reallocate pagecache_page"));
            pagecache_unlock_state(pc);
            return false;
        }
        /* fall through */
    case PAGECACHE_PAGESTATE_ALLOC:
        if (m) {
            r = range_intersection(byte_range_from_page(pc, pp),
                                   irangel(0, pad(pn->length, U64_FROM_BIT(pv->block_order))));
            if (range_span(r)) {
                enqueue_page_completion_statelocked(pc, pp, apply_merge(m));
                change_page_state_locked(pc, pp, PAGECACHE_PAGESTATE_READING);
            } else {
                zero(pp->kvirt, cache_pagesize(pc));
                change_page_state_locked(pc, pp, PAGECACHE_PAGESTATE_NEW);
            }
            pp->refcount++;
        }
        pagecache_unlock_state(pc);

        if (m) {
            if (range_span(r) == 0)
                return true;

            /* issue page reads */
            pagecache_debug("   pc %p, pp %p, r %R, reading...\n", pc, pp, r);
            sg_list sg = allocate_sg_list();
            assert(sg != INVALID_ADDRESS);
            u64 read_size = range_span(r);
            if (read_size < cache_pagesize(pc))
                zero(pp->kvirt + read_size, cache_pagesize(pc) - read_size);
            assert(pagecache_add_sgb(pp, sg, read_size) != INVALID_ADDRESS);
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
        halt("%s: invalid state %d\n", func_ss, page_state(pp));
    }
    pp->refcount++;
    pagecache_unlock_state(pc);
    return true;
}

static void pagecache_page_delete_locked(pagecache pc, pagecache_page pp)
{
    pagecache_node pn = pp->node;

    /* Don't lock the node unconditionally, to avoid deadlock if another thread is trying to
     * acquire the pagecache lock after locking the node. */
    if (!pagecache_trylock_node(pn))
        return;

    rbtree_remove_node(&pn->pages, &pp->rbnode);
    pagecache_unlock_node(pn);
    pagelist_remove(&pc->free, pp);
    deallocate(pc->pp_heap, pp, sizeof(*pp));
}

static void pagecache_page_release_locked(pagecache pc, pagecache_page pp, boolean full_delete)
{
    if (--pp->refcount > 0)
        return;
    pagecache_debug("%s: pp %p state %d\n", func_ss, pp, page_state(pp));
    assert(pp->write_count == 0);
    assert(pp->read_refcount.c == 0);

    change_page_state_locked(pc, pp, PAGECACHE_PAGESTATE_FREE);
    deallocate(pc->contiguous, pp->kvirt, cache_pagesize(pc));
    pp->kvirt = INVALID_ADDRESS;
    pp->phys = INVALID_PHYSICAL;
    u64 pre = fetch_and_add(&pc->total_pages, -1);
    assert(pre > 0);
    pagecache_debug("%s: total pages now %ld\n", func_ss, pre - 1);
    if (full_delete)
        pagecache_page_delete_locked(pc, pp);
}

closure_func_basic(thunk, void, pagecache_page_read_release)
{
    pagecache pc = global_pagecache;
    pagecache_page pp = struct_from_closure(pagecache_page, read_release);
    pagecache_lock_state(pc);
    pagecache_page_release_locked(pc, pp, true);
    pagecache_unlock_state(pc);
}

static pagecache_page allocate_page_nodelocked(pagecache_node pn, u64 offset)
{
    /* allocate - later we can look at blocks of pages at a time */
    pagecache pc = pn->pv->pc;
    u64 pagesize = U64_FROM_BIT(pc->page_order);
    void *p = allocate(pc->contiguous, pagesize);
    if (p == INVALID_ADDRESS)
        return INVALID_ADDRESS;

    pagecache_page pp = allocate(pc->pp_heap, sizeof(struct pagecache_page));
    if (pp == INVALID_ADDRESS)
        goto fail_dealloc_contiguous;

    init_rbnode(&pp->rbnode);
    pp->refcount = 1;
    init_refcount(&pp->read_refcount, 0,
                  init_closure_func(&pp->read_release, thunk, pagecache_page_read_release));
    assert((offset >> PAGECACHE_PAGESTATE_SHIFT) == 0);
    pp->state_offset = ((u64)PAGECACHE_PAGESTATE_ALLOC << PAGECACHE_PAGESTATE_SHIFT) | offset;
    pp->write_count = 0;
    pp->kvirt = p;
    pp->node = pn;
    pp->l.next = pp->l.prev = 0;
    pp->evicted = false;
    pp->phys = physical_from_virtual(p);
    list_init(&pp->bh_completions);
    assert(rbtree_insert_node(&pn->pages, &pp->rbnode));
    fetch_and_add(&pc->total_pages, 1); /* decrement happens without cache lock */
    return pp;
  fail_dealloc_contiguous:
    deallocate(pc->contiguous, p, pagesize);
    return INVALID_ADDRESS;
}

static u64 evict_from_list_locked(pagecache pc, struct pagelist *pl, u64 pages)
{
    u64 evicted = 0;
    list_foreach(&pl->l, l) {
        if (evicted >= pages)
            break;

        pagecache_page pp = struct_from_list(l, pagecache_page, l);
        if (pp->evicted)
            continue;
        assert(pp->refcount != 0);
        pagecache_debug("%s: list %s, release pp %p - %R, state %d, count %ld\n", func_ss,
                        pl == &pc->new ? ss("new") : ss("active"), pp, byte_range_from_page(pc, pp),
                        page_state(pp), pp->refcount);
        pp->evicted = true;
        if (pp->refcount == 1)
            evicted++;
        pagecache_page_release_locked(pc, pp, true);
    }
    return evicted;
}

static void balance_page_lists_locked(pagecache pc)
{
    /* balance active and new lists */
    s64 dp = ((s64)pc->active.pages - (s64)pc->new.pages) / 2;
    pagecache_debug("%s: active %ld, new %ld, dp %ld\n", func_ss, pc->active.pages, pc->new.pages,
                    dp);
    list_foreach(&pc->active.l, l) {
        if (dp <= 0)
            break;
        pagecache_page pp = struct_from_list(l, pagecache_page, l);
        /* We don't presently have a notion of "time" in the cache, so
           just cull unreferenced buffers in LRU fashion until active
           pages are equivalent to new...loosely inspired by linux
           approach. */
        if (pp->refcount == 1) {
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
    if (pp == INVALID_ADDRESS)
        pp = allocate_page_nodelocked(pn, n);
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

static void pagecache_nodelocked_traverse(pagecache_node pn, range pages,
                                          pp_handler handler)
{
    if (range_span(pages) == 0)
        return;
    pagecache_page pp = page_lookup_nodelocked(pn, pages.start);
    pagecache_lock_state(global_pagecache);
    while (true) {
        apply(handler, pp);
        if (++pages.start == pages.end)
            break;
        pp = (pagecache_page)rbnode_get_next((rbnode)pp);
    }
    pagecache_unlock_state(global_pagecache);
}

static void pagecache_node_traverse(pagecache_node pn, range pages, pp_handler handler)
{
    pagecache_lock_node(pn);
    pagecache_nodelocked_traverse(pn, pages, handler);
    pagecache_unlock_node(pn);
}

closure_function(6, 1, void, pagecache_write_sg_finish,
                 pagecache_node, pn, range, q, u64, pi, sg_list, sg, status_handler, completion, context, saved_ctx,
                 status s)
{
    pagecache_node pn = bound(pn);
    pagecache pc = pn->pv->pc;
    range q = bound(q);
    int page_order = pc->page_order;
    int block_order = pn->pv->block_order;
    u64 end = (q.end + MASK(pc->page_order)) >> page_order;
    sg_list sg = bound(sg);
    status_handler completion = bound(completion);

    pagecache_debug("%s: pn %p, q %R, sg %p, status %v\n", func_ss, pn, q, sg, s);
    u64 offset = (bound(pi) == (q.start >> page_order)) ? (q.start & MASK(page_order)) : 0;
    context saved_ctx = 0;
    if (is_ok(s) && sg) {
        /* Prevent page faults while spinlocks are held */
        saved_ctx = bound(saved_ctx);
        use_fault_handler(saved_ctx->fault_handler);
        if (!sg_fault_in(sg, q.end - (bound(pi) << page_order) - offset)) {
            s = timm("result", "invalid user memory");
            s = timm_append(s, "fsstatus", "%d", -EFAULT);
            clear_fault_handler();
        }
    }
    if (!is_ok(s)) {
        pagecache_lock_node(pn);
        pagecache_lock_state(pc);
        for (int i = bound(pi); i < end; i++)  {
            pagecache_page pp = page_lookup_nodelocked(pn, i);
            if (pp != INVALID_ADDRESS)
                pagecache_page_release_locked(pc, pp, false);
        }
        pagecache_unlock_state(pc);
        pagecache_unlock_node(pn);
        if (sg)
            sg_list_release(sg);
        goto exit;
    }

    /* copy data to the page cache */
    range r = irange(q.start & ~MASK(block_order), q.end);
    pagecache_lock_node(pn);
    pagecache_page pp = page_lookup_nodelocked(pn, bound(pi));
    do {
        assert(pp != INVALID_ADDRESS && page_offset(pp) == bound(pi));
        u64 copy_len = MIN(q.end - (bound(pi) << page_order), cache_pagesize(pc)) - offset;
        pagecache_lock_state(pc);
        if (page_state(pp) == PAGECACHE_PAGESTATE_READING) {
            /* A read request occurred in the middle of this write: postpone the completion of this
             * write so that the data being written will overwrite the data fetched by the read
             * request. */
            enqueue_page_completion_statelocked(pc, pp, (status_handler)closure_self());
            pagecache_unlock_state(pc);
            break;
        }
        if (sg) {
            u64 res = sg_copy_to_buf(pp->kvirt + offset, sg, copy_len);
            assert(res == copy_len);
        } else {
            zero(pp->kvirt + offset, copy_len);
        }
        if (page_state(pp) != PAGECACHE_PAGESTATE_DIRTY)
            /* Don't release the page, otherwise if it has been marked for eviction it will be
             * evicted while still dirty. */
            change_page_state_locked(pc, pp, PAGECACHE_PAGESTATE_DIRTY);
        else
            pagecache_page_release_locked(pc, pp, false);
        pagecache_unlock_state(pc);
        offset = 0;
        bound(pi)++;
        pp = (pagecache_page)rbnode_get_next((rbnode)pp);
    } while (bound(pi) < end);
    if ((bound(pi) == end) && !pagecache_set_dirty(pn, r))
        s = timm("result", "failed to add dirty range");
    pagecache_unlock_node(pn);
    if (saved_ctx)
        clear_fault_handler();
    if (bound(pi) < end)
        return;
  exit:
    closure_finish();
    async_apply_status_handler(completion, s);
}

closure_function(4, 1, void, pagecache_write_sg_next,
                 sg_io, write, sg_list, sg, range, q, status_handler, completion,
                 status s)
{
    status_handler completion = bound(completion);
    pagecache_debug("%s: completion %F, status %v\n", func_ss, completion, s);
    if (s == STATUS_OK)
        apply(bound(write), bound(sg), bound(q), completion);
    else
        apply(completion, s);
    closure_finish();
}

closure_function(1, 3, void, pagecache_write_sg,
                 pagecache_node, pn,
                 sg_list sg, range q, status_handler completion)
{
    pagecache_node pn = bound(pn);
    pagecache_volume pv = pn->pv;
    pagecache pc = pv->pc;
    pagecache_debug("%s: node %p, q %R, sg %p, completion %F, from %p\n", func_ss,
                    pn, q, sg, completion, __builtin_return_address(0));

    if (range_span(q) == 0) {
        apply(completion, STATUS_OK);
        return;
    }

    u64 start_offset = q.start & MASK(pc->page_order);
    u64 end_offset = q.end & MASK(pc->page_order);
    range r = range_rshift(q, pc->page_order);
    /* attempt to reserve disk space for the write */
    if (pn->fs_reserve && sg) {
        status ss;
        if ((ss = apply(pn->fs_reserve, q)) != STATUS_OK) {
            apply(completion, ss);
            return;
        }
    }

    context ctx;
    ctx = get_current_context(current_cpu());

    /* prepare pages for writing */
    status_handler finish = closure(pc->h, pagecache_write_sg_finish, pn, q,
                                    q.start >> pc->page_order, sg, completion, ctx);
    if (finish == INVALID_ADDRESS) {
        apply(completion, timm("result", "failed to allocate finish closure"));
        return;
    }
    merge m = allocate_merge(pc->h, finish);
    status_handler sh = apply_merge(m);
    pagecache_lock_node(pn);

    /* initiate reads for rmw start and/or end */
    if (start_offset != 0) {
        touch_or_fill_page_by_num_nodelocked(pn, q.start >> pc->page_order, m);
        r.start++;
    }
    if (end_offset != 0) {
        if ((q.end < pn->length) && /* tail rmw */
                !((q.start & ~MASK(pc->page_order)) ==
                  (q.end & ~MASK(pc->page_order)) && start_offset != 0) /* no double fill */)
            touch_or_fill_page_by_num_nodelocked(pn, q.end >> pc->page_order, m);
        else
            r.end++;
    }

    /* prepare whole pages, blocking for any pending reads */
    u64 pi;
    sstring err_msg;
    boolean mem_cleaned = false;
  begin:
    err_msg = sstring_null();
    for (pi = r.start; pi < r.end; pi++) {
        pagecache_page pp = page_lookup_nodelocked(pn, pi);
        if (pp == INVALID_ADDRESS) {
            pp = allocate_page_nodelocked(pn, pi);
            if (pp == INVALID_ADDRESS) {
                err_msg = ss("failed to allocate pagecache_page");
                break;
            }

            /* When writing a new page at the end of a node whose length is not page-aligned, zero
               the remaining portion of the page. The filesystem will depend on this to properly
               implement file holes. */
            range i = range_intersection(byte_range_from_page(pc, pp), q);
            u64 page_offset = i.end & MASK(pc->page_order);
            if (page_offset) {
                u64 len = U64_FROM_BIT(pc->page_order) - page_offset;
                pagecache_debug("   zero unaligned end, i %R, page offset 0x%lx, len 0x%lx\n",
                                i, page_offset, len);
                zero(pp->kvirt + page_offset, len);
            }
        }
        pagecache_lock_state(pc);
        if ((page_state(pp) == PAGECACHE_PAGESTATE_FREE) && !realloc_pagelocked(pc, pp)) {
            pagecache_unlock_state(pc);
            err_msg = ss("failed to re-allocate pagecache page");
            break;
        }
        pp->refcount++;
        if (page_state(pp) == PAGECACHE_PAGESTATE_READING)
            enqueue_page_completion_statelocked(pc, pp, apply_merge(m));
        pagecache_unlock_state(pc);
    }

    /* extend node length if writing past current end */
    if (q.end > pn->length)
        pn->length = q.end;

    pagecache_unlock_node(pn);
    if (!sstring_is_null(err_msg)) {
        if (!mem_cleaned || (pi != r.start)) {
            pagecache_debug("   trying to free memory (r %R, pi 0x%lx)\n", r, pi);
            mm_service(true);
            mem_cleaned = true;
            r.start = pi;
            pagecache_lock_node(pn);
            goto begin;
        }
        start_offset = (pi << pc->page_order) - q.start;
        if (start_offset > 0) {
            /* Write pages processed so far, then process remaining pages. */
            status_handler write_next = closure_from_context(ctx, pagecache_write_sg_next,
                                                             (sg_io)closure_self(), sg,
                                                             irange(q.start + start_offset, q.end),
                                                             completion);
            if (write_next != INVALID_ADDRESS) {
                closure_member(pagecache_write_sg_finish, finish, q) = irangel(q.start,
                                                                               start_offset);
                closure_member(pagecache_write_sg_finish, finish, completion) = write_next;
                err_msg = sstring_null();
            }
        }
    }
    apply(sh, sstring_is_null(err_msg) ? STATUS_OK : timm_sstring(ss("result"), err_msg));
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
    return evicted;
}

static void pagecache_delete_pages_locked(pagecache pc)
{
    list_foreach(&pc->free.l, l) {
        pagecache_page_delete_locked(pc, struct_from_list(l, pagecache_page, l));
    }
}

u64 pagecache_drain(u64 drain_bytes)
{
    pagecache pc = global_pagecache;
    u64 pages = pad(drain_bytes, cache_pagesize(pc)) >> pc->page_order;

    pagecache_lock_state(pc);
    u64 drained = evict_pages_locked(pc, pages) * cache_pagesize(pc);
    balance_page_lists_locked(pc);
    if (drained < drain_bytes)
        pagecache_delete_pages_locked(pc);
    pagecache_unlock_state(pc);
    if (drained < drain_bytes)
        drained += cache_drain((caching_heap)pc->pp_heap, drain_bytes - drained,
                               PAGECACHE_PAGES_RETAIN * sizeof(struct pagecache_page));
    if (drained < drain_bytes)
        drained += cache_drain((caching_heap)pc->completions, drain_bytes - drained,
                               PAGECACHE_COMPLETIONS_RETAIN * sizeof(struct page_completion));
    return drained;
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
    async_apply_status_handler(complete, STATUS_OK);
}

static void pagecache_scan_shared_mappings(pagecache pc);
static void pagecache_scan_node(pagecache_node pn);

closure_function(5, 1, void, pagecache_commit_complete,
                 pagecache, pc, pagecache_page, first_page, u64, page_count, sg_list, sg, status_handler, sh,
                 status s)
{
    pagecache pc = bound(pc);
    pagecache_page pp = bound(first_page);
    sg_list sg = bound(sg);
    pagecache_debug("%s: pp %p, s %v\n", func_ss, pp, s);
    u64 page_count = bound(page_count);
    pagecache_node pn = pp->node;
    range r = range_lshift(irangel(page_offset(pp), page_count), pc->page_order);
    pagecache_lock_node(pn);
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

        /* release the page, unless its state has been set back to DIRTY due to a write error */
        if (is_ok(s) || (page_state(pp) != PAGECACHE_PAGESTATE_DIRTY))
            pagecache_page_release_locked(pc, pp, false);

        pp = (pagecache_page)rbnode_get_next((rbnode)pp);
    } while (--page_count > 0);
    pagecache_unlock_state(pc);
    if (!is_ok(s))
        pagecache_set_dirty(pn, r);
    pagecache_unlock_node(pn);
    deallocate_sg_list(sg);
    async_apply_status_handler(bound(sh), s);
    closure_finish();
}

static void commit_dirty_node_complete(pagecache_node pn, status_handler complete,
                 status s)
{
    status_handler next = INVALID_ADDRESS;
    pagecache_lock_node(pn);
    list_delete(list_begin(&pn->ops));  /* remove the commit operation that just completed */
    while (!list_empty(&pn->ops)) {
        struct pagecache_node_op_common *op = struct_from_field(list_begin(&pn->ops),
                                                                struct pagecache_node_op_common *,
                                                                l);
        if (op->type == PAGECACHE_NODE_OP_COMMIT) {
            next = (status_handler)&((struct pagecache_node_op_commit *)op)->commit;
            break;
        } else {    /* completion */
            list_delete(&op->l);
            pagecache_unlock_node(pn);
            struct pagecache_node_op_complete *c = (struct pagecache_node_op_complete *)op;
            apply(c->sh, timm_clone(s));
            deallocate(pn->pv->pc->h, c, sizeof(*c));
            pagecache_lock_node(pn);
        }
    }
    pagecache_unlock_node(pn);
    if (next != INVALID_ADDRESS)
        apply(next, STATUS_OK);
    if (complete)
        async_apply_status_handler(complete, s);
    else if (!is_ok(s))
        timm_dealloc(s);
}

define_closure_function(3, 1, void, pagecache_commit_dirty_ranges,
                        pagecache_node, pn, buffer, dirty, status_handler, complete,
                        status s)
{
    pagecache_node pn = bound(pn);
    buffer dirty = bound(dirty);
    pagecache_volume pv = pn->pv;
    pagecache pc = pv->pc;

    if (!is_ok(s)) {
        pagecache_lock_node(pn);
        while (buffer_length(dirty) > 0) {
            pagecache_set_dirty(pn, *(range *)buffer_ref(dirty, 0));
            buffer_consume(dirty, sizeof(range));
        }
        pagecache_unlock_node(pn);
    }
    if (buffer_length(dirty) == 0) {
        deallocate_buffer(dirty);
        commit_dirty_node_complete(pn, bound(complete), s);
        struct pagecache_node_op_commit *op = struct_from_field(closure_self(),
                                                                struct pagecache_node_op_commit *,
                                                                commit);
        deallocate(pc->h, op, sizeof(*op));
        return;
    }

    merge m = allocate_merge(pc->h, (status_handler)closure_self());
    status_handler sh = apply_merge(m);
    u64 committing = 0;
    pagecache_lock_node(pn);
    u64 limit = pn->length;
    while (buffer_length(dirty) > 0 && committing < PAGECACHE_MAX_SG_ENTRIES) {
        range *rp = buffer_ref(dirty, 0);
        if (rp->start >= limit) {
            buffer_consume(dirty, sizeof(range));
            continue;
        }
        rp->end = MIN(rp->end, limit);
        sg_list sg = allocate_sg_list();
        if (sg == INVALID_ADDRESS) {
            msg_err("%s: unable to allocate sg list", func_ss);
            if (committing == 0)
                s = timm("result", "unable to allocate sg list");
            break;
        }
        u64 start = rp->start;
        pagecache_page first_page = page_lookup_nodelocked(pn, start >> pc->page_order);
        u64 page_count = 0;
        pagecache_page pp = first_page;
        range r = *rp;
        sg_buf sgb = 0;

        do {
            u64 page_offset = start & MASK(pc->page_order);
            u64 len = pad(MIN(cache_pagesize(pc) - page_offset, r.end - start),
                          U64_FROM_BIT(pv->block_order));
            if (sgb && (sgb->buf + sgb->size == pp->kvirt)) {
                sgb->size += len;
                sg->count += len;
            } else {
                sgb = sg_list_tail_add(sg, len);
                if (sgb == INVALID_ADDRESS) {
                    msg_warn("%s: sgbuf alloc fail", func_ss);
                    if (committing == 0)
                        s = timm("result", "unable to allocate sg buffer");
                    r.end = start;
                    break;
                }
                sgb->buf = pp->kvirt + page_offset;
                sgb->offset = 0;
                sgb->size = len;
                sgb->refcount = 0;
                committing++;
            }
            pagecache_lock_state(pc);
            /* Reserve the page, unless it is in DIRTY state (in which case it has been reserved
             * when switching to DIRTY state). */
            if (page_state(pp) != PAGECACHE_PAGESTATE_DIRTY)
                pp->refcount++;
            change_page_state_locked(pc, pp, PAGECACHE_PAGESTATE_WRITING);
            pp->write_count++;
            pagecache_unlock_state(pc);
            page_count++;
            start += len;
            pp = (pagecache_page)rbnode_get_next((rbnode)pp);
            if (committing >= PAGECACHE_MAX_SG_ENTRIES && start < r.end) {
                r.end = start;
                break;
            }
        } while (start < r.end);
        if (start >= rp->end)
            buffer_consume(dirty, sizeof(range));
        else
            rp->start = start;
        if (range_span(r) == 0)
            break;
        apply(pn->fs_write, sg, r,
              closure(pc->h, pagecache_commit_complete, pc, first_page, page_count, sg, apply_merge(m)));
    }
    pagecache_unlock_node(pn);
    apply(sh, s);
}

closure_function(2, 1, boolean, dirty_range_handler,
                 rangemap, rm, buffer, b,
                 rmnode n)
{
    buffer b = bound(b);
    assert(buffer_write(b, &n->r, sizeof(n->r)));
    rangemap_remove_range(bound(rm), n);
    return true;
}

static void pagecache_commit_dirty_node(pagecache_node pn, status_handler complete)
{
    pagecache_debug("committing dirty node %p\n", pn);
    pagecache_lock_node(pn);
    heap h = pn->pv->pc->h;
    status_handler sh;
    u64 range_count = rangemap_count(&pn->dirty);
    boolean busy = !list_empty(&pn->ops);
    if (range_count != 0) {
        buffer b = allocate_buffer(h, range_count * sizeof(range));
        if (b == INVALID_ADDRESS)
            goto oom;
        struct pagecache_node_op_commit *op = allocate(h, sizeof(*op));
        if (op == INVALID_ADDRESS) {
            deallocate_buffer(b);
            goto oom;
        }
        rangemap_range_lookup(&pn->dirty, irange(0, infinity),
                              stack_closure(dirty_range_handler, &pn->dirty, b));
        op->common.type = PAGECACHE_NODE_OP_COMMIT;
        list_push_back(&pn->ops, &op->common.l);
        sh = init_closure(&op->commit, pagecache_commit_dirty_ranges, pn, b, complete);
    } else if ((sh = complete) && busy) {
        struct pagecache_node_op_complete *op = allocate(h, sizeof(*op));
        if (op == INVALID_ADDRESS)
            goto oom;
        op->common.type = PAGECACHE_NODE_OP_COMPLETE;
        op->sh = complete;
        list_push_back(&pn->ops, &op->common.l);
    }
    pagecache_lock_volume(pn->pv);
    if (list_inserted(&pn->l))
        list_delete(&pn->l);
    pagecache_unlock_volume(pn->pv);
    pagecache_unlock_node(pn);
    if (!busy && sh)
        apply(sh, STATUS_OK);
    return;
  oom:
    pagecache_unlock_node(pn);
    if (complete)
        apply(complete, timm_oom);
}

static void pagecache_commit_dirty_pages(pagecache pc)
{
    pagecache_debug("%s\n", func_ss);

    pagecache_lock(pc);
    list_foreach(&pc->volumes, l) {
        pagecache_volume pv = struct_from_list(l, pagecache_volume, l);
        pagecache_node pn = 0;
        do {
            pagecache_lock_volume(pv);
            list l = list_get_next(&pv->dirty_nodes);
            pagecache_unlock_volume(pv);
            if (l) {
                pn = struct_from_list(l, pagecache_node, l);
                pagecache_commit_dirty_node(pn, 0);
            } else {
                pn = 0;
            }
        } while (pn);
    }
    pagecache_unlock(pc);
}

static void pagecache_scan(pagecache pc)
{
    pagecache_scan_shared_mappings(pc);
    pagecache_commit_dirty_pages(pc);
}

void pagecache_sync_volume(pagecache_volume pv, status_handler complete)
{
    pagecache_debug("%s: pv %p, complete %p (%F)\n", func_ss, pv, complete, complete);
    pagecache_scan(pv->pc);         /* commit dirty pages */
    pagecache_finish_pending_writes(pv->pc, pv, 0, complete);
}

/* not quite sync; the caller takes care of committing dirty pages */
void pagecache_node_finish_pending_writes(pagecache_node pn, status_handler complete)
{
    pagecache_debug("%s: pn %p, complete %p (%F)\n", func_ss, pn, complete, complete);
    pagecache_finish_pending_writes(pn->pv->pc, 0, pn, complete);
}

void pagecache_sync_node(pagecache_node pn, status_handler complete)
{
    pagecache_debug("%s: pn %p, complete %p (%F)\n", func_ss, pn, complete, complete);
    pagecache_scan_node(pn);
    pagecache_commit_dirty_node(pn, complete);
}

closure_function(1, 1, boolean, purge_range_handler,
                 pagecache_node, pn,
                 rmnode n)
{
    pagecache_node pn = bound(pn);
    pagecache pc = pn->pv->pc;
    int page_order = pc->page_order;
    u64 page_size = U64_FROM_BIT(page_order);
    u64 node_offset = n->r.start;
    pagecache_page pp = page_lookup_nodelocked(pn, node_offset >> page_order);
    do {
        if (page_state(pp) == PAGECACHE_PAGESTATE_DIRTY) {
            change_page_state_locked(pc, pp, PAGECACHE_PAGESTATE_ALLOC);
            pagecache_page_release_locked(pc, pp, false);
            refcount_release(&pn->refcount);
        }
        node_offset += page_size;
        pp = (pagecache_page)rbnode_get_next((rbnode)pp);
    } while (node_offset < n->r.end);
    rangemap_remove_range(&pn->dirty, n);
    return true;
}

/* Wait for completion of in-progress writes to disk, discard any other dirty ranges, then call
 * status handler. */
void pagecache_purge_node(pagecache_node pn, status_handler complete)
{
    pagecache_debug("%s: pn %p, complete %F\n", func_ss, pn, complete);
    pagecache_lock_node(pn);
    pagecache pc = pn->pv->pc;
    pagecache_lock_state(pc);
    destruct_rangemap(&pn->dirty, stack_closure(purge_range_handler, pn));
    pagecache_unlock_state(pc);
    pagecache_lock_volume(pn->pv);
    if (list_inserted(&pn->l))
        list_delete(&pn->l);
    pagecache_unlock_volume(pn->pv);
    boolean busy = !list_empty(&pn->ops);
    status s;
    if (busy && complete) {
        struct pagecache_node_op_complete *op = allocate(pc->h, sizeof(*op));
        if (op != INVALID_ADDRESS) {
            op->common.type = PAGECACHE_NODE_OP_COMPLETE;
            op->sh = complete;
            list_push_back(&pn->ops, &op->common.l);
            complete = 0;
        } else {
            s = timm_oom;
        }
    } else {
        s = STATUS_OK;
    }
    pagecache_unlock_node(pn);
    if (complete)
        apply(complete, s);
}

void pagecache_node_ref(pagecache_node pn)
{
    refcount_reserve(&pn->refcount);
}

void pagecache_node_unref(pagecache_node pn)
{
    refcount_release(&pn->refcount);
}

closure_func_basic(pp_handler, boolean, pagecache_pin_handler,
                   pagecache_page pp)
{
    pp->refcount++;
    return true;
}

void pagecache_nodelocked_pin(pagecache_node pn, range pages)
{
    pagecache_nodelocked_traverse(pn, pages, stack_closure_func(pp_handler, pagecache_pin_handler));
}

closure_func_basic(pp_handler, boolean, pagecache_unpin_handler,
                   pagecache_page pp)
{
    pagecache_page_release_locked(global_pagecache, pp, false);
    return true;
}

void pagecache_node_unpin(pagecache_node pn, range pages)
{
    pagecache_node_traverse(pn, pages, stack_closure_func(pp_handler, pagecache_unpin_handler));
}

closure_function(5, 1, void, pagecache_node_fetch_complete,
                 pagecache, pc, pagecache_page, first_page, u64, page_count, sg_list, sg, status_handler, complete,
                 status s)
{
    pagecache pc = bound(pc);
    pagecache_page pp = bound(first_page);
    u64 page_count = bound(page_count);
    sg_list sg = bound(sg);
    pagecache_debug("%s: page count %ld, status %v\n", func_ss, page_count, s);
    pagecache_lock_state(pc);
    while (page_count-- > 0) {
        change_page_state_locked(pc, pp,
            is_ok(s) ? PAGECACHE_PAGESTATE_NEW : PAGECACHE_PAGESTATE_ALLOC);
        pagecache_page_queue_completions_locked(pc, pp, s);
        pagecache_page_release_locked(pc, pp, false);
        pp = (pagecache_page)rbnode_get_next((rbnode)pp);
    }
    pagecache_unlock_state(pc);
    sg_list_release(sg);
    deallocate_sg_list(sg);
    apply(bound(complete), s);
    closure_finish();
}

static void pagecache_node_fetch_sg(pagecache pc, pagecache_node pn, range r, sg_list sg,
                                    status_handler fetch_complete)
{
    closure_member(pagecache_node_fetch_complete, fetch_complete, page_count) =
        range_span(range_rshift_pad(r, pc->page_order));
    pagecache_debug("fetching %R from node %p\n", r, pn);
    apply(pn->fs_read, sg, r, fetch_complete);
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
    u64 read_limit = pad(pn->length, U64_FROM_BIT(pn->pv->block_order));
    k.state_offset = q.start >> pc->page_order;
    u64 end = (q.end + MASK(pc->page_order)) >> pc->page_order;
    end = MIN(end, k.state_offset + PAGECACHE_MAX_SG_ENTRIES);
    boolean mem_cleaned = false;
  begin:
    pagecache_lock_node(pn);
    pagecache_page pp = (pagecache_page)rbtree_lookup(&pn->pages, &k.rbnode);
    sg_list read_sg = 0;
    range read_r;
    sg_buf sgb = 0;
    sstring err_msg = sstring_null();
    status_handler fetch_complete = 0;
    pagecache_lock_state(pc);
    u64 pi;
    for (pi = k.state_offset; pi < end; pi++) {
        if (pp == INVALID_ADDRESS || page_offset(pp) > pi) {
            pp = allocate_page_nodelocked(pn, pi);
            if (pp == INVALID_ADDRESS) {
                err_msg = ss("failed to allocate pagecache_page");
                break;
            }
        }
        if (touch_page_locked(pn, pp, m)) {
            /* This page does not need to be fetched: fetch pages accumulated so far in read_sg. */
            if (read_sg) {
                pagecache_unlock_state(pc);
                pagecache_node_fetch_sg(pc, pn, read_r, read_sg, fetch_complete);
                pagecache_lock_state(pc);
                read_sg = 0;
                sgb = 0;
            }
        } else {
            /* This page needs to be fetched: add it to read_sg. */
            if (page_state(pp) == PAGECACHE_PAGESTATE_FREE) {
                err_msg = ss("failed to re-allocate page");
                break;
            }
            if (!read_sg) {
                read_sg = allocate_sg_list();
                if (read_sg == INVALID_ADDRESS) {
                    err_msg = ss("failed to allocate read SG list");
                    read_sg = 0;
                    break;
                }
                status_handler fetch_sh = apply_merge(m);
                fetch_complete = closure(pc->h, pagecache_node_fetch_complete, pc, pp, 0, read_sg,
                                         fetch_sh);
                if (fetch_complete == INVALID_ADDRESS) {
                    err_msg = ss("failed to allocate fetch completion");
                    apply(fetch_sh, STATUS_OK);
                    deallocate_sg_list(read_sg);
                    read_sg = 0;
                    break;
                }
                read_r = range_lshift(irangel(page_offset(pp), 0), pc->page_order);
            }
            u64 read_max = read_limit - (pi << pc->page_order);
            u64 read_size = cache_pagesize(pc);
            if (read_size > read_max) {
                zero(pp->kvirt + read_max, read_size - read_max);
                read_size = read_max;
            }
            if (sgb && (sgb->buf + sgb->size == pp->kvirt)) {
                sgb->size += read_size;
                read_sg->count += read_size;
            } else {
                sgb = pagecache_add_sgb(pp, read_sg, read_size);
                if (sgb == INVALID_ADDRESS) {
                    err_msg = ss("failed to allocate SG buffer");
                    break;
                }
            }
            pp->refcount++;
            read_r.end += read_size;
        }
        if (ph && !apply(ph, pp)) {
            err_msg = ss("page fetch handler error");
            break;
        }
        pp = (pagecache_page)rbnode_get_next((rbnode)pp);
    }
    pagecache_unlock_state(pc);
    pagecache_unlock_node(pn);
    if (read_sg)
        pagecache_node_fetch_sg(pc, pn, read_r, read_sg, fetch_complete);
    if (!sstring_is_null(err_msg)) {
        if (!mem_cleaned || (pi != k.state_offset)) {
            pagecache_debug("   trying to free memory (r %R, pi 0x%lx)\n",
                            irange(k.state_offset, end), pi);
            mm_service(true);
            mem_cleaned = true;
            k.state_offset = pi;
            goto begin;
        }
        if (k.state_offset == q.start >> pc->page_order) {  /* no pages could be fetched */
            apply(sh, timm_sstring(ss("result"), err_msg));
            return;
        }
    }

    /* finished issuing requests */
    apply(sh, STATUS_OK);
}

closure_func_basic(pp_handler, boolean, pagecache_read_pp_handler,
                 pagecache_page pp)
{
    pp->refcount++;
    return true;
}

closure_function(4, 1, void, pagecache_read_sg_finish,
                 pagecache_node, pn, range, q, sg_list, sg, status_handler, completion,
                 status s)
{
    status_handler completion = bound(completion);
    if (is_ok(s)) {
        pagecache pc = global_pagecache;
        pagecache_node pn = bound(pn);
        range q = bound(q);
        sg_list sg = bound(sg);
        context user_ctx = context_from_closure(completion);
        context ctx = get_current_context(current_cpu());
        if (!user_ctx)
            user_ctx = ctx;
        if (ctx != user_ctx)
            use_fault_handler(user_ctx->fault_handler);
        /* Fault in memory now to avoid page faults while spinlocks are held. */
        if (!sg_fault_in(sg, range_span(q))) {
            s = timm("result", "invalid user memory");
            s = timm_append(s, "fsstatus", "%d", -EFAULT);
        }
        struct pagecache_page k;
        int page_order = pc->page_order;
        u64 page_size = U64_FROM_BIT(page_order);
        k.state_offset = q.start >> page_order;
        u64 offset = q.start & MASK(page_order);
        pagecache_lock_node(pn);
        pagecache_lock_state(pc);
        pagecache_page pp = (pagecache_page)rbtree_lookup(&pn->pages, &k.rbnode);
        while (pp != INVALID_ADDRESS) {
            u32 copy_len = MIN(page_size - offset, range_span(q));
            if (is_ok(s))
                sg_copy_from_buf(pp->kvirt + offset, sg, copy_len);
            q.start += copy_len;
            if (q.start == q.end) {
                pagecache_page_release_locked(pc, pp, false);
                break;
            }
            offset = 0;
            pagecache_page next = (pagecache_page)rbnode_get_next((rbnode)pp);
            pagecache_page_release_locked(pc, pp, false);
            pp = next;
        }
        pagecache_unlock_state(pc);
        pagecache_unlock_node(pn);
        if (ctx != user_ctx)
            clear_fault_handler();
    }
    async_apply_status_handler(completion, s);
    closure_finish();
}

closure_function(1, 3, void, pagecache_read_sg,
                 pagecache_node, pn,
                 sg_list sg, range q, status_handler completion)
{
    pagecache_node pn = bound(pn);
    pagecache pc = pn->pv->pc;
    pagecache_debug("%s: node %p, q %R, sg %p, completion %F\n", func_ss, pn, q, sg, completion);
    q = range_intersection(q, irangel(0, pn->length));
    if (range_span(q) == 0) {
        apply(completion, STATUS_OK);
        return;
    }
    status_handler read_sg_finish = closure(pc->h, pagecache_read_sg_finish, pn, q, sg, completion);
    if (read_sg_finish != INVALID_ADDRESS) {
        pagecache_node_fetch_internal(pn, q,
                                      stack_closure_func(pp_handler, pagecache_read_pp_handler),
                                      read_sg_finish);
    } else {
        status s = timm("result", "out of memory");
        apply(completion, timm_append(s, "fsstatus", "%d", -ENOMEM));
    }
}


closure_function(3, 3, boolean, pagecache_check_dirty_page,
                 pagecache, pc, pagecache_shared_map, sm, flush_entry, fe,
                 int level, u64 vaddr, pteptr entry)
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
        if (page_state(pp) != PAGECACHE_PAGESTATE_DIRTY) {
            change_page_state_locked(pc, pp, PAGECACHE_PAGESTATE_DIRTY);
            pp->refcount++;
        }
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
    pagecache_debug("%s\n", func_ss);
    flush_entry fe = get_page_flush_entry();
    list_foreach(&pc->shared_maps, l) {
        pagecache_shared_map sm = struct_from_list(l, pagecache_shared_map, l);
        pagecache_debug("   shared map va %R, node_offset 0x%lx\n", sm->n.r, sm->node_offset);
        pagecache_scan_shared_map(pc, sm, fe);
    }
    page_invalidate_sync(fe);
}

static void pagecache_scan_node(pagecache_node pn)
{
    pagecache_debug("%s\n", func_ss);
    flush_entry fe = get_page_flush_entry();
    rangemap_foreach(pn->shared_maps, n) {
        pagecache_shared_map sm = (pagecache_shared_map)n;
        pagecache_debug("   shared map va %R, node_offset 0x%lx\n", n->r, sm->node_offset);
        pagecache_scan_shared_map(pn->pv->pc, sm, fe);
    }
    page_invalidate_sync(fe);
}

closure_func_basic(timer_handler, void, pagecache_scan_timer,
                   u64 expiry, u64 overruns)
{
    pagecache pc = struct_from_closure(pagecache, do_scan_timer);
    if ((overruns != timer_disabled) && !pc->writeback_in_progress) {
        pagecache_scan(pc);
        pc->writeback_in_progress = true;
        pagecache_finish_pending_writes(pc, 0, 0, (status_handler)&pc->writeback_complete);
    }
}

closure_func_basic(status_handler, void, pagecache_writeback_complete,
                   status s)
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
    pagecache_debug("%s: pn %p, q %R, node_offset 0x%lx\n", func_ss, pn, q, node_offset);
    pagecache_lock_state(pc);
    list_insert_before(&pc->shared_maps, &sm->l);
    assert(rangemap_insert(pn->shared_maps, &sm->n));
    pagecache_unlock_state(pc);
}

closure_function(3, 1, boolean, close_shared_pages_intersection,
                 pagecache_node, pn, range, q, flush_entry, fe,
                 rmnode n)
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
    pagecache_debug("%s: node %p, q %R\n", func_ss, pn, q);
    rangemap_range_lookup(pn->shared_maps, q,
                          stack_closure(close_shared_pages_intersection, pn, q, fe));
}

closure_function(2, 1, boolean, scan_shared_pages_intersection,
                 pagecache, pc, flush_entry, fe,
                 rmnode n)
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
    pagecache_debug("%s: node %p, q %R\n", func_ss, pn, q);
    flush_entry fe = get_page_flush_entry();
    rangemap_range_lookup(pn->shared_maps, q,
                          stack_closure(scan_shared_pages_intersection, pn->pv->pc, fe));
    pagecache_commit_dirty_node(pn, 0);
    page_invalidate_sync(fe);
}

boolean pagecache_node_do_page_cow(pagecache_node pn, u64 node_offset, u64 vaddr, pageflags flags)
{
    pagecache_debug("%s: node %p, node_offset 0x%lx, vaddr 0x%lx, flags 0x%lx\n",
                    func_ss, pn, node_offset, vaddr, flags.w);
    pagecache pc = pn->pv->pc;
    u64 pagesize = cache_pagesize(pc);
    void *p = allocate(pc->contiguous, pagesize);
    if (p == INVALID_ADDRESS)
        return false;
    pagecache_lock_node(pn);
    pagecache_page pp = page_lookup_nodelocked(pn, node_offset >> pc->page_order);
    assert(pp != INVALID_ADDRESS);
    assert(pageflags_is_writable(flags));
    assert(page_state(pp) != PAGECACHE_PAGESTATE_FREE);
    assert(pp->kvirt != INVALID_ADDRESS);
    assert(pp->refcount != 0);
    unmap(vaddr, pagesize);
    map(vaddr, physical_from_virtual(p), pagesize, flags);
    runtime_memcpy(pointer_from_u64(vaddr), pp->kvirt, pagesize);
    pagecache_unlock_node(pn);
    pagecache_lock_state(pc);
    pagecache_page_release_locked(pc, pp, true);
    pagecache_unlock_state(pc);
    return true;
}

closure_function(2, 1, boolean, pagecache_fetch_pp_handler,
                 range, q, sg_list, sg,
                 pagecache_page pp)
{
    range r = byte_range_from_page(global_pagecache, pp);
    range i = range_intersection(bound(q), r);
    u64 length = range_span(i);
    sg_buf sgb = sg_list_tail_add(bound(sg), length);
    if (sgb == INVALID_ADDRESS)
        return false;
    sgb->buf = pp->kvirt + (i.start - r.start);
    sgb->size = length;
    sgb->offset = 0;
    sgb->refcount = &pp->read_refcount;
    if (fetch_and_add(&pp->read_refcount.c, 1) == 0)
        pp->refcount++;
    pp->refcount++;
    return true;
}

void pagecache_node_fetch_pages(pagecache_node pn, range r, sg_list sg, status_handler complete)
{
    pagecache_debug("%s: node %p, r %R\n", func_ss, pn, r);
    pp_handler ph = sg ? stack_closure(pagecache_fetch_pp_handler, r, sg) : 0;
    pagecache_node_fetch_internal(pn, r, ph, complete ? complete : ignore_status);
}

closure_function(2, 1, void, get_page_finish,
                 pagecache_page, pp, pagecache_page_handler, handler,
                 status s)
{
    pagecache_page_handler handler = bound(handler);
    if (is_ok(s)) {
        apply(handler, bound(pp)->kvirt);
    } else {
        apply(handler, INVALID_ADDRESS);
    }
    closure_finish();
}

/* not context restoring */
void pagecache_get_page(pagecache_node pn, u64 node_offset, pagecache_page_handler handler)
{
    pagecache pc = pn->pv->pc;
    pagecache_lock_node(pn);
    u64 pi = node_offset >> pc->page_order;
    pagecache_page pp = page_lookup_or_alloc_nodelocked(pn, pi);
    pagecache_debug("%s: pn %p, node_offset 0x%lx, handler %F, pp %p\n",
                    func_ss, pn, node_offset, handler, pp);
    if (pp == INVALID_ADDRESS) {
        pagecache_unlock_node(pn);
        apply(handler, INVALID_ADDRESS);
        return;
    }
    merge m = allocate_merge(pc->h, closure(pc->h, get_page_finish, pp, handler));
    status_handler k = apply_merge(m);
    touch_or_fill_page_nodelocked(pn, pp, m);
    pagecache_unlock_node(pn);
    apply(k, STATUS_OK);
}

/* no-alloc / no-fill path */
void *pagecache_get_page_if_filled(pagecache_node pn, u64 node_offset)
{
    pagecache_lock_node(pn);
    pagecache_page pp = page_lookup_nodelocked(pn, node_offset >> pn->pv->pc->page_order);
    pagecache_debug("%s: pn %p, node_offset 0x%lx, pp %p\n", func_ss, pn, node_offset, pp);
    void *kvirt;
    if (pp == INVALID_ADDRESS) {
        kvirt = INVALID_ADDRESS;
        goto out;
    }
    if (touch_or_fill_page_nodelocked(pn, pp, 0))
        kvirt = pp->kvirt;
    else
        kvirt = INVALID_ADDRESS;
  out:
    pagecache_unlock_node(pn);
    return kvirt;
}

void pagecache_release_page(pagecache_node pn, u64 node_offset)
{
    pagecache pc = pn->pv->pc;
    pagecache_lock_node(pn);
    pagecache_page pp = page_lookup_nodelocked(pn, node_offset >> pn->pv->pc->page_order);
    pagecache_debug("%s: pn %p, node_offset 0x%lx, pp %p\n", func_ss, pn, node_offset, pp);
    if (pp == INVALID_ADDRESS)
        return;
    pagecache_lock_state(pc);
    pagecache_page_release_locked(pc, pp, true);
    pagecache_unlock_state(pc);
    pagecache_unlock_node(pn);
}

closure_function(4, 3, boolean, pagecache_unmap_page_nodelocked,
                 pagecache_node, pn, u64, vaddr_base, u64, node_offset, flush_entry, fe,
                 int level, u64 vaddr, pteptr entry)
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
        pagecache pc = bound(pn)->pv->pc;
        if (phys == pp->phys) {
            /* shared or cow */
            assert(pp->refcount >= 1);
            pagecache_lock_state(pc);
            pagecache_page_release_locked(pc, pp, false);
            pagecache_unlock_state(pc);
        } else {
            /* private copy: free physical page */
            page_free_phys(phys);
        }
    }
    return true;
}

void pagecache_node_unmap_pages(pagecache_node pn, range v /* bytes */, u64 node_offset)
{
    pagecache_debug("%s: pn %p, v %R, node_offset 0x%lx\n", func_ss, pn, v, node_offset);
    flush_entry fe = get_page_flush_entry();
    pagecache_node_close_shared_pages(pn, v, fe);
    pagecache_lock_node(pn);
    traverse_ptes(v.start, range_span(v), stack_closure(pagecache_unmap_page_nodelocked, pn,
                                                        v.start, node_offset, fe));
    pagecache_unlock_node(pn);
    page_invalidate_sync(fe);
}

closure_func_basic(rbnode_handler, boolean, pagecache_page_print_key,
                   rbnode n)
{
    pagecache pc = struct_from_closure(pagecache, page_print_key);
    rprintf(" 0x%lx", page_offset((pagecache_page)n) << cache_pagesize(pc));
    return true;
}

closure_func_basic(rb_key_compare, int, pagecache_page_compare,
                   rbnode a, rbnode b)
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

closure_function(1, 1, boolean, pagecache_page_release,
                 pagecache, pc,
                 rbnode n)
{
    pagecache pc = bound(pc);
    pagecache_page pp = struct_from_list(n, pagecache_page, rbnode);
    pagecache_lock_state(pc);
    if (!pp->evicted)
        pagecache_page_release_locked(pc, pp, false);
    /* a pagecache node being released means no outstanding page references are possible */
    assert(page_state(pp) == PAGECACHE_PAGESTATE_FREE);
    pagelist_remove(&pc->free, pp);
    pagecache_unlock_state(pc);
    deallocate(pc->pp_heap, pp, sizeof(*pp));
    return true;
}

closure_func_basic(rmnode_handler, boolean, pagecache_node_assert,
                   rmnode n)
{
    /* A pagecache node being deallocated must not have any shared maps. */
    assert(0);
    return false;
}

closure_func_basic(thunk, void, pagecache_node_free)
{
    pagecache_node pn = struct_from_closure(pagecache_node, free);
    if (pn->fs_read)
        deallocate_closure(pn->fs_read);
    deallocate_closure(pn->cache_read);
    if (pn->fs_write)
        deallocate_closure(pn->fs_write);
    if (pn->fs_reserve)
        deallocate_closure(pn->fs_reserve);
    deallocate_closure(pn->cache_write);
    pagecache pc = pn->pv->pc;
    destruct_rbtree(&pn->pages, stack_closure(pagecache_page_release, pc));
    deallocate_rangemap(pn->shared_maps, stack_closure_func(rmnode_handler, pagecache_node_assert));
    deallocate(pc->h, pn, sizeof(*pn));
}

closure_func_basic(thunk, void, pagecache_node_queue_free)
{
    pagecache_node pn = struct_from_closure(pagecache_node, queue_free);
    thunk t = (thunk)&pn->free;
    /* freeing the node must be deferred to avoid state lock reentrance */
    async_apply(t);
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
    spin_lock_init(&pn->pages_lock);
    list_init_member(&pn->l);
    init_rangemap(&pn->dirty, h);
    init_rbtree(&pn->pages, (rb_key_compare)&pv->pc->page_compare,
                (rbnode_handler)&pv->pc->page_print_key);
    pn->length = 0;
    pn->cache_read = closure(h, pagecache_read_sg, pn);
    pn->cache_write = closure(h, pagecache_write_sg, pn);
    pn->fs_read = fs_read;
    pn->fs_write = fs_write;
    pn->fs_reserve = fs_reserve;
    list_init(&pn->ops);
    init_closure_func(&pn->free, thunk, pagecache_node_free);
    init_refcount(&pn->refcount, 1,
                  init_closure_func(&pn->queue_free, thunk, pagecache_node_queue_free));
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
    pagecache_lock(pc);
    list_insert_before(&pc->volumes, &pv->l);
    pagecache_unlock(pc);
    list_init(&pv->dirty_nodes);
    spin_lock_init(&pv->lock);
    if (!timer_is_active(&pc->scan_timer)) {
        timestamp t = seconds(PAGECACHE_SCAN_PERIOD_SECONDS);
        register_timer(kernel_timers, &pc->scan_timer, CLOCK_ID_MONOTONIC, t, false, t,
                       (timer_handler)&pc->do_scan_timer);
    }
    pv->length = length;
    pv->block_order = block_order;
    return pv;
}

void pagecache_dealloc_volume(pagecache_volume pv)
{
    pagecache_lock(pv->pc);
    list_delete(&pv->l);
    pagecache_unlock(pv->pc);
    deallocate(pv->pc->h, pv, sizeof(*pv));
}

static inline void page_list_init(struct pagelist *pl)
{
    list_init(&pl->l);
    pl->pages = 0;
}

void init_pagecache(heap general, heap contiguous, u64 pagesize)
{
    pagecache pc = allocate(general, sizeof(struct pagecache));
    assert (pc != INVALID_ADDRESS);

    pc->total_pages = 0;
    pc->page_order = find_order(pagesize);
    assert(pagesize == U64_FROM_BIT(pc->page_order));
    pc->h = general;
    pc->contiguous = contiguous;
    heap dma = heap_dma();
    pc->zero_page = allocate_zero(dma, pagesize);
    assert(pc->zero_page != INVALID_ADDRESS);

    pc->completions = (heap)allocate_objcache(general, general, sizeof(struct page_completion),
                                              PAGESIZE, true);
    assert(pc->completions != INVALID_ADDRESS);
    pc->pp_heap = (heap)allocate_objcache(general, contiguous, sizeof(struct pagecache_page),
                                          PAGESIZE, true);
    assert(pc->pp_heap != INVALID_ADDRESS);
    spin_lock_init(&pc->state_lock);
    spin_lock_init(&pc->global_lock);
    page_list_init(&pc->free);
    page_list_init(&pc->new);
    page_list_init(&pc->active);
    page_list_init(&pc->writing);
    list_init(&pc->volumes);
    list_init(&pc->shared_maps);
    init_closure_func(&pc->page_compare, rb_key_compare, pagecache_page_compare);
    init_closure_func(&pc->page_print_key, rbnode_handler, pagecache_page_print_key);

    pc->writeback_in_progress = false;
    init_timer(&pc->scan_timer);
    init_closure_func(&pc->do_scan_timer, timer_handler, pagecache_scan_timer);
    init_closure_func(&pc->writeback_complete, status_handler, pagecache_writeback_complete);
    global_pagecache = pc;
}
