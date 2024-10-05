#include <unix_internal.h>
#include <storage.h>

//#define VMAP_PARANOIA

//#define PF_DEBUG
#ifdef PF_DEBUG
#define pf_debug(x, ...) do {tprintf(sym(fault), 0, ss(x), ##__VA_ARGS__);} while(0)
#else
#define pf_debug(x, ...)
#endif

//#define VMAP_DEBUG
#ifdef VMAP_DEBUG
#define vmap_debug(x, ...) do {tprintf(sym(vmap), 0, ss(x), ##__VA_ARGS__);} while(0)
#else
#define vmap_debug(x, ...)
#endif

#define vmap_assert(x)                                                  \
    do {                                                                \
        if (!(x)) {                                                     \
            print_frame_trace_from_here();                              \
            if (current)                                                \
                vmap_dump(current->p->vmaps);                           \
            halt("assertion " #x " failed at " __FILE__ ":%d  in %s(); halt\n", \
                 __LINE__, func_ss);                                    \
        }                                                               \
    } while(0)

typedef struct vmap_heap {
    struct heap h;  /* must be first */
    process p;
    boolean randomize;
} *vmap_heap;

static struct {
    heap h;
    heap virtual_backed;
    u64 thp_max_size;

    closure_struct(rb_key_compare, pf_compare);
    closure_struct(rbnode_handler, pf_print);

    struct list pf_freelist;
} mmap_info;

static status demand_page_internal(process p, context ctx, u64 vaddr, vmap vm, pending_fault *pf);

closure_func_basic(thunk, void, pending_fault_complete)
{
    pending_fault pf = struct_from_closure(pending_fault, complete);
    process p = pf->p;
    context ctx = pf->ctx;
    u64 vaddr = pf->addr;
    vmap_lock(p);
    vmap vm = vmap_from_vaddr(p, vaddr);
    status s;
    if (vm != INVALID_ADDRESS)
        s = demand_page_internal(p, ctx, vaddr, vm, &pf);
    else
        s = STATUS_OK;
    pagecache_node pn;
    range ra;   /* read-ahead */
    if (pf->type == PENDING_FAULT_FILEBACKED) {
        pn = pf->filebacked.pn;
        if (is_ok(s))
            /* File read-ahead must be done without holding the vmap lock, because it can suspend
             * the current context. */
            ra = irange(pf->filebacked.node_offset + PAGESIZE,
                        vm->node_offset + range_span(vm->node.r));
        else
            ra = irange(1, 0);  /* dummy invalid range */
    } else {
        pn = 0;
    }
    list_insert_after(&mmap_info.pf_freelist, &pf->l_free);
    vmap_unlock(p);
    pf_debug("%s: vaddr 0x%lx, status %v\n", func_ss, vaddr, s);
    if (!is_ok(s)) {
        msg_err("page fill failed with %v\n", s);
    }
    demand_page_done(ctx, vaddr, s);
    context_schedule_return(ctx);
    if (pn) {
        if (range_valid(ra)) {
            if (range_span(ra) > FILE_READAHEAD_DEFAULT)
                ra.end = ra.start + FILE_READAHEAD_DEFAULT;
            pagecache_node_fetch_pages(pn, ra, 0, 0);
        }
        pagecache_node_unref(pn);
    }
}

pending_fault new_pending_fault_locked(process p, context ctx, u64 addr)
{
    pending_fault pf;
    list l;
    if ((l = list_get_next(&mmap_info.pf_freelist))) {
        pf = struct_from_list(l, pending_fault, l_free);
        list_delete(l);
    } else {
        pf = allocate(mmap_info.h, sizeof(struct pending_fault));
        if (pf == INVALID_ADDRESS)
            return pf;
    }
    pf->addr = addr;
    pf->p = p;
    pf->ctx = ctx;
    init_closure_func(&pf->complete, thunk, pending_fault_complete);
    return pf;
}

#define VMAP_PAGE_SHRINK(v, page_addr, page_size)   do {    \
    page_size >>= 1;                                        \
    if (page_addr + page_size <= v) {                       \
        page_addr += page_size;                             \
    }                                                       \
} while (0)

closure_function(3, 3, boolean, vmap_anon_ptes,
                 u64, v, u64 *, page_addr, u64 *, page_size,
                 int level, u64 curr, pteptr entry_p)
{
    pte entry = pte_from_pteptr(entry_p);
    if (!pte_is_present(entry) || !pte_is_mapping(level, entry))
        return true;
    range cur_mapping = irangel(curr, U64_FROM_BIT(pte_order(level, entry)));
    u64 page_addr = *bound(page_addr);
    u64 page_size = *bound(page_size);
    pf_debug("  page_addr 0x%lx, page_size 0x%lx, current mapping %R\n", page_addr, page_size,
             cur_mapping);
    range ri = range_intersection(cur_mapping, irangel(page_addr, page_size));
    u64 v = bound(v);
    if (range_span(ri) == 0) {
        if (cur_mapping.end <= v)
            return true;
        else    /* we are past (page_addr + page_size), PTE traversal can stop here */
            return false;
    }
    if (cur_mapping.end <= v) {
        while (page_addr < cur_mapping.end)
            VMAP_PAGE_SHRINK(v, page_addr, page_size);
        pf_debug("  shrinking from head, page_addr 0x%lx, page_size 0x%lx\n", page_addr, page_size);
        *bound(page_addr) = page_addr;
        *bound(page_size) = page_size;
        return true;
    }
    if (cur_mapping.start > v) {
        while (page_addr + page_size > cur_mapping.start)
            VMAP_PAGE_SHRINK(v, page_addr, page_size);
        pf_debug("  shrinking from tail, page_addr 0x%lx, page_size 0x%lx\n", page_addr, page_size);
        *bound(page_addr) = page_addr;
        *bound(page_size) = page_size;
        return false;
    }

    /* the current mapping includes v */
    *bound(page_size) = 0;
    return false;
}

/* returns true if successful */
boolean new_zeroed_pages(u64 v, vmap vm, pageflags flags)
{
    u64 page_addr = v & ~MASK(PAGELOG);
    u64 page_size = PAGESIZE;
    if (vm->flags & VMAP_FLAG_THP) {
        u64 max_size = mmap_info.thp_max_size;
        while ((page_size < max_size) && (page_addr >= vm->node.r.start) &&
               (page_addr + page_size <= vm->node.r.end)) {
            page_size <<= 1;
            page_addr = v & ~(page_size - 1);
            if ((page_addr < vm->node.r.start) || (page_addr + page_size > vm->node.r.end)) {
                page_size >>= 1;
                page_addr = v & ~(page_size - 1);
                break;
            }
        }
    }
    pf_debug("%s: v 0x%lx, vmap %R, page_addr 0x%lx, page_size 0x%lx\n", func_ss, v, vm->node.r,
             page_addr, page_size);
    traverse_ptes(page_addr, page_size, stack_closure(vmap_anon_ptes, v, &page_addr, &page_size));
    pf_debug("  after traversing PTEs: page_addr 0x%lx, page_size 0x%lx\n", page_addr, page_size);
    if (page_size == 0)
        /* The mapping must have been done in parallel by another CPU. */
        return true;
    void *m;
    while ((m = allocate(mmap_info.virtual_backed, page_size)) == INVALID_ADDRESS) {
        if (page_size == PAGESIZE) {
            vmap_debug("%s: cannot get physical page\n", func_ss);
            return false;
        }
        VMAP_PAGE_SHRINK(v, page_addr, page_size);
    }
    zero(m, page_size);
    write_barrier();
    u64 p = physical_from_virtual(m);
    map(page_addr, p, page_size, flags);
    return true;
}

static void demand_page_major_fault(context ctx)
{
    count_major_fault();
    context_pre_suspend(ctx);
}

closure_func_basic(thunk, void, pending_fault_anonymous)
{
    pending_fault pf = struct_from_closure(pending_fault, async_handler);
    mm_service(true);
    thunk complete = (thunk)&pf->complete;
    apply(complete);
}

static status demand_anonymous_page(process p, context ctx, u64 vaddr, vmap vm, pending_fault *pf)
{
    pageflags flags = pageflags_from_vmflags(vm->flags);
    if (new_zeroed_pages(vaddr, vm, flags))
        return STATUS_OK;
    else if (*pf)
        return timm_oom;
    pending_fault new_pf = new_pending_fault_locked(p, ctx, vaddr);
    if (new_pf != INVALID_ADDRESS) {
        new_pf->type = PENDING_FAULT_ANONYMOUS;
        init_closure_func(&new_pf->async_handler, thunk, pending_fault_anonymous);
    }
    *pf = new_pf;
    return STATUS_OK;
}

static status mmap_filebacked_page(vmap vm, u64 page_addr, pageflags flags, void *kvirt)
{
    u64 vmap_offset = page_addr - vm->node.r.start;
    boolean pagecache_map;
    status s;
    pagetable_lock();
    u64 p = __physical_from_virtual_locked(pointer_from_u64(page_addr));
    if (p == INVALID_PHYSICAL) {
        pagecache_map = true;
        p = physical_from_virtual(kvirt);
        if (vm->flags & VMAP_FLAG_TAIL_BSS) {
            u64 bss_offset = vm->bss_offset;
            if (point_in_range(irangel(vmap_offset, PAGESIZE), bss_offset)) {
                pagecache_map = false;
                void *new_page = allocate(mmap_info.virtual_backed, PAGESIZE);
                if (new_page == INVALID_ADDRESS) {
                    vmap_debug("%s: cannot get physical page\n", func_ss);
                    s = timm_oom;
                    goto out;
                }
                u64 bss_start = bss_offset - vmap_offset;
                runtime_memcpy(new_page, kvirt, bss_start);
                zero(new_page + bss_start, PAGESIZE - bss_start);
                p = physical_from_virtual(new_page);
            }
        }
        map_nolock(page_addr, p, PAGESIZE, flags);
    } else {
        /* The mapping must have been done in parallel by another CPU. */
        pagecache_map = false;
    }
    s = STATUS_OK;
  out:
    pagetable_unlock();
    if (!pagecache_map)
        pagecache_release_page(vm->cache_node, vm->node_offset + vmap_offset);
    return s;
}

closure_func_basic(pagecache_page_handler, void, pending_fault_page_handler,
                   void *kvirt)
{
    pending_fault pf = struct_from_closure(pending_fault, filebacked.demand_file_page);
    pf->filebacked.page_kvirt = kvirt;
    thunk complete = (thunk)&pf->complete;
    apply(complete);
}

closure_func_basic(thunk, void, pending_fault_filebacked)
{
    pending_fault pf = struct_from_closure(pending_fault, async_handler);
    pagecache_page_handler h = init_closure_func(&pf->filebacked.demand_file_page,
                                                 pagecache_page_handler,
                                                 pending_fault_page_handler);
    pagecache_get_page(pf->filebacked.pn, pf->filebacked.node_offset, h);
}

static status demand_filebacked_page(process p, context ctx, u64 vaddr, vmap vm, pending_fault *pf)
{
    pageflags flags = pageflags_from_vmflags(vm->flags);
    u64 page_addr = vaddr & ~PAGEMASK;
    u64 vmap_offset = page_addr - vm->node.r.start;
    pagecache_node pn = vm->cache_node;
    u64 node_offset = vm->node_offset + vmap_offset;
    boolean shared = (vm->flags & VMAP_FLAG_SHARED) != 0;
    if (!shared && !(vm->flags & VMAP_FLAG_PROG))
        flags = pageflags_readonly(flags); /* cow */

    pf_debug("   node %p (start 0x%lx), offset 0x%lx, vm flags 0x%lx, pageflags 0x%lx\n",
             pn, vm->node.r.start, node_offset, vm->flags, flags.w);

    u64 padlen = pad(pagecache_get_node_length(pn), PAGESIZE);
    pf_debug("   map length 0x%lx\n", padlen);
    if (node_offset >= padlen) {
        pf_debug("   extends past map limit 0x%lx\n", padlen);
        return timm("result", "out of range page");
    }

    void *kvirt;
    status s;
    if (!*pf) {
        kvirt = pagecache_get_page_if_filled(pn, node_offset);
        if (kvirt != INVALID_ADDRESS)
            return mmap_filebacked_page(vm, page_addr, flags, kvirt);
        pending_fault new_pf = new_pending_fault_locked(p, ctx, vaddr);
        if (new_pf != INVALID_ADDRESS) {
            pagecache_node_ref(pn);
            new_pf->type = PENDING_FAULT_FILEBACKED;
            new_pf->filebacked.pn = pn;
            new_pf->filebacked.node_offset = node_offset;
            init_closure_func(&new_pf->async_handler, thunk, pending_fault_filebacked);
        }
        *pf = new_pf;
        return STATUS_OK;
    }
    if (((*pf)->filebacked.pn != pn) || ((*pf)->filebacked.node_offset != node_offset))
        return STATUS_OK;
    kvirt = (*pf)->filebacked.page_kvirt;
    if (kvirt == INVALID_ADDRESS)
        s = timm_oom;
    else
        s = mmap_filebacked_page(vm, page_addr, flags, kvirt);
    return s;
}

static status demand_page_internal(process p, context ctx, u64 vaddr, vmap vm, pending_fault *pf)
{
    if ((vm->flags & (VMAP_FLAG_MMAP | VMAP_FLAG_STACK | VMAP_FLAG_HEAP |
                      VMAP_FLAG_BSS | VMAP_FLAG_PROG)) == 0) {
        msg_err("vaddr 0x%lx matched vmap with invalid flags (0x%x)\n",
                vaddr, vm->flags);
        return timm("result", "vaddr 0x%lx matched vmap with invalid flags (0x%x)\n",
                vaddr, vm->flags);
    }

    pf_debug("%s: %s context, %s, vaddr %p, vm flags 0x%02lx,\n", func_ss,
             context_type_strings[ctx->type],
             string_from_mmap_type(vm->flags & VMAP_MMAP_TYPE_MASK),
             vaddr, vm->flags);
    pf_debug("   vmap %p, context %p\n", vm, ctx);

    boolean anonymous;
    if (vm->flags & VMAP_FLAG_MMAP) {
        int mmap_type = vm->flags & VMAP_MMAP_TYPE_MASK;
        switch (mmap_type) {
        case VMAP_MMAP_TYPE_ANONYMOUS:
            anonymous = true;
            break;
        case VMAP_MMAP_TYPE_FILEBACKED:
            anonymous = false;
            break;
        default:
            return vm->fault(p, ctx, vaddr, vm, pf);
        }
    } else if (vm->flags & VMAP_FLAG_PROG) {
        pf_debug("   file-backed program page fault\n");
        anonymous = false;
    } else {
        pf_debug("   bss / stack / heap page fault\n");
        anonymous = true;
    }
    boolean fault_pending = !!(*pf);
    status s;
    if (anonymous) {
        if (!fault_pending || ((*pf)->type == PENDING_FAULT_ANONYMOUS))
            s = demand_anonymous_page(p, ctx, vaddr, vm, pf);
        else
            s = STATUS_OK;
    } else {
        if (!fault_pending || ((*pf)->type == PENDING_FAULT_FILEBACKED))
            s = demand_filebacked_page(p, ctx, vaddr, vm, pf);
        else
            s = STATUS_OK;
    }
    return s;
}

status do_demand_page(process p, context ctx, u64 vaddr, vmap vm, boolean *done)
{
    pending_fault pf = 0;
    status s = demand_page_internal(p, ctx, vaddr, vm, &pf);
    if (pf) {
        if (pf != INVALID_ADDRESS) {
            demand_page_major_fault(ctx);
            async_apply_bh((thunk)&pf->async_handler);
            *done = false;
        } else {
            s = timm_oom;
            *done = true;
        }
    } else {
        count_minor_fault();
        *done = true;
    }
    return s;
}

vmap vmap_from_vaddr(process p, u64 vaddr)
{
    rangemap rm = p->vmaps;
    vmap vm = (vmap)rangemap_lookup_at_or_next(rm, vaddr);
    if ((vm != INVALID_ADDRESS) && (vm->node.r.start > vaddr)) {
        /* vm does not cover this address; if it is a stack mapping, check whether it can be
         * expanded downwards. */
        if (!(vm->flags & VMAP_FLAG_STACK) || (vm->node.r.end > vaddr + p->rlimit_stack))
            return INVALID_ADDRESS;
        vmap prev = (vmap)rangemap_prev_node(rm, &vm->node);
        vaddr &= ~PAGEMASK;
        if ((prev == INVALID_ADDRESS) || (prev->node.r.end <= vaddr - PROCESS_STACK_GUARD_GAP))
            /* expand stack mapping */
            vm->node.r.start = vaddr;
        else
            /* cannot expand stack mapping because of insufficient gap with previous mapping */
            vm = INVALID_ADDRESS;
    }
    return vm;
}

void vmap_iterator(process p, vmap_handler vmh)
{
    vmap_lock(p);
    vmap vm = (vmap) rangemap_first_node(p->vmaps);
    while (vm != INVALID_ADDRESS) {
        if (!apply(vmh, vm))
            break;
        vm = (vmap) rangemap_next_node(p->vmaps, &vm->node);
    }
    vmap_unlock(p);
}

closure_function(1, 1, boolean, vmap_validate_node,
                 u32, flags,
                 vmap vm)
{
    u32 flags = bound(flags);
    return (vm->flags & flags) == flags;
}

closure_func_basic(range_handler, boolean, vmap_validate_gap,
                   range q)
{
    return false;
}

/* Walk a given range in the process memory map and invoke a vmap handler for each mapping
 * encountered in that range.
 * If `allow_gaps` is false, the presence of any gap in the memory map over the given range makes
 * this function return RM_ABORT; otherwise, this function returns RM_MATCH if at least (part of)
 * one mapping exists in the given range, RM_NOMATCH of no mapping exists. */
static int vmap_range_walk(process p, range q, vmap_handler node_handler, boolean allow_gaps)
{
    range_handler gap_handler = allow_gaps ?
                                0 : stack_closure_func(range_handler, vmap_validate_gap);
    vmap_lock(p);
    int res = rangemap_range_lookup_with_gaps(p->vmaps, q, (rmnode_handler)node_handler,
                                              gap_handler);
    vmap_unlock(p);
    return res;
}

boolean vmap_validate_range(process p, range q, u32 flags)
{
    return (vmap_range_walk(p, q, stack_closure(vmap_validate_node, flags), false) == RM_MATCH);
}

closure_func_basic(rmnode_handler, boolean, vmap_dump_node,
                   rmnode n)
{
    vmap curr = (vmap)n;
    rprintf("  %R, %s%s %s%s\n", curr->node.r,
            (curr->flags & VMAP_FLAG_MMAP) ? ss("mmap ") : sstring_empty(),
            string_from_mmap_type(curr->flags & VMAP_MMAP_TYPE_MASK),
            (curr->flags & VMAP_FLAG_WRITABLE) ? ss("writable ") : sstring_empty(),
            (curr->flags & VMAP_FLAG_EXEC) ? ss("exec ") : sstring_empty());
    return true;
}

void vmap_dump(rangemap pvmap)
{
    rprintf("vmaps:\n");
    rmnode_handler nh = stack_closure_func(rmnode_handler, vmap_dump_node);
    rangemap_range_lookup(pvmap, (range){0, infinity}, nh);
}

static u64 node_vstart(vmap v)
{
    return v->node_offset - v->node.r.start;
}

static boolean vmap_compare_attributes(vmap a, vmap b)
{
    return (a->flags == b->flags &&
            a->allowed_flags == b->allowed_flags &&
            a->cache_node == b->cache_node &&
            a->fd == b->fd /* and bss_offset */ &&
            (!a->cache_node || (node_vstart(a) == node_vstart(b))));
}

#ifdef VMAP_PARANOIA
closure_function(1, 1, boolean, vmap_paranoia_node,
                 vmap *, last,
                 rmnode n)
{
    vmap v = (vmap)n;
    vmap last = *bound(last);
    if (last && vmap_compare_attributes(last, v) && last->node.r.end == v->node.r.start) {
        rprintf("%s: check failed; adjacent nodes %p (%R) and %p (%R) share same attributes\n",
                func_ss, last, last->node.r, v, v->node.r);
        return false;
    }
    *bound(last) = v;
    return true;
}

static void vmap_paranoia_locked(rangemap pvmap)
{
    vmap last = 0;
    rmnode_handler nh = stack_closure(vmap_paranoia_node, &last);
    if (!rangemap_range_lookup(pvmap, (range){0, infinity}, nh)) {
        vmap_dump(pvmap);
        print_frame_trace_from_here();
        halt("%s failed\n", func_ss);
    }
}
#else
#define vmap_paranoia_locked(x)
#endif

/* TODO maybe refcount makes more sense now that we have asynchronous faults */
static void deallocate_vmap_locked(rangemap rm, vmap vm)
{
    vmap_debug("%s: vm %p %R\n", func_ss, vm, vm->node.r);
    if (!(vm->flags & VMAP_FLAG_TAIL_BSS) && vm->fd)
        fdesc_put(vm->fd);
    deallocate(rm->h, vm, sizeof(struct vmap));
}

static vmap allocate_vmap_locked(rangemap rm, struct vmap *k)
{
    range q = k->node.r;
    vmap vm;

    vmap_debug("%s: q %R\n", func_ss, q);
    vm = (vmap)rangemap_lookup_max_lte(rm, q.start);
    vmap next;
    if (vm != INVALID_ADDRESS) {
        if (vm->node.r.end > q.start)
            return INVALID_ADDRESS;
        next = (vmap)rangemap_next_node(rm, &vm->node);
        if (vm->node.r.end == q.start && vmap_compare_attributes(vm, k)) {
            range new = irange(vm->node.r.start, q.end);
            if (next != INVALID_ADDRESS) {
                if (next->node.r.start < q.end)
                    return INVALID_ADDRESS;
                if (next->node.r.start == q.end && vmap_compare_attributes(next, k)) {
                    new.end = next->node.r.end;
                    vmap_debug("   removing %R\n", next->node.r);
                    rangemap_remove_node(rm, &next->node);
                    deallocate_vmap_locked(rm, next);
                }
            }
            vmap_debug("   extend vm %p, was %R, new %R\n", vm, vm->node.r, new);
            vmap_assert(rangemap_reinsert(rm, &vm->node, new));
        } else {
            vm = INVALID_ADDRESS;
        }
    } else {
        next = (vmap)rangemap_first_node(rm);
    }

    if (vm == INVALID_ADDRESS && next != INVALID_ADDRESS &&
        q.end == next->node.r.start && vmap_compare_attributes(next, k)) {
        vm = next;
        range new = irange(q.start, vm->node.r.end);
        vmap_debug("   advance vm %p, was %R, new %R\n", vm, vm->node.r, new);
        if (vm->cache_node) {
            vmap_assert(vm->node.r.start > q.start);
            vm->node_offset -= vm->node.r.start - q.start;
        }
        vmap_assert(rangemap_reinsert(rm, &vm->node, new));
    }

    if (vm != INVALID_ADDRESS) {
        vmap_paranoia_locked(rm);
        return vm;
    }
    vm = allocate(rm->h, sizeof(struct vmap));
    if (vm == INVALID_ADDRESS)
        return vm;
    vmap_debug("   allocated new vmap %p\n", vm);
    rmnode_init(&vm->node, q);
    vm->flags = k->flags;
    vm->allowed_flags = k->allowed_flags;
    vm->node_offset = k->node_offset;
    vm->cache_node = k->cache_node;
    vm->fd = k->fd;
    if (!rangemap_insert(rm, &vm->node)) {
        deallocate(rm->h, vm, sizeof(struct vmap));
        return INVALID_ADDRESS;
    }
    if (vm->fd && !(vm->flags & VMAP_FLAG_TAIL_BSS))
        fetch_and_add(&vm->fd->refcnt, 1);
    vmap_paranoia_locked(rm);
    return vm;
}

vmap allocate_vmap(process p, range q, struct vmap k)
{
    k.node.r = q;
    vmap_lock(p);
    vmap v = allocate_vmap_locked(p->vmaps, &k);
    vmap_unlock(p);
    return v;
}

static inline boolean validate_mmap_range(process p, range q)
{
    return range_valid(q) && q.start >= p->mmap_min_addr && q.end <= USER_LIMIT;
}

closure_function(1, 1, boolean, proc_virt_gap_handler,
                 u64 *, addr,
                 range r)
{
    *bound(addr) = r.start;
    return true;
}

u64 vmap_select_addr(u64 size, range r, boolean randomize)
{
    if (randomize)
        /* ensure there is non-zero room for randomization */
        r.end -= PAGESIZE;
    if (size > range_span(r))
        return INVALID_PHYSICAL;
    if (randomize) {
        u64 offset = (random_u64() % ((range_span(r) + 2 * PAGESIZE - size) >> PAGELOG)) << PAGELOG;
        return r.start + offset;
    }
    return r.start;
}

closure_function(3, 1, boolean, proc_virt_node_handler,
                 u64, size, boolean, randomize, u64 *, addr,
                 rmnode n)
{
    u64 candidate_addr = *bound(addr);
    if (candidate_addr == INVALID_PHYSICAL)
        return true;
    u64 limit = n->r.start;
    vmap next = (vmap)n;
    if (next->flags & VMAP_FLAG_STACK)
        limit -= PROCESS_STACK_GUARD_GAP;
    candidate_addr = vmap_select_addr(bound(size), irange(candidate_addr, limit), bound(randomize));
    *bound(addr) = candidate_addr;
    return (candidate_addr == INVALID_PHYSICAL);
}

/* Does NOT mark the returned address as allocated in the virtual heap. */
static u64 process_get_virt_range_locked(process p, u64 size, range region)
{
    assert(!(size & PAGEMASK));
    vmap_heap vmh = (vmap_heap)p->virtual;
    u64 addr = INVALID_PHYSICAL;
    boolean randomize = vmh->randomize;
    int res = rangemap_range_lookup_with_gaps(p->vmaps, region,
                                              stack_closure(proc_virt_node_handler, size, randomize,
                                                            &addr),
                                              stack_closure(proc_virt_gap_handler, &addr));
    if ((res == RM_MATCH) && (addr != INVALID_PHYSICAL))
        /* The gap handler set a candidate address, but there are no nodes after the last gap, thus
         * the node handler did not have a chance to select an address from the candidate address.
         */
        addr = vmap_select_addr(size, irange(addr, region.end), randomize);
    return addr;
}

u64 process_get_virt_range(process p, u64 size, range region)
{
    vmap_lock(p);
    u64 ret = process_get_virt_range_locked(p, size, region);
    vmap_unlock(p);
    return ret;
}

static u64 process_allocate_range_locked(process p, u64 size, struct vmap k, range region)
{
    u64 virt_addr = process_get_virt_range_locked(p, size, region);
    if (virt_addr != INVALID_PHYSICAL) {
        k.node.r = irangel(virt_addr, size);
        vmap vm = allocate_vmap_locked(p->vmaps, &k);
        if (vm == INVALID_ADDRESS)
            virt_addr = INVALID_PHYSICAL;
    }
    vmap_paranoia_locked(p->vmaps);
    return virt_addr;
}

static void process_remove_range_locked(process p, range q, boolean unmap);

void *process_map_physical(process p, u64 phys_addr, u64 size, u64 vmflags)
{
    vmap_debug("%s: phys_addr 0x%lx, size 0x%lx, vmflags 0x%lx\n",
               func_ss, phys_addr, size, vmflags);
    vmap_lock(p);
    u64 virt_addr = process_allocate_range_locked(p, size, ivmap(vmflags, 0, 0, 0, 0),
                                                  PROCESS_VIRTUAL_MMAP_RANGE);
    vmap_unlock(p);
    if (virt_addr == INVALID_PHYSICAL)
        return INVALID_ADDRESS;
    map(virt_addr, phys_addr, size, pageflags_from_vmflags(vmflags));
    return pointer_from_u64(virt_addr);
}

boolean adjust_process_heap(process p, range new)
{
    vmap_lock(p);
    boolean inserted = rangemap_reinsert(p->vmaps, &p->heap_map->node, new);
    vmap_unlock(p);
    return inserted;
}

sysreturn mremap(void *old_address, u64 old_size, u64 new_size, int flags, void *new_address)
{
    process p = current->p;
    sysreturn rv;

    old_size = pad(old_size, PAGESIZE);
    range old = irangel(u64_from_pointer(old_address), old_size);
    if ((old.start & PAGEMASK) ||
        (flags & ~(MREMAP_MAYMOVE | MREMAP_FIXED)) ||
        new_size == 0 ||
        (old_size == 0 && (flags & MREMAP_MAYMOVE) == 0)) {
        return -EINVAL;
    }

    /* begin locked portion...no direct returns */
    vmap_lock(p);
    vmap old_vmap = (vmap)rangemap_lookup(p->vmaps, old.start);
    if (old_vmap == INVALID_ADDRESS || !range_contains(old_vmap->node.r, old)) {
        vmap_debug("no match, old_vmap %p, old %R\n", old_vmap, old);
        rv = -EFAULT;
        goto unlock_out;
    }

    if (old_size == 0) {
        if ((old_vmap->flags & VMAP_FLAG_SHARED) == 0) {
            rv = -EINVAL;
            goto unlock_out;
        }
        new_size = MIN(new_size, (range_span(old_vmap->node.r) -
                                  (old.start - old_vmap->node.r.start)));
        old.end = old.start + new_size;
    }

    /* only remap mmap, non-custom regions */
    struct vmap k;
    runtime_memcpy(&k, old_vmap, sizeof(k));
    if ((k.flags & VMAP_FLAG_MMAP) == 0 || (k.flags & VMAP_MMAP_TYPE_CUSTOM)) {
        rv = -EINVAL;
        goto unlock_out;
    }

    range new;
    boolean remap_old = false;
    new_size = pad(new_size, PAGESIZE);
    if (flags & MREMAP_FIXED) {
        if ((flags & MREMAP_MAYMOVE) == 0) {
            rv = -EINVAL;
            goto unlock_out;
        }
        new = irangel(u64_from_pointer(new_address), new_size);
        if ((new.start & PAGEMASK) || ranges_intersect(old, new)) {
            rv = -EINVAL;
            goto unlock_out;
        }
        remap_old = true;
    } else {
        if (new_size > old_size) {
            /* grow check */
            new = irangel(old.start, new_size);
            range delta = irange(old.end, new.end);
            if (rangemap_range_intersects(p->vmaps, delta)) {
                /* collision; allocate new */
                if ((flags & MREMAP_MAYMOVE) == 0) {
                    rv = -ENOMEM;
                    goto unlock_out;
                }
                u64 vnew = process_get_virt_range_locked(p, new_size, PROCESS_VIRTUAL_MMAP_RANGE);
                if (vnew == (u64)INVALID_ADDRESS) {
                    msg_err("failed to allocate virtual memory, size %ld\n", new_size);
                    rv = -ENOMEM;
                    goto unlock_out;
                }
                new = irangel(vnew, new_size);
                vmap_debug("new alloc: %R\n", new);
                remap_old = true;
            } else {
                vmap_debug("extending: %R\n", new);
            }
        } else {
            if (new_size < old_size) {
                range delta = irange(old.start + new_size, old.end);
                vmap_debug("shrinking: remove %R, new %R\n", delta, irangel(old.start, new_size));
                process_remove_range_locked(p, delta, true);
            }
            rv = sysreturn_from_pointer(old.start);
            goto unlock_out;
        }
    }

    process_remove_range_locked(p, old, false);

    /* remove mappings under fixed area */
    if (flags & MREMAP_FIXED)
        process_remove_range_locked(p, new, true);

    /* create new vmap with old attributes */
    k.node.r = new;
    if (allocate_vmap_locked(p->vmaps, &k) == INVALID_ADDRESS) {
        msg_err("failed to allocate vmap\n");
        rv = -ENOMEM;
        goto unlock_out;
    }
    rv = sysreturn_from_pointer(new.start);

    if (remap_old) {
        /* remap existing portion */
        thread_log(current, "   remapping existing portion at 0x%lx (old %R)",
                   new.start, old);
        remap_pages(new.start, old.start, range_span(old));
    }
  unlock_out:
    vmap_unlock(p);
    return rv;
}

closure_function(3, 3, boolean, mincore_fill_vec,
                 u64, base, u64, nr_pgs, u8 *, vec,
                 int level, u64 addr, pteptr entry)
{
    pte e = pte_from_pteptr(entry);
    u64 pgoff, i, size;

    if (pte_is_present(e) &&
        (size = pte_map_size(level, e)) != INVALID_PHYSICAL) {
        if (addr <= bound(base))
            pgoff = 0;
        else
            pgoff = ((addr - bound(base)) >> PAGELOG);

        assert(size >= PAGESIZE);
        assert((size & (size - 1)) == 0);
        size >>= PAGELOG;
        u64 foff = pgoff ? 0 : (addr & (size - 1)) >> PAGELOG;

        for (i = 0; (i < size - foff) && (pgoff + i < bound(nr_pgs)); i++)
            bound(vec)[pgoff + i] = 1;
    }

    return true;
}

closure_func_basic(range_handler, boolean, mincore_vmap_gap,
                   range r)
{
    thread_log(current, "   found gap [0x%lx, 0x%lx)", r.start, r.end);
    return false;
}

static sysreturn mincore(void *addr, u64 length, u8 *vec)
{
    u64 start, nr_pgs;

    start = u64_from_pointer(addr);
    if (start & MASK(PAGELOG))
        return -EINVAL;

    length = pad(length, PAGESIZE);
    nr_pgs = length >> PAGELOG;

    if (!fault_in_user_memory(vec, nr_pgs, true))
        return -EFAULT;

    /* -ENOMEM if any unmapped gaps in range */
    process p = current->p;
    vmap_lock(p);
    boolean found = rangemap_range_find_gaps(p->vmaps, irangel(start, length),
                                             stack_closure_func(range_handler, mincore_vmap_gap)) ==
            RM_ABORT;
    vmap_unlock(p);
    if (found)
        return -ENOMEM;

    runtime_memset(vec, 0, nr_pgs);
    traverse_ptes(start, length,
        stack_closure(mincore_fill_vec, start, nr_pgs, vec)
    );
    return 0;
}

closure_function(1, 1, boolean, vmap_update_protections_validate,
                 u32, newflags,
                 rmnode node)
{
    if (bound(newflags) & ~((vmap)node)->allowed_flags)
        return false;
    return true;
}

static void vmap_set_offsets(vmap to, vmap from, u64 delta)
{
    to->node_offset = from->cache_node ? from->node_offset + delta : 0;
    if (from->flags & VMAP_FLAG_TAIL_BSS) {
        assert(from->bss_offset > delta);
        to->bss_offset = from->bss_offset - delta;
    }
}

/*
   case 1: !head && !tail

   node        |------------|
   i:      <...|------------|...>    i may extend outside of node

   case 2: head && !tail

   node:     |---------------|
   i:           |---------------|

   case 3: !head && tail

   node:        |---------------|
   i:        |---------------|

   case 4: head && tail

   node:   <...|------------|...>    node may extend outside of i
   i:          |------------|
*/

static void alter_vmap_key(vmap k, vmap match, u32 flags, u64 offset_delta)
{
    k->flags = flags;
    k->allowed_flags = match->allowed_flags;
    k->cache_node = match->cache_node;
    if (!(flags & VMAP_FLAG_TAIL_BSS))
        k->fd = match->fd;
    vmap_set_offsets(k, match, offset_delta);
}

static void vmap_update_flags_intersection(rangemap pvmap, range q, u32 clear_mask, u32 set_mask,
                                          vmap match)
{
    vmap_debug("%s: vm %p %R prev flags 0x%x\n", func_ss, match, match->node.r, match->flags);
    if ((match->flags & clear_mask) == set_mask)
        return;

    range rn = match->node.r;
    range ri = range_intersection(q, rn);

    boolean head = ri.start > rn.start;
    boolean tail = ri.end < rn.end;

    u32 newflags = (match->flags & ~clear_mask) | set_mask;

    if (!head && !tail) {
        /* updating flags may result in adjacent maps with same attributes;
           removing and reinserting the node will take care of merging */
        rangemap_remove_node(pvmap, &match->node);
        match->flags = newflags;
        vmap_assert(allocate_vmap_locked(pvmap, match) != INVALID_ADDRESS);
        deallocate_vmap_locked(pvmap, match);
        return;
    }

    struct vmap k;
    if (head) {
        /* split non-intersecting part of node */
        vmap_assert(rangemap_reinsert(pvmap, &match->node, irange(rn.start, ri.start)));

        /* create node for intersection */
        alter_vmap_key(&k, match, newflags, ri.start - rn.start);
        k.node.r = ri;
        vmap_assert(allocate_vmap_locked(pvmap, &k) != INVALID_ADDRESS);

        if (tail) {
            /* create node at tail end */
            alter_vmap_key(&k, match, match->flags, ri.end - rn.start);
            k.node.r = irange(ri.end, rn.end);
            vmap_assert(allocate_vmap_locked(pvmap, &k) != INVALID_ADDRESS);
        }
    } else {
        /* move node start back */
        vmap_assert(rangemap_reinsert(pvmap, &match->node, irange(ri.end, rn.end)));
        alter_vmap_key(&k, match, newflags, ri.start - rn.start);
        vmap_set_offsets(match, match, ri.end - rn.start);

        /* create node for intersection */
        k.node.r = ri;
        vmap_assert(allocate_vmap_locked(pvmap, &k) != INVALID_ADDRESS);
    }
}

closure_func_basic(range_handler, boolean, vmap_update_protections_gap,
                   range r)
{
    vmap_debug("%s: gap %R\n", func_ss, r);
    thread_log(current, "   found gap [0x%lx, 0x%lx)", r.start, r.end);
    return false;
}

static sysreturn vmap_update_protections_locked(heap h, rangemap pvmap, range q, u32 newflags)
{
    assert((q.start & MASK(PAGELOG)) == 0);
    assert((q.end & MASK(PAGELOG)) == 0);
    assert(range_span(q) > 0);

    vmap_debug("%s: q %R newflags 0x%x\n", func_ss, q, newflags);
    if (!validate_user_memory(pointer_from_u64(q.start), range_span(q), false) ||
        (rangemap_range_find_gaps(pvmap, q,
                                  stack_closure_func(range_handler, vmap_update_protections_gap))
         == RM_ABORT))
        return -ENOMEM;

    rmnode_handler v_handler = stack_closure(vmap_update_protections_validate, newflags);
    int res = rangemap_range_lookup(pvmap, q, v_handler);
    if (res == RM_NOMATCH)
        return -ENOMEM;
    else if (res == RM_ABORT)
        return -EACCES;

    /* updating protections can lead to merging of nodes, so we cannot traverse */
    range r = q;
    while (range_span(r)) {
        vmap vm = (vmap)rangemap_lookup(pvmap, r.start);
        vmap_assert(vm != INVALID_ADDRESS);
        vmap_update_flags_intersection(pvmap, q, VMAP_FLAG_PROT_MASK, newflags, vm);
        r.start = MIN(r.end, vm->node.r.end);
    }
    update_map_flags(q.start, range_span(q), pageflags_from_vmflags(newflags));
    vmap_paranoia_locked(pvmap);
    return 0;
}

sysreturn mprotect(void * addr, u64 len, int prot)
{
    if (len == 0)
        return 0;

    u64 where = u64_from_pointer(addr);
    u64 padlen = pad(len, PAGESIZE);
    if ((where & MASK(PAGELOG)))
        return -EINVAL;

    u64 new_vmflags = 0;
    if ((prot & PROT_READ))
        new_vmflags |= VMAP_FLAG_READABLE;
    if ((prot & PROT_WRITE))
        new_vmflags |= VMAP_FLAG_WRITABLE;
    if ((prot & PROT_EXEC))
        new_vmflags |= VMAP_FLAG_EXEC;

    process p = current->p;
    vmap_lock(p);
    sysreturn result = vmap_update_protections_locked(mmap_info.h, p->vmaps,
                                                      irangel(where, padlen), new_vmflags);
    vmap_unlock(p);
    return result;
}

/* blow a hole in the process address space intersecting q */
closure_function(3, 1, boolean, vmap_remove_intersection,
                 rangemap, pvmap, range, q, vmap_handler, unmap,
                 vmap match)
{
    rmnode node = &match->node;
    thread_log(current, "%s: q %R, r %R", func_ss, bound(q), node->r);
    rangemap pvmap = bound(pvmap);
    range rn = node->r;
    range ri = range_intersection(bound(q), rn);
    vmap_debug("%s: vm %p %R, ri %R\n", func_ss, match, rn, ri);

    /* trim match at both head and tail ends */
    boolean head = ri.start > rn.start;
    boolean tail = ri.end < rn.end;

    if (!head && !tail) {
        rangemap_remove_node(pvmap, node);
    } else if (head) {
        /* truncate node at start */
        vmap_assert(rangemap_reinsert(pvmap, node, irange(rn.start, ri.start)));

        if (tail) {
            struct vmap k;
            alter_vmap_key(&k, match, match->flags, ri.end - rn.start);
            /* create node at tail end */
            k.node.r = irange(ri.end, rn.end);
            vmap_assert(allocate_vmap_locked(pvmap, &k) != INVALID_ADDRESS);
        }
    } else {
        /* tail only: move node start back */
        vmap_assert(rangemap_reinsert(pvmap, node, irange(ri.end, rn.end)));
    }
    if (bound(unmap)) {
        struct vmap k;
        alter_vmap_key(&k, match, match->flags, ri.start - rn.start);
        k.node.r = ri;
        apply(bound(unmap), &k);
    }
    if (!head) {
        if (tail)
            match->node_offset += ri.end - rn.start;
        else
            deallocate_vmap_locked(pvmap, match);
    }
    vmap_paranoia_locked(pvmap);
    return true;
}

static void vmap_unmap_page_range(process p, vmap k)
{
    range r = k->node.r;
    int type = k->flags & VMAP_MMAP_TYPE_MASK;
    u64 len = range_span(r);
    switch (type) {
    case VMAP_MMAP_TYPE_ANONYMOUS:
        unmap_and_free_phys(r.start, len);
        break;
    case VMAP_MMAP_TYPE_FILEBACKED:
        pagecache_node_unmap_pages(k->cache_node, r, k->node_offset);
        break;
    case VMAP_MMAP_TYPE_CUSTOM:
        unmap(r.start, len);
        break;
    }
}

closure_function(1, 1, boolean, vmap_unmap,
                 process, p,
                 vmap v)
{
    vmap_unmap_page_range(bound(p), v);
    return true;
}

static void process_remove_range_locked(process p, range q, boolean unmap)
{
    vmap_debug("%s: q %R\n", func_ss, q);
    vmap_handler vh = unmap ? stack_closure(vmap_unmap, p) : 0;
    rangemap_range_lookup(p->vmaps, q,
                          (rmnode_handler)stack_closure(vmap_remove_intersection, p->vmaps, q, vh));
}

/* don't truncate vmap; just unmap truncated pages */
void truncate_file_maps(process p, fsfile f, u64 new_length)
{
    vmap_lock(p);
    u64 padlen = pad(new_length, PAGESIZE);
    pagecache_node pn = fsfile_get_cachenode(f);
    rangemap_foreach(p->vmaps, n) {
        vmap vm = (vmap)n;
        /* an invalidate would be preferable to a sync... */
        if (vm->cache_node != pn)
            continue;
        u64 vm_extent = vm->node_offset + range_span(n->r);
        s64 delta = vm_extent - padlen;
        if (delta <= 0)
            continue;
        range v = irange(n->r.end - delta, n->r.end);
        vmap_assert(v.start <= v.end);
        u64 node_offset = vm->node_offset + (v.start - n->r.start);
        pf_debug("%s: vmap %p, %R, delta 0x%lx, remove v %R, node_offset 0x%lx\n",
                 func_ss, vm, n->r, delta, v, node_offset);
        pagecache_node_unmap_pages(pn, v, node_offset);
    }
    vmap_unlock(p);
}

closure_func_basic(vmap_handler, boolean, msync_vmap,
                   vmap vm)
{
    if ((vm->flags & VMAP_FLAG_SHARED) &&
        (vm->flags & VMAP_FLAG_MMAP) &&
        (vm->flags & VMAP_MMAP_TYPE_MASK) == VMAP_MMAP_TYPE_FILEBACKED) {
        vmap_assert(vm->cache_node);
        pagecache_node_scan_and_commit_shared_pages(vm->cache_node, vm->node.r);
    }
    return true;
}

static sysreturn msync(void *addr, u64 length, int flags)
{
    int syncflags = MS_ASYNC | MS_SYNC;
    if ((flags & ~(MS_ASYNC | MS_SYNC | MS_INVALIDATE)) ||
        (flags & syncflags) == syncflags)
        return -EINVAL;

    boolean have_gap = false;
    if (flags & MS_SYNC) {
        process p = current->p;
        range q = irangel(u64_from_pointer(addr), pad(length, PAGESIZE));
        have_gap = (vmap_range_walk(p, q, stack_closure_func(vmap_handler, msync_vmap), false) ==
                RM_ABORT);
    }

    /* TODO: Linux appears to only use MS_INVALIDATE to test whether a
       map is locked (and return -EBUSY if it is). We don't swap out
       pages, so mlock is a stub for us. For now, assume that the safest
       option here is to act as if all files are locked and return
       -EBUSY - but this may need to be revisited. */
    if (flags & MS_INVALIDATE)
        return -EBUSY;

    /* While an fsync for some types of filesystems makes sense here,
       it doesn't seem to be necessary for block storage - unless some
       use case would have an msync followed by a hard reset / poweroff. */
    return have_gap ? -ENOMEM : 0;
}

static sysreturn mmap(void *addr, u64 length, int prot, int flags, int fd, u64 offset)
{
    process p = current->p;

    u64 len = pad(length, PAGESIZE);
    if (len == 0)
        return -EINVAL;

    /* validate parameters and determine vmap flags */
    u64 vmflags = VMAP_FLAG_MMAP;

    int map_type = flags & MAP_TYPE_MASK;
    if (map_type == MAP_SHARED || map_type == MAP_SHARED_VALIDATE)
        vmflags |= VMAP_FLAG_SHARED;
    else if (map_type != MAP_PRIVATE)
        return -EINVAL;

    if ((prot & PROT_READ))
        vmflags |= VMAP_FLAG_READABLE;
    if ((prot & PROT_WRITE))
        vmflags |= VMAP_FLAG_WRITABLE;
    if ((prot & PROT_EXEC))
        vmflags |= VMAP_FLAG_EXEC;

    if (flags & MAP_UNINITIALIZED) {
        return -EINVAL;
    }
    if (flags & MAP_GROWSDOWN) {
        vmflags |= VMAP_FLAG_STACK;
    }

    /* ignore MAP_DENYWRITE, MAP_EXECUTABLE, MAP_LOCKED, MAP_STACK, MAP_NORESERVE */
    int valid_flags = MAP_TYPE_MASK | MAP_FIXED | MAP_ANONYMOUS |
        MAP_GROWSDOWN | MAP_DENYWRITE | MAP_EXECUTABLE | MAP_LOCKED | MAP_NORESERVE |
        MAP_POPULATE | MAP_NONBLOCK | MAP_STACK | MAP_HUGETLB | MAP_SYNC |
        MAP_FIXED_NOREPLACE | MAP_UNINITIALIZED |
#ifdef __x86_64__
        MAP_32BIT |
#endif
        (HUGETLB_FLAG_ENCODE_MASK << HUGETLB_FLAG_ENCODE_SHIFT);
    int unknown_flags = flags & ~valid_flags;
    if (unknown_flags) {
        return -EINVAL;
    }

    /* handle fixed address or hint */
    fdesc desc = 0;
    sysreturn ret = -EINVAL;
    boolean fixed = (flags & (MAP_FIXED | MAP_FIXED_NOREPLACE)) != 0;
    range q = irangel(u64_from_pointer(addr), len);
    vmap_lock(p);
    if (fixed) {
	/* Must be page-aligned */
	if (q.start & MASK(PAGELOG)) {
	    goto out_unlock;
	}
        if (!validate_mmap_range(p, q)) {
            goto out_unlock;
        }
        if ((flags & MAP_FIXED_NOREPLACE) &&
            rangemap_range_intersects(p->vmaps, q)) {
            thread_log(current, "   MAP_FIXED_NOREPLACE and collision in range %R", q);
            ret = -EEXIST;
            goto out_unlock;
        }
    } else if (q.start != 0) {
        q = irangel(pad(q.start, PAGESIZE), len);
        if (rangemap_range_intersects(p->vmaps, q)) {
            thread_log(current, "   hint %R collides, reverting to allocation", q);
            q.start = 0;
        }
    }

    /* having checked parameters, procure backing resources */
    fsfile fsf = 0;
    u32 allowed_flags;
    u64 vmap_mmap_type;
    pagecache_node node = 0;
    if (flags & MAP_ANONYMOUS) {
        vmap_mmap_type = VMAP_MMAP_TYPE_ANONYMOUS;
        vmflags |= VMAP_FLAG_THP;
        allowed_flags = anon_perms(p);
    } else {
        desc = resolve_fd(p, fd); /* must return via out label to release fdesc */
        switch (desc->type) {
        case FDESC_TYPE_REGULAR:
            thread_log(current, "   fd %d: file-backed (regular)", fd);
            vmap_mmap_type = VMAP_MMAP_TYPE_FILEBACKED;
            file f = (file)desc;
            fsf = f->fsf;
            assert(fsf);
            allowed_flags = file_perms(p, f);
            if (!(vmflags & VMAP_FLAG_SHARED)) {
                allowed_flags |= VMAP_FLAG_WRITABLE;
            } else {
                filesystem fs = fsf->fs;
                if (fs->get_seals) {
                    u64 seals;
                    if ((fs->get_seals(fs, fsf, &seals) == 0) &&
                        (seals & (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE))) {
                        if (vmflags & VMAP_FLAG_WRITABLE) {
                            ret = -EPERM;
                            goto out_unlock;
                        }
                        allowed_flags &= ~VMAP_FLAG_WRITABLE;
                    }
                }
            }
            if (offset & PAGEMASK) {
                ret = -EINVAL;
                goto out_unlock;
            }
            node = fsfile_get_cachenode(fsf);
            thread_log(current, "   associated with cache node %p @ offset 0x%lx", node, offset);
            break;
        default:
            thread_log(current, "   fd %d: custom", fd);
            if (!desc->mmap) {
                thread_log(current, "   fail: attempt to mmap file of invalid type %d", desc->type);
                ret = -EINVAL;
                goto out_unlock;
            }
            vmap_mmap_type = VMAP_MMAP_TYPE_CUSTOM;
            allowed_flags = vmflags;
            break;
        }
    }
    if ((vmflags & VMAP_FLAG_PROT_MASK) & ~allowed_flags) {
        thread_log(current, "   fail: forbidden access type 0x%x (allowed 0x%x)",
                   vmflags & VMAP_FLAG_PROT_MASK, allowed_flags);
        ret = -EACCES;
        goto out_unlock;
    }
    vmflags |= vmap_mmap_type;

    /* allocate or update old mapping */
    struct vmap k = ivmap(vmflags, allowed_flags, offset, node, desc);
    if (!fixed && q.start == 0) {
        range alloc_region =
#ifdef __x86_64__
            (flags & MAP_32BIT) ? PROCESS_VIRTUAL_32BIT_RANGE :
#endif
            PROCESS_VIRTUAL_MMAP_RANGE;
        u64 vaddr = process_get_virt_range_locked(p, len, alloc_region);
        if (vaddr == INVALID_PHYSICAL) {
            ret = -ENOMEM;
            thread_log(current, "   failed to get virtual address range");
            goto out_unlock;
        }
        q = irangel(vaddr, len);
    }
    if (vmap_mmap_type == VMAP_MMAP_TYPE_CUSTOM) {
        k.node.r = q;
        ret = apply(desc->mmap, &k, offset);
        if (ret < 0) {
            thread_log(current, "   custom_mmap() failed with %ld", ret);
            goto out_unlock;
        }
    }
    if (fixed)
        process_remove_range_locked(p, q, vmap_mmap_type != VMAP_MMAP_TYPE_CUSTOM);
    k.node.r = q;
    vmap vm = allocate_vmap_locked(p->vmaps, &k);
    vmap_assert(vm != INVALID_ADDRESS);
    vm->fault = k.fault;
    vmap_unlock(p);

    if (vmap_mmap_type == VMAP_MMAP_TYPE_FILEBACKED && (vmflags & VMAP_FLAG_SHARED))
        pagecache_node_add_shared_map(node, irangel(q.start, len), offset);

    /* as man page suggests, ignore MAP_POPULATE if MAP_NONBLOCK is specified */
    if ((flags & (MAP_POPULATE | MAP_NONBLOCK)) == MAP_POPULATE && (prot & PROT_READ)) {
        vmap_debug("   faulting in %R\n", q);
        fault_in_user_memory(pointer_from_u64(q.start), len, false);
    }
    ret = q.start;
  out:
    if (desc)
        fdesc_put(desc);
    return ret;
  out_unlock:
    vmap_unlock(p);
    goto out;
}

static sysreturn munmap(void *addr, u64 length)
{
    process p = current->p;

    u64 where = u64_from_pointer(addr);
    if ((where & MASK(PAGELOG)) || length == 0)
        return -EINVAL;

    vmap_lock(p);
    process_remove_range_locked(p, irangel(where, pad(length, PAGESIZE)), true);
    vmap_unlock(p);
    return 0;
}

closure_function(2, 1, boolean, madvise_vmap_validate,
                 int, advice, sysreturn *, rv,
                 rmnode n)
{
    return true;
}

sysreturn madvise(void *addr, s64 length, int advice)
{
    if ((u64_from_pointer(addr) & PAGEMASK) || (length < 0))
        return -EINVAL;
    u32 clear_mask = 0, set_mask = 0;
    switch (advice) {
    case MADV_HUGEPAGE:
        set_mask = VMAP_FLAG_THP;
        break;
    case MADV_NOHUGEPAGE:
        clear_mask = VMAP_FLAG_THP;
        break;
    default:
        return 0;   /* ignore non-supported advice values */
    }
    process p = current->p;
    rangemap vmaps = p->vmaps;
    range q = irangel(u64_from_pointer(addr), pad(length, PAGESIZE));
    sysreturn rv = 0;
    rmnode_handler vmap_handler = stack_closure(madvise_vmap_validate, advice, &rv);
    range_handler gap_handler = stack_closure_func(range_handler, vmap_validate_gap);
    vmap_lock(p);
    int res = rangemap_range_lookup_with_gaps(vmaps, q, vmap_handler, gap_handler);
    if (res == RM_MATCH) {
        while (range_span(q)) {
            vmap vm = (vmap)rangemap_lookup(vmaps, q.start);
            vmap_update_flags_intersection(vmaps, q, clear_mask, set_mask, vm);
            q.start = MIN(q.end, vm->node.r.end);
        }
        rv = 0;
    } else {
        if (rv == 0)    /* either the address range is not mapped, or there are unmapped gaps */
            rv = -ENOMEM;
    }
    vmap_unlock(p);
    return rv;
}

/* kernel start */
extern void * START;

static u64 vmh_alloc(struct heap *h, bytes b)
{
    process p = ((vmap_heap)h)->p;
    vmap_lock(p);
    u64 ret = process_allocate_range_locked(p, b, ivmap(0, 0, 0, 0, 0),
                                            PROCESS_VIRTUAL_MMAP_RANGE);
    vmap_unlock(p);
    return ret;
}

void vmh_dealloc(struct heap *h, u64 a, bytes b)
{
    vmap_heap vmh = (vmap_heap)h;
    process p = vmh->p;
    range q = irangel(a, b);
    vmap_range_walk(p, q, stack_closure(vmap_remove_intersection, p->vmaps, q, 0), true);
}

closure_function(1, 1, boolean, vmh_allocated_handler,
                 u64 *, allocated,
                 vmap vm)
{
    *bound(allocated) += range_span(vm->node.r);
    return true;
}

bytes vmh_allocated(struct heap *h)
{
    vmap_heap vmh = (vmap_heap)h;
    process p = vmh->p;
    bytes allocated = 0;
    vmap_range_walk(p, irange(0, PROCESS_VIRTUAL_HEAP_LIMIT),
                    stack_closure(vmh_allocated_handler, &allocated), true);
    return allocated;
}

bytes vmh_total(struct heap *h)
{
    return PROCESS_VIRTUAL_HEAP_LIMIT;
}

closure_function(2, 1, boolean, check_vmap_permissions,
                 u64, required_flags, u64, disallowed_flags,
                 vmap vm)
{
    u64 rf = bound(required_flags), df = bound(disallowed_flags);
    return ((vm->flags & rf) == rf && (vm->flags & df) == 0);
}

boolean validate_user_memory_permissions(process p, const void *buf, bytes length,
                                         u64 required_flags, u64 disallowed_flags)
{
    u64 addr = u64_from_pointer(buf);
    range q = irange(addr, pad(addr + length, PAGESIZE));
    int res = vmap_range_walk(p, q, stack_closure(check_vmap_permissions, required_flags,
                                                  disallowed_flags),
                              false);
    return res == RM_MATCH;
}

boolean fault_in_memory(const void *buf, bytes length)
{
    context ctx = get_current_context(current_cpu());
    if (context_set_err(ctx))
        return false;
    /* Fault in non-present pages by touching each page in buffer */
    touch_memory(buf, length);
    context_clear_err(ctx);
    return true;
}

boolean fault_in_user_memory(const void *buf, bytes length, boolean writable)
{
    if (writable) {
        if (!validate_user_memory_permissions(current->p, buf, length, VMAP_FLAG_WRITABLE, 0))
            return false;
    } else {
        if (!validate_user_memory(buf, length, false))
            return false;
    }

    return fault_in_memory(buf, length);
}

void mmap_process_init(process p, tuple root)
{
    kernel_heaps kh = get_kernel_heaps();
    heap h = heap_locked(kh);
    boolean aslr = !get(root, sym(noaslr));
    mmap_info.h = h;
    boolean low_memory = is_low_memory_machine();
    value transparent_hugepage = get(root, sym(transparent_hugepage));
    if (transparent_hugepage) {
        if (is_string(transparent_hugepage)) {
            if (!buffer_strcmp(transparent_hugepage, "never"))
                mmap_info.thp_max_size = PAGESIZE;
        }
        if (!mmap_info.thp_max_size)
            msg_err("invalid 'transparent_hugepage' value '%v'\n", transparent_hugepage);
    }
    if (!mmap_info.thp_max_size)
        mmap_info.thp_max_size = low_memory ? PAGEHEAP_LOWMEM_PAGESIZE : PAGESIZE_2M;
    bytes memory_reserve = low_memory ? PAGEHEAP_LOWMEM_MEMORY_RESERVE : PAGEHEAP_MEMORY_RESERVE;
    mmap_info.virtual_backed = reserve_heap_wrapper(h, (heap)heap_page_backed(kh), memory_reserve);
    spin_lock_init(&p->vmap_lock);
    u64 min_addr;
    if (get_u64(root, sym(mmap_min_addr), &min_addr))
        p->mmap_min_addr = min_addr;
    else
        p->mmap_min_addr = PAGESIZE;
    p->vmaps = allocate_rangemap(h);
    assert(p->vmaps != INVALID_ADDRESS);
    vmap_heap vmh = allocate(h, sizeof(struct vmap_heap));
    assert(vmh != INVALID_ADDRESS);
    vmh->h.alloc = vmh_alloc;
    vmh->h.dealloc = vmh_dealloc;
    vmh->h.allocated = vmh_allocated;
    vmh->h.pagesize = PAGESIZE;
    vmh->h.total = vmh_total;
    vmh->p = p;
    vmh->randomize = aslr;
    p->virtual = &vmh->h;

    /* randomly determine vdso/vvar base and track it */
    u64 vdso_size, vvar_size;

    vdso_size = vdso_raw_length;
    vvar_size = VVAR_NR_PAGES * PAGESIZE;

    p->vdso_base = process_get_virt_range_locked(p, vdso_size + vvar_size, PROCESS_VIRTUAL_MMAP_RANGE);
    struct vmap k = ivmap(VMAP_FLAG_EXEC, 0, 0, 0, 0);
    k.node.r = irangel(p->vdso_base, vdso_size);
    vmap_assert(allocate_vmap_locked(p->vmaps, &k) != INVALID_ADDRESS);

    /* vvar goes right after the vdso */
    k = ivmap(0, 0, 0, 0, 0);
    k.node.r = irangel(p->vdso_base + vdso_size, vvar_size);
    vmap_assert(allocate_vmap_locked(p->vmaps, &k) != INVALID_ADDRESS);

#ifdef __x86_64__
    /* Track vsyscall page */
    k = ivmap(VMAP_FLAG_EXEC, 0, 0, 0, 0);
    k.node.r = irangel(VSYSCALL_BASE, PAGESIZE);
    vmap_assert(allocate_vmap_locked(p->vmaps, &k) != INVALID_ADDRESS);
#endif

    list_init(&mmap_info.pf_freelist);
}

void register_mmap_syscalls(struct syscall *map)
{
    register_syscall(map, mincore, mincore);
    register_syscall(map, mmap, mmap);
    register_syscall(map, mremap, mremap);
    register_syscall(map, msync, msync);
    register_syscall(map, munmap, munmap);
    register_syscall(map, mprotect, mprotect);
    register_syscall(map, madvise, madvise);
}
