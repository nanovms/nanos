#include <unix_internal.h>
#include <storage.h>

//#define VMAP_PARANOIA

//#define PF_DEBUG
#ifdef PF_DEBUG
#define pf_debug(x, ...) do {tprintf(sym(fault), 0, x, ##__VA_ARGS__);} while(0)
#else
#define pf_debug(x, ...)
#endif

//#define VMAP_DEBUG
#ifdef VMAP_DEBUG
#define vmap_debug(x, ...) do {tprintf(sym(vmap), 0, x, ##__VA_ARGS__);} while(0)
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
                 __LINE__, __func__);                                   \
        }                                                               \
    } while(0)

#define vmap_lock(p) u64 _savedflags = spin_lock_irq(&(p)->vmap_lock)
#define vmap_unlock(p) spin_unlock_irq(&(p)->vmap_lock, _savedflags)

typedef struct vmap_heap {
    struct heap h;  /* must be first */
    process p;
    boolean randomize;
} *vmap_heap;

declare_closure_function(0, 2, int, pending_fault_compare,
                         rbnode, a, rbnode, b);
declare_closure_function(0, 1, boolean, pending_fault_print,
                         rbnode, n);
static struct {
    heap h;
    heap virtual_backed;

    closure_struct(pending_fault_compare, pf_compare);
    closure_struct(pending_fault_print, pf_print);

    struct list pf_freelist;
} mmap_info;

static status demand_anonymous_page(pending_fault pf, context ctx, vmap vm, u64 vaddr);

define_closure_function(0, 2, int, pending_fault_compare,
                        rbnode, a, rbnode, b)
{
    u64 pa = ((pending_fault)a)->addr;
    u64 pb = ((pending_fault)b)->addr;
    return pa == pb ? 0 : (pa < pb ? -1 : 1);
}

define_closure_function(0, 1, boolean, pending_fault_print,
                        rbnode, n)
{
    rprintf(" 0x%lx", ((pending_fault)n)->addr);
    return true;
}

define_closure_function(1, 1, void, pending_fault_complete,
                        pending_fault, pf,
                        status, s)
{
    pending_fault pf = bound(pf);
    pf_debug("%s: page 0x%lx, status %v\n", __func__, pf->addr, s);
    if (!is_ok(s)) {
        rprintf("%s: page fill failed with %v\n", __func__, s);
    } else if (pf->bss_start > 0) {
        assert(pf->bss_start < PAGESIZE);
        range r = irangel(pf->addr + pf->bss_start, PAGESIZE - pf->bss_start);
        zero(pointer_from_u64(r.start), range_span(r));
    }
    context ctx;
    process p = pf->p;
    u64 flags = spin_lock_irq(&p->faulting_lock);
    vector_foreach(pf->dependents, ctx) {
        pf_debug("   wake ctx %p\n", ctx);

        demand_page_done(ctx, pf->addr, timm_clone(s));
        context_schedule_return(ctx);
    }
    vector_clear(pf->dependents);
    rbtree_remove_node(&p->pending_faults, &pf->n);
    list_insert_after(&mmap_info.pf_freelist, &pf->l_free);
    spin_unlock_irq(&p->faulting_lock, flags);
    if (!is_ok(s))
        timm_dealloc(s);
}

static pending_fault new_pending_fault_locked(process p, u64 addr)
{
    pending_fault pf;
    list l;
    if ((l = list_get_next(&mmap_info.pf_freelist))) {
        pf = struct_from_list(l, pending_fault, l_free);
        list_delete(l);
    } else {
        pf = allocate(mmap_info.h, sizeof(struct pending_fault));
        assert(pf != INVALID_ADDRESS);
        pf->dependents = allocate_vector(mmap_info.h, sizeof(context) * 4);
        assert(pf->dependents != INVALID_ADDRESS);
    }
    init_rbnode(&pf->n);
    pf->addr = addr;
    pf->bss_start = 0;
    pf->p = p;
    init_closure(&pf->complete, pending_fault_complete, pf);
    assert(rbtree_insert_node(&p->pending_faults, &pf->n));
    return pf;
}

static pending_fault find_pending_fault_locked(process p, u64 addr)
{
    struct pending_fault k;
    k.addr = addr;
    rbnode n = rbtree_lookup(&p->pending_faults, &k.n);
    if (n == INVALID_ADDRESS)
        return 0;
    return (pending_fault)n;
}

/* returns physical address */
u64 new_zeroed_pages(u64 v, u64 length, pageflags flags, status_handler complete)
{
    assert((v & MASK(PAGELOG)) == 0);
    void *m = allocate(mmap_info.virtual_backed, length);
    if (m == INVALID_ADDRESS) {
        vmap_debug("%s: cannot get physical page\n", __func__);
        return INVALID_PHYSICAL;
    }
    zero(m, length);
    write_barrier();
    u64 p = physical_from_virtual(m);
    u64 mapped_p = map_with_complete(v, p, length, flags, complete);
    if (mapped_p != p)
        /* The mapping must have been done in parallel by another CPU. */
        deallocate(mmap_info.virtual_backed, m, length);
    return mapped_p;
}

static void demand_page_major_fault(pending_fault pf, context ctx)
{
    spinlock lock = &pf->p->faulting_lock;
    spin_lock(lock);
    vector_push(pf->dependents, ctx);
    spin_unlock(lock);
    count_major_fault();
    context_pre_suspend(ctx);
}

closure_function(4, 1, void, mmap_anon_page,
                 boolean, flush_done, pending_fault, pf, vmap, vm, u64, vaddr,
                 status, s)
{
    if (!bound(flush_done)) {
        bound(flush_done) = true;
        storage_sync((status_handler)closure_self());
        return;
    }
    if (!is_ok(s)) {
        pf_debug("%s: storage sync failed: %v\n", __func__, s);
        timm_dealloc(s);
    }
    mm_service(false);
    s = demand_anonymous_page(bound(pf), 0, bound(vm), bound(vaddr));
    timm_dealloc(s);
    closure_finish();
}

static status demand_anonymous_page(pending_fault pf, context ctx, vmap vm, u64 vaddr)
{
    status_handler completion = (status_handler)&pf->complete;
    if (new_zeroed_pages(vaddr & ~MASK(PAGELOG), PAGESIZE, pageflags_from_vmflags(vm->flags),
                         completion) == INVALID_PHYSICAL) {
        if (ctx) {
            status_handler sh = closure(mmap_info.h, mmap_anon_page, false, pf, vm, vaddr);
            if (sh != INVALID_ADDRESS) {
                pf_debug("anonymous page major fault, addr %p\n", pf->addr);
                demand_page_major_fault(pf, ctx);
                async_apply_bh((thunk)sh);
                kern_yield();
            }
        }
        apply(completion, timm("result", "out of memory"));
        return timm("result", "out of memory");
    }
    count_minor_fault();
    return STATUS_OK;
}

define_closure_function(3, 0, void, pending_fault_demand_file_page,
                        vmap, vm, u64, node_offset, pageflags, flags)
{
    pending_fault pf = struct_from_field(closure_self(), pending_fault, demand_file_page);
    vmap vm = bound(vm);
    u64 node_offset = bound(node_offset);
    pageflags flags = bound(flags);
    pagecache_node pn = vm->cache_node;
    pf_debug("%s: pending_fault %p, node_offset 0x%lx, page_addr 0x%lx, flags 0x%lx\n",
             __func__, pf, node_offset, pf->addr, flags);
    pagecache_map_page(pn, node_offset, pf->addr, flags,
                       (status_handler)&pf->complete);
    range ra = irange(node_offset + PAGESIZE,
        vm->node_offset + range_span(vm->node.r));
    if (range_valid(ra)) {
        if (range_span(ra) > FILE_READAHEAD_DEFAULT)
            ra.end = ra.start + FILE_READAHEAD_DEFAULT;
        pagecache_node_fetch_pages(pn, ra);
    }
}

static status demand_filebacked_page(process p, context ctx, vmap vm, u64 vaddr, pending_fault pf)
{
    pageflags flags = pageflags_from_vmflags(vm->flags);
    u64 page_addr = vaddr & ~PAGEMASK;
    u64 vmap_offset = page_addr - vm->node.r.start;
    u64 node_offset = vm->node_offset + vmap_offset;
    boolean shared = (vm->flags & VMAP_FLAG_SHARED) != 0;
    if (!shared && !(vm->flags & VMAP_FLAG_PROG))
        flags = pageflags_readonly(flags); /* cow */

    pf_debug("   node %p (start 0x%lx), offset 0x%lx, vm flags 0x%lx, pageflags 0x%lx\n",
             vm->cache_node, vm->node.r.start, node_offset, vm->flags, flags.w);

    u64 padlen = pad(pagecache_get_node_length(vm->cache_node), PAGESIZE);
    pf_debug("   map length 0x%lx\n", padlen);
    status_handler completion = (status_handler)&pf->complete;
    if (node_offset >= padlen) {
        pf_debug("   extends past map limit 0x%lx\n", padlen);
        apply(completion, timm("result", "out of range page"));
        return timm("result", "out of range page");
    }

    if ((vm->flags & VMAP_FLAG_TAIL_BSS) &&
        point_in_range(irangel(vmap_offset, PAGESIZE), vm->bss_offset))
        pf->bss_start = vm->bss_offset - vmap_offset;

    if (pagecache_map_page_if_filled(vm->cache_node, node_offset, page_addr, flags, completion)) {
        pf_debug("   immediate completion\n");
        count_minor_fault();
        return STATUS_OK;
    }

    /* page not filled - schedule a page fill for this thread */
    init_closure(&pf->demand_file_page, pending_fault_demand_file_page, vm, node_offset, flags);
    demand_page_major_fault(pf, ctx);
    async_apply_bh((thunk)&pf->demand_file_page);

    /* no need to reserve context; we're on exception/int stack */
    kern_yield();
}

status do_demand_page(process p, context ctx, u64 vaddr, vmap vm)
{
    u64 page_addr = vaddr & ~PAGEMASK;

    if ((vm->flags & (VMAP_FLAG_MMAP | VMAP_FLAG_STACK | VMAP_FLAG_HEAP |
                      VMAP_FLAG_BSS | VMAP_FLAG_PROG)) == 0) {
        msg_err("vaddr 0x%lx matched vmap with invalid flags (0x%x)\n",
                vaddr, vm->flags);
        return timm("result", "vaddr 0x%lx matched vmap with invalid flags (0x%x)\n",
                vaddr, vm->flags);
    }

    pf_debug("%s: %s context, %s, vaddr %p, vm flags 0x%02lx,\n", __func__,
             context_type_strings[ctx->type],
             string_from_mmap_type(vm->flags & VMAP_MMAP_TYPE_MASK),
             vaddr, vm->flags);
    pf_debug("   vmap %p, context %p\n", vm, ctx);

    u64 flags = spin_lock_irq(&p->faulting_lock);
    pending_fault pf = find_pending_fault_locked(p, page_addr);
    if (pf) {
        pf_debug("   found pending_fault %p\n", pf);
        vector_push(pf->dependents, ctx);
        spin_unlock_irq(&p->faulting_lock, flags);
        count_minor_fault(); /* XXX not precise...stash pt type in faulting thread? */
    } else {
        pf = new_pending_fault_locked(p, page_addr);
        spin_unlock_irq(&p->faulting_lock, flags);
        pf_debug("   new pending_fault %p\n", pf);
        if (vm->flags & VMAP_FLAG_MMAP) {
            int mmap_type = vm->flags & VMAP_MMAP_TYPE_MASK;
            switch (mmap_type) {
            case VMAP_MMAP_TYPE_ANONYMOUS:
                return demand_anonymous_page(pf, ctx, vm, vaddr);
            case VMAP_MMAP_TYPE_FILEBACKED:
                return demand_filebacked_page(p, ctx, vm, vaddr, pf);
            default:
                halt("%s: invalid vmap type %d, flags 0x%lx\n", __func__, mmap_type, vm->flags);
            }
        } else if (vm->flags & VMAP_FLAG_PROG) {
            pf_debug("   file-backed program page fault\n");
            return demand_filebacked_page(p, ctx, vm, vaddr, pf);
        } else {
            pf_debug("   bss / stack / heap page fault\n");
            return demand_anonymous_page(pf, ctx, vm, vaddr);
        }
    }
    context_pre_suspend(ctx);
    kern_yield();
}

static inline vmap vmap_from_vaddr_locked(process p, u64 vaddr)
{
    return (vmap)rangemap_lookup(p->vmaps, vaddr);
}

vmap vmap_from_vaddr(process p, u64 vaddr)
{
    vmap_lock(p);
    vmap vm = vmap_from_vaddr_locked(p, vaddr);
    vmap_unlock(p);
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
                 vmap, vm)
{
    u32 flags = bound(flags);
    return (vm->flags & flags) == flags;
}

closure_function(0, 1, boolean, vmap_validate_gap,
                 range, q)
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
    range_handler gap_handler = allow_gaps ? 0 : stack_closure(vmap_validate_gap);
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

closure_function(0, 1, boolean, vmap_dump_node,
                 rmnode, n)
{
    vmap curr = (vmap)n;
    rprintf("  %R, %s%s %s%s\n", curr->node.r,
            (curr->flags & VMAP_FLAG_MMAP) ? "mmap " : "",
            string_from_mmap_type(curr->flags & VMAP_MMAP_TYPE_MASK),
            (curr->flags & VMAP_FLAG_WRITABLE) ? "writable " : "",
            (curr->flags & VMAP_FLAG_EXEC) ? "exec " : "");
    return true;
}

void vmap_dump(rangemap pvmap)
{
    rprintf("vmaps:\n");
    rmnode_handler nh = stack_closure(vmap_dump_node);
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
                 rmnode, n)
{
    vmap v = (vmap)n;
    vmap last = *bound(last);
    if (last && vmap_compare_attributes(last, v) && last->node.r.end == v->node.r.start) {
        rprintf("%s: check failed; adjacent nodes %p (%R) and %p (%R) share same attributes\n",
                __func__, last, last->node.r, v, v->node.r);
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
        halt("%s failed\n", __func__);
    }
}
#else
#define vmap_paranoia_locked(x)
#endif

/* TODO maybe refcount makes more sense now that we have asynchronous faults */
static void deallocate_vmap_locked(rangemap rm, vmap vm)
{
    vmap_debug("%s: vm %p %R\n", __func__, vm, vm->node.r);
    if (!(vm->flags & VMAP_FLAG_TAIL_BSS) && vm->fd)
        fdesc_put(vm->fd);
    deallocate(rm->h, vm, sizeof(struct vmap));
}

static vmap allocate_vmap_locked(rangemap rm, range q, struct vmap k)
{
    k.node.r = q;
    vmap vm;

    vmap_debug("%s: q %R\n", __func__, q);
    vm = (vmap)rangemap_lookup_max_lte(rm, q.start);
    vmap next;
    if (vm != INVALID_ADDRESS) {
        if (vm->node.r.end > q.start)
            return INVALID_ADDRESS;
        next = (vmap)rangemap_next_node(rm, &vm->node);
        if (vm->node.r.end == q.start && vmap_compare_attributes(vm, &k)) {
            range new = irange(vm->node.r.start, q.end);
            if (next != INVALID_ADDRESS) {
                if (next->node.r.start < q.end)
                    return INVALID_ADDRESS;
                if (next->node.r.start == q.end && vmap_compare_attributes(next, &k)) {
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
        q.end == next->node.r.start && vmap_compare_attributes(next, &k)) {
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
    vm->flags = k.flags;
    vm->allowed_flags = k.allowed_flags;
    vm->node_offset = k.node_offset;
    vm->cache_node = k.cache_node;
    vm->fd = k.fd;
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
    vmap_lock(p);
    vmap v = allocate_vmap_locked(p->vmaps, q, k);
    vmap_unlock(p);
    return v;
}

static inline boolean validate_mmap_range(process p, range q)
{
    return range_valid(q) && q.start >= p->mmap_min_addr && q.end <= USER_LIMIT;
}

closure_function(3, 1, boolean, proc_virt_gap_handler,
                 u64, size, boolean, randomize, u64 *, addr,
                 range, r)
{
    u64 size = bound(size);
    if (range_span(r) <= size)
        return true;

    u64 offset;
    if (bound(randomize))
        offset = (random_u64() % ((range_span(r) - size) >> PAGELOG)) << PAGELOG;
    else
        offset = 0;
    *bound(addr) = r.start + offset;
    return false;           /* finished, not failure */
}

/* Does NOT mark the returned address as allocated in the virtual heap. */
static u64 process_get_virt_range_locked(process p, u64 size, range region)
{
    assert(!(size & PAGEMASK));
    vmap_heap vmh = (vmap_heap)p->virtual;
    u64 addr = INVALID_PHYSICAL;
    rangemap_range_find_gaps(p->vmaps, region,
                             stack_closure(proc_virt_gap_handler, size,
                                           vmh->randomize, &addr));
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
        vmap vm = allocate_vmap_locked(p->vmaps, irangel(virt_addr, size), k);
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
               __func__, phys_addr, size, vmflags);
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
    thread_log(current, "mremap: old_address %p, old_size 0x%lx, new_size 0x%lx, flags 0x%x, "
               "new_address %p", old_address, old_size, new_size, flags, new_address);

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
    struct vmap k = *old_vmap;
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
    if (allocate_vmap_locked(p->vmaps, new, k) == INVALID_ADDRESS) {
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
                 int, level, u64, addr, pteptr, entry)
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

closure_function(0, 1, boolean, mincore_vmap_gap,
                 range, r)
{
    thread_log(current, "   found gap [0x%lx, 0x%lx)", r.start, r.end);
    return false;
}

static sysreturn mincore(void *addr, u64 length, u8 *vec)
{
    u64 start, nr_pgs;

    thread_log(current, "mincore: addr %p, length 0x%lx, vec %p",
               addr, length, vec);

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
                                             stack_closure(mincore_vmap_gap)) == RM_ABORT;
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
                 rmnode, node)
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

struct vmap altered_vmap_key(vmap match, u32 flags, u64 offset_delta)
{
    struct vmap k;
    k.flags = flags;
    k.allowed_flags = match->allowed_flags;
    k.cache_node = match->cache_node;
    if (!(flags & VMAP_FLAG_TAIL_BSS))
        k.fd = match->fd;
    vmap_set_offsets(&k, match, offset_delta);
    return k;
}

void vmap_update_protections_intersection(heap h, rangemap pvmap, range q, u32 newflags,
                                          vmap match)
{
    vmap_debug("%s: vm %p %R prev flags 0x%x\n", __func__, match, match->node.r, match->flags);
    if (newflags == match->flags)
        return;

    range rn = match->node.r;
    range ri = range_intersection(q, rn);

    boolean head = ri.start > rn.start;
    boolean tail = ri.end < rn.end;

    /* protection flags only */
    newflags = (match->flags & ~(VMAP_FLAG_WRITABLE | VMAP_FLAG_EXEC)) | newflags;

    if (!head && !tail) {
        /* updating flags may result in adjacent maps with same attributes;
           removing and reinserting the node will take care of merging */
        rangemap_remove_node(pvmap, &match->node);
        match->flags = newflags;
        vmap_assert(allocate_vmap_locked(pvmap, match->node.r, *match) != INVALID_ADDRESS);
        deallocate_vmap_locked(pvmap, match);
        return;
    }

    struct vmap k;
    if (head) {
        /* split non-intersecting part of node */
        vmap_assert(rangemap_reinsert(pvmap, &match->node, irange(rn.start, ri.start)));

        /* create node for intersection */
        k = altered_vmap_key(match, newflags, ri.start - rn.start);
        vmap_assert(allocate_vmap_locked(pvmap, ri, k) != INVALID_ADDRESS);

        if (tail) {
            /* create node at tail end */
            k = altered_vmap_key(match, match->flags, ri.end - rn.start);
            vmap_assert(allocate_vmap_locked(pvmap, irange(ri.end, rn.end), k) != INVALID_ADDRESS);
        }
    } else {
        /* move node start back */
        vmap_assert(rangemap_reinsert(pvmap, &match->node, irange(ri.end, rn.end)));
        struct vmap l = altered_vmap_key(match, newflags, ri.start - rn.start);
        vmap_set_offsets(match, match, ri.end - rn.start);

        /* create node for intersection */
        vmap_assert(allocate_vmap_locked(pvmap, ri, l) != INVALID_ADDRESS);
    }
}

closure_function(0, 1, boolean, vmap_update_protections_gap,
                 range, r)
{
    vmap_debug("%s: gap %R\n", __func__, r);
    thread_log(current, "   found gap [0x%lx, 0x%lx)", r.start, r.end);
    return false;
}

static sysreturn vmap_update_protections_locked(heap h, rangemap pvmap, range q, u32 newflags)
{
    assert((q.start & MASK(PAGELOG)) == 0);
    assert((q.end & MASK(PAGELOG)) == 0);
    assert(range_span(q) > 0);

    thread_log(current, "%s: validate %R", __func__, q);
    vmap_debug("%s: q %R newflags 0x%x\n", __func__, q, newflags);
    if (!validate_user_memory(pointer_from_u64(q.start), range_span(q), false) ||
        (rangemap_range_find_gaps(pvmap, q, stack_closure(vmap_update_protections_gap))
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
        vmap_update_protections_intersection(h, pvmap, q, newflags, vm);
        r.start = MIN(r.end, vm->node.r.end);
    }
    update_map_flags(q.start, range_span(q), pageflags_from_vmflags(newflags));
    vmap_paranoia_locked(pvmap);
    return 0;
}

sysreturn mprotect(void * addr, u64 len, int prot)
{
    thread_log(current, "mprotect: addr %p, len 0x%lx, prot 0x%x", addr, len, prot);

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
                 vmap, match)
{
    rmnode node = &match->node;
    thread_log(current, "%s: q %R, r %R", __func__, bound(q), node->r);
    rangemap pvmap = bound(pvmap);
    range rn = node->r;
    range ri = range_intersection(bound(q), rn);
    vmap_debug("%s: vm %p %R, ri %R\n", __func__, match, rn, ri);

    /* trim match at both head and tail ends */
    boolean head = ri.start > rn.start;
    boolean tail = ri.end < rn.end;

    if (!head && !tail) {
        rangemap_remove_node(pvmap, node);
    } else if (head) {
        /* truncate node at start */
        vmap_assert(rangemap_reinsert(pvmap, node, irange(rn.start, ri.start)));

        if (tail) {
            struct vmap k = altered_vmap_key(match, match->flags, ri.end - rn.start);
            /* create node at tail end */
            vmap_assert(allocate_vmap_locked(pvmap, irange(ri.end, rn.end), k) != INVALID_ADDRESS);
        }
    } else {
        /* tail only: move node start back */
        vmap_assert(rangemap_reinsert(pvmap, node, irange(ri.end, rn.end)));
        match->node_offset += ri.end - rn.start;
    }
    if (bound(unmap)) {
        struct vmap k = altered_vmap_key(match, match->flags, ri.start - rn.start);
        k.node.r = ri;
        apply(bound(unmap), &k);
    }
    if (!head && !tail)
        deallocate_vmap_locked(pvmap, match);
    vmap_paranoia_locked(pvmap);
    return true;
}

closure_function(1, 1, boolean, dealloc_phys_page,
                 id_heap, physical,
                 range, r)
{
    if (!id_heap_set_area(bound(physical), r.start, range_span(r), true, false)) {
        msg_err("some of physical range %R not allocated in heap\n", r);
        return false;
    }
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
                 vmap, v)
{
    vmap_unmap_page_range(bound(p), v);
    return true;
}

static void process_remove_range_locked(process p, range q, boolean unmap)
{
    vmap_debug("%s: q %R\n", __func__, q);
    vmap_handler vh = unmap ? stack_closure(vmap_unmap, p) : 0;
    rangemap_range_lookup(p->vmaps, q,
                          (rmnode_handler)stack_closure(vmap_remove_intersection, p->vmaps, q, vh));
}

void unmap_and_free_phys(u64 virtual, u64 length)
{
    unmap_pages_with_handler(virtual, length,
        stack_closure(dealloc_phys_page, heap_physical(get_kernel_heaps())));
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
                 __func__, vm, n->r, delta, v, node_offset);
        pagecache_node_unmap_pages(pn, v, node_offset);
    }
    vmap_unlock(p);
}

closure_function(0, 1, boolean, msync_vmap,
                 vmap, vm)
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
    thread_log(current, "%s: addr %p, length 0x%lx, flags %x", __func__,
               addr, length, flags);

    int syncflags = MS_ASYNC | MS_SYNC;
    if ((flags & ~(MS_ASYNC | MS_SYNC | MS_INVALIDATE)) ||
        (flags & syncflags) == syncflags)
        return -EINVAL;

    boolean have_gap = false;
    if (flags & MS_SYNC) {
        process p = current->p;
        range q = irangel(u64_from_pointer(addr), pad(length, PAGESIZE));
        have_gap = (vmap_range_walk(p, q, stack_closure(msync_vmap), false) == RM_ABORT);
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
    thread_log(current, "mmap: addr %p, length 0x%lx, prot 0x%x, flags 0x%x, "
               "fd %d, offset 0x%lx", addr, length, prot, flags, fd, offset);

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
        thread_log(current, "   MAP_UNINITIALIZED is unsupported");
        return -EINVAL;
    }
    if (flags & MAP_GROWSDOWN) {
        thread_log(current, "   MAP_GROWSDOWN is unsupported");
        return -EINVAL;
    }
    if (flags & MAP_HUGETLB)
        thread_log(current, "   MAP_HUGETLB not implemented; ignoring");
    if (flags & MAP_SYNC)
        thread_log(current, "   MAP_SYNC not implemented; ignoring");

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
        thread_log(current, "   unknown flag(s) 0x%x", unknown_flags);
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
	    thread_log(current, "   attempt to map non-aligned FIXED address");
	    goto out_unlock;
	}
        if (!validate_mmap_range(p, q)) {
	    thread_log(current, "   requested fixed range %R is out of bounds", q);
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
        allowed_flags = anon_perms(p);
    } else {
        desc = resolve_fd(p, fd); /* must return via out label to release fdesc */
        switch (desc->type) {
        case FDESC_TYPE_REGULAR:
            thread_log(current, "   fd %d: file-backed (regular)", fd);
            vmap_mmap_type = VMAP_MMAP_TYPE_FILEBACKED;
            allowed_flags = file_perms(p, (file)desc);
            if (!(vmflags & VMAP_FLAG_SHARED))
                allowed_flags |= VMAP_FLAG_WRITABLE;
            if (offset & PAGEMASK) {
                thread_log(current, "   file-backed mapping must have aligned file offset (%ld)",
                           offset);
                ret = -EINVAL;
                goto out_unlock;
            }
            file f = (file)desc;
            fsf = f->fsf;
            assert(fsf);
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
    vmap_assert(allocate_vmap_locked(p->vmaps, q, k) != INVALID_ADDRESS);
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
    thread_log(current, "   returning 0x%lx", ret);
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
    thread_log(current, "munmap: addr %p, size 0x%lx", addr, length);

    u64 where = u64_from_pointer(addr);
    if ((where & MASK(PAGELOG)) || length == 0)
        return -EINVAL;

    vmap_lock(p);
    process_remove_range_locked(p, irangel(where, pad(length, PAGESIZE)), true);
    vmap_unlock(p);
    return 0;
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
                 vmap, vm)
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
                 vmap, vm)
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
    kernel_heaps kh = &p->uh->kh;
    heap h = heap_locked(kh);
    boolean aslr = !get(root, sym(noaslr));
    mmap_info.h = h;
    mmap_info.virtual_backed = reserve_heap_wrapper(h, (heap)heap_page_backed(kh),
                                                    USER_MEMORY_RESERVE);
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
    vmap_assert(allocate_vmap_locked(p->vmaps, irangel(p->vdso_base, vdso_size/*+vvar_size*/),
                                     ivmap(VMAP_FLAG_EXEC, 0, 0, 0, 0)) != INVALID_ADDRESS);

    /* vvar goes right after the vdso */
    vmap_assert(allocate_vmap_locked(p->vmaps, irangel(p->vdso_base + vdso_size, vvar_size),
                                     ivmap(0, 0, 0, 0, 0)) != INVALID_ADDRESS);

#ifdef __x86_64__
    /* Track vsyscall page */
    vmap_assert(allocate_vmap_locked(p->vmaps, irangel(VSYSCALL_BASE, PAGESIZE),
                                     ivmap(VMAP_FLAG_EXEC, 0, 0, 0, 0)) != INVALID_ADDRESS);
#endif

    spin_lock_init(&p->faulting_lock);
    init_rbtree(&p->pending_faults,
                init_closure(&mmap_info.pf_compare, pending_fault_compare),
                init_closure(&mmap_info.pf_print, pending_fault_print));
    list_init(&mmap_info.pf_freelist);
}

void register_mmap_syscalls(struct syscall *map)
{
    register_syscall(map, mincore, mincore, SYSCALL_F_SET_MEM);
    register_syscall(map, mmap, mmap, SYSCALL_F_SET_DESC|SYSCALL_F_SET_MEM);
    register_syscall(map, mremap, mremap, SYSCALL_F_SET_MEM);
    register_syscall(map, msync, msync, SYSCALL_F_SET_MEM);
    register_syscall(map, munmap, munmap, SYSCALL_F_SET_MEM);
    register_syscall(map, mprotect, mprotect, SYSCALL_F_SET_MEM);
    register_syscall(map, madvise, syscall_ignore, SYSCALL_F_SET_MEM);
}
