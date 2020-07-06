#include <unix_internal.h>
#include <page.h>

//#define PF_DEBUG
#ifdef PF_DEBUG
#define pf_debug(x, ...) do {log_printf("FAULT", "[%2d] " x, current_cpu()->id, ##__VA_ARGS__);} while(0)
#else
#define pf_debug(x, ...)
#endif

static boolean vmap_attr_equal(vmap a, vmap b)
{
    return (a->flags == b->flags &&
            a->offset == b->offset &&
            a->cache_node == b->cache_node);
}

static inline u64 page_map_flags(u64 vmflags)
{
    u64 flags = PAGE_NO_FAT | PAGE_USER;
    if ((vmflags & VMAP_FLAG_EXEC) == 0)
        flags |= PAGE_NO_EXEC;
    if ((vmflags & VMAP_FLAG_WRITABLE))
        flags |= PAGE_WRITABLE;
    return flags;
}

#define vmap_lock(p) u64 _savedflags = spin_lock_irq(&(p)->vmap_lock)
#define vmap_unlock(p) spin_unlock_irq(&(p)->vmap_lock, _savedflags)

/* kernel frame return must happen from runloop, not a bh completion service */
closure_function(1, 0, void, kernel_frame_return,
                 kernel_context, kc)
{
    resume_kernel_context(bound(kc));
}

static closure_struct(kernel_frame_return, do_kernel_frame_return);
static boolean kernel_demand_page_completed = false;
static kernel_context faulting_kernel_context;

closure_function(0, 1, void, kernel_demand_pf_complete,
                 status, s)
{
    if (!is_ok(s))
        halt("%s: page fill failed with %v\n", __func__, s);

    if (faulting_kernel_context) {
        init_closure(&do_kernel_frame_return, kernel_frame_return, faulting_kernel_context);
        faulting_kernel_context = 0;
        /* in case we enable for kernel exec later - TODO make helper */
        u64 flags = irq_disable_save();
        enqueue(bhqueue, &do_kernel_frame_return);
        irq_restore(flags);
    }
    kernel_demand_page_completed = true;
}

define_closure_function(2, 1, void, thread_demand_file_page_complete,
                        thread, t, context, frame,
                        status, s)
{
    if (!is_ok(s))
        halt("%s: page fill failed with %v\n", __func__, s); /* TODO: should be sigsegv? */
    schedule_frame(bound(frame));
    refcount_release(&bound(t)->refcount);
}

define_closure_function(7, 0, void, thread_demand_file_page,
                        thread, t, context, frame, pagecache_node, pn, u64, offset_page, u64, page_addr,
                        u64, flags, boolean, shared)
{
    pagecache_map_page(bound(pn), bound(offset_page), bound(page_addr), bound(flags),
                       bound(shared), (status_handler)&bound(t)->demand_file_page_complete);
}

boolean do_demand_page(u64 vaddr, vmap vm, context frame)
{
    boolean in_kernel = is_current_kernel_context(frame);
    if ((vm->flags & VMAP_FLAG_MMAP) == 0) {
        msg_err("vaddr 0x%lx matched vmap with invalid flags (0x%x)\n",
                vaddr, vm->flags);
        return false;
    }

    pf_debug("%s: %s, %s, vaddr 0x%16lx, vm flags 0x%2lx,\n", __func__,
             in_kernel ? "kern" : "user", vm->flags & VMAP_FLAG_ANONYMOUS ? "anon" : "file",
             vaddr, vm->flags);
    pf_debug("   vmap %p, frame %p\n", vm, frame);

    if (vm->flags & VMAP_FLAG_ANONYMOUS) {
        /* XXX make free list */
        u64 paddr = allocate_u64((heap)heap_physical(get_kernel_heaps()), PAGESIZE);
        if (paddr == INVALID_PHYSICAL) {
            msg_err("cannot get physical page; OOM\n");
            return false;
        }

        u64 vaddr_aligned = vaddr & ~MASK(PAGELOG);
        map(vaddr_aligned, paddr, PAGESIZE, page_map_flags(vm->flags));
        zero(pointer_from_u64(vaddr_aligned), PAGESIZE);
        return true;
    } else if (vm->flags & VMAP_FLAG_FILEBACKED) {
        u64 page_addr = vaddr & ~PAGEMASK;
        u64 offset_page = ((page_addr - vm->node.r.start) >> PAGELOG) + vm->offset;
        u64 flags = page_map_flags(vm->flags);
        boolean shared = (vm->flags & VMAP_FLAG_SHARED) != 0;
        pf_debug("   node %p (start 0x%lx), offset 0x%lx\n",
                 vm->cache_node, vm->node.r.start, offset_page << PAGELOG);

        if (in_kernel) {
            /* Kernel-mode page faults are only valid while faulting-in user memory within the confines
               of a syscall (under the kernel lock). As such, we are free to set up an asynchronous page
               fill, allocate memory, etc. */
            assert(!faulting_kernel_context);
            kernel_demand_page_completed = false;
            pagecache_map_page(vm->cache_node, offset_page, page_addr, flags, shared,
                               closure(heap_general(get_kernel_heaps()), kernel_demand_pf_complete));
            if (kernel_demand_page_completed) {
                pf_debug("   immediate completion\n");
                return true;
            }
            faulting_kernel_context = suspend_kernel_context();
        } else {
            /* A user fault can happen outside of the kernel lock. We can try to touch an existing
               page, but we can't allocate anything, fill a page or start a storage operation. */
            if (pagecache_map_page_sync(vm->cache_node, offset_page, page_addr, flags, shared)) {
                pf_debug("   immediate completion\n");
                return true;
            }

            /* schedule a page fill for this thread */
            thread t = current;
            refcount_reserve(&t->refcount);
            init_closure(&t->demand_file_page, thread_demand_file_page, t, frame,
                         vm->cache_node, offset_page, page_addr, flags, shared);
            init_closure(&t->demand_file_page_complete, thread_demand_file_page_complete, t, frame);
            enqueue(runqueue, &t->demand_file_page);
        }

        /* suspending */
        current_cpu()->kernel_context->frame[FRAME_FULL] = false;
        runloop();
    } else {
        halt("%s: can't handle vmap flags 0x%lx\n", __func__, vm->flags);
    }

    return true;
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
        apply(vmh, vm);
        vm = (vmap) rangemap_next_node(p->vmaps, &vm->node);
    }
    vmap_unlock(p);
}

closure_function(0, 1, void, vmap_dump_node,
                 rmnode, n)
{
    vmap curr = (vmap)n;
    rprintf("  %R, %s%s%s%s\n", curr->node.r,
            (curr->flags & VMAP_FLAG_MMAP) ? "mmap " : "",
            (curr->flags & VMAP_FLAG_ANONYMOUS) ? "anonymous " : "",
            (curr->flags & VMAP_FLAG_WRITABLE) ? "writable " : "",
            (curr->flags & VMAP_FLAG_EXEC) ? "exec " : "");
}

void vmap_dump(rangemap pvmap)
{
    rprintf("vmap %p\n", pvmap);
    rmnode_handler nh = stack_closure(vmap_dump_node);
    rangemap_range_lookup(pvmap, (range){0, infinity}, nh);
}

vmap allocate_vmap(rangemap rm, range q, struct vmap k)
{
    vmap vm = allocate(rm->h, sizeof(struct vmap));
    if (vm == INVALID_ADDRESS)
        return vm;
    rmnode_init(&vm->node, q);
    vm->flags = k.flags;
    vm->offset = k.offset;
    vm->cache_node = k.cache_node;
    if (!rangemap_insert(rm, &vm->node)) {
        deallocate(rm->h, vm, sizeof(struct vmap));
        return INVALID_ADDRESS;
    }
    return vm;
}

boolean adjust_process_heap(process p, range new)
{
    vmap_lock(p);
    boolean inserted = rangemap_reinsert(p->vmaps, &p->heap_map->node, new);
    vmap_unlock(p);
    return inserted;
}

sysreturn mremap(void *old_address, u64 old_size, u64 new_size, int flags, void * new_address)
{
    process p = current->p;
    u64 old_addr = u64_from_pointer(old_address);
    sysreturn rv;

    thread_log(current, "mremap: old_address %p, old_size 0x%lx, new_size 0x%lx, flags 0x%x, "
               "new_address %p", old_address, old_size, new_size, flags, new_address);

    if ((flags & MREMAP_MAYMOVE) == 0) {
        msg_err("only supporting MREMAP_MAYMOVE yet\n");
        return -ENOMEM;
    }

    if ((flags & MREMAP_FIXED)) {
        msg_err("no support for MREMAP_FIXED yet\n");
        return -ENOMEM;
    }

    if ((old_addr & MASK(PAGELOG)) ||
        (flags & ~(MREMAP_MAYMOVE | MREMAP_FIXED)) ||
        new_size == 0)
        return -EINVAL;

    heap vh = (heap)p->virtual_page;
    id_heap physical = heap_physical(get_kernel_heaps());

    old_size = pad(old_size, vh->pagesize);
    if (new_size <= old_size)
        return sysreturn_from_pointer(old_address);

    /* begin locked portion...no direct returns */
    vmap_lock(p);

    // XXX redo for filebacked
    /* verify we have a single vmap for the old address range */
    vmap old_vm = vmap_from_vaddr_locked(p, old_addr);
    if ((old_vm == INVALID_ADDRESS) ||
        !range_contains(old_vm->node.r, irange(old_addr, old_addr + old_size))) {
        rv = -EFAULT;
        goto unlock_out;
    }

    // XXX TODO
    assert((old_vm->flags & VMAP_FLAG_FILEBACKED) == 0);

    if (old_vm->flags & VMAP_FLAG_PREALLOC) {
        /* Remapping pre-allocated memory regions is not supported. */
        rv = -EINVAL;
        goto unlock_out;
    }

    /* XXX should determine if we're extending a virtual32 allocation...
     * - for now only let the user move anon mmaps
     */
    u64 match = VMAP_FLAG_MMAP | VMAP_FLAG_ANONYMOUS;
    if ((old_vm->flags & match) != match) {
        msg_err("mremap only supports anon mmap regions at the moment\n");
        rv = -EINVAL;
        goto unlock_out;
    }

    /* remove old mapping, preserving attributes */
    u64 vmflags = old_vm->flags;

    /* we're moving the vmap to a new address region, so we can safely remove
     * the old node entirely */
    rangemap_remove_node(p->vmaps, &old_vm->node);

    /* new virtual allocation */
    u64 maplen = pad(new_size, vh->pagesize);
    u64 vnew = allocate_u64(vh, maplen);
    if (vnew == (u64)INVALID_ADDRESS) {
        msg_err("failed to allocate virtual memory, size %ld\n", maplen);
        rv = -ENOMEM;
        goto unlock_out;
    }

    /* create new vm with old attributes */
    if (allocate_vmap(p->vmaps, irange(vnew, vnew + maplen), *old_vm) == INVALID_ADDRESS) {
        msg_err("failed to allocate vmap\n");
        deallocate_u64(vh, vnew, maplen);
        rv = -ENOMEM;
        goto unlock_out;
    }

    /* balance of physical allocation */
    u64 dlen = maplen - old_size;
    u64 dphys = allocate_u64((heap)physical, dlen);
    if (dphys == INVALID_PHYSICAL) {
        msg_err("failed to allocate physical memory, size %ld\n", dlen);
        deallocate_u64(vh, vnew, maplen);
        rv = -ENOMEM;
        goto unlock_out;
    }
    thread_log(current, "   new physical pages at 0x%lx, size %ld", dphys, dlen);

    /*
     * XXX : if we decide to handle MREMAP_FIXED, we'll need to be careful about
     * making sure destination address ranges are unmapped before mapping over them
     * here
     */

    /* remap existing portion */
    thread_log(current, "   remapping existing portion at 0x%lx (old_addr 0x%lx, size 0x%lx)",
               vnew, old_addr, old_size);
    remap_pages(vnew, old_addr, old_size);

    /* map new portion and zero */
    u64 mapflags = page_map_flags(vmflags);
    thread_log(current, "   mapping and zeroing new portion at 0x%lx, page flags 0x%lx",
               vnew + old_size, mapflags);
    map(vnew + old_size, dphys, dlen, mapflags);
    zero(pointer_from_u64(vnew + old_size), dlen);
    vmap_unlock(p);
    return sysreturn_from_pointer(vnew);
  unlock_out:
    vmap_unlock(p);
    return rv;
}

closure_function(3, 3, boolean, mincore_fill_vec,
                 u64, base, u64, nr_pgs, u8 *, vec,
                 int, level, u64, addr, u64 *, entry)
{
    u64 e = *entry;
    u64 pgoff, i;

    if (pt_entry_is_present(e)) {
        pgoff = (addr - bound(base)) >> PAGELOG;

        if (pt_entry_is_fat(level, e)) {
            /* whole level is mapped */
            for (i = 0; (i < 512) && (pgoff + i < bound(nr_pgs)); i++) {
                bound(vec)[pgoff + i] = 1;
	    }
        } else if (pt_entry_is_pte(level, e)) {
            bound(vec)[pgoff] = 1;
        }
    }

    return true;
}

closure_function(0, 1, void, mincore_vmap_gap,
                 range, r)
{
    thread_log(current, "   found gap [0x%lx, 0x%lx)", r.start, r.end);
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

    if (!validate_user_memory(vec, nr_pgs, true))
        return -EFAULT;

    /* -ENOMEM if any unmapped gaps in range */
    process p = current->p;
    vmap_lock(p);
    boolean found = rangemap_range_find_gaps(p->vmaps,
                                             irange(start, start + length),
                                             stack_closure(mincore_vmap_gap));
    vmap_unlock(p);
    if (found)
        return -ENOMEM;

    runtime_memset(vec, 0, nr_pgs);
    traverse_ptes(start, length,
        stack_closure(mincore_fill_vec, start, nr_pgs, vec)
    );
    return 0;
}

#if 0
closure_function(5, 2, void, mmap_read_complete,
                 thread, t, u64, where, u64, buf_len, buffer, b, u64, mapflags,
                 status, s, bytes, length)
{
    thread t = bound(t);
    u64 where = bound(where);
    buffer b = bound(b);
    u64 mapflags = bound(mapflags);

    if (!is_ok(s)) {
        deallocate_buffer(b);
        set_syscall_error(t, EACCES);
        goto out;
    }

    u64 buf_len = bound(buf_len);
    assert((buf_len & (PAGESIZE - 1)) == 0);
    void * buf = buffer_ref(b, 0);

    /* free existing pages */
    unmap_and_free_phys(where, buf_len);

    /* Note that we rely on the backed heap being physically
       contiguous. If this behavior changes or faulted-in pages are
       ever used, revise this to use the page walker. */
    map(where, physical_from_virtual(buf), buf_len, mapflags);

    /* zero pad */
    if (length < buf_len)
        zero(pointer_from_u64(where + length), buf_len - length);

    /* XXX This is gross. Either support this within the buffer interface or use something besides
       a buffer... */
    physically_backed_dealloc_virtual(b->h, u64_from_pointer(buf), pad(bound(buf_len), b->h->pagesize));
    deallocate(b->h, b, sizeof(struct buffer));

    set_syscall_return(t, where);
  out:
    file_op_maybe_wake(t);
    closure_finish();
}
#endif

#if 0
closure_function(0, 1, void, vmap_dump_node,
                 rmnode, n)
{
    vmap curr = (vmap)n;
    rprintf("  %R, %s%s%s%s\n", curr->node.r,
            (curr->flags & VMAP_FLAG_MMAP) ? "mmap " : "",
            (curr->flags & VMAP_FLAG_ANONYMOUS) ? "anonymous " : "",
            (curr->flags & VMAP_FLAG_WRITABLE) ? "writable " : "",
            (curr->flags & VMAP_FLAG_EXEC) ? "exec " : "");
}

static void vmap_dump(rangemap pvmap)
{
    rprintf("vmap %p\n", pvmap);
    rmnode_handler nh = stack_closure(vmap_dump_node);
    rangemap_range_lookup(pvmap, (range){0, infinity}, nh);
}
#endif

/* XXX refactor ... */
closure_function(4, 1, void, vmap_update_protections_intersection,
                 heap, h, rangemap, pvmap, range, q, u32, newflags,
                 rmnode, node)
{
    rangemap pvmap = bound(pvmap);

    u32 newflags = bound(newflags);
    vmap match = (vmap)node;
    if (newflags == match->flags)
        return;

    range rn = node->r;
    range ri = range_intersection(bound(q), rn);

    boolean head = ri.start > rn.start;
    boolean tail = ri.end < rn.end;

    /*
      case 1: !head && !tail

      node: |----------------|
      q:    |----------------|  (can extend past node start or end)
      attr: qqqqqqqqqqqqqqqqqq

      case 2: head && !tail

      node: |----------------|
      q:       |---------------|
      attr: nnnqqqqqqqqqqqqqqq

      case 3: !head && tail

      node:    |----------------|
      q:    |---------------|
      attr:    qqqqqqqqqqqqqqnnnn

      case 4: head && tail

      node: |----------------|
      q:       |---------|
      attr: nnnqqqqqqqqqqqnnnn

    */

    /* protection flags only */
    newflags = (match->flags & ~(VMAP_FLAG_WRITABLE | VMAP_FLAG_EXEC)) | newflags;

    // XXX TODO review refcount situation
    if (!head && !tail) {
        /* key (range) remains the same, no need to reinsert */
        match->flags = newflags;
    }

//    rprintf("head %d, tail %d, rn %R, i %R\n", head, tail, rn, ri);
    if (head) {
        /* split non-intersecting part of node */
        assert(rangemap_reinsert(pvmap, node, irange(rn.start, ri.start)));

        /* create node for intersection */
        assert(allocate_vmap(pvmap, ri, ivmap(newflags, match->offset + (ri.start - rn.start),
                                              match->cache_node)) != INVALID_ADDRESS);

        if (tail) {
            /* create node at tail end */
            assert(allocate_vmap(pvmap, irange(ri.end, rn.end),
                                ivmap(newflags, match->offset + (ri.end - rn.start),
                                      match->cache_node)) != INVALID_ADDRESS);
        }
    } else if (tail) {
        /* move node start back */
        assert(rangemap_reinsert(pvmap, node, irange(ri.end, node->r.end)));
        match->offset += ri.end - node->r.start;

        /* create node for intersection */
        assert(allocate_vmap(pvmap, ri,
                             ivmap(newflags, match->offset + (ri.start - rn.start),
                                   match->cache_node)));

    }
}

closure_function(0, 1, void, vmap_update_protections_gap,
                 range, r)
{
    thread_log(current, "   found gap [0x%lx, 0x%lx)", r.start, r.end);
}

static boolean vmap_update_protections(heap h, rangemap pvmap, range q, u32 newflags)
{
    assert((q.start & MASK(PAGELOG)) == 0);
    assert((q.end & MASK(PAGELOG)) == 0);
    assert(range_span(q) > 0);

    thread_log(current, "%s: validate %R", __func__, q);
    if (!validate_user_memory(pointer_from_u64(q.start), range_span(q), false) ||
        rangemap_range_find_gaps(pvmap, q, stack_closure(vmap_update_protections_gap))) {
        return false;
    }

    rmnode_handler nh = stack_closure(vmap_update_protections_intersection, h, pvmap, q, newflags);
    if (!rangemap_range_lookup(pvmap, q, nh))
        return false;

    update_map_flags(q.start, range_span(q), page_map_flags(newflags));
    return true;
}

sysreturn mprotect(void * addr, u64 len, int prot)
{
    thread_log(current, "mprotect: addr %p, len 0x%lx, prot 0x%x", addr, len, prot);

    if (len == 0)
        return 0;

    heap h = heap_general(get_kernel_heaps());
    u64 where = u64_from_pointer(addr);
    u64 padlen = pad(len, PAGESIZE);
    if ((where & MASK(PAGELOG)))
        return -EINVAL;

    u64 new_vmflags = 0;
    if ((prot & PROT_EXEC))
        new_vmflags |= VMAP_FLAG_EXEC;
    if ((prot & PROT_WRITE))
        new_vmflags |= VMAP_FLAG_WRITABLE;

    process p = current->p;
    vmap_lock(p);
    boolean result = vmap_update_protections(h, p->vmaps, irangel(where, padlen), new_vmflags);
    vmap_unlock(p);
    return result ? 0 : -ENOMEM;
}

/* If we can re-use a node (range is exact match), just update the
   flags. Otherwise trim back any vmap(s) that overlap with q,
   creating a new node if necessary. After this point, new nodes can
   be created using the gap fill.
 */
closure_function(4, 1, void, vmap_paint_intersection,
                 heap, h, rangemap, pvmap, range, q, struct vmap, k,
                 rmnode, node)
{
    thread_log(current, "%s: q %R, r %R\n", __func__, bound(q), node->r);
    rangemap pvmap = bound(pvmap);

    vmap k = &bound(k);
    vmap match = (vmap)node;
    if (vmap_attr_equal(k, match)) {
        return;
    }

    range rn = node->r;
    range ri = range_intersection(bound(q), rn);
    assert(range_span(ri) > 0); // XXX temp

    /* attribute mismatch; check if we can just reuse matching node */
    if (range_equal(ri, rn)) {
        /* key (range) remains the same, no need to reinsert */
        match->flags = k->flags;
        match->offset = k->offset + (ri.start - bound(q).start); // XXX verify?
        match->cache_node = k->cache_node;
        return;
    }

    /* trim match at both head and tail ends */
    boolean head = ri.start > rn.start;
    boolean tail = ri.end < rn.end;

    if (head) {
        /* truncate node at start */
        rangemap_reinsert(pvmap, node, irange(rn.start, ri.start));

        if (tail) {
            /* create node at tail end */
            assert(allocate_vmap(pvmap, irange(ri.end, rn.end),
                                 ivmap(match->flags,
                                       match->offset + (ri.end - rn.start),
                                       match->cache_node)) != INVALID_ADDRESS);
        }
    } else if (tail) {
        /* tail only: move node start back */
        rangemap_reinsert(pvmap, node, irange(ri.end, rn.end));
        match->offset += ri.end - rn.start;
    }
}

closure_function(4, 1, void, vmap_paint_gap,
                 heap, h, rangemap, pvmap, range, q, struct vmap, k,
                 range, r)
{
    vmap k = &bound(k);
    assert(allocate_vmap(bound(pvmap), r,
                         ivmap(k->flags, k->offset + (r.start - bound(q).start),
                               k->cache_node)) != INVALID_ADDRESS);
}

/* Paint into process vmap */
static void vmap_paint(heap h, process p, u64 where, u64 len, u32 vmflags,
                       pagecache_node cache_node, u32 offset_page)
{
    range q = irange(where, where + len);
    assert((q.start & MASK(PAGELOG)) == 0);
    assert((q.end & MASK(PAGELOG)) == 0);
    assert(range_span(q) > 0);
    rangemap pvmap = p->vmaps;

    vmap_lock(p);
    struct vmap k = ivmap(vmflags, offset_page, cache_node);
    rangemap_range_lookup(pvmap, q, stack_closure(vmap_paint_intersection, h, pvmap, q, k));
    rangemap_range_find_gaps(pvmap, q, stack_closure(vmap_paint_gap, h, pvmap, q, k));

    update_map_flags(q.start, range_span(q), page_map_flags(vmflags));
    vmap_unlock(p);
}

typedef struct varea {
    struct rmnode node;
    id_heap h;
    boolean allow_fixed;
} * varea;

static varea allocate_varea(heap h, rangemap vareas, range r, id_heap vh, boolean allow_fixed)
{
    varea va = allocate(h, sizeof(struct varea));
    if (va == INVALID_ADDRESS)
        return va;
    rmnode_init(&va->node, r);
    va->allow_fixed = allow_fixed;
    va->h = vh;
    if (!rangemap_insert(vareas, &va->node)) {
        deallocate(h, va, sizeof(struct vmap));
        return INVALID_ADDRESS;
    }
    return va;
}

/* XXX defaulting to leniency; revisit */
static boolean mmap_reserve_range(process p, range q)
{
    /* XXX can tweak rangemap range lookup to terminate if a callback
       fails...kind of tired of messing with that interface */
    varea a = (varea)rangemap_first_node(p->vareas);
    while (a != INVALID_ADDRESS) {
        if (ranges_intersect(q, a->node.r)) {
            if (!a->allow_fixed)
                return false;
            if (a->h)
                id_heap_set_area(a->h, q.start, range_span(q), false, true);
        }
        a = (varea)rangemap_next_node(p->vareas, (rmnode)a);
    }
    return true;
}

static sysreturn mmap(void *target, u64 size, int prot, int flags, int fd, u64 offset)
{
    process p = current->p;
    kernel_heaps kh = get_kernel_heaps();
    heap h = heap_general(kh);
    u64 len = pad(size, PAGESIZE);
    thread_log(current, "mmap: target %p, size 0x%lx, len 0x%lx, prot 0x%x, flags 0x%x, "
               "fd %d, offset 0x%lx", target, size, len, prot, flags, fd, offset);

    if (len == 0)
        return -EINVAL;

    /* Determine vmap flags */
    int map_type = flags & MAP_TYPE_MASK;
    u64 vmflags = VMAP_FLAG_MMAP;
    if ((flags & MAP_ANONYMOUS))
        vmflags |= VMAP_FLAG_ANONYMOUS;
    if (map_type == MAP_SHARED || map_type == MAP_SHARED_VALIDATE)
        vmflags |= VMAP_FLAG_SHARED;
    if ((prot & PROT_EXEC))
        vmflags |= VMAP_FLAG_EXEC;
    if ((prot & PROT_WRITE))
        vmflags |= VMAP_FLAG_WRITABLE;

    /* Don't really try to honor a hint, only fixed. */
    boolean fixed = (flags & MAP_FIXED) != 0;
    u64 where = fixed ? u64_from_pointer(target) : 0;

    /* TODO: assert for unsupported:
       MAP_GROWSDOWN
       MAP_UNINITIALIZED
    */

    if (!(flags & MAP_ANONYMOUS)) {
        fdesc desc = resolve_fd(p, fd);
        if (desc->type == FDESC_TYPE_IORING) {
            sysreturn ret;
            if (fixed)
                ret = -ENOMEM;
            else {
                vmflags |= VMAP_FLAG_PREALLOC;
                ret = io_uring_mmap(desc, len, page_map_flags(vmflags), offset);
                if (ret > 0)
                    vmap_paint(h, p, (u64)ret, len, vmflags, 0, 0);
            }
            return ret;
        } else if (desc->type == FDESC_TYPE_REGULAR) { // &&
//                   (flags & MAP_TYPE_MASK) == MAP_SHARED) { // XXX hack for test
            file f = (file)desc;
            /* check:
               offset pagealign

               MAP_LOCKED
               MAP_NONBLOCK
               MAP_POPULATE
            */

//            if (fixed) {
//                rprintf("no fixed 0x%lx\n", where);
//                return -ENOMEM;
//            }

            /* TODO check file conditions */

            vmflags |= VMAP_FLAG_FILEBACKED;
            // XXX hack
            u64 maplen = pad(len, PAGESIZE);
            if (!fixed)
                where = allocate_u64((heap)p->virtual_page, maplen);
            assert(f->fsf);
            pagecache_node node = fsfile_get_cachenode(f->fsf);
//            rprintf("mmap: filebacked, where 0x%lx, node %p, maplen 0x%lx,\n"
//                    "   mmap flags 0x%x, vmflags 0x%x, offset 0x%lx\n",
//                    where, node, maplen, flags, vmflags, offset);
            vmap_paint(h, p, where, maplen, vmflags, node, offset >> PAGELOG);
            return where;
        }
    }

    if (fixed) {
        if (where == 0) {
            thread_log(current, "   attempt to map zero page");
            return -ENOMEM;
        }

	/* Must be page-aligned */
	if (where & MASK(PAGELOG)) {
	    thread_log(current, "   attempt to map non-aligned FIXED address");
	    return -EINVAL;
	}

        /* A specified address is only allowed in certain areas. Programs may specify
           a fixed address to augment some existing mapping. */
        range q = irange(where, where + len);
        if (!mmap_reserve_range(p, q)) {
	    thread_log(current, "   fail: fixed address range %R outside of lowmem or virtual_page heap\n", q);
	    return -ENOMEM;
        }
    }

    /* Allocate from virtual heap if no address specified or hint unavailable */
    if (where == 0) {
        boolean is_32bit = flags & MAP_32BIT;
        u64 maplen = pad(len, PAGESIZE);
        if (is_32bit) {
            /* Allocate from top half of 32-bit address space. */
            where = id_heap_alloc_subrange(p->virtual32, maplen, 0x80000000, 0x100000000);
        } else {
            where = allocate_u64((heap)p->virtual_page, maplen);
        }
        if (where == (u64)INVALID_ADDRESS) {
            /* We'll always want to know about low memory conditions, so just bark. */
            msg_err("failed to allocate %svirtual memory, size 0x%lx\n", is_32bit ? "32-bit " : "", len);
            return -ENOMEM;
        }
    }

    vmap_paint(h, p, where, len, vmflags, 0, 0);

    if (flags & MAP_ANONYMOUS) {
        thread_log(current, "   anon target: 0x%lx, len: 0x%lx (given size: 0x%lx)", where, len, size);
//        /* If mmap this intersects an existing one, zero any mapped pages. */
        // XXX need to replace if file-backed and shared
        // XXX change to unmap
        zero_mapped_pages(where, len);
        return where;
    }

    assert(0);
#if 0
    file f = resolve_fd(p, fd);
    u64 flen = MIN(pad(f->length, PAGESIZE), len);
    if (flen == 0)
        return where;
    heap mh = heap_backed(kh);
    buffer b = allocate_buffer(mh, pad(flen, mh->pagesize));

    thread_log(current, "  read file at 0x%lx, flen %ld, blocking...", where, flen);
    file_op_begin(current);
    filesystem_read_linear(file_get_fsfile(f), buffer_ref(b, 0), irangel(offset, flen),
                           closure(h, mmap_read_complete, current, where, flen, b, page_map_flags(vmflags)));
    return file_op_maybe_sleep(current);
#endif
}

/* invoked with vmap lock taken */
closure_function(2, 1, void, process_unmap_intersection,
                 process, p, range, rq,
                 rmnode, node)
{
    process p = bound(p);
    vmap match = (vmap)node;
    range rn = node->r;
    range ri = range_intersection(bound(rq), rn);

    /* similar logic to attribute update above */
    boolean head = ri.start > rn.start;
    boolean tail = ri.end < rn.end;

//    rprintf("unmap q %R, node %R, head %d, tail %d\n", bound(rq), node->r, head, tail);

    if (head) {
        /* split non-intersecting part of node */
        assert(rangemap_reinsert(p->vmaps, node, irange(rn.start, ri.start)));

        if (tail) {
            /* create node for tail end */
            assert(allocate_vmap(p->vmaps, irange(ri.end, rn.end),
                                 ivmap(match->flags, match->offset + (ri.end - rn.start),
                                       match->cache_node)) != INVALID_ADDRESS);
        }
    } else if (tail) {
        /* move node start back */
        range rt = { ri.end, node->r.end };
        assert(rangemap_reinsert(p->vmaps, node, rt));
    } else {
        /* delete outright */
        rangemap_remove_node(p->vmaps, node);
    }

    /* unmap any mapped pages and possibly return to physical heap */
    u64 len = range_span(ri);
    if (match->flags & VMAP_FLAG_PREALLOC)
        unmap(ri.start, len);
    else if (match->flags & VMAP_FLAG_FILEBACKED)
        rprintf("%s: TODO filebacked\n", __func__);
    else
        unmap_and_free_phys(ri.start, len);

    /* TODO give this varea thing more scrutiny... */

    /* return virtual mapping to heap, if any ... assuming a vmap cannot span heaps!
       XXX: this shouldn't be a lookup per, so consider stashing a link to varea or heap in vmap
       though in practice these are small numbers... */
    varea v = (varea)rangemap_lookup(p->vareas, ri.start);
    if (v != INVALID_ADDRESS && v->h) {
        id_heap_set_area(v->h, ri.start, len, false, false);
    }
}

static void process_unmap_range(process p, range q)
{
    vmap_lock(p);
    rmnode_handler nh = stack_closure(process_unmap_intersection, p, q);
    rangemap_range_lookup(p->vmaps, q, nh);
    vmap_unlock(p);
}

static sysreturn munmap(void *addr, u64 length)
{
    process p = current->p;
    thread_log(current, "munmap: addr %p, size 0x%lx", addr, length);

    u64 where = u64_from_pointer(addr);
    if ((where & MASK(PAGELOG)) || length == 0)
        return -EINVAL;

    u64 padlen = pad(length, PAGESIZE);
    range q = irange(where, where + padlen);

    /* clear out any mapped areas in our meta */
    process_unmap_range(p, q);
    return 0;
}

/* kernel start */
extern void * START;

static void add_varea(process p, u64 start, u64 end, id_heap vheap, boolean allow_fixed)
{
    assert(allocate_varea(heap_general((kernel_heaps)p->uh), p->vareas, irange(start, end),
                          vheap, allow_fixed) != INVALID_ADDRESS);

    /* reserve area by marking as allocated */
    if (vheap && !allow_fixed)
        id_heap_set_area(vheap, start, end - start, true, true);
}

void mmap_process_init(process p)
{
    kernel_heaps kh = &p->uh->kh;
    heap h = heap_general(kh);
    spin_lock_init(&p->vmap_lock);
    p->vareas = allocate_rangemap(h);
    p->vmaps = allocate_rangemap(h);
    assert(p->vareas != INVALID_ADDRESS && p->vmaps != INVALID_ADDRESS);

    /* zero page is off-limits */
    add_varea(p, 0, PAGESIZE, p->virtual32, false);

    /* allow (tracked) reservations in p->virtual */
    add_varea(p, PROCESS_VIRTUAL_HEAP_START, PROCESS_VIRTUAL_HEAP_LIMIT, p->virtual_page, true);

    /* reserve end of p->virtual to user tag region */
    u64 user_va_tag_start = U64_FROM_BIT(USER_VA_TAG_OFFSET);
    u64 user_va_tag_end = user_va_tag_start * tag_max;

    /* allow untracked mmaps in user va tag area */
    add_varea(p, user_va_tag_start, user_va_tag_end, 0, true);

    /* reserve kernel memory and non-canonical addresses */
    add_varea(p, USER_LIMIT, -1ull, 0, false);

    /* randomly determine vdso/vvar base and track it */
    u64 vdso_size, vvar_size;

    vdso_size = vdso_raw_length;
    vvar_size = VVAR_NR_PAGES * PAGESIZE;

    p->vdso_base = allocate_u64((heap)p->virtual_page, vdso_size + vvar_size);
    assert(allocate_vmap(p->vmaps, irangel(p->vdso_base, vdso_size/*+vvar_size*/),
                         ivmap(VMAP_FLAG_EXEC, 0, 0)));

    /* vvar goes right after the vdso */
    assert(allocate_vmap(p->vmaps, irangel(p->vdso_base + vdso_size, vvar_size),
                         ivmap(0, 0, 0)) != INVALID_ADDRESS);

    /* Track vsyscall page */
    assert(allocate_vmap(p->vmaps, irangel(VSYSCALL_BASE, PAGESIZE),
                         ivmap(VMAP_FLAG_EXEC, 0,0)) != INVALID_ADDRESS);

}

void register_mmap_syscalls(struct syscall *map)
{
    register_syscall(map, mincore, mincore);
    register_syscall(map, mmap, mmap);
    register_syscall(map, mremap, mremap);
    register_syscall(map, munmap, munmap);
    register_syscall(map, mprotect, mprotect);
    register_syscall(map, madvise, syscall_ignore);
}
