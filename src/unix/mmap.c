#include <unix_internal.h>

//#define PF_DEBUG
#ifdef PF_DEBUG
#define pf_debug(x, ...) do {log_printf("FAULT", "[%2d] " x, current_cpu()->id, ##__VA_ARGS__);} while(0)
#else
#define pf_debug(x, ...)
#endif

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
        bhqueue_enqueue_irqsafe((thunk)&do_kernel_frame_return);
    }
    kernel_demand_page_completed = true;
}

static closure_struct(kernel_demand_pf_complete, do_kernel_demand_pf_complete);

define_closure_function(3, 1, void, thread_demand_file_page_complete,
                        thread, t, context, frame, u64, vaddr,
                        status, s)
{
    if (!is_ok(s)) {
        rprintf("%s: page fill failed with %v\n", __func__, s);
        deliver_fault_signal(SIGBUS, bound(t), bound(vaddr), BUS_ADRERR);
    }
    schedule_frame(bound(frame));
    refcount_release(&bound(t)->refcount);
}

define_closure_function(5, 0, void, thread_demand_file_page,
                        thread, t, vmap, vm, u64, node_offset, u64, page_addr, u64, flags)
{
    vmap vm = bound(vm);
    pagecache_node pn = vm->cache_node;
    pagecache_map_page(pn, bound(node_offset), bound(page_addr), bound(flags),
                       (status_handler)&bound(t)->demand_file_page_complete);
    range ra = irange(bound(node_offset) + PAGESIZE,
        vm->node_offset + range_span(vm->node.r));
    if (range_valid(ra)) {
        if (range_span(ra) > FILE_READAHEAD_DEFAULT)
            ra.end = ra.start + FILE_READAHEAD_DEFAULT;
        pagecache_node_fetch_pages(pn, ra);
    }
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
             in_kernel ? "kern" : "user", string_from_mmap_type(vm->flags & VMAP_MMAP_TYPE_MASK),
             vaddr, vm->flags);
    pf_debug("   vmap %p, frame %p\n", vm, frame);

    int mmap_type = vm->flags & VMAP_MMAP_TYPE_MASK;
    if (mmap_type == VMAP_MMAP_TYPE_ANONYMOUS) {
        u64 paddr = allocate_u64((heap)heap_physical(get_kernel_heaps()), PAGESIZE);
        if (paddr == INVALID_PHYSICAL) {
            msg_err("cannot get physical page; OOM\n");
            return false;
        }

        u64 vaddr_aligned = vaddr & ~MASK(PAGELOG);
        map(vaddr_aligned, paddr, PAGESIZE, page_map_flags(vm->flags));
        zero(pointer_from_u64(vaddr_aligned), PAGESIZE);
    } else if (mmap_type == VMAP_MMAP_TYPE_FILEBACKED) {
        u64 page_addr = vaddr & ~PAGEMASK;
        u64 node_offset = vm->node_offset + (page_addr - vm->node.r.start);
        boolean shared = (vm->flags & VMAP_FLAG_SHARED) != 0;
        u64 flags = page_map_flags(vm->flags);
        if (!shared)
            flags &= ~PAGE_WRITABLE; /* cow */
        pf_debug("   node %p (start 0x%lx), offset 0x%lx\n",
                 vm->cache_node, vm->node.r.start, node_offset);

        u64 padlen = pad(pagecache_get_node_length(vm->cache_node), PAGESIZE);
        pf_debug("   map length 0x%lx\n", padlen);
        if (node_offset >= padlen) {
            pf_debug("   extends past map limit 0x%lx; sending SIGBUS...\n", padlen);
            if (in_kernel) {
                /* It would be more graceful to let the kernel fault pass (perhaps using a dummy
                   or zero page) and eventually deliver the SIGBUS to the offending thread. For now,
                   assume this is an unrecoverable error and exit here. */
                halt("%s: file-backed access in kernel mode outside of map range, "
                     "node %p (start 0x%lx), offset 0x%lx\n", vm->cache_node,
                     vm->node.r.start, node_offset);
            }
            deliver_fault_signal(SIGBUS, current, vaddr, BUS_ADRERR);
            return true;
        }

        if (in_kernel) {
            /* Kernel-mode page faults are exclusively for faulting-in user pages within the confines
               of a syscall (under the kernel lock). As such, we are free to set up an asynchronous page
               fill, allocate memory, etc. */
            assert(!faulting_kernel_context);
            kernel_demand_page_completed = false;
            pagecache_map_page(vm->cache_node, node_offset, page_addr, flags,
                               (status_handler)&do_kernel_demand_pf_complete);
            if (kernel_demand_page_completed) {
                pf_debug("   immediate completion\n");
                return true;
            }
            faulting_kernel_context = suspend_kernel_context();
        } else {
            /* A user fault can happen outside of the kernel lock. We can try to touch an existing
               page, but we can't allocate anything, fill a page or start a storage operation. */
            if (pagecache_map_page_if_filled(vm->cache_node, node_offset, page_addr, flags)) {
                pf_debug("   immediate completion\n");
                return true;
            }

            /* schedule a page fill for this thread */
            thread t = current;
            refcount_reserve(&t->refcount);
            init_closure(&t->demand_file_page, thread_demand_file_page, t, vm,
                         node_offset, page_addr, flags);
            init_closure(&t->demand_file_page_complete, thread_demand_file_page_complete, t, frame, vaddr);
            enqueue(runqueue, &t->demand_file_page);
        }

        /* suspending */
        current_cpu()->kernel_context->frame[FRAME_FULL] = false;
        runloop();
    } else {
        halt("%s: invalid vmap type %d, flags 0x%lx\n", __func__, mmap_type, vm->flags);
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
    rprintf("  %R, %s%s %s%s\n", curr->node.r,
            (curr->flags & VMAP_FLAG_MMAP) ? "mmap " : "",
            string_from_mmap_type(curr->flags & VMAP_MMAP_TYPE_MASK),
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
    vm->allowed_flags = k.allowed_flags;
    vm->node_offset = k.node_offset;
    vm->cache_node = k.cache_node;
    if (!rangemap_insert(rm, &vm->node)) {
        deallocate(rm->h, vm, sizeof(struct vmap));
        return INVALID_ADDRESS;
    }
    return vm;
}

/* TODO maybe refcount makes more sense now that we have asynchronous faults */
void deallocate_vmap(rangemap rm, vmap vm)
{
    deallocate(rm->h, vm, sizeof(struct vmap));
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

    /* verify we have a single vmap for the old address range */
    vmap old_vm = vmap_from_vaddr_locked(p, old_addr);
    if ((old_vm == INVALID_ADDRESS) ||
        !range_contains(old_vm->node.r, irange(old_addr, old_addr + old_size))) {
        rv = -EFAULT;
        goto unlock_out;
    }

    if (old_vm->flags & VMAP_FLAG_PREALLOC) {
        /* Remapping pre-allocated memory regions is not supported. */
        rv = -EINVAL;
        goto unlock_out;
    }

    /* XXX should determine if we're extending a virtual32 allocation...
     * - for now only let the user move anon mmaps
     */
    u64 match = VMAP_FLAG_MMAP | VMAP_MMAP_TYPE_ANONYMOUS;
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

closure_function(2, 1, void, vmap_update_protections_validate,
                 u32, newflags, boolean *, prot_violation,
                 rmnode, node)
{
    if (*bound(prot_violation))
        return;
    vmap match = (vmap)node;
    if (bound(newflags) & ~match->allowed_flags)
        *bound(prot_violation) = true;
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

/* refactor with vmap_remove_intersection? might be better as-is. */
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
    u64 node_offset = match->node_offset;

    boolean head = ri.start > rn.start;
    boolean tail = ri.end < rn.end;

    /* protection flags only */
    newflags = (match->flags & ~(VMAP_FLAG_WRITABLE | VMAP_FLAG_EXEC)) | newflags;

    if (!head && !tail) {
        /* key (range) remains the same, no need to reinsert */
        match->flags = newflags;
    }

    if (head) {
        /* split non-intersecting part of node */
        assert(rangemap_reinsert(pvmap, node, irange(rn.start, ri.start)));

        /* create node for intersection */
        assert(allocate_vmap(pvmap, ri, ivmap(newflags,
                                              match->allowed_flags,
                                              node_offset + (ri.start - rn.start),
                                              match->cache_node)) != INVALID_ADDRESS);

        if (tail) {
            /* create node at tail end */
            assert(allocate_vmap(pvmap, irange(ri.end, rn.end),
                                ivmap(match->flags,
                                      match->allowed_flags,
                                      node_offset + (ri.end - rn.start),
                                      match->cache_node)) != INVALID_ADDRESS);
        }
    } else if (tail) {
        /* move node start back */
        assert(rangemap_reinsert(pvmap, node, irange(ri.end, rn.end)));
        match->node_offset += ri.end - rn.start;

        /* create node for intersection */
        assert(allocate_vmap(pvmap, ri,
                             ivmap(newflags,
                                   match->allowed_flags,
                                   node_offset + (ri.start - rn.start),
                                   match->cache_node)) != INVALID_ADDRESS);
    }
}

closure_function(0, 1, void, vmap_update_protections_gap,
                 range, r)
{
    thread_log(current, "   found gap [0x%lx, 0x%lx)", r.start, r.end);
}

static sysreturn vmap_update_protections(heap h, rangemap pvmap, range q, u32 newflags)
{
    assert((q.start & MASK(PAGELOG)) == 0);
    assert((q.end & MASK(PAGELOG)) == 0);
    assert(range_span(q) > 0);

    thread_log(current, "%s: validate %R", __func__, q);
    if (!validate_user_memory(pointer_from_u64(q.start), range_span(q), false) ||
        rangemap_range_find_gaps(pvmap, q, stack_closure(vmap_update_protections_gap))) {
        return -ENOMEM;
    }

    boolean prot_violation = false;
    rmnode_handler v_handler = stack_closure(vmap_update_protections_validate,
        newflags, &prot_violation);
    if (!rangemap_range_lookup(pvmap, q, v_handler))
        return -ENOMEM;
    else if (prot_violation)
        return -EACCES;

    rmnode_handler nh = stack_closure(vmap_update_protections_intersection, h, pvmap, q, newflags);
    rangemap_range_lookup(pvmap, q, nh);

    update_map_flags(q.start, range_span(q), page_map_flags(newflags));
    return 0;
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
    sysreturn result = vmap_update_protections(h, p->vmaps, irangel(where, padlen), new_vmflags);
    vmap_unlock(p);
    return result;
}

/* blow a hole in the process address space intersecting q */
closure_function(3, 1, void, vmap_remove_intersection,
                 rangemap, pvmap, range, q, vmap_handler, unmap,
                 rmnode, node)
{
    thread_log(current, "%s: q %R, r %R\n", __func__, bound(q), node->r);
    rangemap pvmap = bound(pvmap);
    vmap match = (vmap)node;
    range rn = node->r;
    range ri = range_intersection(bound(q), rn);

    /* trim match at both head and tail ends */
    boolean head = ri.start > rn.start;
    boolean tail = ri.end < rn.end;
    u64 node_offset = match->node_offset;

    if (!head && !tail) {
        rangemap_remove_node(pvmap, node);
        deallocate_vmap(pvmap, match);
    } else if (head) {
        /* truncate node at start */
        assert(rangemap_reinsert(pvmap, node, irange(rn.start, ri.start)));

        if (tail) {
            /* create node at tail end */
            assert(allocate_vmap(pvmap, irange(ri.end, rn.end),
                                 ivmap(match->flags,
                                       match->allowed_flags,
                                       node_offset + (ri.end - rn.start),
                                       match->cache_node)) != INVALID_ADDRESS);
        }
    } else {
        /* tail only: move node start back */
        assert(rangemap_reinsert(pvmap, node, irange(ri.end, rn.end)));
        match->node_offset += ri.end - rn.start;
    }

    if (bound(unmap)) {
        struct vmap k = ivmap(match->flags,
                              0,
                              node_offset + (ri.start - rn.start),
                              match->cache_node);
        k.node.r = ri;
        apply(bound(unmap), &k);
    }
}

closure_function(4, 1, void, vmap_paint_gap,
                 heap, h, rangemap, pvmap, range, q, struct vmap, k,
                 range, r)
{
    vmap k = &bound(k);
    assert(allocate_vmap(bound(pvmap), r,
                         ivmap(k->flags,
                               k->allowed_flags,
                               k->node_offset + (r.start - bound(q).start),
                               k->cache_node)) != INVALID_ADDRESS);
}

static void vmap_return_virtual(process p, vmap k)
{
    /* could stash the corresponding varea in the vmap */
    range r = k->node.r;
    varea v = (varea)rangemap_lookup(p->vareas, r.start);
    if (v != INVALID_ADDRESS && v->h)
        id_heap_set_area(v->h, r.start, range_span(r), false, false);
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
    case VMAP_MMAP_TYPE_IORING:
        unmap(r.start, len);
        break;
    }

    if ((k->flags & VMAP_FLAG_PREALLOC) == 0)
        vmap_return_virtual(p, k);
}

closure_function(1, 1, void, vmap_unmap,
                 process, p,
                 vmap, v)
{
    vmap_unmap_page_range(bound(p), v);
}

static void process_unmap_range(process p, range q)
{
    vmap_lock(p);
    vmap_handler vh = stack_closure(vmap_unmap, p);
    rangemap_range_lookup(p->vmaps, q, stack_closure(vmap_remove_intersection,
                                                     p->vmaps, q, vh));
    vmap_unlock(p);
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
        assert(v.start <= v.end);
        u64 node_offset = vm->node_offset + (v.start - n->r.start);
        pf_debug("%s: vmap %p, %R, delta 0x%lx, remove v %R, node_offset 0x%lx\n",
                 __func__, vm, n->r, delta, v, node_offset);
        pagecache_node_unmap_pages(pn, v, node_offset);
    }
    vmap_unlock(p);
}

/* Paint into process vmap */
static void vmap_paint(heap h, process p, u64 where, u64 len, u32 vmflags,
                       u32 allowed_flags,
                       pagecache_node cache_node, u32 node_offset)
{
    range q = irangel(where, len);
    assert((q.start & MASK(PAGELOG)) == 0);
    assert((q.end & MASK(PAGELOG)) == 0);
    assert(range_span(q) > 0);
    rangemap pvmap = p->vmaps;

    vmap_lock(p);
    vmap_handler vh = stack_closure(vmap_unmap, p);
    rangemap_range_lookup(pvmap, q, stack_closure(vmap_remove_intersection, pvmap, q, vh));
    rangemap_range_find_gaps(pvmap, q, stack_closure(vmap_paint_gap, h, pvmap, q,
                                                     ivmap(vmflags, allowed_flags,
                                                           node_offset, cache_node)));

    update_map_flags(q.start, range_span(q), page_map_flags(vmflags));
    vmap_unlock(p);
}

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

/* allow mappings outside of managed areas, but require range reserve to pass within one */
static boolean mmap_reserve_range(process p, range q)
{
    varea a = (varea)rangemap_first_node(p->vareas);
    while (a != INVALID_ADDRESS) {
        if (ranges_intersect(q, a->node.r)) {
            if (!a->allow_fixed)
                return false;
            if (a->h)
                if (!id_heap_set_area(a->h, q.start, range_span(q), true, true))
                    return false;
        }
        a = (varea)rangemap_next_node(p->vareas, (rmnode)a);
    }
    return true;
}

closure_function(0, 1, void, msync_vmap,
                 rmnode, n)
{
    vmap vm = (vmap)n;
    if ((vm->flags & VMAP_FLAG_SHARED) &&
        (vm->flags & VMAP_FLAG_MMAP) &&
        (vm->flags & VMAP_MMAP_TYPE_MASK) == VMAP_MMAP_TYPE_FILEBACKED) {
        assert(vm->cache_node);
        pagecache_node_scan_and_commit_shared_pages(vm->cache_node, n->r);
    }
}

closure_function(1, 1, void, msync_gap,
                 boolean *, have_gap,
                 range, r)
{
    *bound(have_gap) = true;
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
        range q = irangel(u64_from_pointer(addr), pad(length, PAGESIZE));
        rangemap_range_lookup_with_gaps(current->p->vmaps, q,
                                        stack_closure(msync_vmap),
                                        stack_closure(msync_gap, &have_gap));
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
    kernel_heaps kh = get_kernel_heaps();
    heap h = heap_general(kh);
    thread_log(current, "mmap: addr %p, length 0x%lx, prot 0x%x, flags 0x%x, "
               "fd %d, offset 0x%lx", addr, length, prot, flags, fd, offset);

    u64 len = pad(length, PAGESIZE);
    if (len == 0)
        return -EINVAL;

    /* Determine vmap flags */
    u64 vmflags = VMAP_FLAG_MMAP;

    int map_type = flags & MAP_TYPE_MASK;
    if (map_type == MAP_SHARED || map_type == MAP_SHARED_VALIDATE)
        vmflags |= VMAP_FLAG_SHARED;
    if ((prot & PROT_EXEC))
        vmflags |= VMAP_FLAG_EXEC;
    if ((prot & PROT_WRITE))
        vmflags |= VMAP_FLAG_WRITABLE;

    /* TODO: assert for unsupported:
       MAP_GROWSDOWN
       MAP_UNINITIALIZED
       MAP_LOCKED
       MAP_NONBLOCK
       MAP_POPULATE
    */

    boolean fixed = (flags & MAP_FIXED) != 0;
    u64 where = fixed ? u64_from_pointer(addr) : 0; /* Don't really try to honor a hint, only fixed. */

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

        /* Release intersecting portions of existing maps */
        range q = irangel(where, len);
        thread_log(current, "   fixed map %R, release intersections and reserve virtual space", q);
        process_unmap_range(p, q);

        /* A specified address is only allowed in certain areas. Programs may specify
           a fixed address to augment some existing mapping. */
        if (!mmap_reserve_range(p, q)) {
	    thread_log(current, "   fail: fixed address range %R outside of lowmem or virtual_page heap\n", q);
	    return -ENOMEM;
        }
    }

    u64 vmap_mmap_type;
    u32 allowed_flags;
    fdesc desc;
    if (flags & MAP_ANONYMOUS) {
        vmap_mmap_type = VMAP_MMAP_TYPE_ANONYMOUS;
        allowed_flags = anon_perms(p);
    } else {
        desc = resolve_fd(p, fd);
        switch (desc->type) {
        case FDESC_TYPE_REGULAR:
            vmap_mmap_type = VMAP_MMAP_TYPE_FILEBACKED;
            allowed_flags = file_perms(p, (file)desc);
            if (!(vmflags & VMAP_FLAG_SHARED))
                allowed_flags |= VMAP_FLAG_WRITABLE;
            break;
        case FDESC_TYPE_IORING:
            vmap_mmap_type = VMAP_MMAP_TYPE_IORING;
            allowed_flags = VMAP_FLAG_WRITABLE | VMAP_FLAG_READABLE;
            break;
        default:
            thread_log(current, "   fail: attempt to mmap file of invalid type %d", desc->type);
            return -EINVAL;
        }
    }
    if ((vmflags & VMAP_FLAG_PROT_MASK) & ~allowed_flags) {
        thread_log(current, "   fail: forbidden access type 0x%x (allowed 0x%x)",
            vmflags & VMAP_FLAG_PROT_MASK, allowed_flags);
        return -EACCES;
    }
    vmflags |= vmap_mmap_type;

    if (!fixed && (vmap_mmap_type == VMAP_MMAP_TYPE_ANONYMOUS ||
                   vmap_mmap_type == VMAP_MMAP_TYPE_FILEBACKED)) {
        boolean is_32bit = (flags & MAP_32BIT) != 0; /* allocate from 32-bit address space */
        where = is_32bit ? id_heap_alloc_subrange(p->virtual32, len, 0x80000000, 0x100000000) :
            allocate_u64((heap)p->virtual_page, len);
        if (where == (u64)INVALID_ADDRESS) {
            /* We'll always want to know about low memory conditions, so just bark. */
            msg_err("failed to allocate %svirtual memory, size 0x%lx\n",
                    is_32bit ? "32-bit " : "", len);
            return -ENOMEM;
        }
        thread_log(current, "   alloc: 0x%lx\n", where);
    }

    sysreturn ret = where;
    switch (vmap_mmap_type) {
    case VMAP_MMAP_TYPE_ANONYMOUS:
        thread_log(current, "   anonymous, specified target 0x%lx", where);
        vmap_paint(h, p, where, len, vmflags, allowed_flags, 0, 0);
        break;
    case VMAP_MMAP_TYPE_IORING:
        thread_log(current, "   fd %d: io_uring", fd);
        if (fixed)
            ret = -ENOMEM;
        else {
            vmflags |= VMAP_FLAG_PREALLOC;
            ret = io_uring_mmap(desc, len, page_map_flags(vmflags), offset);
            thread_log(current, "   io_uring_mmap returned 0x%lx", ret);
            if (ret > 0)
               vmap_paint(h, p, (u64)ret, len, vmflags, allowed_flags, 0, 0);
        }
        break;
    case VMAP_MMAP_TYPE_FILEBACKED:
        thread_log(current, "   fd %d: file-backed (regular)", fd);
        file f = (file)desc;
        if (offset & PAGEMASK) {
            ret = -EINVAL;
        } else {
            assert(f->fsf);
            pagecache_node node = fsfile_get_cachenode(f->fsf);
            thread_log(current, "   associated with cache node %p @ offset 0x%lx", node, offset);
            if (vmflags & VMAP_FLAG_SHARED)
                pagecache_node_add_shared_map(node, irangel(where, len), offset);
            vmap_paint(h, p, where, len, vmflags, allowed_flags, node, offset);
        }
        break;
    default:
        assert(0);
    }
    thread_log(current, "   returning 0x%lx", ret);
    return ret;
}

static sysreturn munmap(void *addr, u64 length)
{
    process p = current->p;
    thread_log(current, "munmap: addr %p, size 0x%lx", addr, length);

    u64 where = u64_from_pointer(addr);
    if ((where & MASK(PAGELOG)) || length == 0)
        return -EINVAL;

    process_unmap_range(p, irangel(where, pad(length, PAGESIZE)));
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
                         ivmap(VMAP_FLAG_EXEC, 0, 0, 0)) != INVALID_ADDRESS);

    /* vvar goes right after the vdso */
    assert(allocate_vmap(p->vmaps, irangel(p->vdso_base + vdso_size, vvar_size),
                         ivmap(0, 0, 0, 0)) != INVALID_ADDRESS);

    /* Track vsyscall page */
    assert(allocate_vmap(p->vmaps, irangel(VSYSCALL_BASE, PAGESIZE),
                         ivmap(VMAP_FLAG_EXEC, 0, 0, 0)) != INVALID_ADDRESS);

    init_closure(&do_kernel_demand_pf_complete, kernel_demand_pf_complete);
}

void register_mmap_syscalls(struct syscall *map)
{
    register_syscall(map, mincore, mincore);
    register_syscall(map, mmap, mmap);
    register_syscall(map, mremap, mremap);
    register_syscall(map, msync, msync);
    register_syscall(map, munmap, munmap);
    register_syscall(map, mprotect, mprotect);
    register_syscall(map, madvise, syscall_ignore);
}
