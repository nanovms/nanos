#include <unix_internal.h>
#include <page.h>

static boolean vmap_attr_equal(vmap a, vmap b)
{
    return a->flags == b->flags;
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

boolean do_demand_page(u64 vaddr, vmap vm)
{
    if ((vm->flags & VMAP_FLAG_MMAP) == 0) {
        msg_err("vaddr 0x%lx matched vmap with invalid flags (0x%x)\n",
                vaddr, vm->flags);
        return false;
    }

    /* XXX make free list */
    kernel_heaps kh = get_kernel_heaps();
    u64 paddr = allocate_u64((heap)heap_physical(kh), PAGESIZE);
    if (paddr == INVALID_PHYSICAL) {
        msg_err("cannot get physical page; OOM\n");
        return false;
    }

    u64 vaddr_aligned = vaddr & ~MASK(PAGELOG);
    map(vaddr_aligned, paddr, PAGESIZE, page_map_flags(vm->flags), heap_pages(kh));
    zero(pointer_from_u64(vaddr_aligned), PAGESIZE);

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

vmap allocate_vmap(rangemap rm, range r, u64 flags)
{
    vmap vm = allocate(rm->h, sizeof(struct vmap));
    if (vm == INVALID_ADDRESS)
        return vm;
    rmnode_init(&vm->node, r);
    vm->flags = flags;
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
    kernel_heaps kh = get_kernel_heaps();
    process p = current->p;
    u64 old_addr = u64_from_pointer(old_address);
    sysreturn rv;

    thread_log(current, "mremap: old_address %p, old_size 0x%lx, new_size 0x%lx, flags 0x%x, new_address %p",
	       old_address, old_size, new_size, flags, new_address);

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
    id_heap physical = heap_physical(kh);
    heap pages = heap_pages(kh);

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
    vmap vm = allocate_vmap(p->vmaps, irange(vnew, vnew + maplen), vmflags);
    if (vm == INVALID_ADDRESS) {
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
    remap_pages(vnew, old_addr, old_size, pages);

    /* map new portion and zero */
    u64 mapflags = page_map_flags(vmflags);
    thread_log(current, "   mapping and zeroing new portion at 0x%lx, page flags 0x%lx",
               vnew + old_size, mapflags);
    map(vnew + old_size, dphys, dlen, mapflags, pages);
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

    /* -ENOMEM if any unmapped gaps in range */
    process p = current->p;
    vmap_lock(p);
    boolean found = rangemap_range_find_gaps(p->vmaps,
                                             (range){start, start + length},
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

    kernel_heaps kh = (kernel_heaps)&t->uh;
    heap pages = heap_pages(kh);

    u64 buf_len = bound(buf_len);
    assert((buf_len & (PAGESIZE - 1)) == 0);
    void * buf = buffer_ref(b, 0);

    /* free existing pages */
    unmap_and_free_phys(where, buf_len);

    /* Note that we rely on the backed heap being physically
       contiguous. If this behavior changes or faulted-in pages are
       ever used, revise this to use the page walker. */
    map(where, physical_from_virtual(buf), buf_len, mapflags, pages);

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

/* XXX refactor */
closure_function(3, 1, void, vmap_attribute_update_intersection,
                 heap, h, rangemap, pvmap, vmap, q,
                 rmnode, node)
{
    rangemap pvmap = bound(pvmap);
    vmap q = bound(q);

    vmap match = (vmap)node;
    if (vmap_attr_equal(q, match))
        return;

    range rn = node->r;
    range rq = q->node.r;
    range ri = range_intersection(rq, rn);

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

    u64 newflags = (match->flags & ~(VMAP_FLAG_WRITABLE | VMAP_FLAG_EXEC)) | q->flags;

    if (head) {
        u64 rtend = rn.end;

        /* split non-intersecting part of node */
        range rhl = { rn.start, ri.start };
        assert(rangemap_reinsert(pvmap, node, rhl));

        /* create node for intersection */
        vmap mh = allocate_vmap(pvmap, ri, newflags);
        assert(mh != INVALID_ADDRESS);

        if (tail) {
            /* create node at tail end */
            range rt = { ri.end, rtend };
            vmap mt = allocate_vmap(pvmap, rt, match->flags);
            assert(mt != INVALID_ADDRESS);
        }
    } else if (tail) {
        /* move node start back */
        range rt = { ri.end, node->r.end };
        assert(rangemap_reinsert(pvmap, node, rt));

        /* create node for intersection */
        vmap mt = allocate_vmap(pvmap, ri, newflags);
        assert(mt != INVALID_ADDRESS);
    } else {
        /* key (range) remains the same, no need to reinsert */
        match->flags = newflags;
    }
}

static void vmap_attribute_update(heap h, rangemap pvmap, vmap q)
{
    range rq = q->node.r;
    assert((rq.start & MASK(PAGELOG)) == 0);
    assert((rq.end & MASK(PAGELOG)) == 0);
    assert(range_span(rq) > 0);

    rmnode_handler nh = stack_closure(vmap_attribute_update_intersection, h, pvmap, q);
    rangemap_range_lookup(pvmap, rq, nh);

    update_map_flags(rq.start, range_span(rq), page_map_flags(q->flags));
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

    range r = { where, where + padlen };
    struct vmap q;
    q.node.r = r;
    q.flags = new_vmflags;

    process p = current->p;
    vmap_lock(p);
    vmap_attribute_update(h, p->vmaps, &q);
    vmap_unlock(p);
    return 0;
}

/* If we can re-use a node (range is exact match), just update the
   flags. Otherwise trim back any vmap(s) that overlap with q,
   creating a new node if necessary. After this point, new nodes can
   be created using the gap fill.
 */
closure_function(3, 1, void, vmap_paint_intersection,
                 heap, h, rangemap, pvmap, vmap, q,
                 rmnode, node)
{
    rangemap pvmap = bound(pvmap);
    vmap q = bound(q);

    vmap match = (vmap)node;
    if (vmap_attr_equal(q, match))
        return;

    range rn = node->r;
    range ri = range_intersection(q->node.r, rn);

    assert(range_span(ri) > 0); // XXX

    /* attribute mismatch; check if we can just reuse matching node */
    if (range_equal(ri, rn)) {
        /* key (range) remains the same, no need to reinsert */
        match->flags = q->flags;
        return;
    }

    /* trim match at both head and tail ends */
    boolean head = ri.start > rn.start;
    boolean tail = ri.end < rn.end;

    if (head) {
        /* truncate node at start */
        range rh = { rn.start, ri.start };
        u64 rtend = rn.end;
        rangemap_reinsert(pvmap, node, rh);

        if (tail) {
            /* create node at tail end */
            range rt = { ri.end, rtend };
            vmap mt = allocate_vmap(pvmap, rt, match->flags);
            assert(mt != INVALID_ADDRESS);
        }
    } else if (tail) {
        /* move node start back */
        range rt = { ri.end, rn.end };
        rangemap_reinsert(pvmap, node, rt);
    }
}

closure_function(3, 1, void, vmap_paint_gap,
                 heap, h, rangemap, pvmap, vmap, q,
                 range, r)
{
    vmap mt = allocate_vmap(bound(pvmap), r, bound(q)->flags);
    assert(mt != INVALID_ADDRESS);
}

static void vmap_paint(heap h, rangemap pvmap, vmap q)
{
    range rq = q->node.r;
    assert((rq.start & MASK(PAGELOG)) == 0);
    assert((rq.end & MASK(PAGELOG)) == 0);
    assert(range_span(rq) > 0);

    rangemap_range_lookup(pvmap, rq, stack_closure(vmap_paint_intersection, h, pvmap, q));
    rangemap_range_find_gaps(pvmap, rq, stack_closure(vmap_paint_gap, h, pvmap, q));

    update_map_flags(rq.start, range_span(rq), page_map_flags(q->flags));
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
    thread_log(current, "mmap: target %p, size 0x%lx, len 0x%lx, prot 0x%x, flags 0x%x, fd %d, offset 0x%lx",
	       target, size, len, prot, flags, fd, offset);

    /* Determine vmap flags */
    u64 vmflags = VMAP_FLAG_MMAP;
    if ((flags & MAP_ANONYMOUS))
        vmflags |= VMAP_FLAG_ANONYMOUS;
    if ((prot & PROT_EXEC))
        vmflags |= VMAP_FLAG_EXEC;
    if ((prot & PROT_WRITE))
        vmflags |= VMAP_FLAG_WRITABLE;

    /* Don't really try to honor a hint, only fixed. */
    boolean fixed = (flags & MAP_FIXED) != 0;
    u64 where = fixed ? u64_from_pointer(target) : 0;

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
            msg_err("failed to allocate %s virtual memory, size 0x%lx\n", is_32bit ? "32-bit" : "", len);
            return -ENOMEM;
        }
    }

    /* Paint into process vmap */
    struct vmap q;
    q.flags = vmflags;
    q.node.r = irange(where, where + len);
    vmap_lock(p);
    vmap_paint(h, p->vmaps, &q);
    vmap_unlock(p);

    if (flags & MAP_ANONYMOUS) {
        thread_log(current, "   anon target: 0x%lx, len: 0x%lx (given size: 0x%lx)", where, len, size);
        /* If mmap this intersects an existing one, zero any mapped pages. */
        zero_mapped_pages(where, len);
        return where;
    }

    file f = resolve_fd(p, fd);
    u64 flen = MIN(pad(f->length, PAGESIZE), len);
    heap mh = heap_backed(kh);
    buffer b = allocate_buffer(mh, pad(flen, mh->pagesize));

    thread_log(current, "  read file at 0x%lx, flen %ld, blocking...", where, flen);
    file_op_begin(current);
    filesystem_read_linear(p->fs, f->n, buffer_ref(b, 0), flen, offset,
                           closure(h, mmap_read_complete, current, where, flen, b, page_map_flags(vmflags)));
    return file_op_maybe_sleep(current);
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
        u64 rtend = rn.end;

        /* split non-intersecting part of node */
        range rhl = { rn.start, ri.start };
        assert(rangemap_reinsert(p->vmaps, node, rhl));

        if (tail) {
            /* create node for tail end */
            range rt = { ri.end, rtend };
            vmap mt = allocate_vmap(p->vmaps, rt, match->flags);
            assert(mt != INVALID_ADDRESS);
        }
    } else if (tail) {
        /* move node start back */
        range rt = { ri.end, node->r.end };
        assert(rangemap_reinsert(p->vmaps, node, rt));
    } else {
        /* delete outright */
        rangemap_remove_node(p->vmaps, node);
    }

    /* unmap any mapped pages and return to physical heap */
    u64 len = range_span(ri);
    unmap_and_free_phys(ri.start, len);

    /* return virtual mapping to heap, if any ... assuming a vmap cannot span heaps!
       XXX: this shouldn't be a lookup per, so consider stashing a link to varea or heap in vmap
       though in practice these are small numbers... */
    varea v = (varea)rangemap_lookup(p->vareas, ri.start);
    assert(v != INVALID_ADDRESS);
    if (v->h)
        id_heap_set_area(v->h, ri.start, len, false, false);
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
    range identity_map = irange(kh->identity_reserved_start, kh->identity_reserved_end);
    spin_lock_init(&p->vmap_lock);
    p->vareas = allocate_rangemap(h);
    p->vmaps = allocate_rangemap(h);
    assert(p->vareas != INVALID_ADDRESS && p->vmaps != INVALID_ADDRESS);

    /* zero page is off-limits */
    add_varea(p, 0, PAGESIZE, p->virtual32, false);

    /* as is the identity heap */
    add_varea(p, identity_map.start, identity_map.end, p->virtual32, false);

    /* and kernel */
    add_varea(p, KERNEL_RESERVE_START, KERNEL_RESERVE_END, p->virtual32, false);

    /* but explicitly allow any maps in between */
    p->lowmem_end = MIN(KERNEL_RESERVE_START, identity_map.start);
    add_varea(p, PAGESIZE, p->lowmem_end, p->virtual32, true);

    /* reserve kernel huge page area */
    add_varea(p, HUGE_PAGESIZE, PROCESS_VIRTUAL_HEAP_START, 0, false);

    /* allow (tracked) reservations in p->virtual */
    add_varea(p, PROCESS_VIRTUAL_HEAP_START, PROCESS_VIRTUAL_HEAP_END, p->virtual_page, true);

    /* reserve end of p->virtual to user tag region */
    u64 user_va_tag_start = U64_FROM_BIT(user_va_tag_offset);
    u64 user_va_tag_end = user_va_tag_start * tag_max;
    add_varea(p, PROCESS_VIRTUAL_HEAP_END, user_va_tag_start, 0, false);

    /* allow untracked mmaps in user va tag area */
    add_varea(p, user_va_tag_start, user_va_tag_end, 0, true);

    /* reserve user va tag area from kernel perspective */
    assert(id_heap_set_area(heap_virtual_huge(kh), user_va_tag_start, user_va_tag_end, true, true));

    /* reserve remainder */
    add_varea(p, user_va_tag_end, U64_FROM_BIT(VIRTUAL_ADDRESS_BITS), 0, false);

    /* randomly determine vdso/vvar base and track it */
    u64 vdso_size, vvar_size, vvar_start;

    vdso_size = vdso_raw_length;
    vvar_size = VVAR_NR_PAGES * PAGESIZE;

    p->vdso_base = allocate_u64((heap)p->virtual_page, vdso_size + vvar_size);
    assert(allocate_vmap(p->vmaps, irange(p->vdso_base, p->vdso_base + vdso_size/*+vvar_size*/),
                         VMAP_FLAG_EXEC) != INVALID_ADDRESS);

    /* vvar goes right after the vdso */
    vvar_start = p->vdso_base + vdso_size;
    assert(allocate_vmap(p->vmaps, irange(vvar_start, vvar_start + vvar_size), 0) != INVALID_ADDRESS);

    /* Track vsyscall page */
    assert(allocate_vmap(p->vmaps, irange(VSYSCALL_BASE, VSYSCALL_BASE + PAGESIZE), VMAP_FLAG_EXEC)
           != INVALID_ADDRESS);
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
