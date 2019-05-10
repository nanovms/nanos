#include <unix_internal.h>

#define VMAP_FLAG_MMAP          1
#define VMAP_FLAG_ANONYMOUS     2
#define VMAP_FLAG_WRITABLE      4
#define VMAP_FLAG_EXEC          8

typedef struct vmap {
    struct rmnode node;
    heap vheap;                 /* presently either p->virtual or p->virtual32 */
    u64 flags;
} *vmap;

static boolean vmap_attr_equal(vmap a, vmap b)
{
    return a->vheap == b->vheap && a->flags == b->flags;
}

/* Page faults may be caused by:

   - user program instructions

   - syscall top halves accessing unmapped anonymous pages

   - syscall bottom halves accessing unmapped anonymous pages (while
     in the interrupt handler!)

     - can consider manually faulting in user pages in top half to
       avoid faults from interrupt handler; this is debatable

   Therefore:

   - allocating a physical page must be fast and safe at interrupt
     level

     - as elsewhere in the kernel, if/when we move from the bifurcated
       runqueue / interrupt processing scheme, we need to put the
       proper locks in place

     - we can easily build a free list of physical pages

       - also note that, given that id deallocations don't need to
         match their source allocations, we can take any size
         deallocation and bust it up into single pages to cache

   - map() needs to be safe at interrupt and non-interrupt levels

   - the page fault handler runs on its own stack (set as IST0 in
     TSS), given that the user stack may live on an anonymous mapping
     and need to have pages faulted in on its own behalf - otherwise
     we eventually wind up with a triple fault as the CPU cannot push
     onto the stack when invoking the exception handler
*/

static inline u64 page_map_flags(u64 vmflags)
{
    u64 flags = PAGE_NO_FAT | PAGE_USER;
    if ((vmflags & VMAP_FLAG_EXEC) == 0)
        flags |= PAGE_NO_EXEC;
    if ((vmflags & VMAP_FLAG_WRITABLE))
        flags |= PAGE_WRITABLE;
    return flags;
}

boolean unix_fault_page(u64 vaddr, context frame)
{
    process p = current->p;
    kernel_heaps kh = get_kernel_heaps();
    u64 error_code = frame[FRAME_ERROR_CODE];

    if ((error_code & FRAME_ERROR_PF_P) == 0) {
        vmap vm = (vmap)rangemap_lookup(p->vmap, vaddr);
        if (vm == INVALID_ADDRESS) {
            msg_err("no vmap found for vaddr 0x%lx\n", vaddr);
            return false;
        }

        u32 flags = VMAP_FLAG_MMAP | VMAP_FLAG_ANONYMOUS;
        if ((vm->flags & flags) != flags) {
            msg_err("vaddr 0x%lx matched vmap with invalid flags (0x%x)\n",
                    vaddr, vm->flags);
            return false;
        }

        /* XXX make free list */
        u64 paddr = allocate_u64(heap_physical(kh), PAGESIZE);
        if (paddr == INVALID_PHYSICAL) {
            msg_err("cannot get physical page; OOM\n");
            return false;
        }
        u64 vaddr_aligned = vaddr & ~MASK(PAGELOG);
        map(vaddr_aligned, paddr, PAGESIZE, page_map_flags(vm->flags), heap_pages(kh));
        zero(pointer_from_u64(vaddr_aligned), PAGESIZE);
        return true;
    } else {
        /* page protection violation */
        rprintf("\nPage protection violation\naddr 0x%lx, rip 0x%lx, "
                "error %s%s%s\n", vaddr, frame[FRAME_RIP],
                (error_code & FRAME_ERROR_PF_RW) ? "W" : "R",
                (error_code & FRAME_ERROR_PF_US) ? "U" : "S",
                (error_code & FRAME_ERROR_PF_ID) ? "I" : "D");
        vmap vm = (vmap)rangemap_lookup(p->vmap, vaddr);
        if (vm == INVALID_ADDRESS) {
            rprintf("no vmap found address\n");
        } else {
            rprintf("matching vmap: range %R, flags: ", vm->node.r);
            if (vm->flags & VMAP_FLAG_MMAP)
                rprintf("mmap ");
            if (vm->flags & VMAP_FLAG_ANONYMOUS)
                rprintf("anonymous ");
            if (vm->flags & VMAP_FLAG_WRITABLE)
                rprintf("writable ");
            if (vm->flags & VMAP_FLAG_EXEC)
                rprintf("executable ");
            rprintf("\n");
        }

#ifndef BOOT
        dump_ptes(pointer_from_u64(vaddr));
#endif

        if ((error_code & FRAME_ERROR_PF_RSV))
            rprintf("bug: pte reserved\n");
        return false;
    }
}

static vmap allocate_vmap(heap h, rangemap rm, range r, heap vheap, u64 flags)
{
    vmap vm = allocate(h, sizeof(struct vmap));
    if (vm == INVALID_ADDRESS)
        return vm;
    rmnode_init(&vm->node, r);
    vm->vheap = vheap;
    vm->flags = flags;
    if (!rangemap_insert(rm, &vm->node)) {
        deallocate(h, vm, sizeof(struct vmap));
        return INVALID_ADDRESS;
    }
    return vm;
}

sysreturn mremap(void *old_address, u64 old_size, u64 new_size, int flags, void * new_address)
{
    kernel_heaps kh = get_kernel_heaps();
    process p = current->p;

    thread_log(current, "mremap: old_address %p, old_size %ld, new_size %ld, flags 0x%x, new_address %p",
	       old_address, old_size, new_size, flags, new_address);

    if ((flags & MREMAP_MAYMOVE) == 0) {
        msg_err("only supporting MREMAP_MAYMOVE yet\n");
        return -ENOMEM;
    }

    if ((flags & MREMAP_FIXED)) {
        msg_err("no support for MREMAP_FIXED yet\n");
        return -ENOMEM;
    }

    if ((u64_from_pointer(old_address) & MASK(PAGELOG)) ||
        (flags & ~(MREMAP_MAYMOVE | MREMAP_FIXED)) ||
        new_size == 0)
        return -EINVAL;

    /* XXX should determine if we're extending a virtual32 allocation... */
    heap vh = p->virtual_page;
    heap physical = heap_physical(kh);
    heap pages = heap_pages(kh);

    old_size = pad(old_size, vh->pagesize);
    if (new_size <= old_size)
        return sysreturn_from_pointer(old_address);

    /* new virtual allocation */
    u64 maplen = pad(new_size, vh->pagesize);
    u64 vnew = allocate_u64(vh, maplen);
    if (vnew == (u64)INVALID_ADDRESS) {
        msg_err("failed to allocate virtual memory, size %ld", maplen);
        return -ENOMEM;
    }

    /* remove old mapping, preserving attributes
     * XXX should verify entire given range
     */
    vmap old_vm = (vmap)rangemap_lookup(p->vmap, u64_from_pointer(old_address));
    if (old_vm == INVALID_ADDRESS)
        return -EFAULT;
    heap vheap = old_vm->vheap;
    u64 vmflags = old_vm->flags;
    rangemap_remove_node(p->vmap, &old_vm->node);

    /* create new vm with old attributes */
    vmap vm = allocate_vmap(heap_general(kh), p->vmap, irange(vnew, vnew + maplen), vheap, vmflags);
    if (vm == INVALID_ADDRESS) {
        msg_err("failed to allocate vmap\n");
        deallocate_u64(vh, vnew, maplen);
        return -ENOMEM;
    }

    /* balance of physical allocation */
    u64 dlen = maplen - old_size;
    u64 dphys = allocate_u64(physical, dlen);
    if (dphys == INVALID_PHYSICAL) {
        msg_err("failed to allocate physical memory, size %ld", dlen);
        deallocate_u64(vh, vnew, maplen);
        return -ENOMEM;
    }
    thread_log(current, "   new physical pages at 0x%lx, size %ld", dphys, dlen);

    /* remove old mapping */
    u64 oldphys = physical_from_virtual(old_address);
    thread_log(current, "   old mapping at phys addr 0x%lx, unmapping", oldphys);
    unmap(u64_from_pointer(old_address), old_size, pages);

    /* map existing portion */
    u64 mapflags = page_map_flags(vm->flags);
    thread_log(current, "   mapping existing portion at 0x%lx", vnew);
    map(vnew, oldphys, old_size, mapflags, pages);

    /* map new portion and zero */
    thread_log(current, "   mapping and zeroing new portion at 0x%lx", vnew + old_size);
    map(vnew + old_size, dphys, dlen, mapflags, pages);
    zero(pointer_from_u64(vnew + old_size), dlen);

    return sysreturn_from_pointer(vnew);
}

static sysreturn mincore(void *addr, u64 length, u8 *vec)
{
    if (validate_virtual(addr, length)) {
        u32 vlen = pad(length, PAGESIZE) >> PAGELOG;
        // presumably it wants the right valid bits set? - go doesn't seem to use it this way
        for (int i = 0; i< vlen; i++) vec[i] = 1;
        return 0;
    }
    return -ENOMEM;
}

static CLOSURE_6_2(mmap_read_complete, void, thread, u64, u64, boolean, buffer, u64, status, bytes);
static void mmap_read_complete(thread t, u64 where, u64 mmap_len, boolean mapped, buffer b, u64 mapflags,
                               status s, bytes length) {
    if (!is_ok(s)) {
        deallocate_buffer(b);
        set_syscall_error(t, EACCES);
        thread_wakeup(t);
	return;
    }

    kernel_heaps kh = (kernel_heaps)&t->uh;
    heap pages = heap_pages(kh);
    heap physical = heap_physical(kh);

    // mutal misalignment?...discontiguous backing?
    u64 length_padded = pad(length, PAGESIZE);
    u64 p = physical_from_virtual(buffer_ref(b, 0));
    if (mapped) {
        update_map_flags(where, length, mapflags);
        runtime_memcpy(pointer_from_u64(where), buffer_ref(b, 0), length);
    } else {
        map(where, p, length_padded, mapflags, pages);
    }

    if (length < length_padded)
        zero(pointer_from_u64(where + length), length_padded - length);

    if (length_padded < mmap_len) {
        u64 bss = pad(mmap_len, PAGESIZE) - length_padded;
        if (!mapped)
            map(where + length_padded, allocate_u64(physical, bss), bss, mapflags, pages);
        else
            update_map_flags(where + length_padded, bss, mapflags);
        zero(pointer_from_u64(where + length_padded), bss);
    }

    if (mapped) {
        deallocate_buffer(b);
    } else {
        /* XXX This is gross. Either support this within the buffer interface or use something besides
           a buffer... */
        physically_backed_dealloc_virtual(b->h, u64_from_pointer(buffer_ref(b, 0)), pad(mmap_len, b->h->pagesize));
        deallocate(b->h, b, sizeof(struct buffer));
    }

    set_syscall_return(t, where);
    thread_wakeup(t);
}

#if 0
static CLOSURE_0_1(vmap_dump_node, void, rmnode);
static void vmap_dump_node(rmnode n)
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
    rmnode_handler nh = closure(heap_general(get_kernel_heaps()), vmap_dump_node);
    rangemap_range_lookup(pvmap, (range){0, infinity}, nh);
}
#endif

/* XXX refactor */
static CLOSURE_3_1(vmap_attribute_update_intersection, void, heap, rangemap, vmap, rmnode);
static void vmap_attribute_update_intersection(heap h, rangemap pvmap, vmap q, rmnode node)
{
    vmap match = (vmap)node;
    if (vmap_attr_equal(q, match))
        return;

    range rn = node->r;
    range rq = q->node.r;
    range ri = range_intersection(rq, rn);
    assert(range_span(ri) > 0); // XXX

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

#if 0  // XXX make debug
    rprintf("pre attr update:\n");
    vmap_dump(pvmap);
#endif
    u64 newflags = (match->flags & ~(VMAP_FLAG_WRITABLE | VMAP_FLAG_EXEC)) | q->flags;

    if (head) {
        u64 rtend = rn.end;

        /* split non-intersecting part of node */
        range rhl = { rn.start, ri.start };
        assert(rangemap_reinsert(pvmap, node, rhl));

#if 0
        vmap_dump(pvmap);
#endif
        /* create node for intersection */
        vmap mh = allocate_vmap(h, pvmap, ri, q->vheap, newflags);
        assert(mh != INVALID_ADDRESS);
        
        if (tail) {
            /* create node at tail end */
            range rt = { ri.end, rtend };
            vmap mt = allocate_vmap(h, pvmap, rt, match->vheap, match->flags);
            assert(mt != INVALID_ADDRESS);
        }
    } else if (tail) {
        /* move node start back */
        range rt = { ri.end, node->r.end };
        assert(rangemap_reinsert(pvmap, node, rt));

        /* create node for intersection */
        vmap mt = allocate_vmap(h, pvmap, ri, q->vheap, newflags);
        assert(mt != INVALID_ADDRESS);
    } else {
        /* key (range) remains the same, no need to reinsert */
        match->vheap = q->vheap;
        match->flags = newflags;
    }
}

static void vmap_attribute_update(heap h, rangemap pvmap, vmap q)
{
    range rq = q->node.r;
    assert((rq.start & MASK(PAGELOG)) == 0);
    assert((rq.end & MASK(PAGELOG)) == 0);
    assert(range_span(rq) > 0);

    rmnode_handler nh = closure(h, vmap_attribute_update_intersection, h, pvmap, q);
    rangemap_range_lookup(pvmap, rq, nh);

    update_map_flags(rq.start, range_span(rq), page_map_flags(q->flags));
}

sysreturn mprotect(void * addr, u64 len, int prot)
{
    thread_log(current, "mprotect: addr %p, len 0x%lx, prot 0x%x", addr, len, prot);

    if (len == 0)
        return 0;

    heap h = heap_general(get_kernel_heaps());
    rangemap pvmap = current->p->vmap;
    u64 where = u64_from_pointer(addr);
    u64 padlen = pad(len, PAGESIZE);
    if ((where & MASK(PAGELOG)))
        return -EINVAL;

    u64 new_vmflags = 0;
    if ((prot & PROT_EXEC))
        new_vmflags |= VMAP_FLAG_EXEC;
    if ((prot & PROT_WRITE))
        new_vmflags |= VMAP_FLAG_WRITABLE;

//    vmap_dump(pvmap);
//    rprintf("vmflags: 0x%lx\n", new_vmflags);

    range r = { where, where + padlen };
    struct vmap q;
    q.node.r = r;
//    q.vheap = resolve_vheap_for_range(r);
    q.vheap = current->p->virtual_page; // XXX
    q.flags = new_vmflags;

    vmap_attribute_update(h, pvmap, &q);
    return 0;
}

static sysreturn mmap(void *target, u64 size, int prot, int flags, int fd, u64 offset)
{
    process p = current->p;
    kernel_heaps kh = get_kernel_heaps();
    heap h = heap_general(kh);
    // its really unclear whether this should be extended or truncated
    u64 len = pad(size, PAGESIZE) & MASK(32);
    u64 where = u64_from_pointer(target);
    u64 end = where + size - 1;
    boolean fixed = (flags & MAP_FIXED) != 0;
    boolean mapped = false;
    thread_log(current, "mmap: target %p, size 0x%lx, prot 0x%x, flags 0x%x, fd %d, offset 0x%lx",
	       target, size, prot, flags, fd, offset);

    vmap vm = 0;
    u64 vmflags = VMAP_FLAG_MMAP;
    if ((flags & MAP_ANONYMOUS))
        vmflags |= VMAP_FLAG_ANONYMOUS;
    if ((prot & PROT_EXEC))
        vmflags |= VMAP_FLAG_EXEC;
    if ((prot & PROT_WRITE))
        vmflags |= VMAP_FLAG_WRITABLE;

    if (where) {
        thread_log(current, "   %s at 0x%lx", fixed ? "fixed" : "hint", where);

        vmap vmap_start = (vmap)rangemap_lookup(p->vmap, where);
        vmap vmap_end = (vmap)rangemap_lookup(p->vmap, end);
        if (vmap_start != INVALID_ADDRESS &&
            vmap_end == vmap_start) {
            mapped = true;
            vm = vmap_start;
        } else {
            /* 32 bit mode is ignored if MAP_FIXED */
            heap vh = p->virtual;
            if (where < HUGE_PAGESIZE && end < HUGE_PAGESIZE) {
                /* bound by kernel and zero page. */
                if (where >= PROCESS_VIRTUAL_32_HEAP_START && end <= PROCESS_VIRTUAL_32_HEAP_END) {
                    /* Attempt to reserve low memory fixed mappings in
                       virtual32 to avoid collisions in any future low mem
                       allocation. Don't fail if we can't reserve or it's
                       already reserved. */
                    id_heap_range_modify(p->virtual32, where, size, false, true);
                    /* XXX vmap? */
                } else if (fixed) {
                    thread_log(current, "   map [0x%lx - 0x%lx] outside of valid 32-bit range [0x%lx - 0x%lx]",
                               where, end, PROCESS_VIRTUAL_32_HEAP_START, PROCESS_VIRTUAL_32_HEAP_END);
                    return -ENOMEM;
                } else {
                    target = 0; /* allocate */
                }
            } else {
                if (where < PROCESS_VIRTUAL_HEAP_START || end > PROCESS_VIRTUAL_HEAP_END) {
                    /* Try to allow outside our process virtual space, as
                       long as we can block it out in virtual_huge. */
                    vh = heap_virtual_huge(kh);
                }

                /* XXX range lookup in rtrie is broke, do manually until
                   fixed... note that this check could pass even if start and
                   end lie in two different mmapped areas. No matter, as we
                   just need to verify that this overlapping map lies in a
                   huge page that we're already using...the overlapping mmap
                   lawlessness is to be tolerated for the moment.

                   This is like a really crude start to vm tracking...
                */
                if (vmap_start == INVALID_ADDRESS || vmap_end == INVALID_ADDRESS) {
                    u64 mapstart = where & ~(HUGE_PAGESIZE - 1);
                    u64 mapend = pad(end, HUGE_PAGESIZE);
                    u64 maplen = mapend - mapstart + 1;

                    if (id_heap_range_modify(vh, mapstart, maplen, true, true)) {
                        vm = allocate_vmap(h, p->vmap, irange(mapstart, mapstart + maplen), vh, vmflags);
                        if (vm == INVALID_ADDRESS) {
                            msg_err("failed to allocate vmap\n");
                            return -ENOMEM;
                        }
                    } else if (fixed) {
                        thread_log(current, "   failed to reserve area [0x%lx - 0x%lx] in id heap",
                                   where, end);
                        return -ENOMEM;
                    } else {
                        target = 0; /* allocate */
                    }
                }
            }
        }
    }

    /* target may have been cleared if we couldn't get that address and
       want to default to allocating... */
    if (!target) {
        if (fixed) {
            thread_log(current, "   attempt to map zero page");
            return -ENOMEM;
        }

        boolean is_32bit = flags & MAP_32BIT;
        heap vh = is_32bit ? p->virtual32 : p->virtual_page;
        u64 maplen = pad(len, vh->pagesize);
        where = allocate_u64(vh, maplen);
        if (where == (u64)INVALID_ADDRESS) {
            /* We'll always want to know about low memory conditions, so just bark. */
            msg_err("failed to allocate %s virtual memory, size 0x%lx",
                    is_32bit ? "32-bit" : "", len);
            return -ENOMEM;
        }
        vm = allocate_vmap(h, p->vmap, irange(where, where + maplen), vh, vmflags);
        if (vm == INVALID_ADDRESS) {
            msg_err("failed to allocate vmap\n");
            deallocate_u64(vh, where, maplen);
            return -ENOMEM;
        }
    }

    // make a generic zero page function
    if (flags & MAP_ANONYMOUS) {
        thread_log(current, "   anon target: %s, 0x%lx, len: 0x%lx (given size: 0x%lx)",
                   mapped ? "existing" : "new", where, len, size);
        if (mapped) {
            if ((vm->flags & VMAP_FLAG_ANONYMOUS) == 0) {
                /* anon overlaid on backed mapping; just zero */
                zero(pointer_from_u64(where), len);
            }

            /* XXX need to check if a new vmap is required... */

            if (vm->flags != vmflags) {
                thread_log(current, "   new vm flags: 0x%lx", vmflags);
                vm->flags = vmflags;
                update_map_flags(where, len, page_map_flags(vmflags));
            }
        }
        return where;
    }

    assert(vm);
    file f = resolve_fd(current->p, fd);
    thread_log(current, "  read file at 0x%lx, %s map, blocking...", where, mapped ? "existing" : "new");

    heap mh = heap_backed(kh);
    buffer b = allocate_buffer(mh, pad(len, mh->pagesize));
    filesystem_read(p->fs, f->n, buffer_ref(b, 0), len, offset,
                    closure(h, mmap_read_complete, current, where, len, mapped, b, page_map_flags(vmflags)));
    runloop();
}

void register_mmap_syscalls(struct syscall *map)
{
    register_syscall(map, mincore, mincore);
    register_syscall(map, mmap, mmap);
    register_syscall(map, mremap, mremap);
    register_syscall(map, munmap, syscall_ignore);
    register_syscall(map, mprotect, mprotect);
    register_syscall(map, madvise, syscall_ignore);
}

