#include <unix_internal.h>

#define VMAP_FLAG_MMAP          1
#define VMAP_FLAG_ANONYMOUS     2

typedef struct vmap {
    struct rmnode node;
    heap vheap;                 /* presently either p->virtual or p->virtual32 */
    u32 flags;
    u32 prot;
} *vmap;

static vmap allocate_vmap(heap h, range r)
{
    vmap vm = allocate(h, sizeof(struct vmap));
    if (vm == INVALID_ADDRESS)
        return vm;
    rmnode_init(&vm->node, r);
    return vm;
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

boolean unix_fault_page(u64 vaddr)
{
    process p = current->p;
    kernel_heaps kh = get_kernel_heaps();
    vmap vm;

    if ((vm = (vmap)rangemap_lookup(p->vmap, vaddr)) != INVALID_ADDRESS) {
        u32 flags = VMAP_FLAG_MMAP | VMAP_FLAG_ANONYMOUS;
        if ((vm->flags & flags) != flags) {
            msg_err("vaddr 0x%lx matched vmap with invalid flags (0x%x)\n", vaddr, vm->flags);
            return false;
        }

        /* XXX make free list */
        u64 paddr = allocate_u64(heap_physical(kh), PAGESIZE);
        if (paddr == INVALID_PHYSICAL) {
            msg_err("cannot get physical page; OOM\n");
            return false;
        }
        u64 vaddr_aligned = vaddr & ~MASK(PAGELOG);
        map(vaddr_aligned, paddr, PAGESIZE, heap_pages(kh));
        zero(pointer_from_u64(vaddr_aligned), PAGESIZE);
        return true;
    }
    msg_err("no vmap found for vaddr 0x%lx\n", vaddr);
    return false;
}

sysreturn mremap(void *old_address, u64 old_size, u64 new_size, int flags, void * new_address)
{
    kernel_heaps kh = get_kernel_heaps();
    process p = current->p;

    thread_log(current, "mremap: old_address %p, old_size %ld, new_size %ld, flags %x, new_address %p",
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

    /* add new vmap - XXX should remove old vmap - make a range lookup
       that makes this easy */
    vmap vm = allocate_vmap(heap_general(kh), irange(vnew, vnew + maplen));
    if (vm == INVALID_ADDRESS) {
        msg_err("failed to allocate vmap\n");
        deallocate_u64(vh, vnew, maplen);
        return -ENOMEM;
    }
    assert(rangemap_insert(p->vmap, &vm->node));

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
    thread_log(current, "   mapping existing portion at 0x%lx", vnew);
    map(vnew, oldphys, old_size, pages);

    /* map new portion and zero */
    thread_log(current, "   mapping and zeroing new portion at 0x%lx", vnew + old_size);
    map(vnew + old_size, dphys, dlen, pages);
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

CLOSURE_4_2(mmap_read_complete, void, thread, u64, u64, buffer, status, bytes);
void mmap_read_complete(thread t, u64 where, u64 mmap_len, buffer b, status s, bytes length) {
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
    map(where, p, length_padded, pages);
    if (length < length_padded)
        zero(pointer_from_u64(where + length), length_padded - length);

    if (length_padded < mmap_len) {
        u64 bss = pad(mmap_len, PAGESIZE) - length_padded;
        map(where + length_padded, allocate_u64(physical, bss), bss, pages);
        zero(pointer_from_u64(where + length_padded), bss);
    }

    set_syscall_return(t, where);
    thread_wakeup(t);
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
    thread_log(current, "mmap: target %p, size %lx, prot %x, flags %x, fd %d, offset %lx",
	       target, size, prot, flags, fd, offset);

    if (where) {
	thread_log(current, "   %s at %lx", fixed ? "fixed" : "hint", where);

        vmap vmap_start = (vmap)rangemap_lookup(p->vmap, where);
        vmap vmap_end = (vmap)rangemap_lookup(p->vmap, end);
        if (vmap_start != INVALID_ADDRESS &&
            vmap_end == vmap_start &&
            (vmap_start->flags & VMAP_FLAG_ANONYMOUS) == 0) {
            mapped = true;
        } else {
            /* 32 bit mode is ignored if MAP_FIXED */
            heap vh = p->virtual;
            if (where < HUGE_PAGESIZE && end < HUGE_PAGESIZE) {
                /* bound by kernel and zero page. */
                if (where >= PROCESS_VIRTUAL_32_HEAP_START || end <= PROCESS_VIRTUAL_32_HEAP_END) {
                    /* Attempt to reserve low memory fixed mappings in
                       virtual32 to avoid collisions in any future low mem
                       allocation. Don't fail if we can't reserve or it's
                       already reserved. */
                    id_heap_reserve(p->virtual32, where, size);
                } else if (fixed) {
                    thread_log(current, "   map [%lx - %lx] outside of valid 32-bit range [%lx - %lx]",
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

                    if (id_heap_reserve(vh, mapstart, maplen)) {
                        vmap vm = allocate_vmap(h, irange(mapstart, mapstart + maplen));
                        if (vm == INVALID_ADDRESS) {
                            msg_err("failed to allocate vmap\n");
                        return -ENOMEM;
                        }
                        vm->flags = VMAP_FLAG_MMAP;
                        if ((flags & MAP_ANONYMOUS))
                            vm->flags |= VMAP_FLAG_ANONYMOUS;
                        assert(rangemap_insert(p->vmap, &vm->node));
                    } else if (fixed) {
                        thread_log(current, "   failed to reserve area [%lx - %lx] in id heap",
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
            msg_err("failed to allocate %s virtual memory, size %lx",
                    is_32bit ? "32-bit" : "", len);
            return -ENOMEM;
        }
        vmap vm = allocate_vmap(h, irange(where, where + maplen));
        if (vm == INVALID_ADDRESS) {
            msg_err("failed to allocate vmap\n");
            deallocate_u64(vh, where, maplen);
            return -ENOMEM;
        }
        vm->flags = VMAP_FLAG_MMAP;
        if ((flags & MAP_ANONYMOUS))
            vm->flags |= VMAP_FLAG_ANONYMOUS;
        assert(rangemap_insert(p->vmap, &vm->node));
    }

    // make a generic zero page function
    if (flags & MAP_ANONYMOUS) {
        if (mapped) {
            /* just zero */
            zero(pointer_from_u64(where), len);
        } else {
            thread_log(current, "   anon nomap target: %lx, len: %lx (given size: %lx)", where, len, size);
        }
        return where;
    }

    file f = resolve_fd(current->p, fd);
    thread_log(current, "  read file, blocking...");

    heap mh = heap_backed(kh);
    buffer b = allocate_buffer(mh, pad(len, mh->pagesize));
    filesystem_read(p->fs, f->n, buffer_ref(b, 0), len, offset,
        closure(h, mmap_read_complete, current, where, len, b));
    runloop();
}

void register_mmap_syscalls(struct syscall *map)
{
    register_syscall(map, mincore, mincore);
    register_syscall(map, mmap, mmap);
    register_syscall(map, mremap, mremap);
    register_syscall(map, munmap, syscall_ignore);
    register_syscall(map, mprotect, syscall_ignore);
    register_syscall(map, madvise, syscall_ignore);
}

