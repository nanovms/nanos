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

/* Keep in mind that not only user instructions will fault in pages;
   any kernel code operating on behalf of a syscall, or otherwise
   holding onto a userspace buffer, can also cause a page
   fault.

   Therefore:

   - allocating a physical page must be trivial and safe at interrupt
     level

     - if we want to avoid either big locks around the id heaps or
       multiple writers, we can preallocate pages and keep them on a
       free list

   - needless to say, map() will need to be safe from either interrupt
     or non-interrupt levels

*/

boolean unix_fault_page(u64 vaddr)
{
    process p = current->p;
    kernel_heaps kh = get_kernel_heaps();
    rmnode n;

    if ((n = rangemap_lookup(p->vmap, vaddr)) != INVALID_ADDRESS) {
        vmap vm = (vmap)n;      /* XXX use macro */
        u32 flags = VMAP_FLAG_MMAP | VMAP_FLAG_ANONYMOUS;
        if ((vm->flags & flags) != flags) {
            console("bad flags\n");
            print_u64(vm->flags);
            halt("");
            return false;
        }
        u64 paddr = allocate_u64(heap_physical(kh), PAGESIZE);
        if (paddr == INVALID_PHYSICAL) {
            msg_err("cannot get physical page; OOM\n");
            halt("");
            return false;
        }
        u64 vaddr_aligned = vaddr & ~MASK(PAGELOG);
        map(vaddr_aligned, paddr, PAGESIZE, heap_pages(kh));
        zero(pointer_from_u64(vaddr_aligned), PAGESIZE);
        return true;
    }
    console("page not found: ");
    print_u64(vaddr);
    console("\n");
    return false;
}

sysreturn mremap(void *old_address, u64 old_size, u64 new_size, int flags, void * new_address)
{
    kernel_heaps kh = get_kernel_heaps();
    process p = current->p;

    thread_log(current, "mremap: old_address %p, old_size %d, new_size %d, flags %P, new_address %p",
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
        msg_err("failed to allocate virtual memory, size %d", maplen);
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
        msg_err("failed to allocate physical memory, size %d", dlen);
        deallocate_u64(vh, vnew, maplen);
        return -ENOMEM;
    }
    thread_log(current, "   new physical pages at 0x%P, size %d", dphys, dlen);

    /* remove old mapping */
    u64 oldphys = physical_from_virtual(old_address);
    thread_log(current, "   old mapping at phys addr 0x%P, unmapping", oldphys);
    unmap(u64_from_pointer(old_address), old_size, pages);

    /* map existing portion */
    thread_log(current, "   mapping existing portion at 0x%P", vnew);
    map(vnew, oldphys, old_size, pages);

    /* map new portion and zero */
    thread_log(current, "   mapping and zeroing new portion at 0x%P", vnew + old_size);
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

CLOSURE_4_1(mmap_load_entire, void, thread, u64, u64, u64, buffer);
void mmap_load_entire(thread t, u64 where, u64 len, u64 offset, buffer b) {
    kernel_heaps kh = (kernel_heaps)&t->uh;
    heap pages = heap_pages(kh);
    heap physical = heap_physical(kh);

    u64 msize = 0;
    u64 blen = buffer_length(b);
    if (blen > offset)
        msize = pad(blen - offset, PAGESIZE);
    if (msize > len)
        msize = len;

    // mutal misalignment?...discontiguous backing?
    u64 p = physical_from_virtual(buffer_ref(b, offset));
    map(where, p, msize, pages);

    if (len > msize) {
        u64 bss = pad(len, PAGESIZE) - msize;
        map(where + msize, allocate_u64(physical, bss), bss, pages);
        zero(pointer_from_u64(where + msize), bss);
    }
    set_syscall_return(t, where);
    thread_wakeup(t);
}

CLOSURE_1_1(mmap_load_entire_fail, void, thread, status);
void mmap_load_entire_fail(thread t, status v) {
    set_syscall_error(t, EACCES);
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
    thread_log(current, "mmap: target %p, size %P, prot %P, flags %P, fd %d, offset %P\n",
	       target, size, prot, flags, fd, offset);

    if (where) {
	thread_log(current, "   %s at %P", fixed ? "fixed" : "hint", where);

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
                    thread_log(current, "   map [%P - %P] outside of valid 32-bit range [%P - %P]",
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
                        thread_log(current, "   failed to reserve area [%P - %P] in id heap",
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
            msg_err("failed to allocate %s virtual memory, size %P",
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
#if 0
        if (mapped) {
            rprintf("zero only at 0x%P, 0x%P\n", where, len);
        } else {
            heap pages = heap_pages(kh);
            heap physical = heap_physical(kh);
            u64 m = allocate_u64(physical, len);
            if (m == INVALID_PHYSICAL) {
                msg_err("failed to allocate physical memory, size %d\n", len);
                return -ENOMEM;
            }
            map(where, m, len, pages);
            thread_log(current, "   anon target: %P, len: %P (given size: %P)", where, len, size);
        }
        zero(pointer_from_u64(where), len);
#else
        if (mapped) {
            /* just zero */
//            rprintf("anon zero: 0x%P, 0x%P\n", where, len);
            zero(pointer_from_u64(where), len);
        } else {
#if 0
            u64 end = where + len;
            for (u64 v = where; v < end; v += PAGESIZE) {
                u64 p = physical_from_virtual(pointer_from_u64(v));
                if (p != INVALID_PHYSICAL)
                    rprintf("fuckme: 0x%P -> 0x%P\n", v, p);
            }
#endif
//            heap pages = heap_pages(kh);
            /* shouldn't have to...debug */
//            unmap(where, len, pages);
//            rprintf("anon nomap: 0x%P, 0x%P\n", where, len);
            thread_log(current, "   anon nomap target: %P, len: %P (given size: %P)", where, len, size);
        }
#endif
        return where;
    }

    file f = resolve_fd(current->p, fd);
    thread_log(current, "  read file, blocking...");
    filesystem_read_entire(p->fs, f->n, heap_backed(kh),
                           closure(h, mmap_load_entire, current, where, len, offset),
                           closure(h, mmap_load_entire_fail, current));
    runloop();
}

void register_mmap_syscalls(void **map)
{
    register_syscall(map, SYS_mincore, mincore);
    register_syscall(map, SYS_mmap, mmap);
    register_syscall(map, SYS_mremap, mremap);        
    register_syscall(map, SYS_munmap, syscall_ignore);
    register_syscall(map, SYS_mprotect, syscall_ignore);
    register_syscall(map, SYS_madvise, syscall_ignore);
}

