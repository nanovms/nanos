#include <unix_internal.h>

sysreturn mremap(void *old_address, u64 old_size,  u64 new_size, int flags,  void *new_address )
{
    kernel_heaps kh = get_kernel_heaps();

    // this seems poorly thought out - what if there is a backing file?
    // and if its anonymous why do we care where it is..i guess this
    // is just for large realloc operations? if these aren't aligned
    // its completely unclear what to do
    u64 align =  ~MASK(PAGELOG);
    if (new_size > old_size) {
        u64 diff = pad(new_size - old_size, PAGESIZE);
        u64 base = u64_from_pointer(old_address + old_size) & align;
        void *r = allocate(heap_physical(kh),diff);
        if (u64_from_pointer(r) == INVALID_PHYSICAL) {
            // MAP_FAILED
            return sysreturn_from_pointer(r);
        }
        map(base, physical_from_virtual(r), diff, heap_pages(kh));
        zero(pointer_from_u64(base), diff); 
    }
    //    map(u64_from_pointer(new_address)&align, physical_from_virtual(old_address), old_size, current->p->pages);
    return sysreturn_from_pointer(old_address);
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
    heap pages = heap_pages(kh);
    heap physical = heap_physical(kh);
    // its really unclear whether this should be extended or truncated
    u64 len = pad(size, PAGESIZE);
    //gack
    len = len & MASK(32);
    u64 where = u64_from_pointer(target);
    u64 end = where + size - 1;
    thread_log(current, "mmap: target %p, size %P, prot %P, flags %P, fd %d, offset %P",
	       target, size, prot, flags, fd, offset);
    // xx - go wants to specify target without map fixed, and has some strange
    // retry logic around it

    /* XXX it's very wasteful to use a huge page with each anonymous
       map if not 32-bit - make some logic which determines if the
       requested size/alignment would be better served by vh (status
       quo) or a per-process virtual pagesize heap */
    boolean is_32bit = flags & MAP_32BIT;
    heap vh = is_32bit ? p->virtual32 : p->virtual;
    u64 maplen = pad(len, vh->pagesize);
    if (!(flags & MAP_FIXED) && !target) {
	where = allocate_u64(vh, maplen);
	if (where == (u64)INVALID_ADDRESS) {
	    thread_log(current, "   failed to allocate %s virtual memory, size %P",
		       is_32bit ? "32-bit" : "", len);
	    return -ENOMEM;
	}
        rtrie_insert(p->vmap, where, maplen, (void *)1 /* XXX nz for now, later vm area */);
    } else {
	thread_log(current, "   fixed at %P", where);
        /* XXX range lookup in rtrie is broke, do manually until
           fixed... note that this check could pass even if start and
           end lie in two different mmapped areas. No matter, as we
           just need to verify that this overlapping map lies in a
           huge page that we're already using...the overlapping mmap
           lawlessness is to be tolerated for the moment.

           This is like a really crude start to vm tracking...
        */
        if (!rtrie_lookup(p->vmap, where, 0) || !rtrie_lookup(p->vmap, end, 0)) {
            u64 mstart = where & ~(vh->pagesize - 1);
            if (id_heap_reserve(vh, mstart, maplen)) {
                rtrie_insert(p->vmap, mstart, maplen, (void *)1 /* XXX */);
            } else {
                thread_log(current, "   failed to reserve area [%P - %P] in id heap\n",
                           where, end);
                return -ENOMEM;
            }
        }
    }

    // make a generic zero page function
    if (flags & MAP_ANONYMOUS) {
        u64 m = allocate_u64(physical, len);
        if (m == INVALID_PHYSICAL) return m;
        map(where, m, len, pages);
        thread_log(current, "   anon target: %P, len: %P (given size: %P)", where, len, size);
        zero(pointer_from_u64(where), len);
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

