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
    thread_log(current, "mmap file target: %p, phys: %P, msize: %P, len: %P\n", where, p, msize, len);
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
    set_syscall_return(t, -1ull);
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

    thread_log(current, "mmap: target %p, size %P, prot %P, flags %P, fd %d, offset %P\n",
	       target, size, prot, flags, fd, offset);
    // xx - go wants to specify target without map fixed, and has some strange
    // retry logic around it
    if (!(flags &MAP_FIXED) && !target) {
	where = allocate_u64((flags & MAP_32BIT) ? p->virtual32 : p->virtual, len);
	if (where == (u64)INVALID_ADDRESS) {
	    thread_log(current, "   failed to allocate %s virtual memory, size %P\n",
		       (flags & MAP_32BIT) ? "32-bit" : "", len);
	    return -1ull;
	}
    } else {
	/* XXX rb tree check */
	thread_log(current, "   fixed at %p\n", target);
    }

    // make a generic zero page function
    if (flags & MAP_ANONYMOUS) {
        u64 m = allocate_u64(physical, len);
        if (m == INVALID_PHYSICAL) return m;
        map(where, m, len, pages);
        thread_log(current, "   anon target: %P, len: %P (given size: %P)\n", where, len, size);
        zero(pointer_from_u64(where), len);
        return where;
    }

    file f = resolve_fd(current->p, fd);
    thread_log(current, "  read file, blocking...\n");
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
}

