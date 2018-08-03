#include <unix_internal.h>

void *mremap(void *old_address, u64 old_size,  u64 new_size, int flags,  void *new_address )
{
    // this seems poorly thought out - what if there is a backing file?
    // and if its anonymous why do we care where it is..i guess this
    // is just for large realloc operations? if these aren't aligned
    // its completely unclear what to do
    u64 align =  ~MASK(PAGELOG);
    if (new_size > old_size) {
        u64 diff = pad(new_size - old_size, PAGESIZE);
        u64 base = u64_from_pointer(old_address + old_size) & align;
        void *r = allocate(current->p->physical,diff);
        if (u64_from_pointer(r) == INVALID_PHYSICAL) {
            // MAP_FAILED
            return r;
        }
        map(base, physical_from_virtual(r), diff, current->p->pages);
        zero(pointer_from_u64(base), diff); 
    }
    //    map(u64_from_pointer(new_address)&align, physical_from_virtual(old_address), old_size, current->p->pages);
    return old_address;
}


static int mincore(void *addr, u64 length, u8 *vec)
{
    if (validate_virtual(addr, length)) {
        u32 vlen = pad(length, PAGESIZE) >> PAGELOG;
        // presumably it wants the right valid bits set? - go doesn't seem to use it this way
        for (int i = 0; i< vlen; i++) vec[i] = 1;
        return 0;
    }
    return -ENOMEM;
}


static void *mmap(void *target, u64 size, int prot, int flags, int fd, u64 offset)
{
    process p = current->p;
    // its really unclear whether this should be extended or truncated
    u64 len = pad(size, PAGESIZE);
    //gack
    len = len & MASK(32);
    u64 where = u64_from_pointer(target);

    // xx - go wants to specify target without map fixed, and has some strange
    // retry logic around it
    if (!(flags &MAP_FIXED) && !target) {
        if (flags & MAP_32BIT)
            where = allocate_u64(current->p->virtual32, len);
        else
            where = allocate_u64(current->p->virtual, len);
    }

    // make a generic zero page function
    if (flags & MAP_ANONYMOUS) {
        u64  m = allocate_u64(p->physical, len);
        if (m == INVALID_PHYSICAL) return pointer_from_u64(m);
        map(where, m, len, p->pages);
        zero(pointer_from_u64(where), len);
        return pointer_from_u64(where);
    }
    
    // check that fd is valid
    file f = p->files[fd];
    buffer b;
    if (!(b = table_find(f->n, sym(contents)))) return pointer_from_u64(-1ull);
        
    u64 msize = 0;
    u64 blen = buffer_length(b);
    if (blen > offset) msize = pad(blen-offset, PAGESIZE);
    if (msize > len) msize = len;
    
    // mutal misalignment?...discontiguous backing?
    map(where, physical_from_virtual(buffer_ref(b, offset)), msize, p->pages);

    if (len > msize) {
        u64 bss = pad(len, PAGESIZE) - msize;
        map(where + msize, allocate_u64(p->physical, bss), bss, p->pages);
        zero(pointer_from_u64(where+msize), bss);
    }
    // ok, if we change pages entries we need to flush the tlb...dont need
    // to do this every time.. there is also a per-page variant
    u64 x;
    mov_from_cr("cr3", x);
    mov_to_cr("cr3", x);    
    return pointer_from_u64(where);
}

void register_mmap_syscalls(void **map)
{
    register_syscall(map, SYS_mincore, mincore);
    register_syscall(map, SYS_mmap, mmap);
    register_syscall(map, SYS_mremap, mremap);        
    register_syscall(map, SYS_munmap, syscall_ignore);
    register_syscall(map, SYS_mprotect, syscall_ignore);
}

