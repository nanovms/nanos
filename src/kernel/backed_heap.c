#include <kernel.h>

#define backed_heap_lock(bh)    u64 _flags = spin_lock_irq(&(bh)->lock)
#define backed_heap_unlock(bh)  spin_unlock_irq(&(bh)->lock, _flags)

void physically_backed_dealloc_virtual(backed_heap bh, u64 x, bytes length)
{
    u64 padlen = pad(length, bh->h.pagesize);
    if (x & (bh->h.pagesize - 1)) {
	msg_err("attempt to free unaligned area at %lx, length %x; leaking\n", x, length);
	return;
    }

    unmap(x, padlen);
    deallocate(bh->virtual, pointer_from_u64(x), padlen);
}

static inline void *backed_alloc_map(backed_heap bh, bytes len, u64 *phys)
{
    len = pad(len, bh->h.pagesize);
    void *virt;
    u64 p = allocate_u64(bh->physical, len);
    if (p != INVALID_PHYSICAL) {
        virt = allocate(bh->virtual, len);
        if (virt != INVALID_ADDRESS) {
            map(u64_from_pointer(virt), p, len, pageflags_writable(pageflags_memory()));
            if (phys)
                *phys = p;
        } else {
            deallocate_u64(bh->physical, p, len);
        }
    } else {
        virt = INVALID_ADDRESS;
    }
    return virt;
}

static inline void backed_dealloc_unmap(backed_heap bh, void *virt, u64 phys, bytes len)
{
    if (u64_from_pointer(virt) & (bh->h.pagesize - 1)) {
        msg_err("attempt to free unaligned area at %lx, length %x; leaking\n", virt, len);
        return;
    }
    if (phys == 0) {
        phys = physical_from_virtual(virt);
        assert(phys != INVALID_PHYSICAL);
    }
    len = pad(len, bh->h.pagesize);
    unmap(u64_from_pointer(virt), len);
    deallocate_u64(bh->physical, phys, len);
    deallocate(bh->virtual, virt, len);
}

static void physically_backed_dealloc(heap h, u64 x, bytes length)
{
    backed_dealloc_unmap((backed_heap)h, pointer_from_u64(x), 0, length);
}

static u64 physically_backed_alloc(heap h, bytes length)
{
    return u64_from_pointer(backed_alloc_map((backed_heap)h, length, 0));
}

static u64 backed_alloc_locking(heap h, bytes length)
{
    backed_heap bh = (backed_heap)h;
    backed_heap_lock(bh);
    u64 x = physically_backed_alloc(h, length);
    backed_heap_unlock(bh);
    return x;
}

static void backed_dealloc_locking(heap h, u64 x, bytes length)
{
    backed_heap bh = (backed_heap)h;
    backed_heap_lock(bh);
    physically_backed_dealloc(h, x, length);
    backed_heap_unlock(bh);
}

static void *backed_alloc_map_locking(backed_heap bh, bytes len, u64 *phys)
{
    void *virt;
    backed_heap_lock(bh);
    virt = backed_alloc_map(bh, len, phys);
    backed_heap_unlock(bh);
    return virt;
}

void backed_dealloc_unmap_locking(backed_heap bh, void *virt, u64 phys, bytes len)
{
    backed_heap_lock(bh);
    backed_dealloc_unmap(bh, virt, phys, len);
    backed_heap_unlock(bh);
}

backed_heap physically_backed(heap meta, heap virtual, heap physical, u64 pagesize, boolean locking)
{
    backed_heap b = allocate(meta, sizeof(struct backed_heap));
    if (b == INVALID_ADDRESS)
        return INVALID_ADDRESS;
    if (locking) {
        b->h.alloc = backed_alloc_locking;
        b->h.dealloc = backed_dealloc_locking;
        b->alloc_map = backed_alloc_map_locking;
        b->dealloc_unmap = backed_dealloc_unmap_locking;
        spin_lock_init(&b->lock);
    } else {
        b->h.alloc = physically_backed_alloc;
        b->h.dealloc = physically_backed_dealloc;
        b->alloc_map = backed_alloc_map;
        b->dealloc_unmap = backed_dealloc_unmap;
    }
    b->physical = physical;
    b->virtual = virtual;
    b->h.pagesize = pagesize;
    return b;
}
