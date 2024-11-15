#include <kernel.h>

typedef struct page_backed_heap {
    struct backed_heap bh;
    heap physical;
    heap virtual;
    struct spinlock lock;
} *page_backed_heap;

#define page_backed_heap_lock(bh)    u64 _flags = spin_lock_irq(&(bh)->lock)
#define page_backed_heap_unlock(bh)  spin_unlock_irq(&(bh)->lock, _flags)

void page_backed_dealloc_virtual(backed_heap bh, u64 x, bytes length)
{
    page_backed_heap pbh = (page_backed_heap)bh;
    u64 padlen = pad(length, pbh->bh.h.pagesize);
    if (x & (pbh->bh.h.pagesize - 1)) {
	msg_err("%s error: unaligned area at %lx, length %x; leaking", func_ss, x, length);
	return;
    }

    unmap(x, padlen);
    deallocate(pbh->virtual, pointer_from_u64(x), padlen);
}

static inline void *page_backed_alloc_map(backed_heap bh, bytes len, u64 *phys)
{
    page_backed_heap pbh = (page_backed_heap)bh;
    len = pad(len, pbh->bh.h.pagesize);
    void *virt;
    u64 p = allocate_u64(pbh->physical, len);
    if (p != INVALID_PHYSICAL) {
        virt = allocate(pbh->virtual, len);
        if (virt != INVALID_ADDRESS) {
            map(u64_from_pointer(virt), p, len, pageflags_writable(pageflags_memory()));
            if (phys)
                *phys = p;
        } else {
            deallocate_u64(pbh->physical, p, len);
        }
    } else {
        virt = INVALID_ADDRESS;
    }
    return virt;
}

static inline void page_backed_dealloc_unmap(backed_heap bh, void *virt, u64 phys, bytes len)
{
    page_backed_heap pbh = (page_backed_heap)bh;
    if (u64_from_pointer(virt) & (pbh->bh.h.pagesize - 1)) {
        msg_err("%s error: unaligned area at %lx, length %x; leaking", func_ss, virt, len);
        return;
    }
    if (phys == 0) {
        phys = physical_from_virtual(virt);
        assert(phys != INVALID_PHYSICAL);
    }
    len = pad(len, pbh->bh.h.pagesize);
    unmap(u64_from_pointer(virt), len);
    deallocate_u64(pbh->physical, phys, len);
    deallocate(pbh->virtual, virt, len);
}

static void page_backed_dealloc(heap h, u64 x, bytes length)
{
    page_backed_dealloc_unmap((backed_heap)h, pointer_from_u64(x), 0, length);
}

static u64 page_backed_alloc(heap h, bytes length)
{
    return u64_from_pointer(page_backed_alloc_map((backed_heap)h, length, 0));
}

static u64 page_backed_alloc_locking(heap h, bytes length)
{
    page_backed_heap pbh = (page_backed_heap)h;
    page_backed_heap_lock(pbh);
    u64 x = page_backed_alloc(h, length);
    page_backed_heap_unlock(pbh);
    return x;
}

static void page_backed_dealloc_locking(heap h, u64 x, bytes length)
{
    page_backed_heap pbh = (page_backed_heap)h;
    page_backed_heap_lock(pbh);
    page_backed_dealloc(h, x, length);
    page_backed_heap_unlock(pbh);
}

static void *page_backed_alloc_map_locking(backed_heap bh, bytes len, u64 *phys)
{
    page_backed_heap pbh = (page_backed_heap)bh;
    void *virt;
    page_backed_heap_lock(pbh);
    virt = page_backed_alloc_map(bh, len, phys);
    page_backed_heap_unlock(pbh);
    return virt;
}

void page_backed_dealloc_unmap_locking(backed_heap bh, void *virt, u64 phys, bytes len)
{
    page_backed_heap pbh = (page_backed_heap)bh;
    page_backed_heap_lock(pbh);
    page_backed_dealloc_unmap(bh, virt, phys, len);
    page_backed_heap_unlock(pbh);
}

backed_heap allocate_page_backed_heap(heap meta, heap virtual, heap physical,
                                      u64 pagesize, boolean locking)
{
    page_backed_heap pbh = allocate(meta, sizeof(*pbh));
    if (pbh == INVALID_ADDRESS)
        return INVALID_ADDRESS;
    if (locking) {
        pbh->bh.h.alloc = page_backed_alloc_locking;
        pbh->bh.h.dealloc = page_backed_dealloc_locking;
        pbh->bh.alloc_map = page_backed_alloc_map_locking;
        pbh->bh.dealloc_unmap = page_backed_dealloc_unmap_locking;
        spin_lock_init(&pbh->lock);
    } else {
        pbh->bh.h.alloc = page_backed_alloc;
        pbh->bh.h.dealloc = page_backed_dealloc;
        pbh->bh.alloc_map = page_backed_alloc_map;
        pbh->bh.dealloc_unmap = page_backed_dealloc_unmap;
    }
    pbh->physical = physical;
    pbh->virtual = virtual;
    pbh->bh.h.pagesize = pagesize;
    pbh->bh.h.management = 0;
    return &pbh->bh;
}
