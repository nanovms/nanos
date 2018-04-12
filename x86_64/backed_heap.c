#include <sruntime.h>

typedef struct backed {
    struct heap h;
    heap physical;
    heap virtual;
    heap pages;
    heap cache;    
} *backed;
    

static void physically_backed_dealloc(heap h, u64 x, bytes length)
{
    backed b = (backed)h;
    // leak the virtual
    if (length == h->pagesize) {
        deallocate(b->cache, physical_from_virtual(pointer_from_u64(x)), length);
    } else {
        deallocate(b->physical, physical_from_virtual(pointer_from_u64(x)), length);
    }
}


static u64 physically_backed_alloc(heap h, bytes length)
{
    backed b = (backed)h;
    u64 len = pad(length, h->pagesize);
    u64 p = allocate_u64(b->physical, len);

    if (p != INVALID_PHYSICAL) {
        u64 v = allocate_u64(b->virtual, len);
        if (v != INVALID_PHYSICAL) {
            // map should return allocation status
            map(v, p, len, b->pages);
            return v;
        }
    }
    return INVALID_PHYSICAL; 
}

heap physically_backed(heap meta, heap virtual, heap physical, heap pages)
{
    backed b = allocate(meta, sizeof(struct backed));
    b->h.alloc = physically_backed_alloc;
    // freelist
    b->h.dealloc = physically_backed_dealloc;
    b->physical = physical;
    b->virtual = virtual;
    b->pages = pages;
    b->h.pagesize = PAGESIZE;
    b->cache = wrap_freelist(meta, physical, PAGESIZE);
    return (heap)b;
}
