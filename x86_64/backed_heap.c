#include <runtime.h>

typedef struct backed {
    struct heap h;
    heap physical;
    heap virtual;
    heap pages;
} *backed;

static void physically_backed_dealloc(heap h, u64 x, bytes length)
{
    backed b = (backed)h;
    if ((x & (PAGESIZE-1)) | (length & (PAGESIZE-1))) {
	msg_err("attempt to free unaligned area at %P, length %P; leaking\n", x, length);
	return;
    }

    deallocate(b->physical, physical_from_virtual(pointer_from_u64(x)), length);
    deallocate(b->virtual, pointer_from_u64(x), length);
    unmap(x, length, b->pages);
}


static u64 physically_backed_alloc(heap h, bytes length)
{
    backed b = (backed)h;
    u64 len = pad(length, h->pagesize);
    u64 p = allocate_u64(b->physical, len);

    if (p != INVALID_PHYSICAL) {
        u64 v = allocate_u64(b->virtual, len);
        if (v != INVALID_PHYSICAL) {
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
    b->h.dealloc = physically_backed_dealloc;
    b->physical = physical;
    b->virtual = virtual;
    b->pages = pages;
    b->h.pagesize = PAGESIZE;
    return (heap)b;
}
