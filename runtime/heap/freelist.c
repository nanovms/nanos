#include <runtime.h>

typedef struct freelist {
    struct heap h;
    heap parent;
    void *free;
    u64 size;
} *freelist;

static void freelist_deallocate(heap h, u64 x, bytes size)
{
    freelist f = (freelist)h;
    *(void **)pointer_from_u64(x) = f->free;
    f->free = pointer_from_u64(x);
}

static u64 freelist_allocate(heap h, bytes size)
{
    freelist f = (freelist)h;
    // flag size !=
    if (!f->free) {
        console("freelist spill\n");
        return allocate_u64(f->parent, MAX(size, sizeof(void *)));
    }
    console("freelist cached\n");
    void *result = f->free;
    f->free = *(void **)f->free;
    return u64_from_pointer(result);
}

heap wrap_freelist(heap meta, heap parent, bytes size)
{
    freelist f = allocate(meta, sizeof(struct freelist));
    f->h.alloc = freelist_allocate;
    f->h.dealloc = freelist_deallocate;
    f->parent = parent;
    f->h.pagesize = size; // not necessarily a power of two
    f->free = 0;
    return ((heap)f);
}
