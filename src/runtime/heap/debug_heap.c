#include <runtime.h>

typedef struct dheap {
    struct heap h;
    heap parent;
} *dheap;

static u64 debug_alloc(heap h, bytes size)
{
    dheap d = (dheap)h;
    u64 result = allocate_u64(d->parent, size);
    if (result != INVALID_PHYSICAL)
        rprintf("alloc %p %p -> %p %p (%p)\n",  d->parent, size, result,
                physical_from_virtual(pointer_from_u64(result)),
                d->parent->alloc); 
    return result;
}

static void debug_dealloc(heap h, u64 x, bytes size)
{
}

heap debug_heap(heap meta, heap target)
{
    dheap n = allocate(meta, sizeof(struct dheap));
    assert(n != INVALID_ADDRESS);
    n->h.alloc = debug_alloc;
    n->h.dealloc = debug_dealloc;
    n->parent = target;
    return (heap)n;
}

