#include <runtime.h>

typedef struct za {
    struct heap me;
    heap parent;
} *za;

static u64 zalloc(heap h, bytes size)
{
    za z = (void *)h;
    void *n = allocate(z->parent, size);
    zero(n, size);
    return u64_from_pointer(n);
}

heap zero_wrap(heap meta, heap parent)
{
    za z = allocate(meta, sizeof(struct za));
    z->me.alloc = zalloc;
    z->me.dealloc = z->parent->dealloc;
    z->me.pagesize = parent->pagesize;
    return (heap)z;
}
