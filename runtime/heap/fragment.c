#include <runtime.h>

// like pagechunk, but no attempt to manage free
typedef struct frag {
    struct heap h;
    heap parent;
    u64 offset;
    u64 base;
} *frag;

u64 frag_alloc(heap h, bytes size)
{
    frag f = (frag)h;
    u64 len = pad(size, h->pagesize);
    if ((f->offset + len) >= f->parent->pagesize) {
        f->offset = 0;
        f->base = allocate_u64(f->parent, pad(size, f->parent->pagesize));
    }
    u64 result = f->base + f->offset;
    f->offset += len;
    h->allocated += len;
    return result;
}

heap allocate_fragmentor(heap meta, heap parent, bytes size)
{
    frag f = allocate(meta, sizeof (struct frag));
    f->parent = parent;
    f->h.alloc = frag_alloc;
    f->h.dealloc = leak;
    f->h.pagesize = size;
    f->h.allocated = 0;
    // trigger initial allocation
    f->offset = parent->pagesize;
    f->base = 0;
}
