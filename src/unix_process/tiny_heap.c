#include <runtime.h>

typedef struct tiny {
    struct heap h;
    void *next;
    u64 offset;
    void *base;
    heap parent;
}*tiny;
    
static u64 alloc(heap h, u64 size)
{
    tiny t = (tiny)h;

    if ((t->offset +size) > t->parent->pagesize) {
        void *new = allocate(t->parent, t->parent->pagesize);
        if (new == INVALID_ADDRESS)
            return INVALID_PHYSICAL;
        t->base = new;
        t->offset = sizeof(void *);
        return alloc(h, size);
    }
    u64 res = u64_from_pointer(t->base) + t->offset;
    t->offset += size;
    return res;
}


static void destroy(heap h)
{
    tiny t = (tiny)h;
    heap p = t->parent;
    void * x=t->base;
    while(x) {
        void *next = *(void **)x;
        deallocate(p, next, p->pagesize);
        x = next;
    }
}

heap make_tiny_heap(heap parent)
{
    void *x = mem_alloc(parent, parent->pagesize, MEM_NOFAIL);
    tiny t = (tiny)x;
    t->h.alloc = alloc;
    t->h.dealloc = leak;
    t->h.destroy = destroy;
    t->base = x;
    t->parent = parent;
    t->offset = sizeof(struct tiny);
    return x;
}
