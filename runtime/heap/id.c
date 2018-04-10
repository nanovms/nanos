#include <runtime.h>

typedef struct id_heap {
    struct heap h;
    u64 length;
    u64 base;
} *id_heap;

static u64 idalloc(heap h, bytes count)
{
    id_heap i = (id_heap)h;
    u64 result = i->base;
    i->base += pad(count, h->pagesize);
    return result;
}

heap create_id_heap(heap h, u64 base, u64 length, u64 pagesize)
{
    id_heap i = allocate(h, sizeof(struct id_heap));
    i->base = base;
    i->h.alloc = idalloc;
    i->h.dealloc = leak;
    i->h.pagesize = pagesize;    
    return((heap)i);
}

