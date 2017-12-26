#include <core/core.h>

typedef struct leaky {
    struct heap h;
    heap parent;
    int offset;
    int length;
    void *buffer;
} *leaky;

static void leaky_advance_page(leaky l, int len)
{
    void *old = l->buffer;
    l->length = pad(len, l->parent->pagesize);
    l->buffer = l->parent->allocate(l->parent, l->length);

    *((void **)l->buffer) = old;
    l->offset = sizeof(void *);
    l->length -= sizeof(void *);
}

static void *leaky_alloc(leaky l, int bytes)
{
    if ((l->offset + bytes) > l->length)
        leaky_advance_page(l, bytes);
    void *r = l->buffer + l->offset;
    l->offset = l->offset + bytes;
    l->h.allocated += bytes;
    return(r);
}

static void leaky_destroy(leaky l)
{

    void **n, **i = l->buffer;

    while (i) {
        n = *i;
        l->parent->deallocate(l->parent, i);
        i = n;
    }
}

static void nothing()
{
}

heap allocate_leaky_heap(heap p)
{
    void *b = p->allocate(p, sizeof(struct leaky));
    *(void **)b = 0; // end the free chain
    leaky l = construct_type(b + sizeof(void *), t_heap);
    l->h.allocate = leaky_alloc;
    l->h.deallocate = nothing;
    l->h.destroy = leaky_destroy;
    l->h.pagesize = 1;
    l->parent = p;
    l->offset = (unsigned long)(l+1) - (unsigned long)b; // even more sleeze
    l->buffer = b;
    l->length = p->pagesize;
    return(&l->h);
}

