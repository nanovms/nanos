#include <core/core.h>

typedef struct pageheader *pageheader;

struct pageheader {
    iu32 refcnt;
    pageheader next;
};

typedef struct rolling {
    struct heap h;
    heap   parent;
    int    offset;
    int    length;
    pageheader buffer;
    iu32  refcount;
} *rolling;

static void rolling_advance_page(rolling l, int len)
{
    l->length = l->parent->pagesize;
    l->length = (((len-1)/l->length)+1)*l->length;

    void *old = l->buffer;
    l->buffer = l->parent->allocate(l->parent, l->length);
    *((void **)l->buffer) = old;
    l->offset = sizeof(void *);
}

static void *rolling_alloc(rolling c, int bytes)
{
    if ((c->offset + bytes) > c->length)
        rolling_advance_page(c, bytes);
    c->refcount++;
    void *r = c->buffer + c->offset;
    c->offset += bytes;
    return(r);
}

static void rolling_free(rolling c, void *x)
{
    pageheader p = (pageheader)page_of(x, c->parent->pagesize);
    if (!--p->refcnt) c->parent->deallocate(c->parent, p);
}

static void rolling_destroy(rolling c)
{

    for (pageheader i = c->buffer;
         c->parent->deallocate(c->parent, i), ((rolling)i != c);
         i = i->next);
}

// where heap p must be aligned
heap allocate_rolling_heap(heap p)
{
    rolling l = p->allocate(p, sizeof(struct rolling));
    l->h.allocate = rolling_alloc;
    l->h.deallocate = rolling_free;
    l->h.pagesize = 1; 
    l->h.destroy = rolling_destroy;
    l->buffer = (void *)l;
    l->parent = p;
    l->offset = sizeof(struct rolling);
    l->length = p->pagesize;
    return(&l->h);
}

