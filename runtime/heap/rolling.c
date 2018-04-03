#include <runtime.h>

typedef struct pageheader *pageheader;

struct pageheader {
    u32 references;
    u32 length; // can shift by pagesize
    pageheader next;
};

typedef struct rolling {
    struct heap h;
    heap   parent;
    int    offset;
    pageheader p;
} *rolling;

static void rolling_advance_page(rolling l, int len)
{
    u64 length = pad(len + sizeof(struct pageheader), l->parent->pagesize);
    pageheader n = allocate(l->parent, length);
    n->next = l->p;
    n->length = length;
    n->references = 0;
    n->next = l->p;
    l->p = n;
    l->offset = sizeof(struct pageheader);
}

static u64 rolling_alloc(heap h, bytes len)
{
    rolling r = (void *)h;

    if ((r->offset + len) > r->p->length) {
        if (len > r->parent->pagesize) {
            // cant allocate in the remainder of a multipage allocation, since we cant find the header
            len = pad(len + sizeof(struct pageheader), r->parent->pagesize) - sizeof(struct pageheader);
        }
        rolling_advance_page(r, len);
    }
    void *a = (void *)r->p + r->offset;
    r->p->references++;
    r->offset += len;
    return(u64_from_pointer(a));
}

static void rolling_free(heap h, u64 x, u64 length)
{
    rolling r = (void *)h;
    pageheader p = pointer_from_u64(x&(~MASK(r->parent->pagesize)));
    if (!--p->references) deallocate(r->parent, p, p->length);
}

static void rolling_destroy(rolling c)
{
    for (pageheader i = c->p;
         deallocate(c->parent, i, i->length), ((rolling)i != c);
         i = i->next);
}

// where heap p must be aligned
heap allocate_rolling_heap(heap p)
{
    rolling l = allocate(p, sizeof(struct rolling));
    rprintf("rolllo %p\n", l);
    l->h.alloc = rolling_alloc;
    l->h.dealloc = rolling_free;
    l->h.pagesize = 1; 
    l->h.destroy = rolling_destroy;
    l->p = (void *)l;
    l->parent = p;
    l->offset = sizeof(struct rolling);
    return(&l->h);
}

