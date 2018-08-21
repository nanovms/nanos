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

// multipage allocations dont work!
static void rolling_advance_page(rolling l, int len)
{
    u64 length = pad(len + sizeof(struct pageheader), l->parent->pagesize);
    l->offset = sizeof(struct pageheader);    
    if (length > l->parent->pagesize) {
        print_u64(len);
        console("\n");
        l->offset = length;
    }
    pageheader n = allocate(l->parent, length);
    n->next = l->p;
    n->length = length;
    n->references = 0;
    l->p = n;
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

// assumes parent->pagesize is a power of two
static void rolling_free(heap h, u64 x, u64 length)
{
    rolling r = (void *)h;
    // allow passthrough larger allocations
    pageheader p = pointer_from_u64(x&(~(r->parent->pagesize-1)));

    if (!--p->references) {
        deallocate(r->parent, p, h->pagesize);
    }
}

static void rolling_destroy(heap h)
{
    rolling c = (rolling)h;
    for (pageheader i = c->p;
         deallocate(c->parent, i, i->length), ((rolling)i != c);
         i = i->next);
}


// pass align
heap allocate_rolling_heap(heap p, u64 align)
{
    rolling l = allocate(p, pad(sizeof(struct rolling), p->pagesize));
    // where heap p alignment must be >= 2* rolling alignment (to allow space for the headers),
    if (align >= p->pagesize) return INVALID_ADDRESS;
    l->h.alloc = rolling_alloc;
    l->h.dealloc = rolling_free;
    l->h.pagesize = align; 
    l->h.destroy = rolling_destroy;
    l->p = (void *)l;
    l->parent = p;
    l->offset = sizeof(struct rolling);
    return(&l->h);
}

