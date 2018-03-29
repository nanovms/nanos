#include <runtime.h>

typedef struct pagecache {
    struct heap h;
    heap parent;
    void *freepages;
} *pagecache;


void *cache_alloc(pagecache p, int size)
{
    if (p->freepages) {
        void *x = p->freepages;
        p->freepages = *(void **)p->freepages;
        return(x);
    } else {
        void *z = p->parent->allocate(p->parent, size);
        return(z);
    }
}

void cache_free(pagecache p, void **n)
{
    *n = p->freepages;
    p->freepages = n;
}

void cache_destroy(pagecache p)
{
    void **i;
    for (i = p->freepages; i ; i = *i)
        return(p->parent->deallocate(p->parent, i));
    p->parent->deallocate(p->parent, p);
}

heap allocate_pagecache(heap h)
{
    // this eats a whole parent page
    pagecache p = h->allocate(h, sizeof(struct pagecache));
    p->h.allocate = cache_alloc;
    p->h.deallocate = cache_free;
    p->h.destroy = cache_destroy;
    p->h.pagesize = h->pagesize;
    p->parent = h;
    p->freepages = 0;
    return(&p->h);
}
