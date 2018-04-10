#include <basic_runtime.h>

/*
 * this is really a conflation of strategies and should
 * be replaced by several simpler things
 */

typedef struct pageheader *pageheader;

typedef struct pagealloc {
    struct heap h;
    heap parent;
    int pageheader_size;
    pageheader pages;
} *pagealloc;

// head of each parent page 
struct pageheader {
    u64 base;
    pageheader next;
    int refcnt;
};


static void free_page(pagealloc p, void *x)
{
    
}

static void *allocate_pages(pagealloc p, bytes len)
{
    bytes s = pad(len, len);
    pageheader *i= &p->freepages;
    int count=1;
    
    for (; *i; i=&(*i)->next){
        bits k = sizeof_page(p, *i);
        /* bad policy to take the first sufficiently large object? */
        if (k <= s) {
            void *result;
            if (s < k) {
                // shave off from the end
                result = *(void **)i + (k-s);
                set_sizeof_page(p, *i, k - s);
                set_sizeof_page(p, result, s);
            } else {
                // consume the entry
                result = *i;
                *i = *((void **)*i);
            }
            return(result);
        }
    }

    int olen = pad(s, p->h.pagesize);

    pageheader n = p->parent->allocate(p->parent, p->parent->pagesize);
    void *result = (void *)n + p->pageheader_size;

    set_sizeof_page(p, result, olen);

    if ((olen + p->pageheader_size) < p->parent->pagesize) {
        void *empty = result + olen;
        set_sizeof_page(p, empty, p->parent->pagesize - olen - p->pageheader_size);
        free_page(p, empty);
    }

    return(result);
}


heap allocate_pagechunk(heap meta, heap h, bytes size)
{
    pagealloc p = allocate(meta, sizeof(struct pagealloc));
    p->h.allocate = allocate_pages;
    p->h.deallocate = free_page;
    p->h.pagesize = s;
    p->freepages = 0;
    p->parent = h;

    return((heap)p);
}
