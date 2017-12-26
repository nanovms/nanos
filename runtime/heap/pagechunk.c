#include <core/core.h>

/*
 * this is really a conflation of strategies and should
 * be replaced by several simpler things
 */

typedef struct pageheader *pageheader;

typedef struct pagealloc {
    struct heap h;
    heap parent;
    int pageheader_size;
    pageheader freepages;
} *pagealloc;

// head of each parent page 
struct pageheader {
    pageheader next;
    bits sizes[];
};


static bits sizeof_page(pagealloc p, void *x)
{
    pageheader z = page_of(x, p->parent->pagesize);
    int offset = ((unsigned long)x - (unsigned long)z)/ p->h.pagesize;
    return(z->sizes[offset]);
}

static void set_sizeof_page(pagealloc p, void *x, bits s)
{
    pageheader z = page_of(x, p->parent->pagesize);
    int offset = ((unsigned long)x - (unsigned long)z)/ p->h.pagesize;
    z->sizes[offset] = s;
}


static void free_page(pagealloc p, void *x)
{
    *(void **)x = p->freepages;
    p->freepages = x;
}

static void *allocate_pages(pagealloc p, bits len)
{
    bits s = pad(len, p->h.pagesize);
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


heap allocate_pagechunk(heap h, bits s)
{
    pagealloc p = (pagealloc)h->allocate(h, h->pagesize);
    p->h.allocate = allocate_pages;
    p->h.deallocate = free_page;
    p->h.pagesize = s;
    p->freepages = 0;
    p->parent = h;
    
    p->pageheader_size = 
        subdivide(s, sizeof(bits), 
                  p->parent->pagesize, sizeof(struct pagealloc));

    void *empty = (void *)p + sizeof(pagealloc) + p->pageheader_size;
    set_sizeof_page(p, empty, p->parent->pagesize - p->pageheader_size);
    free_page(p, empty);
    return((heap)p);
}
