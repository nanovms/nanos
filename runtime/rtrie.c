#include <runtime.h>


// there should be a generic platform header for this
static inline u64 msb(u64 x)
{
    u64 r;
    __asm__("bsr %0, %1":"=g"(r):"g"(x));
    return r;
}


typedef struct rtnode {
    u64 key;
    void *value;
    u64 length; // position in the top 8 for 56 bits
    // could be indices in a contiguous array
    struct rtnode *children[2];
} *rtnode;

typedef struct rtrie {
    heap h;
    rtnode root;
} *rtrie;

rtnode *traverse(rtnode *w, u64 key)
{
    if (!*w) return w;
    rtnode r = *w;
    
    u64 position = r->length >> 56;
    if ((key >= r->key) && (key < (r->key + r->length & MASK(56))))
        return w;
    u64 intermediate = r->key ^ key;
    if (msb(intermediate) > position) {
        if (key & (1<<position)) return r->children;
        return r->children + 1;
    }
}

void *rtrie_lookup(rtrie r, u64 point)
{
}


// nonzero value
// non-overlapping regions
void rtrie_insert(rtrie r, u64 start, u64 length, void *value)
{
    if (!r->root) {
    }
}


rtrie rtree_create(heap h)
{
    rtrie r = allocate(h, sizeof(struct rtrie));
    r->h = h;
    r->root = 0;
    return r;
}

