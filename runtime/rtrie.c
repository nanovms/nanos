#include <runtime.h>

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

static void insert(rtnode *w, rtnode n)
{
    if (!*w) {
        *w = n;
        return;
    }
    rtnode r = *w;
    u64 position = r->length >> 56;    
    u64 intermediate = r->key ^ n->key;
    if (msb(intermediate) > position) {
        if (n->key & (1<<position))
            insert(r->children + 1, n);
        else
            insert(r->children, n);
    } else {
        *w = n;
        insert(w, n);
    }
}

static rtnode lookup(rtnode r, u64 point)
{
    if (!r) return r;
    if ((point > r->key) && (point < (r->key + r->length))) return r;
    u64 position = r->length >> 56;
    if (point & position) {
        return lookup(r->children[1], point);
    }
    return lookup(r->children[0], point);
}


void *rtrie_lookup(rtrie r, u64 point)
{
    rtnode n = lookup(r->root, point);
    if (!n) return n;
    return n->value;
}

// non-overlapping regions
void rtrie_insert(rtrie r, u64 start, u64 length, void *value)
{
    rtnode n = allocate(r->h, sizeof(struct rtnode));
    n->key = start;
    n->value = value;
    n->length = length;
    n->children[0] = 0;
    n->children[1] = 0;    
    insert(&r->root, n);
}


rtrie rtree_create(heap h)
{
    rtrie r = allocate(h, sizeof(struct rtrie));
    r->h = h;
    r->root = 0;
    return r;
}

