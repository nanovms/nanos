#include <runtime.h>

typedef struct rtnode {
    u64 base;
    void *value;
    u64 length; // position in the top 8 for 56 bits
    // could be indices in a contiguous array
    struct rtnode *children[2];
} *rtnode;

struct rtrie {
    heap h;
    rtnode root;
};

static void insert(rtnode *w, rtnode n)
{
    if (!*w) {
        *w = n;
        return;
    }
    rtnode r = *w;
    u64 position = r->length >> 56;    
    u64 intermediate = r->base ^ n->base;
    if (msb(intermediate) > position) {
        if (n->base & (1<<position))
            insert(r->children + 1, n);
        else
            insert(r->children, n);
    } else {
        *w = n;
        insert(w, n);
    }
}

// non-overlapping regions
void rtrie_insert(rtrie r, u64 start, u64 length, void *value)
{
    rtnode n = allocate(r->h, sizeof(struct rtnode));
    n->base = start;
    n->value = value;
    n->length = length;
    n->children[0] = 0;
    n->children[1] = 0;    
    insert(&r->root, n);
}

// xxx - incomplete
static void remove_internal(rtnode *w, u64 base, u64 length)
{
    rtnode r = *w;
    if (r) {
        int xfer =  MIN(r->length, length);                
        if (base = r->base) {
            r->base += xfer;
            base += xfer;
            length -= xfer;
        }

        if ((base + length) == (r->base + length))  {
            r->length =- xfer;
            length -= xfer;            
        }
    }
}


void rtrie_remove(rtrie r, u64 start, u64 length)
{
    remove_internal(&r->root, start, length);
}

static rtnode rtlookup(rtnode r, u64 point)
{
    if (!r) return r;
    if ((point > r->base) && (point < (r->base + r->length))) return r;
    u64 position = r->length >> 56;
    if (point & position) {
        return rtlookup(r->children[1], point);
    }
    return rtlookup(r->children[0], point);
}


void *rtrie_lookup(rtrie r, u64 point)
{
    rtnode n = rtlookup(r->root, point);
    if (!n) return n;
    return n->value;
}

static void range_lookup(rtnode r, u64 point, u64 length, subrange s)
{
    if (r) {
        if ((point > r->base) && (point < (r->base + r->length)))
            apply(s, r->base, r->length);
        u64 position = r->length >> 56;
        if (point & position) {
            range_lookup(r->children[1], point, length, s);
        }
        range_lookup(r->children[0], point, length, s);
    }
}

// ordered
void rtrie_range_lookup(rtrie r, u64 start, u64 length, subrange s)
{
    range_lookup(r->root, start, length, s);
}


rtrie rtrie_create(heap h)
{
    rtrie r = allocate(h, sizeof(struct rtrie));
    r->h = h;
    r->root = 0;
    return r;
}


static u64 rtrie_extent_max(rtnode r)
{
    if (!r) return 0;
    if (!rtrie_extent_max(r->children[1])) return (r->base + r->length);
}
 
static u64 rtrie_extent_min(rtnode r)
{
    if (!r) return 0;
    if (!rtrie_extent_min(r->children[0])) return (r->base + r->length);
}

void rtrie_extent(rtrie r, u64 *min, u64 *max)
{
    // boundary conditions here
    *min = rtrie_extent_min(r->root);
    *max = rtrie_extent_max(r->root);    
}

 typedef struct rtalloc {
     struct heap h;
     rtrie r;
 } *rtalloc;

// at least for this usage, we could really use multiple return values
u64 rtrie_alloc_internal(rtnode *rn, u64 length)
 {
     rtnode r = *rn;
     u64 result;
     if ((result = rtrie_alloc_internal(r->children, length))  != INVALID_PHYSICAL) return result;
     if ((result = rtrie_alloc_internal(r->children +1, length)) != INVALID_PHYSICAL) return result;
     if (r->length  > length) {
         u64 result = r->base;
         r->base += length;
         r->length -= length;
         // if length == 0 *rn = 0;
         return result;
     }
     return INVALID_PHYSICAL;
 }
     
 u64 rtrie_alloc(heap h, bytes length)
 {
     rtrie r = (rtrie)h;
     rtrie_alloc_internal(&r->root, length);
 }
 
 heap rtrie_allocator(heap h, rtrie r)
 {
     rtalloc ra = allocate(h, sizeof(struct rtalloc));
     ra->h.alloc = rtrie_alloc;
     return &ra->h;
 }
 
