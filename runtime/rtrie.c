#include <runtime.h>

#define pivot(r) (r).end

/*
   The rtrie code was essentially acting as a big list of ranges due
   to the pivot bit not being updated. Strangely enough, this was
   working for existing cases in the kernel, while fixing the trie
   implementation actually causes failures in certain corner cases
   when looking up an address in a range.

   So this is just a temporary hack to make sure we're not pivoting on
   bit 0 (or an arbitrary bit) and bifurcating the search space. Until
   we have a better solution for a range trie (or other structure)
   implementation, this will have to do for now.
*/

#if 0 // XXX temporary hack, see above
#define child(__r, __v) ((__r)->children + (((1<<(__r)->pivot_bit) & (__v))?1:0))
#else
#define child(__r, __v) ((__r)->children)
#endif
#define point_in_range(__r, __p) ((__p >= __r.start) && (__p < __r.end))

// two trees? start and end?

// (cut a b) -> (difference a (intersect a b))

// this seems like it should be simpler (?)
static void cut(range from, range snip, range *d1, range *d2)
{
    *d1 = from; // empty intersection
    *d2 = (range){0, 0};

    range i = range_intersection(from, snip);
    if (!range_empty(i)) {
        if (i.start == from.start) {
            if (i.end == from.end) {
                *d1 = (range){0, 0};
            } else {
                *d1 = (range){i.end, from.end};
            }
        } else {
            if (i.end == from.end) {
                *d1= (range){i.start, from.start};
            } else {
                u64 smin = MIN(from.start, snip.start);
                u64 smax = MAX(from.start, snip.start);
                u64 emin = MIN(from.end, snip.end);
                u64 emax = MAX(from.end, snip.end);
                *d1 = (range){smin, smax};
                *d2 = (range){emin, emax};
            }
        }
    }
}

typedef struct rtnode {
    range r;
    void *value;
    u8 pivot_bit; // alignment
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
    u64 intermediate = pivot(r->r) ^ pivot(n->r);
    // XXX temporary hack; see comment above
    if (1 || msb(intermediate) > r->pivot_bit) {
        insert(child(r, pivot(n->r)), n);
    } else {
        *w = n;
        insert(w, n);
    }
}

// non-overlapping regions
void rtrie_insert(rtrie r, u64 start, u64 length, void *value)
{
    rtnode n = allocate(r->h, sizeof(struct rtnode));
    n->r.start = start;
    n->r.end = start + length;    
    n->value = value;
    n->pivot_bit = 0;		/* XXX temp hack until rtrie fixed */
    n->children[0] = 0;
    n->children[1] = 0;    
    insert(&r->root, n);
}

static void delete_node(rtnode *w)
{
    rtnode r = *w;
    if (r) {
        if (!r->children[1]) {*w = r->children[0] ; return;}
        if (!r->children[0]) {*w = r->children[1] ; return;}
        // not always best to destroy the left, there could be some coloring/accounting
        rtnode nr = *w = r->children[0];
        nr->pivot_bit = r->pivot_bit;
        delete_node(r->children);
    }
}

static void remove_internal(rtrie rt, rtnode *w, struct range k)
{
    rtnode r = *w;
    range extra_k = (range){0, 0}, here, extra_here;

    if (r) {
        range d1 = k, d2 = (range){0,0};        
        range i = range_intersection(r->r, k);
        if (!range_empty(i)) {
            cut(k, i, &k, &extra_k);
            cut(r->r, i, &r->r, &extra_here);

            // dont always have to restructure
            if (pivot(here) != pivot(r->r)) {
                delete_node(w);
                if (!range_empty(here)) insert(&rt->root, r);
                if (!range_empty(extra_here))
                    rtrie_insert(rt, extra_here.start, extra_here.start - extra_here.end, r->value);
            }
        }
    }
    if (!range_empty(k))
        remove_internal(rt, child(*w, pivot(k)), k);
    if (!range_empty(extra_k))
        remove_internal(rt, child(*w, pivot(extra_k)), extra_k);
}


void rtrie_remove(rtrie r, u64 start, u64 length)
{
    remove_internal(r, &r->root, (range){start, start+length});
}

static rtnode rtlookup(rtnode r, u64 point)
{
    if (!r) return r;
    if ((point >= r->r.start) && (point < (r->r.end))) return r;
    return rtlookup(*child(r, point), point);
}


void *rtrie_lookup(rtrie r, u64 point, range * rrange)
{
    rtnode n = rtlookup(r->root, point);
    if (!n) return n;
    if (rrange) *rrange = n->r;
    return n->value;
}

static void range_lookup(rtnode r, range qrange, subrange s)
{
    if (r) {
        if (point_in_range(r->r, qrange.start))
            apply(s, r->r, r->value);
        // may be both end and start
        range_lookup(*child(r, qrange.start), qrange, s);
    }
}

// ordered
void rtrie_range_lookup(rtrie r, range q, subrange s)
{
    range_lookup(r->root, q, s);
}

static void format_range(buffer dest, buffer fmt, vlist *a)
{
    range r = varg(*a, range);
    bprintf(dest, "(%P %P)", r.start, r.end);
    
}

rtrie rtrie_create(heap h)
{
    // xxx move
    register_format('R', format_range);
    rtrie r = allocate(h, sizeof(struct rtrie));
    r->h = h;
    r->root = 0;
    return r;
}


// this needs to max, since the tree isn't on end, but start
static u64 rtrie_extent_max(rtnode r)
{
    u64 k;
    if (!r) return 0;
    if (!(k = rtrie_extent_max(r->children[1]))) return (r->r.end);
}
 
static u64 rtrie_extent_min(rtnode r)
{
    if (!r) return 0;
    if (!rtrie_extent_min(r->children[0])) return (r->r.start);
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
u64 rtrie_alloc_internal(rtrie root, rtnode *rn, u64 length)
 {
     rtnode r = *rn;
     if (r) {
         u64 result;
         if ((result = rtrie_alloc_internal(root, r->children, length))  != INVALID_PHYSICAL) return result;
         if ((result = rtrie_alloc_internal(root, r->children +1, length)) != INVALID_PHYSICAL) return result;
         if (range_span(r->r)  > length) {
             u64 result = r->r.start;
             r->r.start += length;
             return result;
         }
     }
     return INVALID_PHYSICAL;
 }
     
u64 rtrie_alloc(heap h, bytes length)
{
    rtalloc ra = (rtalloc)h;
    rtrie_alloc_internal(ra->r, &ra->r->root, length);
}

heap rtrie_allocator(heap h, rtrie r)
{
    rtalloc ra = allocate(h, sizeof(struct rtalloc));
    ra->h.alloc = rtrie_alloc;
    ra->r = r;
    return &ra->h;
}

