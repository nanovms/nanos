typedef struct rtrie *rtrie;

// [start, end)
typedef struct range {
    u64 start, end;
} range;

#define irange(__s, __e)  (range){__s, __e}        
typedef closure_type(subrange, void, range r, void *);
void rtrie_range_lookup(rtrie r, range q, subrange s);
void *rtrie_lookup(rtrie r, u64 point, range * rrange);
void rtrie_insert(rtrie r, u64 start, u64 length, void *value);
void rtrie_extents(rtrie r, u64 *min, u64 *max);
rtrie rtrie_create(heap h);
void rtrie_extent(rtrie r, u64 *min, u64 *max);
void rtrie_remove(rtrie r, u64 start, u64 length);
heap rtrie_allocator(heap h, rtrie r);


static inline range range_intersection(range a, range b)
{
    range dest = {MAX(a.start, b.start), MIN(a.end, b.end)};
    if (dest.end <= dest.start) dest = (range){0, 0};
    return dest;
}

static inline u64 range_span(range r)
{
    return r.end - r.start;
}

static inline boolean range_empty(range a)
{
    return range_span(a) == 0;
}

static inline boolean range_equal(range a, range b)
{
    return (a.start == b.start) && (a.end == b.end);
}
