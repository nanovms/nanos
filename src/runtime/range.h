#pragma once
typedef struct rangemap *rangemap;

// [start, end)
typedef struct range {
    u64 start, end;
} range;

#define irange(__s, __e)  (range){__s, __e}        
#define point_in_range(__r, __p) ((__p >= __r.start) && (__p < __r.end))
#define range_hole ((void *)infinity)

typedef closure_type(subrange, void, range r, void *);

boolean rangemap_insert(rangemap r, u64 start, u64 length, void *value);
boolean rangemap_remove(rangemap r, u64 start, u64 length);
void *rangemap_lookup(rangemap r, u64 point, range * rrange);
void rangemap_range_lookup(rangemap r, range q, subrange s);
void rangemap_range_lookup_aligned(rangemap r, range q, u64 alignment, subrange s);
rangemap allocate_rangemap(heap h);
void deallocate_rangemap(rangemap r);

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
