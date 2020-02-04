typedef struct rangemap {
    heap h;
    struct list root;
} *rangemap;

// [start, end)
typedef struct range {
    u64 start, end;
} range;

typedef struct rmnode {
    range r;
    struct list l;
} *rmnode;

#define irange(__s, __e)  (range){__s, __e}        
#define point_in_range(__r, __p) ((__p >= __r.start) && (__p < __r.end))

/* XXX might want to add a boolean return to abort op */
typedef closure_type(rmnode_handler, void, rmnode);
typedef closure_type(range_handler, void, range);

boolean rangemap_insert(rangemap rm, rmnode n);
boolean rangemap_reinsert(rangemap rm, rmnode n, range k);
boolean rangemap_remove_range(rangemap rm, range r);
rmnode rangemap_lookup(rangemap rm, u64 point);
rmnode rangemap_lookup_at_or_next(rangemap rm, u64 point);
boolean rangemap_range_lookup(rangemap rm, range q, rmnode_handler nh);
boolean rangemap_range_find_gaps(rangemap rm, range q, range_handler rh);
rangemap allocate_rangemap(heap h);
void deallocate_rangemap(rangemap rm);

static inline range range_from_rmnode(rmnode n)
{
    return n->r;
}

static inline void rmnode_set_range(rmnode n, range r)
{
    n->r = r;
}

static inline void rmnode_init(rmnode n, range r)
{
    rmnode_set_range(n, r);
    list_init(&n->l);
}

static inline rmnode rangemap_prev_node(rangemap rm, rmnode n)
{
    if (n->l.prev == &rm->root)
        return INVALID_ADDRESS;
    return struct_from_list(n->l.prev, rmnode, l);
}

static inline rmnode rangemap_next_node(rangemap rm, rmnode n)
{
    if (n->l.next == &rm->root)
        return INVALID_ADDRESS;
    return struct_from_list(n->l.next, rmnode, l);
}

static inline rmnode rangemap_first_node(rangemap rm)
{
    if (rm->root.next == &rm->root)
        return INVALID_ADDRESS;
    else
        return struct_from_list(rm->root.next, rmnode, l);
}

static inline void rangemap_remove_node(rangemap rm, rmnode n)
{
    list_delete(&n->l);
}

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

static inline boolean ranges_intersect(range a, range b)
{
    return !range_empty(range_intersection(a, b));
}

static inline boolean range_contains(range a, range b)
{
    return (a.start <= b.start) && (a.end >= b.end);
}

static inline boolean range_equal(range a, range b)
{
    return (a.start == b.start) && (a.end == b.end);
}

static inline boolean range_valid(range r)
{
    return r.start <= r.end;
}

static inline void range_add(range *r, s64 delta)
{
    r->start += delta;
    r->end += delta;
}
