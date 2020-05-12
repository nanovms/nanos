typedef struct rangemap {
    heap h;
    struct rbtree t;
} *rangemap;

// [start, end)
typedef struct range {
    u64 start, end;
} range;

typedef struct rmnode {
    struct rbnode n;            /* must be first */
    range r;
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
boolean rangemap_range_intersects(rangemap rm, range q);
boolean rangemap_range_lookup(rangemap rm, range q, rmnode_handler node_handler);
boolean rangemap_range_lookup_with_gaps(rangemap rm, range q, rmnode_handler node_handler,
                                        range_handler gap_handler);
boolean rangemap_range_find_gaps(rangemap rm, range q, range_handler gap_handler);

rangemap allocate_rangemap(heap h);
void destruct_rangemap(rangemap rm, rmnode_handler destructor);
void deallocate_rangemap(rangemap rm, rmnode_handler destructor);

static inline range range_rshift(range r, int order)
{
    return irange(r.start >> order, r.end >> order);
}

static inline range range_lshift(range r, int order)
{
    return irange(r.start << order, r.end << order);
}

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
    init_rbnode(&n->n);
}

static inline rmnode rangemap_prev_node(rangemap rm, rmnode n)
{
    return (rmnode)rbnode_get_prev(&n->n);
}

static inline rmnode rangemap_next_node(rangemap rm, rmnode n)
{
    return (rmnode)rbnode_get_next(&n->n);
}

static inline rmnode rangemap_first_node(rangemap rm)
{
    return (rmnode)rbtree_find_first(&rm->t);
}

static inline void rangemap_remove_node(rangemap rm, rmnode n)
{
    rbtree_remove_node(&(rm->t), &n->n);
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

#define rangemap_foreach(rm, n)                                         \
    for (rmnode __next, (n) = (rmnode)rbtree_find_first(&rm->t);        \
         __next = ((n) == INVALID_ADDRESS) ? 0 : rangemap_next_node(rm, n), \
             ((n) != INVALID_ADDRESS);                                  \
         (n) = __next)

#define rangemap_foreach_of_range(rm, n, k)                                \
    for (rmnode __next, (n) = rangemap_lookup_at_or_next(rm, (k)->r.start); \
         (__next = ((n) == INVALID_ADDRESS) ? 0 : rangemap_next_node(rm, n)), \
             ((n) != INVALID_ADDRESS &&                                 \
              range_span(range_intersection((k)->r, (n)->r)) > 0);      \
         (n) = __next)
