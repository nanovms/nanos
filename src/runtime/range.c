#include <runtime.h>

/* Calculates the set difference between range a and range b, i.e. the sub-ranges of a that don't
 * intersect with b. The result is returned in d1 and d2. */
void range_difference(range a, range b, range *d1, range *d2)
{
    b = range_intersection(a, b);
    if (range_span(b)) {
        d1->start = a.start;
        d1->end = b.start;
        d2->start = b.end;
        d2->end = a.end;
    } else {
        d1->start = a.start;
        d1->end = a.end;
        d2->start = d2->end = 0;
    }
}

boolean rangemap_insert(rangemap rm, rmnode n)
{
    init_rbnode(&n->n);
    rangemap_foreach_of_range(rm, curr, n) {
        if (curr->r.start >= n->r.end)
            break;
        range i = range_intersection(curr->r, n->r);
        if (range_span(i)) {
            msg_warn("attempt to insert %p (%R) but overlap with %p (%R)\n",
                     n, n->r, curr, curr->r);
            return false;
        }
    }
    if (!rbtree_insert_node(&rm->t, &n->n)) {
        halt("scan found no intersection but rb insert failed, node %p (%R)\n",
             n, n->r);
    }
    return true;
}

boolean rangemap_reinsert(rangemap rm, rmnode n, range k)
{
    rangemap_remove_node(rm, n);
    n->r = k;
    return rangemap_insert(rm, n);
}

rmnode rangemap_lookup(rangemap rm, u64 point)
{
    struct rmnode k;
    k.r = irange(point, point + 1);
    rangemap_foreach_of_range(rm, curr, &k) {
        if (curr->r.start >= k.r.end)
            break;
        if (range_span(range_intersection(curr->r, k.r)))
            return curr;
    }
    return INVALID_ADDRESS;
}

/* return either an exact match or the neighbor to the right */
rmnode rangemap_lookup_at_or_next(rangemap rm, u64 point)
{
    struct rmnode k;
    k.r = irange(point, point + 1);
    if (!rm->t.root)
        return INVALID_ADDRESS;
    rmnode n = (rmnode)rbtree_lookup_max_lte(&rm->t, &k.n);
    if (n == INVALID_ADDRESS) {
        n = (rmnode)rbtree_find_first(&rm->t);
        assert(n);              /* already checked root */
    }

    /* we use max lte because rbtree isn't aware of range ends...so we
       may need to advance by one if the result end is less than k start */
    while (n != INVALID_ADDRESS && n->r.end <= k.r.start)
        n = rangemap_next_node(rm, n);
    return n;
}

boolean rangemap_range_intersects(rangemap rm, range q)
{
    struct rmnode k;
    k.r = q;
    rangemap_foreach_of_range(rm, n, &k) {
        if (!range_empty(range_intersection(n->r, q)))
            return true;
    }
    return false;
}

/* inlined for optimized variants */
static inline boolean rangemap_range_lookup_internal(rangemap rm, range q,
                                                     rmnode_handler node_handler,
                                                     range_handler gap_handler)
{
    boolean match = false;
    u64 lastedge = q.start;
    struct rmnode k;
    k.r = q;
    rangemap_foreach_of_range(rm, curr, &k) {
        if (gap_handler) {
            u64 edge = curr->r.start;
            range i = range_intersection(irange(lastedge, edge), q);
            if (range_span(i)) {
                match = true;
                apply(gap_handler, i);
            }
            lastedge = curr->r.end;
        }

        if (node_handler) {
            range i = range_intersection(curr->r, q);
            if (!range_empty(i)) {
                match = true;
                apply(node_handler, curr);
            }
        }
    }

    if (gap_handler) {
        /* check for a gap between the last node and q.end */
        range i = range_intersection(irange(lastedge, q.end), q);
        if (range_span(i)) {
            match = true;
            apply(gap_handler, i);
        }
    }
    return match;
}

boolean rangemap_range_lookup(rangemap rm, range q, rmnode_handler node_handler)
{
    return rangemap_range_lookup_internal(rm, q, node_handler, 0);
}

boolean rangemap_range_lookup_with_gaps(rangemap rm, range q, rmnode_handler node_handler,
                                        range_handler gap_handler)
{
    return rangemap_range_lookup_internal(rm, q, node_handler, gap_handler);
}

boolean rangemap_range_find_gaps(rangemap rm, range q, range_handler gap_handler)
{
    return rangemap_range_lookup_internal(rm, q, 0, gap_handler);
}

define_closure_function(0, 2, int, rmnode_compare,
                 rbnode, a, rbnode, b)
{
    u64 sa = ((rmnode)a)->r.start;
    u64 sb = ((rmnode)b)->r.start;
    return sa == sb ? 0 : (sa < sb ? -1 : 1);
}

define_closure_function(0, 1, boolean, print_key,
                 rbnode, n)
{
    rprintf(" %R", ((rmnode)n)->r);
    return true;
}

rangemap allocate_rangemap(heap h)
{
    rangemap rm = allocate(h, sizeof(struct rangemap));
    if (rm == INVALID_ADDRESS)
        return rm;
    rm->h = h;
    init_rbtree(&rm->t, init_closure(&rm->compare, rmnode_compare), init_closure(&rm->print, print_key));
    return rm;
}

closure_function(1, 1, boolean, destruct_rmnode,
                 rmnode_handler, destructor,
                 rbnode, n)
{
    apply(bound(destructor), (rmnode)n);
    return true;
}

void destruct_rangemap(rangemap rm, rmnode_handler destructor)
{
    destruct_rbtree(&rm->t, stack_closure(destruct_rmnode, destructor));
}

void deallocate_rangemap(rangemap rm, rmnode_handler destructor)
{
    destruct_rangemap(rm, destructor);
    if (rm->h)
        deallocate(rm->h, rm, sizeof(struct rangemap));
}
