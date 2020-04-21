#include <runtime.h>

boolean rangemap_insert(rangemap rm, rmnode n)
{
    list_foreach(&rm->root, l) {
        rmnode curr = struct_from_list(l, rmnode, l);
        range i = range_intersection(curr->r, n->r);
        if (range_span(i)) {
            /* XXX bark for now until we know we have all potential cases handled... */
            msg_warn("attempt to insert %p (%R) but overlap with %p (%R)\n", n, n->r, curr, curr->r);
            return false;
        }
        if (curr->r.start > n->r.start) {
            list_insert_before(l, &n->l);
            return true;
        }
    }
    list_insert_before(&rm->root, &n->l);
    return true;
}

boolean rangemap_reinsert(rangemap rm, rmnode n, range k)
{
    rangemap_remove_node(rm, n);
    n->r = k;
    return rangemap_insert(rm, n);
}

boolean rangemap_remove_range(rangemap rm, range k)
{
    boolean match = false;
    list l = list_get_next(&rm->root);

    while (l && l != &rm->root) {
        rmnode curr = struct_from_list(l, rmnode, l);
        list next = list_get_next(l);
        range i = range_intersection(curr->r, k);

        /* no intersection */
        if (range_empty(i)) {
            l = next;
            continue;
        }

        match = true;

        /* complete overlap (delete) */
        if (range_equal(curr->r, i)) {
            rangemap_remove_node(rm, curr);
            l = next;
            continue;
        }

        /* check for tail trim */
        if (curr->r.start < i.start) {
            /* check for hole */
            if (curr->r.end > i.end) {
                halt("unexpected hole trim: curr %R, key %R\n", curr->r, k);
#if 0
                /* XXX - I'm not positive that this is the right thing
                   to do; take a closer look at what, if anything,
                   would need benefit from this - plus this would
                   violate any refcounts kept on behalf of opaque
                   value. */
                rmnode rn = allocate(rt->h, sizeof(struct rmnode));
                rn->r.start = i.end;
                rn->r.end = curr->r.end;
                rn->value = curr->value; /* XXX this is perhaps most dubious */
                msg_warn("unexpected hole trim: curr %R, key %R\n", curr->r, k);
                list_insert_after(l, &rn->l);
#endif
            }
            curr->r.end = i.start;
        } else if (curr->r.end > i.end) { /* head trim */
            curr->r.start = i.end;
        }
        l = next;               /* valid even if we inserted one */
    }

    return match;
}

rmnode rangemap_lookup(rangemap rm, u64 point)
{
    list_foreach(&rm->root, i) {
        rmnode curr = struct_from_list(i, rmnode, l);
        if (point_in_range(curr->r, point))
            return curr;
    }
    return INVALID_ADDRESS;
}

/* return either an exact match or the neighbor to the right */
rmnode rangemap_lookup_at_or_next(rangemap rm, u64 point)
{
    list_foreach(&rm->root, i) {
        rmnode curr = struct_from_list(i, rmnode, l);
        if (point_in_range(curr->r, point) ||
            curr->r.start > point)
            return curr;
    }
    return INVALID_ADDRESS;
}

boolean rangemap_range_intersects(rangemap rm, range q)
{
    list_foreach(&rm->root, i) {
        rmnode curr = struct_from_list(i, rmnode, l);
        if (!range_empty(range_intersection(curr->r, q)))
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
    list_foreach(&rm->root, i) {
        rmnode curr = struct_from_list(i, rmnode, l);

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

rangemap allocate_rangemap(heap h)
{
    rangemap rm = allocate(h, sizeof(struct rangemap));
    rm->h = h;
    list_init(&rm->root);
    return rm;
}

void deallocate_rangemap(rangemap r)
{
}


