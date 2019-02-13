#include <runtime.h>

boolean rangemap_insert(rangemap rm, rmnode n)
{
    struct list * l;
    list_foreach(&rm->root, l) {
        rmnode curr = struct_from_list(l, rmnode, l);
        range i = range_intersection(curr->r, n->r);
        /* check for overlap...kinda harsh to assert, add error handling... */
        if (range_span(i)) {
            /* XXX bark for now until we know we have all potential cases handled... */
            msg_warn("attempt to insert range %R but overlap with %R (%p)\n",
                     n->r, curr->r, curr);
            return false;
        }
        if (curr->r.start > n->r.start)
            break;
    }
    list_insert_before(l, &n->l);
    return true;
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
    struct list * i;
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
    struct list * i;
    list_foreach(&rm->root, i) {
        rmnode curr = struct_from_list(i, rmnode, l);
        if (point_in_range(curr->r, point) ||
            curr->r.start > point)
            return curr;
    }
    return INVALID_ADDRESS;
}

/* can be called with rh == 0 for true/false match */
boolean rangemap_range_lookup(rangemap rm, range q, rmnode_handler nh)
{
    boolean match = false;
    struct list * i;
    list_foreach(&rm->root, i) {
        rmnode curr = struct_from_list(i, rmnode, l);
        range i = range_intersection(curr->r, q);

        if (!range_empty(i)) {
            match = true;
            if (nh == 0)        /* abort search if match w/o handler */
                return true;
            apply(nh, curr);
        }
    }
    return match;
}

boolean rangemap_range_find_gaps(rangemap rm, range q, range_handler rh)
{
    boolean match = false;
    u64 lastedge = q.start;
    struct list * l;
    list_foreach(&rm->root, l) {
        rmnode curr = struct_from_list(l, rmnode, l);
        u64 edge = curr->r.start;
        range i = range_intersection(irange(lastedge, edge), q);
        if (range_span(i)) {
            match = true;
            apply(rh, i);
        }
        lastedge = curr->r.end;
    }

    /* check for a gap between the last node and q.end */
    range i = range_intersection(irange(lastedge, q.end), q);
    if (range_span(i)) {
        match = true;
        apply(rh, i);
    }
    return match;
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


