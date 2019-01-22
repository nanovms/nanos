#include <runtime.h>

/* This isn't a tree of any kind - just an ordered list with iterative
   operations. Sacrifice efficiency until we are absolutely sure of
   the interface and function. (e.g. - do we want to allow overlapping
   regions? how exactly should range deletion work?) Later on, this
   implementation can be swapped with one that uses an rbtree, a skip
   list, or something else. */

typedef struct rmnode {
    range r;
    void *value;
    struct list l;
} *rmnode;

struct rangemap {
    heap h;
    struct list root;
};

void rangemap_insert(rangemap r, u64 start, u64 length, void *value)
{
    rmnode n = allocate(r->h, sizeof(struct rmnode));
    n->r.start = start;
    n->r.end = start + length;    
    n->value = value;

    struct list * i;
    list_foreach(&r->root, i) {
        rmnode curr = struct_from_list(i, rmnode, l);
        /* check for overlap...kinda harsh to assert, add error handling... */
        if (point_in_range(curr->r, start)) {
            msg_err("attempt to insert range %R but overlap with %R (%p)\n",
                    n->r, curr->r, curr->value);
            halt("sadness\n");
        }
        assert(!point_in_range(curr->r, start + length - 1));
        if (curr->r.start > start)
            break;
    }
    list_insert_before(i, &n->l);
}

/* XXX assuming we don't ever allow an outsider to hold a
   reference... in which case we'd need refcounts or rcu */
static void delete_node(rangemap r, rmnode n)
{
    list_delete(&n->l);
    deallocate(r->h, n, sizeof(struct rmnode));
}

static void rangemap_remove_internal(rangemap rt, range k)
{
    list l = list_get_next(&rt->root);

    while (l) {
        rmnode curr = struct_from_list(l, rmnode, l);
        list next = list_get_next(l);
        range i = range_intersection(curr->r, k);

        /* no intersection */
        if (range_empty(i)) {
            l = next;
            continue;
        }

        /* complete overlap (delete) */
        if (range_equal(curr->r, i)) {
            delete_node(rt, curr);
            l = next;
            continue;
        }

        /* check for tail trim */
        if (curr->r.start < i.start) {
            /* check for hole */
            if (curr->r.end > i.end) {
                /* XXX - I'm not positive that this is the right thing
                   to do; take a closer look at what, if anything,
                   would need benefit from this - plus this would
                   violate any refcounts kept on behalf of opaque
                   value. */
                rmnode rn = allocate(rt->h, sizeof(struct rmnode));
                rn->r.start = i.end;
                rn->r.end = curr->r.end;
                rn->value = curr->value; /* XXX this is perhaps most dubious */
                msg_err("unexpected hole trim: curr %R, key %R\n", curr->r, k);
                list_insert_after(l, &rn->l);
            }
            curr->r.end = i.start;
        } else if (curr->r.end > i.end) { /* head trim */
            curr->r.start = i.end;
        }
        l = next;               /* valid even if we inserted one */
    }
}

/* XXX nuke */
void rangemap_remove(rangemap r, u64 start, u64 length)
{
    rangemap_remove_internal(r, (range){start, start+length});
}

void *rangemap_lookup(rangemap r, u64 point, range * rrange)
{
    struct list * i;
    list_foreach(&r->root, i) {
        rmnode curr = struct_from_list(i, rmnode, l);
        if (point_in_range(curr->r, point)) {
            *rrange = curr->r;
            return curr->value;
        }
    }
    return 0;
}

void rangemap_range_lookup(rangemap r, range q, subrange s)
{
    struct list * i;
    u64 last_covered = q.start;
    list_foreach(&r->root, i) {
        rmnode curr = struct_from_list(i, rmnode, l);
        range i = range_intersection(curr->r, q);

        if (!range_empty(i))
            apply(s, curr->r, curr->value);
        else if (curr->r.start > last_covered)
            apply(s, irange(last_covered, curr->r.start), range_hole);
        last_covered = curr->r.end;
    }

    /* check for hole after last entry */
    if (last_covered < q.end)
        apply(s, irange(last_covered, q.end), range_hole);
}

rangemap allocate_rangemap(heap h)
{
    rangemap r = allocate(h, sizeof(struct rangemap));
    r->h = h;
    list_init(&r->root);
    return r;
}

void deallocate_rangemap(rangemap r)
{
}


