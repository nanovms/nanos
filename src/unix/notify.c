#include <unix_internal.h>

typedef struct notify_entry {
    u32 eventmask;
    u32 * last;
    event_handler eh;
    struct list l;
} *notify_entry;

typedef struct notify_set {
    /* XXX add mutex */
    heap h;
    struct list entries;
} *notify_set;

notify_set allocate_notify_set(heap h)
{
    notify_set s = allocate(h, sizeof(struct notify_set));
    if (s == INVALID_ADDRESS)
	return s;
    s->h = h;
    list_init(&s->entries);
    /* XXX mutex init */
    return s;
}

void deallocate_notify_set(notify_set s)
{
    list l = list_begin(&s->entries);
    if (!l)
        return;

    /* XXX free mutex - shouldn't be possible for anything to grab it now */
    do {
        notify_entry n = struct_from_list(l, notify_entry, l);
        list next = list_get_next(l);
        list_delete(l);
        /* XXX should we invoke callbacks with a flag that says we're done?
           refcnts, etc */
        deallocate(s->h, n, sizeof(struct notify_entry));
        l = next;
    } while(l != &s->entries);

    deallocate(s->h, s, sizeof(struct notify_set));
}

boolean notify_add(notify_set s, u32 eventmask, u32 * last, event_handler eh)
{
    notify_entry n = allocate(s->h, sizeof(struct notify_entry));
    if (n == INVALID_ADDRESS)
	return false;
    n->eventmask = eventmask;
    n->last = last;
    n->eh = eh;
    /* XXX take mutex */
    list_insert_before(&s->entries, &n->l);
    /* XXX release mutex */
    return true;
}

void notify_dispatch(notify_set s, u32 events)
{
    /* XXX take mutex */
    list l = list_get_next(&s->entries);
    if (!l)
	return;

    /* XXX not using list foreach because of intermediate
       deletes... make a macro for that */
    do {
	notify_entry n = struct_from_list(l, notify_entry, l);
	list next = list_get_next(l);
	u32 masked = events & n->eventmask;
        u32 r = edge_events(masked, n->eventmask, n->last ? *n->last : 0);
        if (n->last)
            *n->last = masked;
	if (r && apply(n->eh, r)) {
	    list_delete(l);
	    deallocate(s->h, n, sizeof(struct notify_entry));
	}
	l = next;
    } while(l != &s->entries);
    /* XXX release mutex */
}

