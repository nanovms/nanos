#include <unix_internal.h>

struct notify_entry {
    u32 eventmask;
    event_handler eh;
    struct list l;
};

struct notify_set {
    /* XXX add mutex */
    heap h;
    struct list entries;
};

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
    notify_release(s);
    deallocate(s->h, s, sizeof(struct notify_set));
}

notify_entry notify_add(notify_set s, u32 eventmask, event_handler eh)
{
    // XXX make cache
    notify_entry n = allocate(s->h, sizeof(struct notify_entry));
    if (n == INVALID_ADDRESS)
        return n;
    n->eventmask = eventmask;
    n->eh = eh;
    /* XXX take mutex */
    list_insert_before(&s->entries, &n->l);
    /* XXX release mutex */
    return n;
}

void notify_remove(notify_set s, notify_entry e)
{
    list_delete(&e->l);
    deallocate(s->h, e, sizeof(struct notify_entry));
}

void notify_dispatch(notify_set s, u32 events)
{
    /* XXX take mutex */
    list_foreach(&s->entries, l) {
        notify_entry n = struct_from_list(l, notify_entry, l);

        /* no guarantee that a transition is represented here; event
           handler needs to keep track itself if edge trigger is used */
        assert(n->eh);
        apply(n->eh, events & n->eventmask);
    }
    /* XXX release mutex */
}

void notify_release(notify_set s)
{
    /* XXX take mutex */
    list_foreach(&s->entries, l) {
        notify_entry n = struct_from_list(l, notify_entry, l);
        apply(n->eh, NOTIFY_EVENTS_RELEASE);
        list_delete(l);
        deallocate(s->h, n, sizeof(struct notify_entry));
    }
    /* XXX release mutex */
}
