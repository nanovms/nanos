#include <unix_internal.h>

struct notify_entry {
    u64 eventmask;
    event_handler eh;
    struct list l;
};

struct notify_set {
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
    return s;
}

void deallocate_notify_set(notify_set s)
{
    notify_release(s);
    deallocate(s->h, s, sizeof(struct notify_set));
}

notify_entry notify_add(notify_set s, u64 eventmask, event_handler eh)
{
    // XXX make cache
    notify_entry n = allocate(s->h, sizeof(struct notify_entry));
    if (n == INVALID_ADDRESS)
        return n;
    n->eventmask = eventmask;
    n->eh = eh;
    list_insert_before(&s->entries, &n->l);
    return n;
}

void notify_remove(notify_set s, notify_entry e, boolean release)
{
    list_delete(&e->l);
    if (release)
        apply(e->eh, NOTIFY_EVENTS_RELEASE, 0);
    deallocate(s->h, e, sizeof(struct notify_entry));
}

// XXX poll waiters too
void notify_entry_update_eventmask(notify_entry n, u64 eventmask)
{
    n->eventmask = eventmask;
}

u64 notify_get_eventmask_union(notify_set s)
{
    u64 u = 0;
    list_foreach(&s->entries, l) {
        notify_entry n = struct_from_list(l, notify_entry, l);
        u |= n->eventmask;
    }
    return u;
}

void notify_dispatch_for_thread(notify_set s, u64 events, thread t)
{
    list_foreach(&s->entries, l) {
        notify_entry n = struct_from_list(l, notify_entry, l);

        /* no guarantee that a transition is represented here; event
           handler needs to keep track itself if edge trigger is used */
        assert(n->eh);
        apply(n->eh, events & n->eventmask, t);
    }
}

void notify_dispatch(notify_set s, u64 events)
{
    notify_dispatch_for_thread(s, events, 0);
}

void notify_release(notify_set s)
{
    list_foreach(&s->entries, l) {
        notify_entry n = struct_from_list(l, notify_entry, l);
        apply(n->eh, NOTIFY_EVENTS_RELEASE, 0);
        list_delete(l);
        deallocate(s->h, n, sizeof(struct notify_entry));
    }
}
