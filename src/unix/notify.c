#include <unix_internal.h>

struct notify_entry {
    u64 eventmask;
    u64 flags;
    event_handler eh;
    struct list l;
};

struct notify_set {
    heap h;
    struct spinlock lock;
    struct list entries;
};

notify_set allocate_notify_set(heap h)
{
    notify_set s = allocate(h, sizeof(struct notify_set));
    if (s == INVALID_ADDRESS)
        return s;
    s->h = h;
    spin_lock_init(&s->lock);
    list_init(&s->entries);
    return s;
}

void deallocate_notify_set(notify_set s)
{
    notify_release(s);
    deallocate(s->h, s, sizeof(struct notify_set));
}

notify_entry notify_add_with_flags(notify_set s, u64 eventmask, u64 flags, event_handler eh)
{
    notify_entry n = allocate(s->h, sizeof(struct notify_entry));
    if (n == INVALID_ADDRESS)
        return n;
    n->eventmask = eventmask;
    n->flags = flags;
    n->eh = eh;
    spin_lock(&s->lock);
    list_insert_before(&s->entries, &n->l);
    spin_unlock(&s->lock);
    return n;
}

void notify_remove(notify_set s, notify_entry e, boolean release)
{
    spin_lock(&s->lock);
    list_delete(&e->l);
    if (release)
        apply(e->eh, NOTIFY_EVENTS_RELEASE, 0);
    spin_unlock(&s->lock);
    deallocate(s->h, e, sizeof(struct notify_entry));
}

u64 notify_entry_get_eventmask(notify_entry n)
{
    return n->eventmask;
}

// XXX poll waiters too
void notify_entry_update_eventmask(notify_entry n, u64 eventmask)
{
    n->eventmask = eventmask;
}

u64 notify_get_eventmask_union(notify_set s)
{
    u64 u = 0;
    spin_lock(&s->lock);
    list_foreach(&s->entries, l) {
        notify_entry n = struct_from_list(l, notify_entry, l);
        u |= n->eventmask;
    }
    spin_unlock(&s->lock);
    return u;
}

boolean notify_dispatch_with_arg(notify_set s, u64 events, void *arg)
{
    boolean consumed = false;
    spin_lock(&s->lock);
    list_foreach(&s->entries, l) {
        notify_entry n = struct_from_list(l, notify_entry, l);
        /* no guarantee that a transition is represented here; event
           handler needs to keep track itself if edge trigger is used */
        if (!consumed || !(n->flags & NOTIFY_FLAGS_EXCLUSIVE)) {
            assert(n->eh);
            u64 ret = apply(n->eh, events & n->eventmask, arg);
            if (ret & NOTIFY_RESULT_RELEASE) {
                list_delete(l);
                deallocate(s->h, n, sizeof(struct notify_entry));
            }
            if (ret & NOTIFY_RESULT_CONSUMED)
                consumed = true;
        }
    }
    spin_unlock(&s->lock);
    return consumed;
}

void notify_dispatch(notify_set s, u64 events)
{
    notify_dispatch_for_thread(s, events, 0);
}

void notify_release(notify_set s)
{
    spin_lock(&s->lock);
    list_foreach(&s->entries, l) {
        notify_entry n = struct_from_list(l, notify_entry, l);
        list_delete(l);
        apply(n->eh, NOTIFY_EVENTS_RELEASE, 0);
        deallocate(s->h, n, sizeof(struct notify_entry));
    }
    spin_unlock(&s->lock);
}
