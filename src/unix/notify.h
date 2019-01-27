typedef struct notify_set *notify_set;

/* NOTIFY_EVENTS_RELEASE is a special value of events to signal to the
   event_handler that a notify_set is being deallocated.
   event_handlers should detect this special case and release
   resources (e.g. epollfd) accordingly. */
#define NOTIFY_EVENTS_RELEASE (-1u)

/* We're using epoll events internally, expecting they will properly
   serve as a superset of all {epoll,poll,select} events. */
static inline u32 edge_events(u32 events, u32 eventmask, u32 * last)
{
    u64 masked = events & eventmask;
    u64 delta;
    if (last) {
        delta = masked ^ *last;
        *last = masked;
    } else {
        delta = 0;
    }
    /* report only rising events if edge triggered */
    return (eventmask & EPOLLET) ? (delta & masked) : masked;
}

notify_set allocate_notify_set(heap h);

void deallocate_notify_set(notify_set s);

boolean notify_add(notify_set s, u32 eventmask, u32 * last, event_handler eh);

void notify_dispatch(notify_set s, u32 events);

void notify_release(notify_set s);
