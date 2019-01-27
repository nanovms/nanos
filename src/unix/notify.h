typedef struct notify_set *notify_set;

/* An event_handler only returns true if the event was positively
   reported to the user program. This is critical for proper edge
   detect support. */
typedef closure_type(event_handler, boolean, u32 events);

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
        /* only reset last bits for cleared events; set events will be
           updated in last if the notify event handler is successfully
           applied (meaning that the rising edge was definitely
           reported to user program) */
        *last &= ~(delta & ~events);
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
