typedef struct notify_set *notify_set;

/* We're using epoll events internally, expecting they will properly
   serve as a superset of all {epoll,poll,select} events. */
static inline u32 edge_events(u32 masked, u32 eventmask, u32 last)
{
    u32 r;
    /* report only rising events if edge triggered */
    if ((eventmask & EPOLLET) && (masked != last)) {
	r = (masked ^ last) & masked;
    } else {
	r = masked;
    }
    return r;
}

notify_set allocate_notify_set(heap h);

void deallocate_notify_set(notify_set s);

boolean notify_add(notify_set s, u32 eventmask, u32 * last, event_handler eh);

void notify_dispatch(notify_set s, u32 events);
