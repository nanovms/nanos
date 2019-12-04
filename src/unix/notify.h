typedef struct notify_set *notify_set;
typedef struct notify_entry *notify_entry;

typedef closure_type(event_handler, void, u64 events);

/* NOTIFY_EVENTS_RELEASE is a special value of events to signal to the
   event_handler that a notify_set is being deallocated.
   event_handlers should detect this special case and release
   resources (e.g. epollfd) accordingly. */
#define NOTIFY_EVENTS_RELEASE (-1ull)

notify_set allocate_notify_set(heap h);

void deallocate_notify_set(notify_set s);

notify_entry notify_add(notify_set s, u64 eventmask, event_handler eh);

void notify_remove(notify_set s, notify_entry e, boolean release);

void notify_dispatch(notify_set s, u64 events);

void notify_release(notify_set s);
