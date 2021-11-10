typedef struct notify_set *notify_set;
typedef struct notify_entry *notify_entry;

/* Notify handlers receive event changes, including falling edges;
   if the last argument is a non-zero thread pointer, event changes
   are relevant only for waiters on that thread. */
typedef closure_type(event_handler, boolean, u64 events, void *arg);

/* NOTIFY_EVENTS_RELEASE is a special value of events to signal to the
   event_handler that a notify_set is being deallocated.
   event_handlers should detect this special case and release
   resources (e.g. epollfd) accordingly. */
#define NOTIFY_EVENTS_RELEASE (-1ull)

notify_set allocate_notify_set(heap h);

void deallocate_notify_set(notify_set s);

notify_entry notify_add(notify_set s, u64 eventmask, event_handler eh);

void notify_remove(notify_set s, notify_entry e, boolean release);

void notify_entry_update_eventmask(notify_entry n, u64 eventmask);

u64 notify_get_eventmask_union(notify_set s);

void notify_dispatch(notify_set s, u64 events);

void notify_dispatch_with_arg(notify_set s, u64 events, void *arg);

#define notify_dispatch_for_thread  notify_dispatch_with_arg

void notify_release(notify_set s);
