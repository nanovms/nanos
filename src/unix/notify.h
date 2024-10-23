typedef struct notify_set *notify_set;
typedef struct notify_entry *notify_entry;

/* Notify handlers receive event changes, including falling edges;
   if the last argument is a non-zero thread pointer, event changes
   are relevant only for waiters on that thread. */
closure_type(event_handler, u64, u64 events, void *arg);

#define NOTIFY_FLAGS_EXCLUSIVE  U64_FROM_BIT(0)

#define NOTIFY_RESULT_CONSUMED  U64_FROM_BIT(0)
#define NOTIFY_RESULT_RELEASE   U64_FROM_BIT(1)

/* NOTIFY_EVENTS_RELEASE is a special value of events to signal to the
   event_handler that a notify_set is being deallocated.
   event_handlers should detect this special case and release
   resources (e.g. epollfd) accordingly. */
#define NOTIFY_EVENTS_RELEASE (-1ull)

notify_set allocate_notify_set(heap h);

void deallocate_notify_set(notify_set s);

notify_entry notify_add_with_flags(notify_set s, u64 eventmask, u64 flags, event_handler eh);

#define notify_add(s, e, h)  notify_add_with_flags(s, e, 0, h)

void notify_remove(notify_set s, notify_entry e, boolean release);

u64 notify_entry_get_eventmask(notify_entry n);
void notify_entry_update_eventmask(notify_entry n, u64 eventmask);

u64 notify_get_eventmask_union(notify_set s);

void notify_dispatch(notify_set s, u64 events);

boolean notify_dispatch_with_arg(notify_set s, u64 events, void *arg);

#define notify_dispatch_for_thread  notify_dispatch_with_arg

void notify_release(notify_set s);
