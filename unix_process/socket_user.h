#pragma once

typedef struct notifier {
    heap h;
    boolean (*addfd)(struct notifier *n, descriptor f, u32 events, thunk a);
    void (*delfd)(struct notifier *n, descriptor f);
    void (*spin)(struct notifier *n);
} *notifier;

#define add_descriptor(n, f, e, a) ((n)->addfd(n, f, e, a))
#define delete_descriptor(n, f) ((n)->delfd(n, f))
#define notifier_spin(n) ((n)->spin(n));

typedef closure_type(new_connection, buffer_handler, buffer_handler);
void connection(heap h,
		notifier n,
                buffer target,
                new_connection c,
                status_handler failure);
void listen_port(heap h, notifier n, u16 port, new_connection);
notifier create_epoll_notifier(heap h);
