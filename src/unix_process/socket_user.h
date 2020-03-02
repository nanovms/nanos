typedef struct notifier {
    heap h;
    boolean (*_register)(struct notifier *n, descriptor f, u32 events, thunk a);
    void (*reset_fd)(struct notifier *n, descriptor f);
    void (*spin)(struct notifier *n);
} *notifier;

#define notifier_register(n, f, e, a) ((n)->_register(n, f, e, a))
#define notifier_reset_fd(n, f) ((n)->reset_fd(n, f))
#define notifier_spin(n) ((n)->spin(n));

typedef closure_type(new_connection, buffer_handler, buffer_handler);
void connection(heap h,
		notifier n,
                buffer target,
                new_connection c,
                status_handler failure);
void listen_port(heap h, notifier n, u16 port, new_connection);
notifier create_select_notifier(heap h);
notifier create_poll_notifier(heap h);
notifier create_epoll_notifier(heap h);
