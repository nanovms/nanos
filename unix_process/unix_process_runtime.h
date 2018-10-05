#include <runtime.h>

typedef int descriptor;
heap init_process_runtime();
heap allocate_mmapheap(heap meta, bytes size);
heap make_tiny_heap(heap parent);

typedef struct notifier {
    heap h;
    boolean (*_register)(struct notifier *n, descriptor f, u32 events, thunk a);
    void (*reset_fd)(struct notifier *n, descriptor f);
    void (*spin)(struct notifier *n);
} *notifier;

#define notifier_register(n, f, e, a) ((n)->_register(n, f, e, a))
#define notifier_reset_fd(n, f) ((n)->reset_fd(n, f))
#define notifier_spin(n) ((n)->spin(n));

notifier create_select_notifier(heap h);
notifier create_epoll_notifier(heap h);
void register_descriptor_except(notifier n, descriptor f, thunk each);
void register_descriptor_read(notifier n, descriptor f, thunk each);
void register_descriptor_write(notifier n, descriptor f, thunk each);    

typedef struct registration {
    descriptor fd;
    u32 events;			/* for select */
    thunk a;
    struct registration * next;
}  *registration;

#include <socket_user.h>
