#include <unix_process_runtime.h>
#include <sys/epoll.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

typedef struct epoll_notifier {
    struct notifier n;
    vector registrations;
    descriptor fd;
} *epoll_notifier;

static boolean epoll_register(notifier n, descriptor f, u32 events, thunk a)
{
    #ifdef SOCKET_USER_EPOLL_DEBUG
    rprintf("epoll register fd: notifier %p, fd %d, events %P, thunk %p\n", n, f, events, a);
    #endif
    epoll_notifier e = (epoll_notifier)n;
    registration new = allocate(n->h, sizeof(struct registration));
    new->fd = f;
    new->a = a;
    new->next = vector_get(e->registrations, f);
    vector_set(e->registrations, f, new);

    struct epoll_event ev;
    ev.events = events;
    ev.data.ptr = new;
    epoll_ctl(e->fd, EPOLL_CTL_ADD, f, &ev);
    return true;
}

static void epoll_reset_fd(notifier n, descriptor f)
{
    #ifdef SOCKET_USER_EPOLL_DEBUG
    rprintf("epoll_reset_fd fd: notifier %p, fd %d\n", n, f);
    #endif
    epoll_notifier e = (epoll_notifier)n;
    registration r;
    if (!(r = vector_get(e->registrations, f)))
        return;

    epoll_ctl(e->fd, EPOLL_CTL_DEL, f, 0);
    do {
        registration next;
        assert(r->fd == f);
        next = r->next;
        deallocate(n->h, r, sizeof(struct registration));
        r = next;
    } while(r);
    vector_set(e->registrations, f, 0);
}

static CLOSURE_2_0(unreg, void, descriptor, descriptor);
static void unreg(descriptor e, descriptor f)
{
    rprintf("remove\n");
}

void register_descriptor_write(notifier n, descriptor f, thunk each)
{
    registration r = allocate(n->h, sizeof(struct registration));
    r->fd = f;
    r->a = each;
    notifier_register(n, f, EPOLLOUT, each);
}

void register_descriptor_except(notifier n, descriptor f, thunk each)
{
    registration r = allocate(n->h, sizeof(struct registration));
    r->fd = f;
    r->a = each;
    notifier_register(n, f, EPOLLRDHUP, each);
}

void register_descriptor_read(notifier n, descriptor f, thunk each)
{
    registration r = allocate(n->h, sizeof(struct registration));
    r->fd = f;
    r->a = each;
    struct epoll_event ev;
    ev.events = EPOLLIN|EPOLLRDHUP|EPOLLET;
    ev.data.ptr = r;
    notifier_register(n, f, EPOLLIN|EPOLLRDHUP|EPOLLET, each);    
}


u64 milliseconds_from_time(time t)
{
    return((t*1000)>>32);
}

static void epoll_spin(notifier n)
{
#ifdef SOCKET_USER_EPOLL_DEBUG
    rprintf("epoll_spin enter: notifier %p\n", n);
#endif
    epoll_notifier e = (epoll_notifier)n;
    struct epoll_event ev[10];
    while (1) {
        int res = epoll_wait(e->fd, ev, sizeof(ev)/sizeof(struct epoll_event), -1);
        if (res == -1)
	    halt ("epoll failed with %s (%d)\n", strerror(errno));
        for (int i = 0; i < res; i++) {
            registration r = ev[i].data.ptr;
#ifdef SOCKET_USER_EPOLL_DEBUG
	    rprintf("   fd %d, events %P\n", r->fd, ev[i].events);
#endif
            if (ev[i].events & EPOLLHUP)  {
		notifier_reset_fd(n, r->fd);
                // always the right thing to do?
                close(r->fd);
            } else {
                apply(r->a);
            }
        }
    }
}

notifier create_epoll_notifier(heap h)
{
    descriptor f;
    if ((f = epoll_create(1)) < 0) {
        msg_err("epoll_create failed, %s (%d)\n", strerror(errno), errno);
        return 0;
    }
    epoll_notifier e = allocate(h, sizeof(struct epoll_notifier));
    e->n.h = h;
    e->n._register = epoll_register;
    e->n.reset_fd = epoll_reset_fd;
    e->n.spin = epoll_spin;
    e->registrations = allocate_vector(h, 10);
    e->fd = f;
    return (notifier)e;
}
