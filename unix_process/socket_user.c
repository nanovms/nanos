//#define SOCKET_USER_EPOLL_DEBUG

#include <runtime.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <socket_user.h>
#include <errno.h>
#include <fcntl.h>
#include <ip.h>

typedef struct registration {
    descriptor fd;
    thunk a;
    struct registration * next;
}  *registration;

typedef struct epoll_notifier {
    struct notifier n;
    vector registrations;
    descriptor fd;
} *epoll_notifier;

typedef struct select_notifier {
    struct notifier n;
    vector registrations;
} *select_notifier;

static boolean epoll_addfd(notifier n, descriptor f, u32 events, thunk a)
{
#ifdef SOCKET_USER_EPOLL_DEBUG
    rprintf("epoll add fd: notifier %p, fd %d, events %P, thunk %p\n", n, f, events, a);
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

static void epoll_delfd(notifier n, descriptor f)
{
#ifdef SOCKET_USER_EPOLL_DEBUG
    rprintf("epoll del fd: notifier %p, fd %d\n", n, f);
#endif
    epoll_notifier e = (epoll_notifier)n;
    registration r;
    if (!(r = vector_get(e->registrations, f))) {
	msg_err("no registration for fd %d\n", f);
	return;
    }

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
		delete_descriptor(n, r->fd);
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
    e->n.addfd = epoll_addfd;
    e->n.delfd = epoll_delfd;
    e->n.spin = epoll_spin;
    e->registrations = allocate_vector(h, 10);
    zero(e->registrations->contents, sizeof(void *) * 10); /* XXX move to allocate vector? */
    e->fd = f;
    return (notifier)e;
}

void set_nonblocking(descriptor d)
{
    int flags = fcntl(d, F_GETFL);
    if (fcntl(d, F_SETFL, flags | O_NONBLOCK)) {
        halt("fcntl %E\n", errno);
    }
}

static void fill_v4_sockaddr(struct sockaddr_in *in, u32 address, u16 port)
{
    u32 p = htonl(address);
    memcpy(&in->sin_addr, &p, sizeof(u32));
    in->sin_family = AF_INET;
    in->sin_port = htons(port);
}


static CLOSURE_2_0(unreg, void, descriptor, descriptor);
static void unreg(descriptor e, descriptor f)
{
    rprintf("remove\n");
}

static void register_descriptor_write(heap h, notifier n, descriptor f, thunk each)
{
    registration r = allocate(h, sizeof(struct registration));
    r->fd = f;
    r->a = each;
    add_descriptor(n, f, EPOLLOUT, each);
}

static void register_descriptor(heap h, notifier n, descriptor f, thunk each)
{
    registration r = allocate(h, sizeof(struct registration));
    r->fd = f;
    r->a = each;
    add_descriptor(n, f, EPOLLIN|EPOLLRDHUP|EPOLLET, each);
}

static CLOSURE_4_0(connection_input, void, heap, descriptor, notifier, buffer_handler);
static void connection_input(heap h, descriptor f, notifier n, buffer_handler p)
{
    // can reuse?
    buffer b = allocate_buffer(h, 512);
    int res = read(f, b->contents, b->length);

    if (res < 0) {
        // should pass status
        apply(p, 0);
        return;
    }
    
    // this should have been taken care of by EPOLLHUP, but the
    // kernel doesn't support it        
    if (res == 0) {
	delete_descriptor(n, f);
        close(f);
        apply(p, 0);
    } else {
        b->end = res;
        apply(p, b);
    }
}


static CLOSURE_1_1(connection_output, void, descriptor, buffer);
static void connection_output(descriptor c, buffer b)
{
    if (b)  {
        write(c, b->contents, buffer_length(b));
    } else {
        close(c);
    }
}

static CLOSURE_4_0(accepting, void, heap, notifier, descriptor, new_connection);
static void accepting(heap h, notifier n, descriptor c, new_connection nc )
{
    struct sockaddr_in where;
    socklen_t len = sizeof(struct sockaddr_in);
    int s = accept(c, (struct sockaddr *)&where, &len);
    if (s < 0 ) halt("accept %E\n", errno);
    buffer_handler out = closure(h, connection_output, s);
    buffer_handler in = apply(nc, out);
    register_descriptor(h, n, s, closure(h, connection_input, h, s, n, in));
}


static CLOSURE_4_0(connection_start, void, heap, descriptor, notifier, new_connection);
void connection_start(heap h, descriptor s, notifier n, new_connection c)
{
    buffer_handler out = closure(h, connection_output, s);
    buffer_handler input = apply(c, out);
    // dont stay for write
    delete_descriptor(n, s);
    register_descriptor(h, n, s, closure(h, connection_input, h, s, n, input));
}

// more general registration than epoll fd
// asynch
void connection(heap h,
                notifier n,
                buffer target,
                new_connection c,
                status_handler failure)
{
    struct sockaddr_in where;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    u32 v4;
    u16 port;
    parse_v4_address_and_port(alloca_wrap(target), &v4, &port);
    fill_v4_sockaddr(&where, v4, port);
    // this is still blocking!
    int res = connect(s, (struct sockaddr *)&where, sizeof(struct sockaddr_in));
    if (res) {
        rprintf("zikkay %d %p\n", res, failure);        
        apply(failure, timm("errno", "%d", errno,
                            "errstr", "%E", errno));
    } else {
        register_descriptor_write(h, n, s, closure(h, connection_start, h, s, n, c));
    }
}


// should rety with asynch completion
void listen_port(heap h, notifier n, u16 port, new_connection nc)
{
    struct sockaddr_in where;

    descriptor service = socket(AF_INET, SOCK_STREAM, 0);
    memset(&where.sin_addr, 0, sizeof(unsigned int));
    where.sin_family = AF_INET;
    where.sin_port = htons(port);
    if (setsockopt(service, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int)) < 0)
        perror("setsockopt(SO_REUSEADDR) failed");
    
    if (bind(service, (struct sockaddr *)&where, sizeof(struct sockaddr_in)))
        halt("bind %E", errno);

    if (listen(service, 5))
        halt("listen %E", errno);

    register_descriptor(h, n, service, closure(h, accepting, h, n, service, nc));
}
