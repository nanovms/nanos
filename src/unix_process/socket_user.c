//#define SOCKET_USER_EPOLL_DEBUG

#include <runtime.h>
#include <sys/socket.h>
//#include <stdlib.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#ifndef NO_EPOLL
#include <sys/epoll.h>
#else
#define EPOLLIN POLLIN
#define EPOLLOUT POLLOUT
#define EPOLLPRI POLLPRI
#define EPOLLHUP POLLHUP
#endif
#include <socket_user.h>
#include <errno.h>
#include <fcntl.h>
#include <ip.h>
#include <poll.h>

/* Helper functions to ignore unused result (eliminate CC warning) */
static inline void igr(int x) {}

typedef struct registration {
    descriptor fd;
    u32 events;			/* for select */
    thunk a;
    struct registration * next;
}  *registration;

typedef struct select_bitmaps {
    bitmap r;
    bitmap w;
    bitmap e;
} select_bitmaps;

typedef struct select_notifier {
    struct notifier n;
    vector registrations;
    descriptor nfds;		/* highest fd given plus one */
    select_bitmaps fds;
    select_bitmaps tmp;
} *select_notifier;

static inline void select_bitmaps_init(heap h, select_bitmaps * b)
{
    b->r = allocate_bitmap(h, h, infinity);
    b->w = allocate_bitmap(h, h, infinity);
    b->e = allocate_bitmap(h, h, infinity);
}

static boolean select_register(notifier n, descriptor f, u32 events, thunk a)
{
#ifdef SOCKET_USER_EPOLL_DEBUG
    rprintf("select_register: notifier %p, fd %d, events %x, thunk %p\n", n, f, events, a);
#endif
    select_notifier s = (select_notifier)n;
    registration new = allocate(n->h, sizeof(struct registration));
    new->fd = f;
    new->events = events;
    new->a = a;
    new->next = vector_get(s->registrations, f);
    vector_set(s->registrations, f, new);
    if (f >= s->nfds)
	s->nfds = f + 1;

    if ((events & EPOLLIN))
	bitmap_set(s->fds.r, f, 1);
    if ((events & EPOLLOUT))
	bitmap_set(s->fds.w, f, 1);
    if ((events & EPOLLPRI))
	bitmap_set(s->fds.e, f, 1);

    return true;
}

static void select_reset_fd(notifier n, descriptor f)
{
#ifdef SOCKET_USER_EPOLL_DEBUG
    rprintf("select_reset_fd: fd %d, notifier %p\n", f, n);
#endif
    select_notifier s = (select_notifier)n;
    registration r;
    if (!(r = vector_get(s->registrations, f)))
	return;

    bitmap_set(s->fds.r, f, 0);
    bitmap_set(s->fds.w, f, 0);
    bitmap_set(s->fds.e, f, 0);

    do {
	registration next;
	assert(r->fd == f);
	next = r->next;
	deallocate(n->h, r, sizeof(struct registration));
	r = next;
    } while(r);
    vector_set(s->registrations, f, 0);
}

static void select_spin(notifier n)
{
#ifdef SOCKET_USER_EPOLL_DEBUG
    rprintf("select_spin enter: notifier %p\n", n);
#endif
    select_notifier s = (select_notifier)n;

    while (1) {
	bitmap_copy(s->tmp.r, s->fds.r);
	bitmap_copy(s->tmp.w, s->fds.w);
	bitmap_copy(s->tmp.e, s->fds.e);
	u64 * rp = bitmap_base(s->tmp.r);
	u64 * wp = bitmap_base(s->tmp.w);
	u64 * ep = bitmap_base(s->tmp.e);
#ifdef SOCKET_USER_EPOLL_DEBUG
	rprintf("   calling select with nfds = %d\n", s->nfds);
	rprintf("      r: %lx\tw: %lx\te: %lx\n", *rp, *wp, *ep);
#endif
	int res = select(s->nfds, (fd_set*)rp, (fd_set*)wp, (fd_set*)ep, 0);
#ifdef SOCKET_USER_EPOLL_DEBUG
	rprintf("   returned %d\n", res);
	rprintf("      r: %lx\tw: %lx\te: %lx\n", *rp, *wp, *ep);
#endif
        if (res == -1)
	    halt ("select failed with %s (%d)\n", strerror(errno), errno);
	if (res == 0)
	    continue;
	int words = pad(s->nfds, 64) >> 6;
        for (int i = 0; i < words; i++) {
	    // XXX refactor
	    u64 u = *rp | *wp | *ep;

	    bitmap_word_foreach_set(u, bit, fd, (i << 6)) {
		u32 events = 0;
		u64 mask = 1ull << bit;
		if (*rp & mask)
		    events |= EPOLLIN;
		if (*wp & mask)
		    events |= EPOLLOUT;
		if (*wp & mask)
		    events |= EPOLLPRI;
#ifdef SOCKET_USER_EPOLL_DEBUG
		rprintf("   fd %d, events %x:\n", fd, events);
#endif
		registration r = vector_get(s->registrations, fd);
		do {
		    if (r->events & events) {
#ifdef SOCKET_USER_EPOLL_DEBUG
			rprintf("      match events %x, applying thunk %p\n",
				r->events, r->a);
#endif
			apply(r->a);
		    }
		    r = r->next;
		} while (r);
	    }
	    rp++;
	    wp++;
	    ep++;
        }
    }
}

notifier create_select_notifier(heap h)
{
    select_notifier s = allocate(h, sizeof(struct select_notifier));
    s->n.h = h;
    s->n._register = select_register;
    s->n.reset_fd = select_reset_fd;
    s->n.spin = select_spin;
    s->registrations = allocate_vector(h, 10);
    select_bitmaps_init(h, &s->fds);
    select_bitmaps_init(h, &s->tmp);
    s->nfds = 0;
    return (notifier)s;
}

typedef struct poll_notifier {
    struct notifier n;
    vector registrations;
    buffer poll_fds;
} *poll_notifier;

#define NFDS(poll_fds) (buffer_length(poll_fds) / sizeof(struct pollfd))

static boolean poll_register(notifier n, descriptor f, u32 events, thunk a)
{
#ifdef SOCKET_USER_EPOLL_DEBUG
    rprintf("poll_register: notifier %p, fd %d, events %x, thunk %p\n", n, f, events, a);
#endif
    poll_notifier p = (poll_notifier)n;
    registration new = allocate(n->h, sizeof(struct registration));
    new->fd = f;
    new->events = events;
    new->a = a;
    new->next = vector_get(p->registrations, f);
    vector_set(p->registrations, f, new);

    extend_total(p->poll_fds, (f+1) * sizeof(struct pollfd));
    struct pollfd *fds = buffer_ref(p->poll_fds, 0);
    fds[f].fd = f;
    fds[f].events = events;

    return true;
}

static void poll_reset_fd(notifier n, descriptor f)
{
#ifdef SOCKET_USER_EPOLL_DEBUG
    rprintf("poll_reset_fd: fd %d, notifier %p\n", f, n);
#endif
    poll_notifier p = (poll_notifier)n;
    registration r;
    if (!(r = vector_get(p->registrations, f)))
        return;

    assert(f < NFDS(p->poll_fds));
    struct pollfd *fds = buffer_ref(p->poll_fds, 0);
    fds[f].fd = -1;

    do {
        registration next;
        assert(r->fd == f);
        next = r->next;
        deallocate(n->h, r, sizeof(struct registration));
        r = next;
    } while(r);
    vector_set(p->registrations, f, 0);
}

static void poll_spin(notifier n)
{
#ifdef SOCKET_USER_EPOLL_DEBUG
    rprintf("poll_spin enter: notifier %p\n", n);
#endif
    poll_notifier p = (poll_notifier)n;
    while (1) {
        struct pollfd *fds = (struct pollfd *) buffer_ref(p->poll_fds, 0);
#ifdef SOCKET_USER_EPOLL_DEBUG
        rprintf("   calling poll with nfds = %d\n", NFDS(p->poll_fds));
#endif
        for (int i = 0; i < NFDS(p->poll_fds); i++) {
            fds[i].revents = 0;
#ifdef SOCKET_USER_EPOLL_DEBUG
            rprintf("      fd %d, events %x, revents %x\n", fds[i].fd, fds[i].events, fds[i].revents);
#endif
        }

        int res = poll(buffer_ref(p->poll_fds, 0), NFDS(p->poll_fds), -1);
#ifdef SOCKET_USER_EPOLL_DEBUG
        rprintf("   returned %d\n", res);
#endif
        if (res == -1)
            halt("poll failed with %s (%d)\n", strerror(errno), errno);
        for (int i = 0; i < NFDS(p->poll_fds); i++) {
            if (fds[i].revents == 0)
                continue;

#ifdef SOCKET_USER_EPOLL_DEBUG
            rprintf("   fd %d, events %x, revents %x:\n", fds[i], fds[i].events, fds[i].revents);
#endif
            if (fds[i].revents & POLLHUP) {
                rprintf("   fd %d: POLLHUP, closing\n", fds[i].fd);
                notifier_reset_fd(n, fds[i].fd);
                // always the right thing to do?
                close(fds[i].fd);
                continue;
            }

            registration r = vector_get(p->registrations, fds[i].fd);
            do {
                if (r->events & fds[i].revents) {
#ifdef SOCKET_USER_EPOLL_DEBUG
                    rprintf("      match events %x, applying thunk %p\n",
                        r->events, r->a);
#endif
                    apply(r->a);
                }
                r = r->next;
            } while (r);
        }
    }
}

notifier create_poll_notifier(heap h)
{
    poll_notifier p = allocate(h, sizeof(struct select_notifier));
    p->n.h = h;
    p->n._register = poll_register;
    p->n.reset_fd = poll_reset_fd;
    p->n.spin = poll_spin;
    p->registrations = allocate_vector(h, 10);

    p->poll_fds = allocate_buffer(h, 10 * sizeof(struct pollfd));
    buffer_produce(p->poll_fds, 10 * sizeof(struct pollfd));
    struct pollfd *fds = (struct pollfd *) buffer_ref(p->poll_fds, 0);
    for (int i = 0; i < NFDS(p->poll_fds); i++) {
        fds[i].fd = -1;
    }

    return (notifier)p;
}

#ifndef NO_EPOLL
typedef struct epoll_notifier {
    struct notifier n;
    vector registrations;
    descriptor fd;
} *epoll_notifier;

static boolean epoll_register(notifier n, descriptor f, u32 events, thunk a)
{
#ifdef SOCKET_USER_EPOLL_DEBUG
    rprintf("epoll register fd: notifier %p, fd %d, events %x, thunk %p\n", n, f, events, a);
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
	    halt("epoll failed with %s (%d)\n", strerror(errno), errno);
        for (int i = 0; i < res; i++) {
            registration r = ev[i].data.ptr;
#ifdef SOCKET_USER_EPOLL_DEBUG
	    rprintf("   fd %d, events %x\n", r->fd, ev[i].events);
#endif
            if (ev[i].events & EPOLLHUP)  {
                descriptor fd = r->fd;
		notifier_reset_fd(n, fd);
                // always the right thing to do?
                close(fd);
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
#endif

void set_nonblocking(descriptor d)
{
    int flags = fcntl(d, F_GETFL);
    if (fcntl(d, F_SETFL, flags | O_NONBLOCK)) {
        halt("fcntl %s\n", strerror(errno));
    }
}

static void fill_v4_sockaddr(struct sockaddr_in *in, u32 address, u16 port)
{
    u32 p = htonl(address);
    memcpy(&in->sin_addr, &p, sizeof(u32));
    in->sin_family = AF_INET;
    in->sin_port = htons(port);
}

static void register_descriptor_write(heap h, notifier n, descriptor f, thunk each)
{
    registration r = allocate(h, sizeof(struct registration));
    r->fd = f;
    r->a = each;
    notifier_register(n, f, EPOLLOUT, each);
}

static void register_descriptor(heap h, notifier n, descriptor f, thunk each)
{
    registration r = allocate(h, sizeof(struct registration));
    r->fd = f;
    r->a = each;
    notifier_register(n, f, EPOLLIN|EPOLLHUP, each);
}

closure_function(4, 0, void, connection_input,
                 heap, h, descriptor, f, notifier, n, buffer_handler, p)
{
    // can reuse?
    descriptor f = bound(f);
    buffer b = allocate_buffer(bound(h), 512);
    int res = read(f, b->contents, b->length);
    if (res > 0) {
        b->end = res;
        apply(bound(p), b);
	return;
    }
    if (res < 0 && errno != ENOTCONN)
	rprintf("read error: %s (%d)\n", strerror(errno), errno);
    notifier_reset_fd(bound(n), f);
    close(f);
    apply(bound(p), 0);        // should pass status
}


closure_function(2, 1, status, connection_output,
                 descriptor, c, notifier, n,
                 buffer, b)
{
    descriptor c = bound(c);
    if (b)  {
        igr(write(c, b->contents, buffer_length(b)));
    } else {
	notifier_reset_fd(bound(n), c);
        close(c);
    }
    return STATUS_OK;           /* pff */
}

closure_function(4, 0, void, accepting,
                 heap, h, notifier, n, descriptor, c, new_connection, nc)
{
    heap h = bound(h);
    notifier n = bound(n);
    struct sockaddr_in where;
    socklen_t len = sizeof(struct sockaddr_in);
    int s = accept(bound(c), (struct sockaddr *)&where, &len);
    if (s < 0 ) halt("accept %s\n", strerror(errno));
    buffer_handler out = closure(h, connection_output, s, n);
    buffer_handler in = apply(bound(nc), out);
    register_descriptor(h, n, s, closure(h, connection_input, h, s, n, in));
}


closure_function(4, 0, void, connection_start,
                 heap, h, descriptor, s, notifier, n, new_connection, c)
{
    heap h = bound(h);
    descriptor s = bound(s);
    notifier n = bound(n);
    buffer_handler out = closure(h, connection_output, s, n);
    buffer_handler input = apply(bound(c), out);
    // dont stay for write
    notifier_reset_fd(n, s);
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
    assert(parse_v4_address_and_port(alloca_wrap(target), &v4, &port));
    fill_v4_sockaddr(&where, v4, port);
    // this is still blocking!
    int res = connect(s, (struct sockaddr *)&where, sizeof(struct sockaddr_in));
    if (res) {
        rprintf("zikkay %d %p\n", res, failure);        
        apply(failure, timm("errno", "%d", errno,
                            "errstr", "%s", strerror(errno)));
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
        halt("bind %s", strerror(errno));

    if (listen(service, 5))
        halt("listen %s", strerror(errno));

    register_descriptor(h, n, service, closure(h, accepting, h, n, service, nc));
}
