#include <unix_internal.h>
#include <lwip.h>
#include <lwip/udp.h>
#include <net_system_structs.h>

struct sockaddr_in {
    u16 family;
    u16 port;
    u32 address;
} *sockaddr_in;

struct sockaddr {
    u16 family;
} *sockaddr;

typedef u32 socklen_t;

// xxx - what is the difference between IN_CONNECTION and open
// nothing seems to track whether the tcp state is actually
// connected

// XXX change these over to actual tcp connection states...but
// defined in tcp-specific area
enum tcp_socket_state {
    TCP_SOCK_UNDEFINED = 0,
    TCP_SOCK_CREATED = 1,
    TCP_SOCK_IN_CONNECTION = 2,
    TCP_SOCK_OPEN = 3,
    TCP_SOCK_CLOSED = 4,
    TCP_SOCK_LISTENING = 5,
};

enum udp_socket_state {
    UDP_SOCK_UNDEFINED = 0,
    UDP_SOCK_CREATED = 1,
    UDP_SOCK_BOUND = 2,
};

typedef struct notify_entry {
    u32 eventmask;
    u32 * last;
    event_handler eh;
    struct list l;
} *notify_entry;

typedef struct sock {
    struct file f;
    int type;
    process p;
    heap h;
    queue incoming;
    queue waiting; // service waiting before notify, do we really need 2 queues here?
    struct list notify;		/* XXX: add spinlock when available */
    // the notion is that 'waiters' should take priority    
    int fd;
    status lwip_status;
} *sock;

typedef struct tcpsock {
    struct sock sock;
    struct tcp_pcb *lw;
    enum tcp_socket_state state; // half open?
} *tcpsock;

typedef struct udpsock {
    struct sock sock;
    struct udp_pcb *lw;
    enum udp_socket_state state;
} *udpsock;

#ifdef NETSYSCALL_DEBUG
#define net_debug(x, ...) do {log_printf(" NET", "%s: " x, __func__, ##__VA_ARGS__);} while(0)
#else
#define net_debug(x, ...)
#endif

static inline u32 socket_poll_events(sock s)
{
    boolean in = queue_length(s->incoming) > 0;

    /* XXX socket state isn't giving a complete picture; needs to specify
       which transport ends are shut down */
    if (s->type == SOCK_STREAM) {
	tcpsock ts = (tcpsock)s;
	if (ts->state == TCP_SOCK_LISTENING) {
	    return in ? EPOLLIN : 0;
	} else if (ts->state == TCP_SOCK_OPEN) {
	    return in ? EPOLLIN | EPOLLRDNORM : 0;
	} else {
	    return EPOLLIN | EPOLLHUP | EPOLLRDHUP | EPOLLRDNORM;
	}
    }
    assert(s->type == SOCK_DGRAM);
    return in ? EPOLLIN | EPOLLRDNORM : 0;
}

static inline boolean notify_enqueue(sock s, u32 eventmask, u32 * last, event_handler eh)
{
    notify_entry n = allocate(s->h, sizeof(struct notify_entry));
    if (n == INVALID_ADDRESS)
	return false;
    n->eventmask = eventmask;
    n->last = last;
    n->eh = eh;
    list_insert_before(&s->notify, &n->l); /* XXX lock */
    return true;
}

/* XXX stuck in syscall.c, move to generic file place */
extern u32 edge_events(u32 masked, u32 eventmask, u32 last);

/* XXX this should move to a more general place for use with other types of fds */
static void notify_dispatch(sock s)
{
    /* XXX need to take a lock here, circle back once we have them */
    list l = list_get_next(&s->notify);
    if (!l)
	return;

    u32 events = socket_poll_events(s);

    /* XXX not using list foreach because of intermediate
       deletes... make a macro for that */
    do {
	notify_entry n = struct_from_list(l, notify_entry, l);
	list next = list_get_next(l);
	u32 masked = events & n->eventmask;
	u32 r = edge_events(masked, n->eventmask, *n->last);
	*n->last = masked;
	if (r && apply(n->eh, r)) {
	    list_delete(l);
	    deallocate(s->h, n, sizeof(struct notify_entry));
	}
	l = next;
    } while(l != &s->notify);
}

typedef closure_type(lwip_status_handler, void, err_t);

static void wakeup(sock s, err_t err)
{
    lwip_status_handler fstatus;
    net_debug("sock %d\n", s->fd);
    // return status if not handled so someone else can try?
    // shouldnt a close event wake up everyone?
    if ((fstatus = dequeue(s->waiting))) {
        apply(fstatus, err);
    }  else {
	notify_dispatch(s);
    }
}

static inline void error_message(sock s, err_t err) {
    switch (err) {
        case ERR_ABRT:
            msg_err("connection closed on fd %d due to tcp_abort or timer\n", s->fd);
            break;
        case ERR_RST:
            msg_err("connection closed on fd %d due to remote reset\n", s->fd);
            break;
        default:
            msg_err("fd %d: unknown error %d\n", s->fd, err);
    }
}

static void remote_sockaddr_in(sock s, struct sockaddr_in *sin)
{
    sin->family = AF_INET;
    if (s->type == SOCK_STREAM) {
	tcpsock ts = (tcpsock)s;
	sin->port = ntohs(ts->lw->remote_port);
	sin->address = ntohl(*(u32 *)&ts->lw->remote_ip);
    } else {
	assert(s->type == SOCK_DGRAM);
	udpsock us = (udpsock)s;
	sin->port = ntohs(us->lw->remote_port);
	sin->address = ntohl(*(u32 *)&us->lw->remote_ip);
    }
}

static inline s64 lwip_to_errno(s8 err)
{
    switch (err) {
    case ERR_OK: return 0;
    case ERR_MEM: return -ENOMEM;
    case ERR_BUF: return -ENOMEM;
    case ERR_TIMEOUT: return -ENOMEM;
    case ERR_RTE: return -ENOMEM;
    case ERR_INPROGRESS: return -EAGAIN;
    case ERR_VAL: return -EINVAL;
    case ERR_WOULDBLOCK: return -EAGAIN;
    case ERR_USE: return -EBUSY;
    case ERR_ALREADY: return -EBUSY;
    case ERR_ISCONN: return -EINVAL;
    case ERR_CONN: return -EINVAL;
    case ERR_IF: return -EINVAL;
    case ERR_ABRT: return -EINVAL;
    case ERR_RST: return -EINVAL;
    case ERR_CLSD: return -EPIPE;
    case ERR_ARG: return -EINVAL;
    }
    return -EINVAL;		/* XXX unknown - check return value */
}

static inline void pbuf_consume(struct pbuf *p, u64 length)
{
    p->len -= length;
    p->payload += length;
}

// racy
static CLOSURE_5_1(read_complete, void, sock, thread, void *, u64, boolean, err_t);
static void read_complete(sock s, thread t, void *dest, u64 length, boolean sleeping, err_t lwip_status)
{
    net_debug("sock %d, thread %d, dest %p, len %d, sleeping %d, s->state %d\n",
	      s->fd, t->tid, dest, length, sleeping, s->state);
    if (s->type == SOCK_STREAM && ((tcpsock)s)->state != TCP_SOCK_OPEN) {
       set_syscall_error(t, ENOTCONN);
       goto out;
    }

    if (lwip_status == ERR_OK) {
	// could copy in multiple pbufs just to save them from coming back tomorrow
	struct pbuf *p = queue_peek(s->incoming);
	u64 xfer = 0;
	if (p) {
	    xfer = MIN(length, p->len);
	    runtime_memcpy(dest, p->payload, xfer);
	    pbuf_consume(p, xfer);
	    if (p->len == 0) {
		dequeue(s->incoming);
		pbuf_free(p);
		/* reset a triggered EPOLLIN condition */
		if (queue_length(s->incoming) == 0)
		    notify_dispatch(s);
	    }
	    if (s->type == SOCK_STREAM)
		tcp_recved(((tcpsock)s)->lw, xfer);
	}
	set_syscall_return(t, xfer);
    } else {
	set_syscall_return(t, lwip_to_errno(lwip_status));
    }

  out:
    if (sleeping)
	thread_wakeup(t);
}

static CLOSURE_1_3(socket_read, sysreturn, sock, void *, u64, u64);
static sysreturn socket_read(sock s, void *dest, u64 length, u64 offset)
{
    net_debug("sock %d, type %d, thread %d, dest %p, length %d, offset %d, s->state %d\n",
	      s->fd, s->type, current->tid, dest, length, offset, s->state);
    if (s->type == SOCK_STREAM && ((tcpsock)s)->state != TCP_SOCK_OPEN)
        return set_syscall_error(current, ENOTCONN);

    // xxx - there is a fat race here between checking queue length and posting on the waiting queue
    if (queue_length(s->incoming)) {
        read_complete(s, current, dest, length, false, ERR_OK);
        return sysreturn_value(current);        
    } else {
        // should be an atomic operation
        if (!enqueue(s->waiting, closure(s->h, read_complete, s, current, dest, length, true)))
	    msg_err("waiting queue full\n");
        thread_sleep(current);
    }
    return 0;			/* suppress warning */
}

static CLOSURE_1_3(socket_write, sysreturn, sock, void *, u64, u64);
static sysreturn socket_write(sock s, void *source, u64 length, u64 offset)
{
    net_debug("sock %d, type %d, thread %d, source %p, length %d, offset %d, s->state %d\n",
	      s->fd, s->type, current->tid, source, length, offset, s->state);
    err_t err = ERR_OK;
    if (s->type == SOCK_STREAM) {
	tcpsock ts = (tcpsock)s;
	if (ts->state != TCP_SOCK_OPEN) 		/* XXX maybe defer to lwip for connect state */
	    return set_syscall_error(current, EPIPE);
	err = tcp_write(ts->lw, source, length, TCP_WRITE_FLAG_COPY);
	if (err != ERR_OK)
	    goto out_lwip_err;
	err = tcp_output(ts->lw);
	if (err != ERR_OK)
	    goto out_lwip_err;
    } else if (s->type == SOCK_DGRAM) {
	udpsock us = (udpsock)s;
	// XXX remote address dummy
	if (us->state != UDP_SOCK_BOUND) {
	    msg_err("no peer address set\n");
	    return set_syscall_error(current, EDESTADDRREQ);
	}
	struct pbuf * pbuf = pbuf_alloc(PBUF_TRANSPORT, length, PBUF_RAM);
	if (!pbuf) {
	    msg_err("failed to allocate pbuf for udp_send()\n");
	    return set_syscall_error(current, ENOBUFS);
	}
	runtime_memcpy(pbuf->payload, source, length);
	err = udp_send(us->lw, pbuf);
	if (err != ERR_OK)
	    goto out_lwip_err;
    } else {
	msg_err("socket type %d unsupported\n", s->type);
	return set_syscall_error(current, EINVAL);
    }
    net_debug("completed\n");
    return set_syscall_return(current, length);
  out_lwip_err:
    net_debug("lwip error %d\n", err);
    return set_syscall_return(current, lwip_to_errno(err));
}

static CLOSURE_1_3(socket_check, boolean, sock, u32, u32 *, event_handler);
static boolean socket_check(sock s, u32 eventmask, u32 * last, event_handler eh)
{
    u32 events = socket_poll_events(s);
    u32 masked = events & eventmask;
    net_debug("sock %d, type %d, eventmask %P, events %P\n",
	      s->fd, s->type, eventmask, events);
    if (masked) {
	u32 report = edge_events(masked, eventmask, *last);
	*last = masked;
	return apply(eh, report);
    } else {
	if (!notify_enqueue(s, eventmask, last, eh))
	    msg_err("notify enqueue fail: out of memory\n");
    }
    return true;
}

#define SOCK_QUEUE_LEN 32

static CLOSURE_1_0(socket_close, sysreturn, sock);
static sysreturn socket_close(sock s)
{
    net_debug("sock %d, type %d\n", s->fd, s->type);
    heap h = heap_general(get_kernel_heaps());
    if (s->type == SOCK_STREAM && ((tcpsock)s)->state == TCP_SOCK_OPEN) {
        tcp_close(((tcpsock)s)->lw);
    }
    // xxx - we should really be cleaning this up, but tcp_close apparently
    // doesnt really stop everything synchronously, causing weird things to
    // happen when the stale references to these objects get used. investigate.
    //    deallocate_queue(s->notify, SOCK_QUEUE_LEN);
    //    deallocate_queue(s->waiting, SOCK_QUEUE_LEN);
    //    deallocate_queue(s->incoming, SOCK_QUEUE_LEN);
    //    unix_cache_free(get_unix_heaps(), socket, s);
    return 0;
}

static int allocate_sock(process p, int type, sock * rs)
{
    sock s = unix_cache_alloc(get_unix_heaps(), socket);
    if (s == INVALID_ADDRESS) {
	msg_err("failed to allocate struct sock\n");
	return -ENOMEM;
    }
    file f = (file)s;
    int fd = allocate_fd(p, f);
    if (fd == INVALID_PHYSICAL) {
	unix_cache_free(get_unix_heaps(), socket, f);
	return -EMFILE;
    }
    heap h = heap_general(get_kernel_heaps());
    f->read = closure(h, socket_read, s);
    f->write = closure(h, socket_write, s);
    f->close = closure(h, socket_close, s);
    f->check = closure(h, socket_check, s);
    s->type = type;
    s->p = p;
    s->h = h;
    s->incoming = allocate_queue(h, SOCK_QUEUE_LEN);
    s->waiting = allocate_queue(h, SOCK_QUEUE_LEN);
    list_init(&s->notify);	/* XXX lock init */
    s->fd = fd;
    s->lwip_status = STATUS_OK;
    return fd;
}

static int allocate_tcp_sock(process p, struct tcp_pcb *pcb)
{
    tcpsock ts;
    int fd = allocate_sock(p, SOCK_STREAM, (sock*)&ts);
    if (fd >= 0) {
	ts->lw = pcb;
	ts->state = TCP_SOCK_CREATED;
    }
    return fd;
}

static int allocate_udp_sock(process p, struct udp_pcb * pcb)
{
    udpsock us;
    int fd = allocate_sock(p, SOCK_DGRAM, (sock*)&us);
    if (fd >= 0) {
	us->lw = pcb;
	us->state = UDP_SOCK_CREATED;
    }
    return fd;
}

sysreturn socket(int domain, int type, int protocol)
{
    if (domain != AF_INET)
        return -EAFNOSUPPORT;

    if (type == SOCK_STREAM) {
        struct tcp_pcb *p;
        if (!(p = tcp_new_ip_type(IPADDR_TYPE_ANY)))
            return -ENOMEM;

        int fd = allocate_tcp_sock(current->p, p);
        net_debug("new tcp fd %d, pcb %p\n", fd, p);
        return fd;
    } else if (type == SOCK_DGRAM) {
        struct udp_pcb *p;
        if (!(p = udp_new()))
            return -ENOMEM;

        int fd = allocate_udp_sock(current->p, p);
        net_debug("new udp fd %d, pcb %p\n", fd, p);
        return fd;
    }
    msg_err("unsupported socket type %d\n", type);
    return -EINVAL;
}

static err_t tcp_input_lower(void *z, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
    sock s = z;
    tcpsock ts = (tcpsock)s;
    net_debug("sock %d, pcb %p, buf %p, err %d\n", s->fd, pcb, p, err);

    if (err) {
        // later timmf
        s->lwip_status = timm("lwip error", "%d", err);
    }
    
    if (p) {
        if (!enqueue(s->incoming, p))
	    msg_err("incoming queue full\n");
    } else {
        ts->state = TCP_SOCK_CLOSED;
    }
    wakeup(s, 0);
    return ERR_OK;
}

sysreturn bind(int sockfd, struct sockaddr *addr, socklen_t addrlen)
{
    sock s = resolve_fd(current->p, sockfd);
    net_debug("sock %d, type %d\n", sockfd, s->type);
    if (!addr || addrlen < sizeof(struct sockaddr_in))
	return -EINVAL;
    struct sockaddr_in *sin = (struct sockaddr_in *)addr;
    ip_addr_t ipaddr = IPADDR4_INIT(sin->address);
    err_t err;
    if (s->type == SOCK_STREAM) {
	tcpsock ts = (tcpsock)s;
	if (ts->state == TCP_SOCK_OPEN)
	    return -EINVAL;	/* already bound */
	err = tcp_bind(ts->lw, &ipaddr, ntohs(sin->port));
	if (err == ERR_OK)
	    ts->state = TCP_SOCK_OPEN;
    } else if (s->type == SOCK_DGRAM) {
	udpsock us = (udpsock)s;
	err = udp_bind(us->lw, &ipaddr, ntohs(sin->port));
	if (err == ERR_OK)
	    us->state = UDP_SOCK_BOUND;
    } else {
	msg_err("unsupported socket type %d\n", s->type);
	return -EINVAL;
    }
    return lwip_to_errno(err);
}

void error_handler_tcp(void* arg, err_t err)
{
    sock s = (sock)arg;
    tcpsock ts = (tcpsock)arg;
    lwip_status_handler sp = NULL;
    net_debug("sock %d, err %d\n", s->fd, err);
    if (!s)
	return;
    error_message(s, err);
    if (err != ERR_OK)
	ts->state = TCP_SOCK_UNDEFINED;
    if ((sp = dequeue(s->waiting)))
        apply(sp, err);
}

static CLOSURE_1_1(set_completed_state, void, thread, err_t);
static void set_completed_state(thread th, err_t lwip_status)
{
    net_debug("thread %d, lwip_status %d\n", th->tid, lwip_status);
    set_syscall_return(th, lwip_to_errno(lwip_status));
    thread_wakeup(th);
}

static err_t connect_tcp_complete(void* arg, struct tcp_pcb* tpcb, err_t err)
{
   lwip_status_handler sp = NULL;
   sock s = (sock)arg;
   tcpsock ts = (tcpsock)arg;
   ts->state = TCP_SOCK_OPEN;
   net_debug("sock %d, pcb %p, err %d\n", s->fd, tpcb, err);
   if ((sp = dequeue(s->waiting))) {
	net_debug("... applying status handler %p\n", sp);
        apply(sp, err);
   }
   return ERR_OK;
}

static int connect_tcp(sock s, const ip_addr_t* address, unsigned short port)
{
    tcpsock ts = (tcpsock)s;
    net_debug("sock %d, addr %P, port %d\n", s->fd, address->addr, port);
    if (!enqueue(s->waiting, closure(s->h, set_completed_state, current)))
	msg_err("waiting queue full\n");
    tcp_arg(ts->lw, ts);
    tcp_err(ts->lw, error_handler_tcp);
    ts->state = TCP_SOCK_IN_CONNECTION;
    int err = tcp_connect(ts->lw, address, port, connect_tcp_complete);
    if (ERR_OK != err) {
        return err;
    }
    thread_sleep(current);
    return ERR_OK;
}

sysreturn connect(int sockfd, struct sockaddr * addr, socklen_t addrlen)
{
    int err = ERR_OK;
    sock s = resolve_fd(current->p, sockfd);
    struct sockaddr_in * sin = (struct sockaddr_in*)addr;
    ip_addr_t ipaddr = IPADDR4_INIT(sin->address);
    if (s->type == SOCK_STREAM) {
	tcpsock ts = (tcpsock)s;
	if (ts->state == TCP_SOCK_IN_CONNECTION) {
	    err = ERR_ALREADY;
	} else if (ts->state == TCP_SOCK_OPEN) {
	    err = ERR_ISCONN;
	} else {
	    err = connect_tcp(s, &ipaddr, sin->port);
	}
    } else if (s->type == SOCK_DGRAM) {
	udpsock us = (udpsock)s;
	/* Set remote endpoint */
	err = udp_connect(us->lw, &ipaddr, sin->port);
    } else {
	msg_err("can't connect on socket type %d\n", s->type);
	return -EINVAL;
    }
    return lwip_to_errno(err);
}

static void lwip_tcp_conn_err(void * z, err_t b) {
    sock s = z;
    net_debug("sock %d, err %d\n", s->fd, b);
    error_message(s, b);
    ((tcpsock)s)->state = TCP_SOCK_UNDEFINED;
}

static err_t accept_tcp_from_lwip(void * z, struct tcp_pcb * lw, err_t b)
{
    sock s = z;
    event_handler eh;
    int fd = allocate_tcp_sock(s->p, lw);
    if (fd < 0)
	return ERR_MEM;

    // XXX - what if this has been closed in the meantime?
    // refcnt

    net_debug("new fd %d, pcb %p, err %d\n", fd, lw, b);
    sock sn = vector_get(s->p->files, fd);
    ((tcpsock)sn)->state = TCP_SOCK_OPEN;
    sn->fd = fd;
    tcp_arg(lw, sn);
    tcp_recv(lw, tcp_input_lower);
    tcp_err(lw, lwip_tcp_conn_err);
    if (!enqueue(s->incoming, sn))
	msg_err("incoming queue full\n");

    wakeup(s, b);
    return ERR_OK;
}

sysreturn listen(int sockfd, int backlog)
{
    sock s = resolve_fd(current->p, sockfd);
    if (s->type != SOCK_STREAM)
	return -EOPNOTSUPP;
    net_debug("sock %d, backlog %d\n", sockfd, backlog);
    tcpsock ts = (tcpsock)s;
    ts->lw = tcp_listen_with_backlog(ts->lw, backlog);
    ts->state = TCP_SOCK_LISTENING;
    tcp_arg(ts->lw, ts);
    tcp_accept(ts->lw, accept_tcp_from_lwip);
    tcp_err(ts->lw, lwip_tcp_conn_err);
    return 0;    
}

static CLOSURE_4_1(accept_finish, void, sock, thread, struct sockaddr *, socklen_t *, err_t);
static void accept_finish(sock s, thread target, struct sockaddr *addr, socklen_t *addrlen, err_t lwip_status)
{
    sock sn = dequeue(s->incoming);
    net_debug("sock %d, target thread %d, status %d\n", sn->fd, target->tid, lwip_status);
    if (lwip_status == ERR_OK) {
	remote_sockaddr_in(sn, (struct sockaddr_in *)addr);
	*addrlen = sizeof(struct sockaddr_in);
	set_syscall_return(target, sn->fd);
    } else {
	set_syscall_return(target, lwip_to_errno(lwip_status));
    }
    /* XXX I'm not clear on what the behavior should be if a listen
       socket is used with EPOLLET. For now, let's handle it as if
       it's a regular socket. */
    if (queue_length(s->incoming) == 0)
	notify_dispatch(s);
    thread_wakeup(target);
}

sysreturn accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    sock s = resolve_fd(current->p, sockfd);        
    if (s->type != SOCK_STREAM)
	return -EOPNOTSUPP;
    net_debug("sock %d\n", sockfd);

    if (((tcpsock)s)->state != TCP_SOCK_LISTENING)
	return set_syscall_return(current, -EINVAL);

    // ok, this is a reasonable interlock to build, the dating app
    // it would be nice if we didn't have to sleep and wakeup for the nonblocking case
    if (queue_length(s->incoming)) {
        accept_finish(s, current, addr, addrlen, ERR_OK);
    } else {
        if (!enqueue(s->waiting, closure(s->h, accept_finish, s, current, addr, addrlen)))
	    msg_err("waiting queue full\n");
    }
    thread_sleep(current);
    return 0;			/* suppress warning */
}

sysreturn accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
    return(accept(sockfd, addr, addrlen));
}

sysreturn getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    sock s = resolve_fd(current->p, sockfd);
    struct sockaddr_in sin;
    sin.family = AF_INET;
    if (s->type == SOCK_STREAM) {
	tcpsock ts = (tcpsock)s;
	sin.port = ntohs(ts->lw->local_port);
	sin.address = ntohl(*(u32 *)&(ts->lw->local_ip));
    } else if (s->type == SOCK_DGRAM) {
	udpsock us = (udpsock)s;
	sin.port = ntohs(us->lw->local_port);
	sin.address = ntohl(*(u32 *)&(us->lw->local_ip));
    } else {
	msg_err("not supported for socket type %d\n", s->type);
	return -EINVAL;
    }
    u64 len = MIN(*addrlen, sizeof(sin));
    runtime_memcpy(addr, &sin, len);
    *addrlen = len;
    return 0;
}

sysreturn getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    sock s = resolve_fd(current->p, sockfd);
    struct sockaddr_in sin;
    remote_sockaddr_in(s, &sin);
    u64 len = MIN(*addrlen, sizeof(sin));
    runtime_memcpy(addr, &sin, len);
    *addrlen = len;
    return 0;    
}

sysreturn setsockopt(int sockfd,
                     int level,
                     int optname,
                     void *optval,
                     socklen_t optlen)
{
    //    rprintf("sockopt %d %d\n", sockfd, optname);
    return 0;
}

void register_net_syscalls(void **map)
{
    register_syscall(map, SYS_socket, socket);
    register_syscall(map, SYS_bind, bind);
    register_syscall(map, SYS_listen, listen);
    register_syscall(map, SYS_accept, accept);
    register_syscall(map, SYS_accept4, accept4);    
    register_syscall(map, SYS_connect, connect);
    register_syscall(map, SYS_setsockopt, setsockopt);
    register_syscall(map, SYS_connect, connect);
    register_syscall(map, SYS_getsockname, getsockname);
    register_syscall(map, SYS_getpeername, getpeername);    
}

boolean netsyscall_init(unix_heaps uh)
{
    kernel_heaps kh = (kernel_heaps)uh;
    heap socket_cache = allocate_objcache(heap_general(kh), heap_backed(kh),
					  sizeof(struct sock), PAGESIZE);
    if (socket_cache == INVALID_ADDRESS)
	return false;
    uh->socket_cache = socket_cache;
    return true;
}
