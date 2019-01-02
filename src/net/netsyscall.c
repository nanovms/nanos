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
    union {
	struct {
	    struct tcp_pcb *lw;
	    enum tcp_socket_state state; // half open?
	} tcp;
	struct {
	    struct udp_pcb *lw;
	    enum udp_socket_state state;
	} udp;
    } info;
} *sock;

//#define NETSYSCALL_DEBUG

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
	if (s->info.tcp.state == TCP_SOCK_LISTENING) {
	    return in ? EPOLLIN : 0;
	} else if (s->info.tcp.state == TCP_SOCK_OPEN) {
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
        u32 r = edge_events(masked, n->eventmask, n->last ? *n->last : 0);
        if (n->last)
            *n->last = masked;
	if (r && apply(n->eh, r)) {
	    list_delete(l);
	    deallocate(s->h, n, sizeof(struct notify_entry));
	}
	l = next;
    } while(l != &s->notify);
}

typedef closure_type(lwip_status_handler, void, err_t);

static void wakeup_sock(sock s, err_t err)
{
    lwip_status_handler fstatus;
    net_debug("sock %d\n", s->fd);
    // return status if not handled so someone else can try?
    // shouldnt a close event wake up everyone?
    if ((fstatus = dequeue(s->waiting)))
        apply(fstatus, err);
    else
	notify_dispatch(s);
}

static inline void error_message(sock s, err_t err) {
    switch (err) {
        case ERR_ABRT:
            msg_warn("connection closed on fd %d due to tcp_abort or timer\n", s->fd);
            break;
        case ERR_RST:
            msg_warn("connection closed on fd %d due to remote reset\n", s->fd);
            break;
        default:
            msg_err("fd %d: unknown error %d\n", s->fd, err);
    }
}

static void remote_sockaddr_in(sock s, struct sockaddr_in *sin)
{
    sin->family = AF_INET;
    if (s->type == SOCK_STREAM) {
	struct tcp_pcb * lw = s->info.tcp.lw;
	sin->port = ntohs(lw->remote_port);
	sin->address = ntohl(*(u32 *)&lw->remote_ip);
    } else {
	assert(s->type == SOCK_DGRAM);
	struct udp_pcb * lw = s->info.udp.lw;
	sin->port = ntohs(lw->remote_port);
	sin->address = ntohl(*(u32 *)&lw->remote_ip);
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

struct udp_entry {
    struct pbuf * p;
    u32 raddr;
    u16 rport;
};

/* XXX This needs some more work:
   - address race issues if multiple threads are reading from the same socket
   - make udp_entry something universal regardless of protocol
   - generally refactor / simplify
*/
static CLOSURE_7_1(read_complete, void, sock, thread, void *, u64, boolean,
		   struct sockaddr *, socklen_t *, err_t);
static void read_complete(sock s, thread t, void *dest, u64 length, boolean sleeping,
			  struct sockaddr *src_addr, socklen_t *addrlen,
			  err_t lwip_status)
{
    net_debug("sock %d, thread %d, dest %p, len %d, sleeping %d\n",
	      s->fd, t->tid, dest, length, sleeping);
    if (s->type == SOCK_STREAM && s->info.tcp.state != TCP_SOCK_OPEN) {
       set_syscall_error(t, ENOTCONN);
       goto out;
    }

    if (lwip_status == ERR_OK) {
	u64 xfer = 0;
	struct pbuf * p = 0;
	u32 raddr;
	u16 rport;
	if (s->type == SOCK_STREAM) {
	    /* XXX Take another stab at this for TCP, consuming
	       multiple pbufs in the incoming queue if necessary to
	       fill the request size. This will suffice for now,
	       albeit with less efficiency. */
	    p = queue_peek(s->incoming);
	    raddr = ntohl(*(u32 *)&s->info.tcp.lw->remote_ip);
	    rport = ntohs(s->info.tcp.lw->remote_port);
	} else {
	    assert(s->type == SOCK_DGRAM);
	    struct udp_entry * e = queue_peek(s->incoming);
	    if (e) {
		p = e->p;
		raddr = e->raddr;
		rport = e->rport;
	    }
	}

	if (p) {
	    xfer = MIN(length, p->len);
	    runtime_memcpy(dest, p->payload, xfer);
	    pbuf_consume(p, xfer);

	    if (src_addr) {
		struct sockaddr_in sin;
		sin.family = AF_INET;
		sin.port = rport;
		sin.address = raddr;
		u32 len = MIN(sizeof(sin), *addrlen);
		*addrlen = len;
		runtime_memcpy(src_addr, &sin, len);
	    }

	    if (p->len == 0) {
		void * r = dequeue(s->incoming);
		if (s->type == SOCK_DGRAM)
		    deallocate(s->h, r, sizeof(struct udp_entry));
		pbuf_free(p);
		/* reset a triggered EPOLLIN condition */
		if (queue_length(s->incoming) == 0)
		    notify_dispatch(s);
	    }
	    if (s->type == SOCK_STREAM)
		tcp_recved(s->info.tcp.lw, xfer);
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
    net_debug("sock %d, type %d, thread %d, dest %p, length %d, offset %d\n",
	      s->fd, s->type, current->tid, dest, length, offset);
    if (s->type == SOCK_STREAM && s->info.tcp.state != TCP_SOCK_OPEN)
        return set_syscall_error(current, ENOTCONN);

    // xxx - there is a fat race here between checking queue length and posting on the waiting queue
    if (queue_length(s->incoming)) {
        read_complete(s, current, dest, length, false, 0, 0, ERR_OK);
        return sysreturn_value(current);        
    } else {
        // should be an atomic operation
        if (!enqueue(s->waiting, closure(s->h, read_complete, s, current, dest, length, true, 0, 0)))
	    msg_err("waiting queue full\n");
        thread_sleep(current);
    }
    return 0;			/* suppress warning */
}

static CLOSURE_1_3(socket_write, sysreturn, sock, void *, u64, u64);
static sysreturn socket_write(sock s, void *source, u64 length, u64 offset)
{
    net_debug("sock %d, type %d, thread %d, source %p, length %d, offset %d\n",
	      s->fd, s->type, current->tid, source, length, offset);
    err_t err = ERR_OK;
    if (s->type == SOCK_STREAM) {
	if (s->info.tcp.state != TCP_SOCK_OPEN) 		/* XXX maybe defer to lwip for connect state */
	    return set_syscall_error(current, EPIPE);
	err = tcp_write(s->info.tcp.lw, source, length, TCP_WRITE_FLAG_COPY);
	if (err != ERR_OK)
	    goto out_lwip_err;
	err = tcp_output(s->info.tcp.lw);
	if (err != ERR_OK)
	    goto out_lwip_err;
    } else if (s->type == SOCK_DGRAM) {
	/* XXX check if remote endpoint set? let LWIP check? */
	struct pbuf * pbuf = pbuf_alloc(PBUF_TRANSPORT, length, PBUF_RAM);
	if (!pbuf) {
	    msg_err("failed to allocate pbuf for udp_send()\n");
	    return set_syscall_error(current, ENOBUFS);
	}
	runtime_memcpy(pbuf->payload, source, length);
	err = udp_send(s->info.udp.lw, pbuf);
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
        u32 report = edge_events(masked, eventmask, last ? *last : 0);
        if (last)
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
    //heap h = heap_general(get_kernel_heaps());
    if (s->type == SOCK_STREAM && s->info.tcp.state == TCP_SOCK_OPEN)
        tcp_close(s->info.tcp.lw);
    // xxx - we should really be cleaning this up, but tcp_close apparently
    // doesnt really stop everything synchronously, causing weird things to
    // happen when the stale references to these objects get used. investigate.
    //    deallocate_queue(s->notify, SOCK_QUEUE_LEN);
    //    deallocate_queue(s->waiting, SOCK_QUEUE_LEN);
    //    deallocate_queue(s->incoming, SOCK_QUEUE_LEN);
    //    unix_cache_free(get_unix_heaps(), socket, s);
    return 0;
}

static void udp_input_lower(void *z, struct udp_pcb *pcb, struct pbuf *p,
			    const ip_addr_t * addr, u16 port)
{
    sock s = z;
#ifdef NETSYSCALL_DEBUG
    u8 *n = (u8 *)addr;
#endif
    net_debug("sock %d, pcb %p, buf %p, src addr %d.%d.%d.%d, port %d\n",
	      s->fd, pcb, p, n[0], n[1], n[2], n[3], port);
    assert(pcb == s->info.udp.lw);
    if (p) {
	/* could make a cache if we care to */
	struct udp_entry * e = allocate(s->h, sizeof(*e));
	assert(e != INVALID_ADDRESS);
	e->p = p;
	e->raddr = ip4_addr_get_u32(addr);
	e->rport = port;
	if (!enqueue(s->incoming, e))
	    msg_err("incomding queue full\n");
    } else {
	msg_err("null pbuf\n");
    }
    wakeup_sock(s, 0);
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
    *rs = s;
    return fd;
}

static int allocate_tcp_sock(process p, struct tcp_pcb *pcb)
{
    sock s;
    int fd = allocate_sock(p, SOCK_STREAM, &s);
    if (fd >= 0) {
	s->info.tcp.lw = pcb;
	s->info.tcp.state = TCP_SOCK_CREATED;
    }
    return fd;
}

static int allocate_udp_sock(process p, struct udp_pcb * pcb)
{
    sock s;
    int fd = allocate_sock(p, SOCK_DGRAM, &s);
    if (fd >= 0) {
	s->info.udp.lw = pcb;
	s->info.udp.state = UDP_SOCK_CREATED;
	udp_recv(pcb, udp_input_lower, s);
    }
    return fd;
}

sysreturn socket(int domain, int type, int protocol)
{
    if (domain != AF_INET) {
        msg_warn("domain %d not supported\n", domain);
        return -EAFNOSUPPORT;
    }

    /* check flags */
    int flags = type & ~SOCK_TYPE_MASK;
    if (check_flags_and_clear(flags, SOCK_NONBLOCK))
	msg_warn("non-blocking sockets not yet supported; ignored\n");

    if (check_flags_and_clear(flags, SOCK_CLOEXEC))
	msg_warn("close-on-exec not applicable; ignored\n");

    if ((flags & ~SOCK_TYPE_MASK) != 0)
        msg_warn("unhandled type flags 0x%P\n", flags);

    type &= SOCK_TYPE_MASK;
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
    msg_warn("unsupported socket type %d\n", type);
    return -EINVAL;
}

static err_t tcp_input_lower(void *z, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
    sock s = z;
    net_debug("sock %d, pcb %p, buf %p, err %d\n", s->fd, pcb, p, err);

    if (err) {
        // later timmf
        s->lwip_status = timm("lwip error", "%d", err);
    }

    /* A null pbuf indicates connection closed. */
    if (p) {
        if (!enqueue(s->incoming, p))
	    msg_err("incoming queue full\n");
    } else {
        s->info.tcp.state = TCP_SOCK_CLOSED;
    }

    wakeup_sock(s, 0);
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
	if (s->info.tcp.state == TCP_SOCK_OPEN)
	    return -EINVAL;	/* already bound */
        net_debug("calling tcp_bind, pcb %p, ip %P, port %d\n",
                  s->info.tcp.lw, *(u64*)&ipaddr, ntohs(sin->port));
	err = tcp_bind(s->info.tcp.lw, &ipaddr, ntohs(sin->port));
	if (err == ERR_OK)
	    s->info.tcp.state = TCP_SOCK_OPEN;
    } else if (s->type == SOCK_DGRAM) {
        net_debug("calling udp_bind, pcb %p, ip %P, port %d\n",
                  s->info.udp.lw, *(u32*)&ipaddr, ntohs(sin->port));
	err = udp_bind(s->info.udp.lw, &ipaddr, ntohs(sin->port));
    } else {
	msg_warn("unsupported socket type %d\n", s->type);
	return -EINVAL;
    }
    return lwip_to_errno(err);
}

void error_handler_tcp(void* arg, err_t err)
{
    sock s = (sock)arg;
    lwip_status_handler sp = NULL;
    net_debug("sock %d, err %d\n", s->fd, err);
    if (!s)
	return;
    error_message(s, err);
    if (err != ERR_OK)
	s->info.tcp.state = TCP_SOCK_UNDEFINED;
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
   s->info.tcp.state = TCP_SOCK_OPEN;
   net_debug("sock %d, pcb %p, err %d\n", s->fd, tpcb, err);
   if ((sp = dequeue(s->waiting))) {
	net_debug("... applying status handler %p\n", sp);
        apply(sp, err);
   }
   return ERR_OK;
}

static inline int connect_tcp(sock s, const ip_addr_t* address, unsigned short port)
{
    net_debug("sock %d, addr %P, port %d\n", s->fd, address->addr, port);
    if (!enqueue(s->waiting, closure(s->h, set_completed_state, current)))
	msg_err("waiting queue full\n");
    struct tcp_pcb * lw = s->info.tcp.lw;
    tcp_arg(lw, s);
    tcp_err(lw, error_handler_tcp);
    s->info.tcp.state = TCP_SOCK_IN_CONNECTION;
    int err = tcp_connect(lw, address, port, connect_tcp_complete);
    if (err == ERR_OK)
	thread_sleep(current);
    return err;
}

sysreturn connect(int sockfd, struct sockaddr * addr, socklen_t addrlen)
{
    int err = ERR_OK;
    sock s = resolve_fd(current->p, sockfd);
    struct sockaddr_in * sin = (struct sockaddr_in*)addr;
    ip_addr_t ipaddr = IPADDR4_INIT(sin->address);
    if (s->type == SOCK_STREAM) {
	if (s->info.tcp.state == TCP_SOCK_IN_CONNECTION) {
	    err = ERR_ALREADY;
	} else if (s->info.tcp.state == TCP_SOCK_OPEN) {
	    err = ERR_ISCONN;
	} else if (s->info.tcp.state == TCP_SOCK_LISTENING) {
            msg_warn("attempt to connect on listening socket fd = %d; ignored\n", sockfd);
	    err = ERR_ARG;
	}
    } else if (s->type == SOCK_DGRAM) {
	/* Set remote endpoint */
	err = udp_connect(s->info.udp.lw, &ipaddr, sin->port);
    } else {
	msg_err("can't connect on socket type %d\n", s->type);
	return -EINVAL;
    }
    return lwip_to_errno(err);
}

#define MSG_OOB         0x00000001
#define MSG_DONTROUTE   0x00000004
#define MSG_PROBE       0x00000010
#define MSG_TRUNC       0x00000020
#define MSG_DONTWAIT    0x00000040
#define MSG_EOR         0x00000080
#define MSG_CONFIRM     0x00000800
#define MSG_NOSIGNAL    0x00004000
#define MSG_MORE        0x00008000

sysreturn sendto(int sockfd, void * buf, u64 len, int flags,
		 struct sockaddr *dest_addr, socklen_t addrlen)
{
    int err = ERR_OK;
    sock s = resolve_fd(current->p, sockfd);
    net_debug("sendto %d, buf %p, len %d, flags %P, dest_addr %p, addrlen %d\n",
              sockfd, buf, len, flags, dest_addr, addrlen);

    /* Process flags */
    if (flags & MSG_CONFIRM)
	msg_warn("MSG_CONFIRM unimplemented; ignored\n");

    if (flags & MSG_DONTROUTE)
	msg_warn("MSG_DONTROUTE unimplemented; ignored\n");

    if (flags & MSG_DONTWAIT)
	msg_warn("MSG_DONTWAIT unimplemented; ignored\n");

    if (flags & MSG_EOR) {
	msg_warn("MSG_EOR unimplemented\n");
	return -EOPNOTSUPP;
    }

    if (flags & MSG_MORE)
	msg_warn("MSG_MORE unimplemented; ignored\n");

    if (flags & MSG_NOSIGNAL)
	msg_warn("MSG_NOSIGNAL unimplemented; ignored\n");

    if (flags & MSG_OOB)
	msg_warn("MSG_OOB unimplemented; ignored\n");

    /* Ignore dest if TCP */
    if (s->type == SOCK_DGRAM && dest_addr) {
	struct sockaddr_in * sin = (struct sockaddr_in *)dest_addr;
	ip_addr_t ipaddr = IPADDR4_INIT(sin->address);
	if (addrlen < sizeof(*sin))
	    return -EINVAL;
	err = udp_connect(s->info.udp.lw, &ipaddr, sin->port);
        if (err != ERR_OK) {
            msg_err("udp_connect failed: %s\n", lwip_strerr(err));
            return lwip_to_errno(err);
        }
    }

    return socket_write(s, buf, len, 0);
}

sysreturn recvfrom(int sockfd, void * buf, u64 len, int flags,
		   struct sockaddr *src_addr, socklen_t *addrlen)
{
    sock s = resolve_fd(current->p, sockfd);
    net_debug("sock %d, type %d, thread %d, buf %p, len %d\n",
	      s->fd, s->type, current->tid, buf, len);
    if (s->type == SOCK_STREAM && s->info.tcp.state != TCP_SOCK_OPEN)
        return set_syscall_error(current, ENOTCONN);
    /* XXX see above about race...methinks we should just dequeue and pass the entry
       as is...and also consolidate the entry between tcp and udp */
    if (queue_length(s->incoming)) {
        read_complete(s, current, buf, len, false, src_addr, addrlen, ERR_OK);
        return sysreturn_value(current);
    } else {
        // should be an atomic operation
        if (!enqueue(s->waiting, closure(s->h, read_complete, s, current, buf,
					 len, true, src_addr, addrlen)))
	    msg_err("waiting queue full\n");
        thread_sleep(current);
    }
    return 0;			/* suppress warning */
}

static void lwip_tcp_conn_err(void * z, err_t b) {
    sock s = z;
    net_debug("sock %d, err %d\n", s->fd, b);
    error_message(s, b);
    s->info.tcp.state = TCP_SOCK_UNDEFINED;
}

static err_t accept_tcp_from_lwip(void * z, struct tcp_pcb * lw, err_t b)
{
    sock s = z;
    int fd = allocate_tcp_sock(s->p, lw);
    if (fd < 0)
	return ERR_MEM;

    // XXX - what if this has been closed in the meantime?
    // refcnt

    net_debug("new fd %d, pcb %p, err %d\n", fd, lw, b);
    sock sn = vector_get(s->p->files, fd);
    sn->info.tcp.state = TCP_SOCK_OPEN;
    sn->fd = fd;
    tcp_arg(lw, sn);
    tcp_recv(lw, tcp_input_lower);
    tcp_err(lw, lwip_tcp_conn_err);
    if (!enqueue(s->incoming, sn))
	msg_err("incoming queue full\n");

    wakeup_sock(s, b);
    return ERR_OK;
}

sysreturn listen(int sockfd, int backlog)
{
    sock s = resolve_fd(current->p, sockfd);
    if (s->type != SOCK_STREAM)
	return -EOPNOTSUPP;
    net_debug("sock %d, backlog %d\n", sockfd, backlog);
    struct tcp_pcb * lw = tcp_listen_with_backlog(s->info.tcp.lw, backlog);
    s->info.tcp.lw = lw;
    s->info.tcp.state = TCP_SOCK_LISTENING;
    tcp_arg(lw, s);
    tcp_accept(lw, accept_tcp_from_lwip);
    tcp_err(lw, lwip_tcp_conn_err);
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

    if (s->info.tcp.state != TCP_SOCK_LISTENING)
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
	sin.port = ntohs(s->info.tcp.lw->local_port);
	sin.address = ip4_addr_get_u32(&s->info.tcp.lw->local_ip);
    } else if (s->type == SOCK_DGRAM) {
	sin.port = ntohs(s->info.udp.lw->local_port);
	sin.address = ip4_addr_get_u32(&s->info.udp.lw->local_ip);
    } else {
	msg_warn("not supported for socket type %d\n", s->type);
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
    msg_warn("unimplemented: fd %d, level %d, optname %d\n",
	    sockfd, level, optname);
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
    register_syscall(map, SYS_sendto, sendto);
    register_syscall(map, SYS_recvfrom, recvfrom);
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
