/* TODO

   - consider switching on blockq timeout
   - check err handling of tcp_output
   - do udp tx bottom half
*/

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
    u8 sa_data[14];
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
    TCP_SOCK_LISTENING = 4,
};

enum udp_socket_state {
    UDP_SOCK_UNDEFINED = 0,
    UDP_SOCK_CREATED = 1,
};

typedef closure_type(lwip_status_handler, void, err_t);

typedef struct sock {
    struct fdesc f;              /* must be first */
    int type;
    process p;
    heap h;
    blockq rxbq;                 /* for incoming queue */
    queue incoming;
    blockq txbq;                 /* for lwip protocol tx buffer */
    notify_set ns;
    // the notion is that 'waiters' should take priority    
    int fd;
    err_t lwip_error;           /* lwIP error code; ERR_OK if normal */
    union {
	struct {
	    struct tcp_pcb *lw;
	    enum tcp_socket_state state; // half open?
            lwip_status_handler connect_bh;
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
	    return (in ? EPOLLIN | EPOLLRDNORM : 0) |
                (s->info.tcp.lw->state == ESTABLISHED ?
                (tcp_sndbuf(s->info.tcp.lw) ? EPOLLOUT | EPOLLWRNORM : 0) :
                EPOLLIN | EPOLLHUP);
	} else {
	    return 0;
	}
    }
    assert(s->type == SOCK_DGRAM);
    return (in ? EPOLLIN | EPOLLRDNORM : 0) | EPOLLOUT | EPOLLWRNORM;
}

static inline void notify_sock(sock s)
{
    u32 events = socket_poll_events(s);
    net_debug("sock %d, events %lx\n", s->fd, events);
    notify_dispatch(s->ns, events);
}

/* May be called from irq/softirq */
static void set_lwip_error(sock s, err_t err)
{
    /* XXX lock / atomic / barrier */
    s->lwip_error = err;
}

static err_t get_lwip_error(sock s)
{
    /* XXX lock / atomic / barrier */
    return s->lwip_error;
}

#define WAKEUP_SOCK_RX          0x00000001
#define WAKEUP_SOCK_TX          0x00000002
#define WAKEUP_SOCK_EXCEPT      0x00000004 /* flush, and thus implies rx & tx */

static void wakeup_sock(sock s, int flags)
{
    net_debug("sock %d, flags %d\n", s->fd, flags);

    /* exception leads to release of all blocking requests */
    if ((flags & WAKEUP_SOCK_EXCEPT)) {
        blockq_flush(s->rxbq);
        blockq_flush(s->txbq);
    } else {
        if ((flags & WAKEUP_SOCK_RX))
            blockq_wake_one(s->rxbq);

        if ((flags & WAKEUP_SOCK_TX))
            blockq_wake_one(s->txbq);
    }
    notify_sock(s);
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
	sin->address = ip4_addr_get_u32(&lw->remote_ip);
    } else {
	assert(s->type == SOCK_DGRAM);
	struct udp_pcb * lw = s->info.udp.lw;
	sin->port = ntohs(lw->remote_port);
	sin->address = ip4_addr_get_u32(&lw->remote_ip);
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
    struct pbuf * pbuf;
    u32 raddr;
    u16 rport;
};

/* called with corresponding blockq lock held */
static CLOSURE_6_1(sock_read_bh, sysreturn, sock, thread, void *, u64,
		   struct sockaddr *, socklen_t *, boolean);
static sysreturn sock_read_bh(sock s, thread t, void *dest, u64 length,
                              struct sockaddr *src_addr, socklen_t *addrlen,
                              boolean blocked)
{
    sysreturn rv = 0;
    err_t err = get_lwip_error(s);
    net_debug("sock %d, thread %ld, dest %p, len %ld, blocked %d, lwip err %d\n",
	      s->fd, t->tid, dest, length, blocked, err);
    assert(length > 0);
    assert(s->type == SOCK_STREAM || s->type == SOCK_DGRAM);

    if (s->type == SOCK_STREAM && s->info.tcp.state != TCP_SOCK_OPEN) {
        rv = -ENOTCONN;         /* XXX or 0? */
        goto out;
    }

    if (err != ERR_OK) {
        rv = lwip_to_errno(err);
        goto out;
    }

    /* check if we actually have data */
    void * p = queue_peek(s->incoming);
    if (!p) {
        if (s->type == SOCK_STREAM && s->info.tcp.lw->state != ESTABLISHED) {
            rv = 0;
            goto out;
        }
        if ((s->f.flags & SOCK_NONBLOCK)) {
            rv = -EAGAIN;
            goto out;
        }
        return infinity;               /* back to chewing more cud */
    }

    if (src_addr) {
        struct sockaddr sa;
        zero(&sa, sizeof(sa));
        struct sockaddr_in * sin = (struct sockaddr_in *)&sa;
        sin->family = AF_INET;
        if (s->type == SOCK_STREAM) {
	    sin->address = ip4_addr_get_u32(&s->info.tcp.lw->remote_ip);
	    sin->port = htons(s->info.tcp.lw->remote_port);
        } else {
            struct udp_entry * e = p;
            sin->address = e->raddr;
            sin->port = htons(e->rport);
        }
        u32 len = MIN(sizeof(struct sockaddr), *addrlen);
        *addrlen = sizeof(struct sockaddr);
        runtime_memcpy(src_addr, sin, len);
    }

    u64 xfer_total = 0;

    /* TCP: consume multiple buffers to fill request, if available. */
    do {
        struct pbuf * pbuf = s->type == SOCK_STREAM ? (struct pbuf *)p :
            ((struct udp_entry *)p)->pbuf;
        assert(pbuf->len > 0);

        u64 xfer = MIN(length, pbuf->len);
        runtime_memcpy(dest, pbuf->payload, xfer);
        pbuf_consume(pbuf, xfer);
        length -= xfer;
        xfer_total += xfer;
        dest = (char *) dest + xfer;

        if (pbuf->len == 0) {
            assert(dequeue(s->incoming) == p);
            if (s->type == SOCK_DGRAM)
                deallocate(s->h, p, sizeof(struct udp_entry));
            pbuf_free(pbuf);
            p = queue_peek(s->incoming);
            if (!p)
                notify_sock(s); /* reset a triggered EPOLLIN condition */
        }

        if (s->type == SOCK_STREAM)
            tcp_recved(s->info.tcp.lw, xfer);
    } while(s->type == SOCK_STREAM && length > 0 && p); /* XXX simplify expression */

    rv = xfer_total;
  out:
    if (blocked)
        thread_wakeup(t);
    net_debug("   returning %ld\n", rv);
    return set_syscall_return(t, rv);
}

static CLOSURE_1_3(socket_read, sysreturn, sock, void *, u64, u64);
static sysreturn socket_read(sock s, void *dest, u64 length, u64 offset)
{
    net_debug("sock %d, type %d, thread %ld, dest %p, length %ld, offset %ld\n",
	      s->fd, s->type, current->tid, dest, length, offset);
    if (s->type == SOCK_STREAM && s->info.tcp.state != TCP_SOCK_OPEN)
        return set_syscall_error(current, ENOTCONN);

    blockq_action ba = closure(s->h, sock_read_bh, s, current, dest, length, 0, 0);
    sysreturn rv = blockq_check(s->rxbq, current, ba);

    /* We didn't block... */
    if (rv != infinity)
        return rv;              /* error or success: return as-is */

    /* XXX ideally we could just prevent this case if we had growing
       queues... for now bark and return EAGAIN

       we could mess around with making a timer or something, but it
       would just be easier to make queues growable */

    msg_err("thread %ld unable to block; queue full\n", current->tid);
    return set_syscall_error(current, EAGAIN);
}

static CLOSURE_4_1(socket_write_tcp_bh, sysreturn, sock, thread, void *, u64, boolean);
static sysreturn socket_write_tcp_bh(sock s, thread t, void * buf, u64 remain, boolean blocked)
{
    sysreturn rv = 0;
    err_t err = get_lwip_error(s);
    net_debug("fd %d, thread %ld, buf %p, remain %ld, blocked %d, lwip err %d\n",
              s->fd, t->tid, buf, remain, blocked, err);
    assert(remain > 0);

    if (err != ERR_OK) {
        rv = lwip_to_errno(err);
        goto out;
    }

    if (s->type == SOCK_STREAM && s->info.tcp.state != TCP_SOCK_OPEN) {
        rv = -ENOTCONN;
        goto out;
    }

    /* Note that the actual transmit window size is truncated to 16
       bits here (and tcp_write() doesn't accept more than 2^16
       anyway), so even if we have a large transmit window due to
       LWIP_WND_SCALE, we still can't write more than 2^16. Sigh... */
    u64 avail = tcp_sndbuf(s->info.tcp.lw);
    if (avail == 0) {
      full:
        if (!blocked && (s->f.flags & SOCK_NONBLOCK)) {
            net_debug(" send buf full and non-blocking, return EAGAIN\n");
            rv = -EAGAIN;
            goto out;
        } else {
            net_debug(" send buf full, sleep\n");
            return infinity;           /* block again */
        }
    }

    /* Figure actual length and flags */
    u64 n;
    u8 apiflags = TCP_WRITE_FLAG_COPY;
    if (avail < remain) {
        n = avail;
        apiflags |= TCP_WRITE_FLAG_MORE;
    } else {
        n = remain;
    }

    /* XXX need to pore over lwIP error conditions here */
    err = tcp_write(s->info.tcp.lw, buf, n, apiflags);
    if (err == ERR_OK) {
        /* XXX prob add a flag to determine whether to continuously
           post data, e.g. if used by send/sendto... */
        err = tcp_output(s->info.tcp.lw);
        if (err == ERR_OK) {
            net_debug(" tcp_write and tcp_output successful for %ld bytes\n", n);
            rv = n;
            if (n == avail) {
                notify_sock(s); /* reset a triggered EPOLLOUT condition */
            }
        } else {
            net_debug(" tcp_output() lwip error: %d\n", err);
            rv = lwip_to_errno(err);
            /* XXX map error to socket tcp state */
        }
    } else if (err == ERR_MEM) {
        /* XXX some ambiguity in lwIP - investigate */
        net_debug(" tcp_write() returned ERR_MEM\n");
        goto full;
    } else {
        net_debug(" tcp_write() lwip error: %d\n", err);
        rv = lwip_to_errno(err);
    }
  out:
    if (blocked)
        thread_wakeup(t);

    return set_syscall_return(t, rv);
}

static CLOSURE_1_3(socket_write, sysreturn, sock, void *, u64, u64);
static sysreturn socket_write(sock s, void *source, u64 length, u64 offset)
{
    net_debug("sock %d, type %d, thread %ld, source %p, length %ld, offset %ld\n",
	      s->fd, s->type, current->tid, source, length, offset);
    err_t err = ERR_OK;
    if (s->type == SOCK_STREAM) {
	if (s->info.tcp.state != TCP_SOCK_OPEN) 		/* XXX maybe defer to lwip for connect state */
	    return set_syscall_error(current, EPIPE);
        if (length == 0)
            return set_syscall_return(current, 0);
        blockq_action ba = closure(s->h, socket_write_tcp_bh, s, current, source, length);
        sysreturn rv = blockq_check(s->txbq, current, ba);
        if (rv != infinity)
            return rv;          /* error or success; return as-is */
        /* XXX again, need to just fix the queue stuff */
        msg_err("thread %ld unable to block; queue full\n", current->tid);
        return set_syscall_error(current, EAGAIN); /* bogus */
    } else if (s->type == SOCK_DGRAM) {
        /* XXX check how much we can queue, maybe make udp bh */
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
    u32 report = edge_events(events, eventmask, last);
    net_debug("sock %d, type %d, eventmask %x, last %d, events %x, report %x\n",
	      s->fd, s->type, eventmask, last ? *last : -1, events, report);
    if (report) {
        if (apply(eh, report)) {
            if (last)
                *last = events & eventmask;
            return true;
        } else {
            return false;
        }
    } else {
	if (!notify_add(s->ns, eventmask, last, eh))
	    msg_err("notify enqueue fail: out of memory\n");
    }
    return true;
}

#define SOCK_QUEUE_LEN 128

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
	e->pbuf = p;
	e->raddr = ip4_addr_get_u32(addr);
	e->rport = port;
	if (!enqueue(s->incoming, e))
	    msg_err("incoming queue full\n");
    } else {
	msg_err("null pbuf\n");
    }
    wakeup_sock(s, WAKEUP_SOCK_RX);
}

#define SOCK_BLOCKQ_LEN 32
static int allocate_sock(process p, int type, u32 flags, sock * rs)
{
    sock s = unix_cache_alloc(get_unix_heaps(), socket);
    if (s == INVALID_ADDRESS) {
	msg_err("failed to allocate struct sock\n");
	return -ENOMEM;
    }
    int fd = allocate_fd(p, s);
    if (fd == INVALID_PHYSICAL) {
	unix_cache_free(get_unix_heaps(), socket, s);
	return -EMFILE;
    }
    fdesc_init(&s->f, FDESC_TYPE_SOCKET);
    heap h = heap_general(get_kernel_heaps());
    s->f.read = closure(h, socket_read, s);
    s->f.write = closure(h, socket_write, s);
    s->f.close = closure(h, socket_close, s);
    s->f.check = closure(h, socket_check, s);
    s->f.flags = flags;
    s->type = type;
    s->p = p;
    s->h = h;
    s->incoming = allocate_queue(h, SOCK_QUEUE_LEN);
    s->rxbq = allocate_blockq(h, "sock receive", SOCK_BLOCKQ_LEN, 0 /* XXX */);
    s->txbq = allocate_blockq(h, "sock transmit", SOCK_BLOCKQ_LEN, 0 /* XXX */);
    s->ns = allocate_notify_set(h);
    s->fd = fd;
    set_lwip_error(s, ERR_OK);
    *rs = s;
    return fd;
}

static int allocate_tcp_sock(process p, struct tcp_pcb *pcb, u32 flags)
{
    sock s;
    int fd = allocate_sock(p, SOCK_STREAM, flags, &s);
    if (fd >= 0) {
	s->info.tcp.lw = pcb;
	s->info.tcp.state = TCP_SOCK_CREATED;
        s->info.tcp.connect_bh = 0;
    }
    return fd;
}

static int allocate_udp_sock(process p, struct udp_pcb * pcb, u32 flags)
{
    sock s;
    int fd = allocate_sock(p, SOCK_DGRAM, flags, &s);
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
    boolean nonblock = false;
    if (check_flags_and_clear(flags, SOCK_NONBLOCK))
        nonblock = true;

    if (check_flags_and_clear(flags, SOCK_CLOEXEC))
	msg_warn("close-on-exec not applicable; ignored\n");

    if ((flags & ~SOCK_TYPE_MASK) != 0)
        msg_warn("unhandled type flags 0x%x\n", flags);

    type &= SOCK_TYPE_MASK;
    if (type == SOCK_STREAM) {
        struct tcp_pcb *p;
        if (!(p = tcp_new_ip_type(IPADDR_TYPE_ANY)))
            return -ENOMEM;

        int fd = allocate_tcp_sock(current->p, p, nonblock ? SOCK_NONBLOCK : 0);
        net_debug("new tcp fd %d, pcb %p\n", fd, p);
        return fd;
    } else if (type == SOCK_DGRAM) {
        struct udp_pcb *p;
        if (!(p = udp_new()))
            return -ENOMEM;

        int fd = allocate_udp_sock(current->p, p, nonblock ? SOCK_NONBLOCK : 0);
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

    if (err != ERR_OK) {
        /* shouldn't happen according to lwIP sources; just report */
        msg_err("Unexpected error from lwIP: %d\n", err);
    }

    /* A null pbuf indicates connection closed. */
    if (p) {
        if (!enqueue(s->incoming, p)) {
	    msg_err("incoming queue full\n");
            return ERR_BUF;     /* XXX verify */
        }
        wakeup_sock(s, WAKEUP_SOCK_RX);
    } else {
        wakeup_sock(s, WAKEUP_SOCK_EXCEPT);
    }

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
        net_debug("calling tcp_bind, pcb %p, ip %x, port %d\n",
                  s->info.tcp.lw, *(u32*)&ipaddr, ntohs(sin->port));
	err = tcp_bind(s->info.tcp.lw, &ipaddr, ntohs(sin->port));
	if (err == ERR_OK)
	    s->info.tcp.state = TCP_SOCK_OPEN;
    } else if (s->type == SOCK_DGRAM) {
        net_debug("calling udp_bind, pcb %p, ip %x, port %d\n",
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
    net_debug("sock %d, err %d\n", s->fd, err);
    if (!s || err == ERR_OK)
	return;

    /* Warning: Don't try to use the pcb. According to lwIP docs, it
       may have been deallocated already. */
    s->info.tcp.lw = 0;

    error_message(s, err); // XXX nuke this

    if (err == ERR_ABRT ||
        err == ERR_RST ||
        err == ERR_CLSD) {
        set_lwip_error(s, err);
        wakeup_sock(s, WAKEUP_SOCK_EXCEPT);
    } else {
        /* We have no context for any other errors at this point,
           so bark and ignore... */
        msg_err("unhandled lwIP error %d\n", err);
    }
}

static void lwip_tcp_conn_err(void * z, err_t b) {
    sock s = z;
    net_debug("sock %d, err %d\n", s->fd, b);
    error_message(s, b);
    s->info.tcp.state = TCP_SOCK_UNDEFINED;
    set_lwip_error(s, b);
    wakeup_sock(s, WAKEUP_SOCK_EXCEPT);
}

static err_t lwip_tcp_sent(void * arg, struct tcp_pcb * pcb, u16 len)
{
    sock s = (sock)arg;
    net_debug("fd %d, pcb %p, len %d\n", s->fd, pcb, len);
    wakeup_sock(s, WAKEUP_SOCK_TX);
    return ERR_OK;
}

static CLOSURE_1_1(connect_tcp_bh, void, thread, err_t);
static void connect_tcp_bh(thread t, err_t lwip_status)
{
    net_debug("thread %ld, lwip_status %d\n", t->tid, lwip_status);
    set_syscall_return(t, lwip_to_errno(lwip_status));
    thread_wakeup(t);
}

static err_t connect_tcp_complete(void* arg, struct tcp_pcb* tpcb, err_t err)
{
   sock s = (sock)arg;
   net_debug("sock %d, pcb %p, err %d\n", s->fd, tpcb, err);
   assert(s->info.tcp.state == TCP_SOCK_IN_CONNECTION);
   assert(s->info.tcp.connect_bh);
   s->info.tcp.state = TCP_SOCK_OPEN;
   apply(s->info.tcp.connect_bh, err);
   s->info.tcp.connect_bh = 0;
   return ERR_OK;
}

/* XXX move to blockq */
static inline int connect_tcp(sock s, const ip_addr_t* address, unsigned short port)
{
    net_debug("sock %d, addr %x, port %d\n", s->fd, address->addr, port);
    lwip_status_handler bh = closure(s->h, connect_tcp_bh, current);
    struct tcp_pcb * lw = s->info.tcp.lw;
    tcp_arg(lw, s);
    tcp_recv(lw, tcp_input_lower);
    tcp_err(lw, error_handler_tcp);
    tcp_sent(lw, lwip_tcp_sent);
    s->info.tcp.state = TCP_SOCK_IN_CONNECTION;
    set_lwip_error(s, ERR_OK);
    assert(s->info.tcp.connect_bh == 0);
    s->info.tcp.connect_bh = bh;
    int err = tcp_connect(lw, address, port, connect_tcp_complete);
    if (err == ERR_OK)
	thread_sleep(current);
    return err;
}

sysreturn connect(int sockfd, struct sockaddr * addr, socklen_t addrlen)
{
    int err = ERR_OK;
    sock s = resolve_fd(current->p, sockfd);
    if (!addr || addrlen < sizeof(struct sockaddr_in)) {
        return -EINVAL;
    }
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
        } else {
            err = connect_tcp(s, &ipaddr, ntohs(sin->port));
        }
    } else if (s->type == SOCK_DGRAM) {
	/* Set remote endpoint */
	err = udp_connect(s->info.udp.lw, &ipaddr, ntohs(sin->port));
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
    net_debug("sendto %d, buf %p, len %ld, flags %x, dest_addr %p, addrlen %d\n",
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
	err = udp_connect(s->info.udp.lw, &ipaddr, ntohs(sin->port));
        if (err != ERR_OK) {
            msg_err("udp_connect failed: %d\n", err);
            return lwip_to_errno(err);
        }
    }

    return socket_write(s, buf, len, 0);
}

sysreturn recvfrom(int sockfd, void * buf, u64 len, int flags,
		   struct sockaddr *src_addr, socklen_t *addrlen)
{
    sock s = resolve_fd(current->p, sockfd);
    net_debug("sock %d, type %d, thread %ld, buf %p, len %ld\n",
	      s->fd, s->type, current->tid, buf, len);
    if (s->type == SOCK_STREAM && s->info.tcp.state != TCP_SOCK_OPEN)
        return set_syscall_error(current, ENOTCONN);

    if (len == 0)
        return 0;

    blockq_action ba = closure(s->h, sock_read_bh, s, current, buf, len, src_addr, addrlen);
    sysreturn rv = blockq_check(s->rxbq, current, ba);

    /* We didn't block... */
    if (rv != infinity)
        return rv;              /* error or success: return as-is */

    /* XXX same crap */
    msg_err("thread %d unable to block; queue full\n", current->tid);
    return set_syscall_error(current, EAGAIN);
}

static err_t accept_tcp_from_lwip(void * z, struct tcp_pcb * lw, err_t err)
{
    sock s = z;

    if (err == ERR_MEM) {
        set_lwip_error(s, err);
        wakeup_sock(s, WAKEUP_SOCK_EXCEPT);
        return err;               /* lwIP doesn't care */
    }

    /* XXX such a thing as nonblock inherited from listen socket? */
    int fd = allocate_tcp_sock(s->p, lw, 0);
    if (fd < 0)
	return ERR_MEM;

    // XXX - what if this has been closed in the meantime?
    // refcnt

    net_debug("new fd %d, pcb %p\n", fd, lw);
    sock sn = vector_get(s->p->files, fd);
    sn->info.tcp.state = TCP_SOCK_OPEN;
    sn->fd = fd;
    set_lwip_error(s, ERR_OK);
    tcp_arg(lw, sn);
    tcp_recv(lw, tcp_input_lower);
    tcp_err(lw, lwip_tcp_conn_err);
    tcp_sent(lw, lwip_tcp_sent);
    if (!enqueue(s->incoming, sn)) {
        msg_err("queue overrun; shouldn't happen with lwIP listen backlog\n");
        return ERR_BUF;         /* lwIP will do tcp_abort */
    }

    /* consume a slot in the lwIP listen backlog */
    tcp_backlog_delayed(lw);

    wakeup_sock(s, WAKEUP_SOCK_RX);
    return ERR_OK;
}

sysreturn listen(int sockfd, int backlog)
{
    sock s = resolve_fd(current->p, sockfd);
    if (s->type != SOCK_STREAM)
	return -EOPNOTSUPP;
    backlog = MAX(backlog, SOCK_QUEUE_LEN);
    net_debug("sock %d, backlog %d\n", sockfd, backlog);
    struct tcp_pcb * lw = tcp_listen_with_backlog(s->info.tcp.lw, backlog);
    s->info.tcp.lw = lw;
    s->info.tcp.state = TCP_SOCK_LISTENING;
    set_lwip_error(s, ERR_OK);
    tcp_arg(lw, s);
    tcp_accept(lw, accept_tcp_from_lwip);
    tcp_err(lw, lwip_tcp_conn_err);
    return 0;    
}

static CLOSURE_5_1(accept_bh, sysreturn, sock, thread, struct sockaddr *, socklen_t *, int, boolean);
static sysreturn accept_bh(sock s, thread t, struct sockaddr *addr, socklen_t *addrlen, int flags, boolean blocked)
{
    sysreturn rv = 0;
    err_t err = get_lwip_error(s);
    net_debug("sock %d, target thread %ld, lwip err %d\n", s->fd, t->tid, err);

    if (err != ERR_OK) {
        rv = lwip_to_errno(err);
        goto out;
    }

    sock sn = dequeue(s->incoming);
    if (!sn) {
        if (s->f.flags & SOCK_NONBLOCK) {
            rv = -EAGAIN;
            goto out;
        }
        return infinity;               /* block */
    }

    net_debug("child sock %d\n", sn->fd);

    sn->f.flags = flags;
    if (addr)
        remote_sockaddr_in(sn, (struct sockaddr_in *)addr);
    if (addrlen)
        *addrlen = sizeof(struct sockaddr);

    /* XXX Check what the behavior should be if a listen socket is
       used with EPOLLET. For now, let's handle it as if it's a
       regular socket. */
    if (queue_length(s->incoming) == 0)
	notify_sock(s);

    /* release slot in lwIP listen backlog */
    tcp_backlog_accepted(sn->info.tcp.lw);

    rv = sn->fd;
  out:
    if (blocked)
        thread_wakeup(t);

    return set_syscall_return(t, rv);
}

sysreturn accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
    sock s = resolve_fd(current->p, sockfd);        
    if (s->type != SOCK_STREAM)
	return -EOPNOTSUPP;
    net_debug("sock %d, addr %p, addrlen %p, flags %x\n", sockfd, addr, addrlen, flags);

    if ((s->info.tcp.state != TCP_SOCK_LISTENING) ||
            (flags & ~(SOCK_NONBLOCK | SOCK_CLOEXEC)))
	return set_syscall_error(current, EINVAL);

    blockq_action ba = closure(s->h, accept_bh, s, current, addr, addrlen, flags);
    sysreturn rv = blockq_check(s->rxbq, current, ba);

    /* We didn't block... */
    if (rv != infinity)
        return rv;              /* error or success: return as-is */

    /* XXX */
    msg_err("thread %ld unable to block; queue full\n", current->tid);
    return set_syscall_error(current, EAGAIN);
}

sysreturn accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    return accept4(sockfd, addr, addrlen, 0);
}

sysreturn getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    sock s = resolve_fd(current->p, sockfd);
    struct sockaddr sa;
    zero(&sa, sizeof(sa));
    struct sockaddr_in * sin = (struct sockaddr_in *)&sa;
    sin->family = AF_INET;
    if (s->type == SOCK_STREAM) {
	sin->port = ntohs(s->info.tcp.lw->local_port);
	sin->address = ip4_addr_get_u32(&s->info.tcp.lw->local_ip);
    } else if (s->type == SOCK_DGRAM) {
	sin->port = ntohs(s->info.udp.lw->local_port);
	sin->address = ip4_addr_get_u32(&s->info.udp.lw->local_ip);
    } else {
	msg_warn("not supported for socket type %d\n", s->type);
	return -EINVAL;
    }
    u64 len = MIN(*addrlen, sizeof(struct sockaddr));
    runtime_memcpy(addr, sin, len);
    *addrlen = sizeof(struct sockaddr);
    return 0;
}

sysreturn getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    sock s = resolve_fd(current->p, sockfd);
    struct sockaddr sa;
    zero(&sa, sizeof(sa));
    remote_sockaddr_in(s, (struct sockaddr_in *)&sa);
    u64 len = MIN(*addrlen, sizeof(struct sockaddr));
    runtime_memcpy(addr, &sa, len);
    *addrlen = sizeof(struct sockaddr);
    return 0;    
}

sysreturn setsockopt(int sockfd,
                     int level,
                     int optname,
                     void *optval,
                     socklen_t optlen)
{
    msg_warn("setsockopt unimplemented: fd %d, level %d, optname %d\n",
	    sockfd, level, optname);
    return 0;
}

sysreturn getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen)
{
    sock s = resolve_fd(current->p, sockfd);
    net_debug("sock %d, type %d, thread %ld, level %d, optname %d\n, optlen %d\n",
        s->fd, s->type, current->tid, level, optname, optlen ? *optlen : -1)

    union {
        int val;
    } ret_optval;

    switch (optname) {
    case SO_TYPE:
        ret_optval.val = s->type;
        break;
    default:
        msg_warn("getsockopt unimplemented optname: fd %d, level %d, optname %d\n",
            sockfd, level, optname);
        return set_syscall_error(current, ENOPROTOOPT);
    }

    if (optval && optlen) {
        int ret_optlen = MIN(*optlen, sizeof(ret_optval));
        runtime_memcpy(optval, &ret_optval, ret_optlen);
        *optlen = ret_optlen;
    }

    return 0;
}

void register_net_syscalls(struct syscall *map)
{
    register_syscall(map, socket, socket);
    register_syscall(map, bind, bind);
    register_syscall(map, listen, listen);
    register_syscall(map, accept, accept);
    register_syscall(map, accept4, accept4);
    register_syscall(map, connect, connect);
    register_syscall(map, sendto, sendto);
    register_syscall(map, recvfrom, recvfrom);
    register_syscall(map, setsockopt, setsockopt);
    register_syscall(map, getsockname, getsockname);
    register_syscall(map, getpeername, getpeername);
    register_syscall(map, getsockopt, getsockopt);
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
