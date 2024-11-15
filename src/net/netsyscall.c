/* TODO

   - consider switching on blockq timeout
   - check err handling of tcp_output
   - do udp tx bottom half
*/

#include <unix_internal.h>
#include <lwip.h>
#include <lwip/priv/tcp_priv.h>
#include <lwip/udp.h>
#include <net_system_structs.h>
#include <socket.h>

//#define NETSYSCALL_DEBUG
#ifdef NETSYSCALL_DEBUG
#define net_debug(x, ...) do {log_printf(ss(" NET"), ss("%s: " x), func_ss, ##__VA_ARGS__);} while(0)
#else
#define net_debug(x, ...)
#endif

#define MTU_MAX (32 * KB)

#define resolve_socket(__p, __fd) ({fdesc f = resolve_fd(__p, __fd); \
    if (f->type != FDESC_TYPE_SOCKET) {              \
        fdesc_put(f);                                \
        return set_syscall_error(current, ENOTSOCK); \
    }                                                \
    (struct sock *)f;})

struct sockaddr_in {
    u16 family;
    u16 port;
    u32 address;
    u8 sin_zero[8];
} *sockaddr_in;

struct in6_addr {
    u8 s6_addr[16];
};

struct sockaddr_in6 {
    u16 family;
    u16 port;
    u32 sin6_flowinfo;
    struct in6_addr sin6_addr;
    u32 sin6_scope_id;
};

struct ifconf {
    int ifc_len;
    union {
        char *ifc_buf;
        struct ifreq *ifc_req;
    } ifc;
};

struct linger {
    int l_onoff;
    int l_linger;
};

// xxx - what is the difference between IN_CONNECTION and open
// nothing seems to track whether the tcp state is actually
// connected

// XXX change these over to actual tcp connection states...but
// defined in tcp-specific area
enum tcp_socket_state {
    TCP_SOCK_UNDEFINED = 0,
    TCP_SOCK_CREATED = 1,
    TCP_SOCK_IN_CONNECTION = 2,
    TCP_SOCK_ABORTING_CONNECTION = 3,
    TCP_SOCK_OPEN = 4,
    TCP_SOCK_LISTENING = 5,
};

enum udp_socket_state {
    UDP_SOCK_UNDEFINED = 0,
    UDP_SOCK_CREATED = 1,
    UDP_SOCK_SHUTDOWN = 2,
};

typedef struct netsock {
    struct sock sock;             /* must be first */
    process p;
    queue incoming;
    err_t lwip_error;             /* lwIP error code; ERR_OK if normal */
    u8 ipv6only:1;
    union {
	struct {
	    struct tcp_pcb *lw;
	    tcpflags_t flags;
	    enum tcp_socket_state state; // half open?
	} tcp;
	struct {
	    struct udp_pcb *lw;
	    enum udp_socket_state state;
	} udp;
    } info;
    closure_struct(file_io, read);
    closure_struct(file_io, write);
    closure_struct(file_iov, writev);
    closure_struct(fdesc_events, events);
    closure_struct(fdesc_ioctl, ioctl);
    closure_struct(fdesc_close, close);
} *netsock;

/* Mask of TCP flags expressing socket configuration settings (as opposed to flags describing the
 * current state of a socket). */
#define SOCK_TCP_CFG_FLAGS   TF_NODELAY

#define netsock_lock(s)     spin_lock(&(s)->sock.f.lock)
#define netsock_unlock(s)   spin_unlock(&(s)->sock.f.lock)

#define DEFAULT_SO_RCVBUF   0x34000 /* same as Linux */

#define TCP_CONG_CTRL_ALGO  "reno"  /* TCP congestion control algorithm name */

int so_rcvbuf;

static sysreturn netsock_bind(struct sock *sock, struct sockaddr *addr,
        socklen_t addrlen);
static sysreturn netsock_listen(struct sock *sock, int backlog);
static sysreturn netsock_connect(struct sock *sock, struct sockaddr *addr,
        socklen_t addrlen);
static sysreturn netsock_accept4(struct sock *sock, struct sockaddr *addr,
                                 socklen_t *addrlen, int flags, context ctx, boolean in_bh,
                                 io_completion completion);
static sysreturn netsock_getsockname(struct sock *sock, struct sockaddr *addr, socklen_t *addrlen);
static sysreturn netsock_getsockopt(struct sock *sock, int level,
                                    int optname, void *optval, socklen_t *optlen);
static sysreturn netsock_setsockopt(struct sock *sock, int level,
                                    int optname, void *optval, socklen_t optlen);
static sysreturn netsock_sendto(struct sock *sock, void *buf, u64 len,
                                int flags, struct sockaddr *dest_addr, socklen_t addrlen,
                                context ctx, boolean in_bh, io_completion completion);
static sysreturn netsock_recvfrom(struct sock *sock, void *buf, u64 len,
                                  int flags, struct sockaddr *src_addr, socklen_t *addrlen,
                                  context ctx, boolean in_bh, io_completion completion);
static sysreturn netsock_sendmsg(struct sock *sock, const struct msghdr *msg,
                                 int flags, boolean in_bh, io_completion completion);
static sysreturn netsock_recvmsg(struct sock *sock, struct msghdr *msg,
                                 int flags, boolean in_bh, io_completion completion);

BSS_RO_AFTER_INIT static thunk net_loop_poll;
static boolean net_loop_poll_queued;

closure_function(0, 0, void, netsock_poll) {
    net_loop_poll_queued = false;
    netif_poll_loopback();
}

static void netsock_check_loop(void)
{
    /* Not race-free, but the worst that can happen is that the thunk is
     * enqueued more than once. */
    if (!net_loop_poll_queued) {
        net_loop_poll_queued = true;
        async_apply(net_loop_poll);
    }
}

static netsock get_netsock(struct sock *sock)
{
    if ((sock->domain != AF_INET) && (sock->domain != AF_INET6))
        return 0;
    return (netsock)sock;
}

static u32 netsock_events_locked(netsock s)
{
    boolean in = !queue_empty(s->incoming);
    u32 rv;
    if (s->sock.type == SOCK_STREAM) {
        switch (s->info.tcp.state) {
        case TCP_SOCK_LISTENING:
            rv = in ? EPOLLIN : 0;
            break;
        case TCP_SOCK_OPEN:
            /* We can't take the lwIP lock here given that notifies are
               triggered by lwIP callbackes, but the lwIP state read is atomic
               as is the TCP sendbuf size read. */
            rv = (in ? EPOLLIN | EPOLLRDNORM : 0) |
                (s->info.tcp.lw->state == ESTABLISHED ?
                 (tcp_sndbuf(s->info.tcp.lw) ? EPOLLOUT | EPOLLWRNORM : 0) :
                 EPOLLIN | EPOLLOUT);
            break;
        case TCP_SOCK_UNDEFINED:
            rv = EPOLLIN | EPOLLOUT;
            break;
        case TCP_SOCK_CREATED:
            rv = EPOLLHUP | EPOLLOUT;
            break;
        default:
            rv = 0;
        }
    } else {
        assert(s->sock.type == SOCK_DGRAM);
        rv = (in ? EPOLLIN | EPOLLRDNORM : 0) | EPOLLOUT | EPOLLWRNORM;
    }
    return rv;
}

closure_func_basic(fdesc_events, u32, socket_events,
                   thread t /* ignore */)
{
    netsock s = struct_from_field(closure_self(), netsock, events);
    netsock_lock(s);
    u32 events = netsock_events_locked(s);
    netsock_unlock(s);
    return events;
}

/* called on sock init or call from lwIP, thus locked */
static void set_lwip_error(netsock s, err_t err)
{
    s->lwip_error = err;
}

static err_t get_lwip_error(netsock s)
{
    return s->lwip_error;
}

static err_t get_and_clear_lwip_error(netsock s)
{
#ifdef __riscv
    /* riscv can't do atomics < 4 bytes */
    err_t e;
    netsock_lock(s);
    e = s->lwip_error;
    s->lwip_error = ERR_OK;
    netsock_unlock(s);
    return e;
#else
    return __atomic_exchange_n(&s->lwip_error, ERR_OK, __ATOMIC_ACQUIRE);
#endif
}

/* Called with netsock lock held, returns with lock released. */
static void netsock_notify_events(netsock s)
{
    u32 events = netsock_events_locked(s);
    netsock_unlock(s);
    notify_dispatch(s->sock.f.ns, events);
}

#define WAKEUP_SOCK_RX          0x00000001
#define WAKEUP_SOCK_TX          0x00000002
#define WAKEUP_SOCK_EXCEPT      0x00000004 /* flush, and thus implies rx & tx */

/* Called with netsock lock held, returns with lock released. */
static void wakeup_sock(netsock s, int flags)
{
    net_debug("sock %d, flags %d\n", s->sock.fd, flags);

    /* exception leads to release of all blocking requests */
    if ((flags & WAKEUP_SOCK_EXCEPT)) {
        socket_flush_q(&s->sock);
    } else {
        if ((flags & WAKEUP_SOCK_RX))
            blockq_wake_one(s->sock.rxbq);

        if ((flags & WAKEUP_SOCK_TX))
            blockq_wake_one(s->sock.txbq);
    }
    netsock_notify_events(s);
}

static inline void sockaddr_to_ip6addr(struct sockaddr_in6 *addr,
                                       ip_addr_t *ip_addr)
{
    ip_addr->type = IPADDR_TYPE_V6;
    runtime_memcpy(&ip_addr->u_addr.ip6, &addr->sin6_addr.s6_addr,
        sizeof(addr->sin6_addr.s6_addr));
}

static inline void ip6addr_to_sockaddr(ip_addr_t *ip_addr,
                                       struct sockaddr_in6 *addr)
{
    addr->family = AF_INET6;
    runtime_memcpy(&addr->sin6_addr.s6_addr, &ip_addr->u_addr.ip6,
        sizeof(addr->sin6_addr.s6_addr));
}

static sysreturn sockaddr_to_addrport(netsock s, struct sockaddr *addr,
                                      socklen_t addrlen,
                                      ip_addr_t *ip_addr, u16 *port)
{
    *ip_addr = (ip_addr_t){};
    if (s->sock.domain == AF_INET) {
        if (addrlen < sizeof(struct sockaddr_in))
            return -EINVAL;
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        ip_addr_set_ip4_u32(ip_addr, sin->address);
        *port = ntohs(sin->port);
    } else {
        if (addrlen < sizeof(struct sockaddr_in6))
            return -EINVAL;
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
        sockaddr_to_ip6addr(sin6, ip_addr);
        *port = ntohs(sin6->port);
    }
    /* If this is an an IPv4 mapped address then this socket
        is dual-stack, so convert the address to IPv4 to encourage
        LwIP to use that transport
    */
    if (s->sock.domain == AF_INET6 && !s->ipv6only &&
            ip6_addr_isipv4mappedipv6(ip_2_ip6(ip_addr))) {
        unmap_ipv4_mapped_ipv6(ip_2_ip4(ip_addr), ip_2_ip6(ip_addr));
        IP_SET_TYPE_VAL(*ip_addr, IPADDR_TYPE_V4);
    }
    return 0;
}

static void addrport_to_sockaddr(int af, ip_addr_t *ip_addr, u16 port,
                                 struct sockaddr *addr, socklen_t *len)
{
    struct sockaddr_storage sa;
    socklen_t addr_len;

    zero(&sa, sizeof(sa));
    if (af == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)&sa;
        sin->family = AF_INET;
        sin->port = htons(port);
        sin->address = ip_addr_get_ip4_u32(ip_addr);
        addr_len = sizeof(struct sockaddr_in);
    } else {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&sa;
        sin6->port = htons(port);
        if (IP_IS_V4(ip_addr)) {
            ip_addr_t ipv6_addr;
            ip4_2_ipv4_mapped_ipv6(&ipv6_addr.u_addr.ip6, &ip_addr->u_addr.ip4);
            ip6addr_to_sockaddr(&ipv6_addr, sin6);
        } else
            ip6addr_to_sockaddr(ip_addr, sin6);
        sin6->sin6_flowinfo = 0;
        sin6->sin6_scope_id = 0;
        addr_len = sizeof(struct sockaddr_in6);
    }
    runtime_memcpy(addr, &sa, MIN(addr_len, *len));
    *len = addr_len;
}

static void remote_sockaddr(netsock s, struct sockaddr *addr, socklen_t *len)
{
    ip_addr_t *ip_addr;
    u16_t port;
    if (s->sock.type == SOCK_STREAM) {
        struct tcp_pcb *lw = s->info.tcp.lw;
        assert(lw);
        port = lw->remote_port;
        ip_addr = &lw->remote_ip;
    } else {
        assert(s->sock.type == SOCK_DGRAM);
        struct udp_pcb *lw = s->info.udp.lw;
        assert(lw);
        port = lw->remote_port;
        ip_addr = &lw->remote_ip;
    }
    addrport_to_sockaddr(s->sock.domain, ip_addr, port, addr, len);
}

static struct tcp_pcb *netsock_tcp_get(netsock s)
{
    netsock_lock(s);
    struct tcp_pcb *tcp_lw = s->info.tcp.lw;
    if (tcp_lw)
        tcp_ref(tcp_lw);
    netsock_unlock(s);
    if (tcp_lw)
        tcp_lock(tcp_lw);
    return tcp_lw;
}

static void netsock_tcp_put(struct tcp_pcb * tcp_lw)
{
    tcp_unlock(tcp_lw);
    tcp_unref(tcp_lw);
}

static void netsock_tcp_close(netsock s, struct tcp_pcb *tcp_lw)
{
    netsock_lock(s);
    if (s->info.tcp.state != TCP_SOCK_UNDEFINED) {
        tcp_close(tcp_lw);
        tcp_arg(tcp_lw, 0);
        s->info.tcp.state = TCP_SOCK_UNDEFINED;
    }
    netsock_unlock(s);
}

static inline s64 lwip_to_errno(s8 err)
{
    switch (err) {
    case ERR_OK: return 0;
    case ERR_MEM: return -ENOMEM;
    case ERR_BUF: return -ENOBUFS;
    case ERR_TIMEOUT: return -EAGAIN;
    case ERR_RTE: return -EHOSTUNREACH;
    case ERR_INPROGRESS: return -EINPROGRESS;
    case ERR_VAL: return -EINVAL;
    case ERR_WOULDBLOCK: return -EAGAIN;
    case ERR_USE: return -EADDRINUSE;
    case ERR_ALREADY: return -EALREADY;
    case ERR_ISCONN: return -EISCONN;
    case ERR_CONN: return -ENOTCONN;
    case ERR_IF: return -EINVAL;
    case ERR_ABRT: return -ECONNABORTED;
    case ERR_RST: return -ECONNRESET;
    case ERR_CLSD: return -ENOTCONN;
    case ERR_ARG: return -EIO;
    case ERR_MSGSIZE: return -EMSGSIZE;
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
    ip_addr_t raddr;
    u16 rport;
};

static sysreturn sock_read_bh_internal(netsock s, struct msghdr *msg, int flags,
                                       io_completion completion, u64 bqflags, context ctx)
{
    sysreturn rv = 0;
    if (context_set_err(ctx)) {
        rv = -EFAULT;
        goto out;
    }
    iovec iov = msg->msg_iov;
    u64 length = msg->msg_iovlen;
    context_clear_err(ctx);

    netsock_lock(s);
    err_t err = get_lwip_error(s);
    struct tcp_pcb *tcp_lw = 0;
    boolean notify = false;
    net_debug("sock %d, ctx %p, iov %p, len %ld, flags 0x%x, bqflags 0x%lx, lwip err %d\n",
              s->sock.fd, ctx, iov, length, flags, bqflags, err);
    assert(s->sock.type == SOCK_STREAM || s->sock.type == SOCK_DGRAM);

    if ((s->sock.type == SOCK_STREAM && s->info.tcp.state != TCP_SOCK_OPEN) ||
            (s->sock.type == SOCK_DGRAM && s->info.udp.state == UDP_SOCK_SHUTDOWN)) {
        rv = 0;
        goto out_unlock;
    }

    if (err != ERR_OK) {
        rv = lwip_to_errno(err);
        goto out_unlock;
    }

    if (bqflags & BLOCKQ_ACTION_NULLIFY) {
        rv = -ERESTARTSYS;
        goto out_unlock;
    }

    /* check if we actually have data */
    void * p = queue_peek(s->incoming);
    if (p == INVALID_ADDRESS) {
        if (s->sock.type == SOCK_STREAM &&
            (!s->info.tcp.lw || s->info.tcp.lw->state != ESTABLISHED)) {
            rv = 0;
            goto out_unlock;
        }
        if ((s->sock.f.flags & SOCK_NONBLOCK) || (flags & MSG_DONTWAIT)) {
            rv = -EAGAIN;
            goto out_unlock;
        }
        netsock_unlock(s);
        return blockq_block_required((unix_context)ctx, bqflags);
    }

    u64 xfer_total = 0;
    if (context_set_err(ctx)) {
        rv = -EFAULT;
        goto rx_done;
    }
    msg->msg_controllen = 0;
    msg->msg_flags = 0;
    sockaddr src_addr = msg->msg_name;
    if (src_addr) {
        socklen_t *addrlen = &msg->msg_namelen;
        if (s->sock.type == SOCK_STREAM) {
            remote_sockaddr(s, src_addr, addrlen);
        } else {
            struct udp_entry * e = p;
            addrport_to_sockaddr(s->sock.domain, &e->raddr, e->rport, src_addr,
                                 addrlen);
        }
    }

    u64 iov_offset = 0;
    u32 pbuf_idx = 0;
    if ((s->sock.type == SOCK_STREAM) && !(flags & MSG_PEEK)) {
        tcp_lw = s->info.tcp.lw;
        tcp_ref(tcp_lw);
    }

    /* TCP: consume multiple buffers to fill request, if available. */
    do {
        struct pbuf * pbuf = s->sock.type == SOCK_STREAM ? (struct pbuf *)p :
            ((struct udp_entry *)p)->pbuf;
        struct pbuf *cur_buf = pbuf;

        while ((length > 0) && cur_buf) {
            if (cur_buf->len > 0) {
                u64 xfer = MIN(iov->iov_len - iov_offset, cur_buf->len);
                runtime_memcpy(iov->iov_base + iov_offset, cur_buf->payload, xfer);
                if (!(flags & MSG_PEEK)) {
                    pbuf_consume(cur_buf, xfer);
                    if (s->sock.type == SOCK_STREAM)
                        s->sock.rx_len -= xfer;
                }
                xfer_total += xfer;
                iov_offset += xfer;
                if (iov_offset == iov->iov_len) {
                    length--;
                    iov++;
                    iov_offset = 0;
                }
            }
            if ((cur_buf->len == 0) || (flags & MSG_PEEK))
                cur_buf = cur_buf->next;
        }

        if (flags & MSG_PEEK) {
            if (!cur_buf)
                p = queue_peek_at(s->incoming, ++pbuf_idx);
        } else if (!cur_buf || (s->sock.type == SOCK_DGRAM)) {
            assert(dequeue(s->incoming) == p);
            if (s->sock.type == SOCK_DGRAM) {
                s->sock.rx_len -= pbuf->tot_len;
                if (cur_buf) {
                    msg->msg_flags |= MSG_TRUNC;
                    if (flags & MSG_TRUNC)
                        xfer_total = pbuf->tot_len;
                }
                deallocate(s->sock.h, p, sizeof(struct udp_entry));
            }
            pbuf_free(pbuf);
            p = queue_peek(s->incoming);
            if (p == INVALID_ADDRESS)
                notify = true;  /* reset a triggered EPOLLIN condition */
        }
    } while(s->sock.type == SOCK_STREAM && length > 0 && p != INVALID_ADDRESS); /* XXX simplify expression */
    context_clear_err(ctx);

  rx_done:
    if (xfer_total) {
        if (s->sock.type == SOCK_STREAM)
            /* Calls to tcp_recved() may have enqueued new packets in the loopback interface. */
            netsock_check_loop();
        rv = xfer_total;
    }
  out_unlock:
    if (notify)
        netsock_notify_events(s);
    else
        netsock_unlock(s);
    if (tcp_lw) {
        if (rv > 0) {
            tcp_lock(tcp_lw);
            tcp_recved(tcp_lw, rv);
            tcp_unlock(tcp_lw);
        }
        tcp_unref(tcp_lw);
    }
  out:
    net_debug("   completion %p, rv %ld\n", completion, rv);
    apply(completion, rv);
    return rv;
}

closure_function(7, 1, sysreturn, sock_read_bh,
                 netsock, s, void *, dest, u64, length, int, flags, struct sockaddr *, src_addr, socklen_t *, addrlen, io_completion, completion,
                 u64 flags)
{
    struct iovec iov = {
        .iov_base = bound(dest),
        .iov_len = bound(length),
    };
    struct msghdr msg = {
        .msg_name = bound(src_addr),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };
    context ctx = context_from_closure(closure_self());
    sysreturn rv = 0;
    if (msg.msg_name) {
        if (!context_set_err(ctx)) {
            msg.msg_namelen = *bound(addrlen);
            context_clear_err(ctx);
        } else {
            rv = -EFAULT;
        }
    }
    if (!rv)
        rv = sock_read_bh_internal(bound(s), &msg, bound(flags), bound(completion), flags, ctx);
    else
        apply(bound(completion), rv);
    if (rv != BLOCKQ_BLOCK_REQUIRED) {
        if ((rv > 0) && msg.msg_name) {
            if (!context_set_err(ctx)) {
                *bound(addrlen) = msg.msg_namelen;
                context_clear_err(ctx);
            }
        }
        closure_finish();
    }
    return rv;
}

closure_function(4, 1, sysreturn, recvmsg_bh,
                 netsock, s, struct msghdr *, msg, int, flags, io_completion, completion,
                 u64 flags)
{
    sysreturn rv = sock_read_bh_internal(bound(s), bound(msg), bound(flags), bound(completion),
                                         flags, context_from_closure(closure_self()));
    if (rv != BLOCKQ_BLOCK_REQUIRED)
        closure_finish();
    return rv;
}

closure_func_basic(file_io, sysreturn, socket_read,
                   void *dest, u64 length, u64 offset, context ctx, boolean bh, io_completion completion)
{
    netsock s = struct_from_field(closure_self(), netsock, read);
    net_debug("sock %d, type %d, ctx %p, dest %p, length %ld, offset %ld\n",
              s->sock.fd, s->sock.type, ctx, dest, length, offset);
    if (s->sock.type == SOCK_STREAM && s->info.tcp.state != TCP_SOCK_OPEN)
        return io_complete(completion,
            (s->info.tcp.state == TCP_SOCK_UNDEFINED) ? 0 : -ENOTCONN);

    blockq_action ba = closure_from_context(ctx, sock_read_bh, s, dest, length, 0, 0,
                                            0, completion);
    return blockq_check(s->sock.rxbq, ba, bh);
}

closure_function(6, 1, sysreturn, socket_write_tcp_bh,
                 netsock, s, void *, buf, struct iovec *, iov, u64, length, int, flags, io_completion, completion,
                 u64 bqflags)
{
    netsock s = bound(s);
    void *buf = bound(buf);
    u64 remain = bound(length);
    int flags = bound(flags);
    sysreturn rv = 0;
    io_completion completion = bound(completion);
    netsock_lock(s);
    err_t err = get_lwip_error(s);
    net_debug("fd %d, buf %p, remain %ld, flags 0x%x, bqflags 0x%lx, lwip err %d\n",
              s->sock.fd, buf, remain, flags, bqflags, err);
    assert(remain > 0);

    if (err != ERR_OK) {
        rv = lwip_to_errno(err);
        goto out_unlock;
    }

    if (s->sock.type == SOCK_STREAM && s->info.tcp.state != TCP_SOCK_OPEN) {
        rv = -ENOTCONN;
        goto out_unlock;
    }

    if (bqflags & BLOCKQ_ACTION_NULLIFY) {
        rv = -ERESTARTSYS;
        goto out_unlock;
    }

    context ctx = context_from_closure(closure_self());
    struct tcp_pcb *tcp_lw = s->info.tcp.lw;
    tcp_ref(tcp_lw);
    netsock_unlock(s);
    tcp_lock(tcp_lw);

    /* Note that the actual transmit window size is truncated to 16
       bits here (and tcp_write() doesn't accept more than 2^16
       anyway), so even if we have a large transmit window due to
       LWIP_WND_SCALE, we still can't write more than 2^16. Sigh... */
    u64 avail = tcp_sndbuf(tcp_lw);
    if (avail == 0) {
        /* directly poll for loopback traffic in case the enqueued netsock_poll is backed up */
        tcp_unlock(tcp_lw);
        netif_poll_loopback();
        tcp_lock(tcp_lw);
        avail = tcp_sndbuf(tcp_lw);
        if (avail == 0) {
          full:
            tcp_unlock(tcp_lw);
            tcp_unref(tcp_lw);
            if ((bqflags & BLOCKQ_ACTION_BLOCKED) == 0 &&
                ((s->sock.f.flags & SOCK_NONBLOCK) || (flags & MSG_DONTWAIT))) {
                net_debug(" send buf full and non-blocking, return EAGAIN\n");
                rv = -EAGAIN;
                goto out;
            }
            net_debug(" send buf full, sleep\n");
            return blockq_block_required((unix_context)ctx, bqflags);
        }
    }
    struct iovec *iov = bound(iov);
    if (context_set_err(ctx)) {
        if (rv == 0)
            rv = -EFAULT;
        goto write_done;
    }

    /* Figure actual length and flags */
    u64 buf_offset = 0;
    u64 n;
    while (remain) {
        u8 apiflags = TCP_WRITE_FLAG_COPY;
        if (iov) {
            do {
                n = iov->iov_len - buf_offset;
                if (n == 0) {
                    iov++;
                    remain--;
                    buf_offset = 0;
                }
            } while ((n == 0) && remain);
            if (!remain)
                break;
            buf = iov->iov_base;
            if (remain)
                apiflags |= TCP_WRITE_FLAG_MORE;
        } else {
            n = remain;
        }
        if (avail < n) {
            n = avail;
            apiflags |= TCP_WRITE_FLAG_MORE;
        }

        err = tcp_write(tcp_lw, buf + buf_offset, n, apiflags);
        if (err == ERR_OK) {
            buf_offset += n;
            rv += n;
            if ((avail = tcp_sndbuf(tcp_lw)) == 0)
                break;
            if (!iov)
                remain -= n;
            continue;
        }
        if (err == ERR_MEM) {
            /* XXX some ambiguity in lwIP - investigate */
            net_debug(" tcp_write() returned ERR_MEM\n");
            goto full;
        } else {
            net_debug(" tcp_write() lwip error: %d\n", err);
            rv = lwip_to_errno(err);
        }
        break;
    }
    context_clear_err(ctx);
  write_done:
    if (err == ERR_OK) {
        /* XXX prob add a flag to determine whether to continuously
           post data, e.g. if used by send/sendto... */
        err = tcp_output(tcp_lw);
        if (err == ERR_OK) {
            net_debug(" tcp_write and tcp_output successful for %ld bytes\n", rv);
            netsock_check_loop();
            if (avail == 0)
                fdesc_notify_events(&s->sock.f); /* reset a triggered EPOLLOUT condition */
        } else {
            net_debug(" tcp_output() lwip error: %d\n", err);
            rv = lwip_to_errno(err);
            /* XXX map error to socket tcp state */
        }
    }
    tcp_unlock(tcp_lw);
    tcp_unref(tcp_lw);
    goto out;
  out_unlock:
    netsock_unlock(s);
  out:
    closure_finish();
    net_debug("   completion %p, rv %ld\n", completion, rv);
    apply(completion, rv);
    return rv;
}

static sysreturn socket_write_udp(netsock s, void *source, struct iovec *iov, u64 length,
                                  struct sockaddr *dest_addr, socklen_t addrlen)
{
    ip_addr_t ipaddr;
    u16 port = 0;
    context ctx = get_current_context(current_cpu());
    if (dest_addr) {
        if (context_set_err(ctx))
            return -EFAULT;
        sysreturn ret = sockaddr_to_addrport(s, dest_addr, addrlen,
            &ipaddr, &port);
        context_clear_err(ctx);
        if (ret)
            return ret;
    }
    err_t err = ERR_OK;

    /* XXX check how much we can queue, maybe make udp bh */
    netsock_lock(s);
    if (!dest_addr && !udp_is_flag_set(s->info.udp.lw, UDP_FLAGS_CONNECTED)) {
        netsock_unlock(s);
        return -EDESTADDRREQ;
    }

    u64 xfer_len = source ? length : iov_total_len(iov, length);
    struct pbuf *pbuf = pbuf_alloc(PBUF_TRANSPORT, xfer_len, PBUF_RAM);
    if (!pbuf) {
        netsock_unlock(s);
        msg_err("failed to allocate pbuf for udp_send()\n");
        return -ENOBUFS;
    }
    if (context_set_err(ctx)) {
        netsock_unlock(s);
        pbuf_free(pbuf);
        return -EFAULT;
    }
    if (source)
        runtime_memcpy(pbuf->payload, source, length);
    else
        iov_to_buf(pbuf->payload, iov, length);
    context_clear_err(ctx);
    if (dest_addr)
        err = udp_sendto(s->info.udp.lw, pbuf, &ipaddr, port);
    else
        err = udp_send(s->info.udp.lw, pbuf);
    netsock_unlock(s);
    pbuf_free(pbuf);
    if (err != ERR_OK) {
        net_debug("lwip error %d\n", err);
        return lwip_to_errno(err);
    }
    netsock_check_loop();
    return xfer_len;
}

static sysreturn socket_write_internal(struct sock *sock, void *source, struct iovec *iov,
                                       u64 length, int flags,
                                       struct sockaddr *dest_addr, socklen_t addrlen,
                                       context ctx, boolean bh, io_completion completion)
{
    netsock s = (netsock) sock;
    sysreturn rv;

    if (sock->type == SOCK_STREAM) {
	if (s->info.tcp.state != TCP_SOCK_OPEN) { /* XXX maybe defer to lwip for connect state */
	    rv = -EPIPE;
	    goto out;
	}

        if (length == 0) {
            rv = 0;
            goto out;
        }
        blockq_action ba = closure_from_context(ctx, socket_write_tcp_bh, s, source, iov, length,
                                                flags, completion);
        return blockq_check(sock->txbq, ba, bh);
    } else {
        rv = socket_write_udp(s, source, iov, length, dest_addr, addrlen);
    }
    net_debug("completed\n");
out:
    apply(completion, rv);
    return rv;
}

closure_func_basic(file_io, sysreturn, socket_write,
                   void *source, u64 length, u64 offset, context ctx, boolean bh, io_completion completion)
{
    netsock ns = struct_from_field(closure_self(), netsock, write);
    struct sock *s = &ns->sock;
    net_debug("sock %d, type %d, ctx %p, source %p, length %ld, offset %ld\n",
              s->fd, s->type, ctx, source, length, offset);
    return socket_write_internal(s, source, 0, length, 0, 0, 0, ctx, bh, completion);
}

closure_func_basic(file_iov, sysreturn, socket_writev,
                   struct iovec *iov, int count, u64 offset, context ctx, boolean bh, io_completion completion)
{
    netsock ns = struct_from_field(closure_self(), netsock, writev);
    struct sock *s = &ns->sock;
    net_debug("sock %d, type %d, count %d, offset %ld\n", s->fd, s->type, count, offset);
    return socket_write_internal(s, 0, iov, count, 0, 0, 0, ctx, bh, completion);
}

static boolean siocgifconf_get_len(struct netif *n, void *priv)
{
    if (netif_is_up(n) && netif_is_link_up(n) && !ip4_addr_isany(netif_ip4_addr(n))) {
        struct ifconf *ifconf = priv;
        ifconf->ifc_len += sizeof(struct ifreq);
    }
    return false;
}

typedef struct siocgifconf_priv {
    struct ifconf *ifconf;
    sysreturn rv;
} *siocgifconf_priv;

static boolean siocgifconf_populate(struct netif *n, void *priv)
{
    if (netif_is_up(n) && netif_is_link_up(n) && !ip4_addr_isany(netif_ip4_addr(n))) {
        siocgifconf_priv ifconf_priv = priv;
        struct ifconf *ifconf = ifconf_priv->ifconf;
        context ctx = get_current_context(current_cpu());
        if (context_set_err(ctx)) {
            ifconf_priv->rv = -EFAULT;
            return true;
        }
        int iface = ifconf->ifc_len / sizeof(struct ifreq);
        netif_name_cpy(ifconf->ifc.ifc_req[iface].ifr_name, n);
        struct sockaddr_in *addr = (struct sockaddr_in *)&ifconf->ifc.ifc_req[iface].ifr.ifr_addr;
        addr->family = AF_INET;
        runtime_memcpy(&addr->address, netif_ip4_addr(n), sizeof(ip4_addr_t));
        ifconf->ifc_len += sizeof(struct ifreq);
        context_clear_err(ctx);
    }
    return false;
}

typedef sysreturn (*socket_ifreq_handler)(struct ifreq *ifreq, struct netif *netif);

static sysreturn socket_ifreq(struct ifreq *ifreq, boolean set, socket_ifreq_handler handler)
{
    context ctx = get_current_context(current_cpu());
    if (!validate_user_memory(ifreq, sizeof(struct ifreq), !set) || context_set_err(ctx))
        return -EFAULT;
    struct netif *netif = netif_find(sstring_from_cstring(ifreq->ifr_name, IFNAMSIZ));
    context_clear_err(ctx);
    if (!netif)
        return -ENODEV;
    sysreturn rv;
    if (!context_set_err(ctx)) {
        rv = handler(ifreq, netif);
        context_clear_err(ctx);
    } else {
        rv = -EFAULT;
    }
    netif_unref(netif);
    return rv;
}

static sysreturn socket_get_flags(struct ifreq *ifreq, struct netif *netif)
{
    ifreq->ifr.ifr_flags = ifflags_from_netif(netif);
    return 0;
}

static sysreturn socket_set_flags(struct ifreq *ifreq, struct netif *netif)
{
    return ifflags_to_netif(netif, ifreq->ifr.ifr_flags) ? 0 : -EINVAL;
}

static sysreturn socket_get_addr(struct ifreq *ifreq, struct netif *netif)
{
    struct sockaddr_in *addr = (struct sockaddr_in *)&ifreq->ifr.ifr_addr;
    addr->family = AF_INET;
    runtime_memcpy(&addr->address, netif_ip4_addr(netif), sizeof(ip4_addr_t));
    return 0;
}

static sysreturn socket_set_addr(struct ifreq *ifreq, struct netif *netif)
{
    struct sockaddr_in *addr = (struct sockaddr_in *)&ifreq->ifr.ifr_addr;
    if (addr->family != AF_INET)
        return -EINVAL;
    ip4_addr_t lwip_addr = {
        .addr = addr->address,
    };
    netif_set_ipaddr(netif, &lwip_addr);
    return 0;
}

static sysreturn socket_get_netmask(struct ifreq *ifreq, struct netif *netif)
{
    struct sockaddr_in *addr = (struct sockaddr_in *)&ifreq->ifr.ifr_netmask;
    addr->family = AF_INET;
    runtime_memcpy(&addr->address, netif_ip4_netmask(netif), sizeof(ip4_addr_t));
    return 0;
}

static sysreturn socket_set_netmask(struct ifreq *ifreq, struct netif *netif)
{
    struct sockaddr_in *addr = (struct sockaddr_in *)&ifreq->ifr.ifr_netmask;
    if (addr->family != AF_INET)
        return -EINVAL;
    ip4_addr_t lwip_addr = {
        .addr = addr->address,
    };
    netif_set_netmask(netif, &lwip_addr);
    return 0;
}

static sysreturn socket_get_mtu(struct ifreq *ifreq, struct netif *netif)
{
    ifreq->ifr.ifr_mtu = netif->mtu;
    return 0;
}

static sysreturn socket_set_mtu(struct ifreq *ifreq, struct netif *netif)
{
    int mtu = ifreq->ifr.ifr_mtu;
    if ((mtu <= 0) || (mtu > MTU_MAX))
        return -EINVAL;
    netif->mtu = mtu;
    return 0;
}

static sysreturn socket_get_hwaddr(struct ifreq *ifreq, struct netif *netif)
{
    struct sockaddr *addr = &ifreq->ifr.ifr_hwaddr;
    addr->family = netif_get_type(netif);
    runtime_memcpy(&addr->sa_data, netif->hwaddr, MIN(netif->hwaddr_len, sizeof(addr->sa_data)));
    return 0;
}

static sysreturn socket_get_index(struct ifreq *ifreq, struct netif *netif)
{
    ifreq->ifr.ifr_ivalue = netif->num;
    return 0;
}

/* socket configuration controls; not netsock specific, but reliant on lwIP calls */
sysreturn socket_ioctl(struct sock *s, unsigned long request, vlist ap)
{
    net_debug("sock %d, request 0x%x\n", s->fd, request);
    switch (request) {
    case SIOCGIFNAME: {
        struct ifreq *ifreq = varg(ap, struct ifreq *);
        context ctx = get_current_context(current_cpu());
        if (!validate_user_memory(ifreq, sizeof(struct ifreq), true) || context_set_err(ctx))
            return -EFAULT;
        struct netif *netif = netif_get_by_index(ifreq->ifr.ifr_ivalue);
        context_clear_err(ctx);
        if (!netif)
            return -ENODEV;
        sysreturn rv;
        if (!context_set_err(ctx)) {
            netif_name_cpy(ifreq->ifr_name, netif);
            context_clear_err(ctx);
            rv = 0;
        } else {
            rv = -EFAULT;
        }
        netif_unref(netif);
        return rv;
    }
    case SIOCGIFCONF: {
        struct ifconf *ifconf = varg(ap, struct ifconf *);
        context ctx = get_current_context(current_cpu());
        if (!validate_user_memory(ifconf, sizeof(struct ifconf), true) || context_set_err(ctx))
            return -EFAULT;
        ifconf->ifc_len = 0;
        boolean get_len = (ifconf->ifc.ifc_req == NULL);
        context_clear_err(ctx);
        if (get_len) {
            netif_iterate(siocgifconf_get_len, ifconf);
            return 0;
        } else {
            struct siocgifconf_priv priv = {
                .ifconf = ifconf,
                .rv = 0,
            };
            netif_iterate(siocgifconf_populate, &priv);
            return priv.rv;
        }
    }
    case SIOCGIFFLAGS:
        return socket_ifreq(varg(ap, struct ifreq *), false, socket_get_flags);
    case SIOCSIFFLAGS:
        return socket_ifreq(varg(ap, struct ifreq *), true, socket_set_flags);
    case SIOCGIFADDR:
        return socket_ifreq(varg(ap, struct ifreq *), false, socket_get_addr);
    case SIOCSIFADDR:
        return socket_ifreq(varg(ap, struct ifreq *), true, socket_set_addr);
    case SIOCGIFNETMASK:
        return socket_ifreq(varg(ap, struct ifreq *), false, socket_get_netmask);
    case SIOCSIFNETMASK:
        return socket_ifreq(varg(ap, struct ifreq *), true, socket_set_netmask);
    case SIOCGIFMTU:
        return socket_ifreq(varg(ap, struct ifreq *), false, socket_get_mtu);
    case SIOCSIFMTU:
        return socket_ifreq(varg(ap, struct ifreq *), true, socket_set_mtu);
    case SIOCGIFHWADDR:
        return socket_ifreq(varg(ap, struct ifreq *), false, socket_get_hwaddr);
    case SIOCGIFINDEX:
        return socket_ifreq(varg(ap, struct ifreq *), false, socket_get_index);
    default:
        return ioctl_generic(&s->f, request, ap);
    }
}

closure_func_basic(fdesc_ioctl, sysreturn, netsock_ioctl,
                   unsigned long request, vlist ap)
{
    netsock s = struct_from_field(closure_self(), netsock, ioctl);
    net_debug("sock %d, request 0x%x\n", s->sock.fd, request);
    switch (request) {
    case FIONREAD: {
        int nbytes = 0;
        netsock_lock(s);
        void *p = queue_peek(s->incoming);
        if (p != INVALID_ADDRESS) {
            struct pbuf *buf = 0;
            switch (s->sock.type) {
            case SOCK_STREAM:
                /* For TCP, return the number of immediately readable bytes */
                if (s->info.tcp.state == TCP_SOCK_OPEN)
                    buf = p;
                break;
            case SOCK_DGRAM:
                /* For UDP, return the size of the next datagram (if any) */
                buf = ((struct udp_entry *)p)->pbuf;
                break;
            default:
                break;
            }
            while (buf) {
                nbytes += (int)buf->len;
                buf = buf->next;
            }
        }
        netsock_unlock(s);
        if (!set_user_value(varg(ap, int *), nbytes))
            return -EFAULT;
        return 0;
    }
    default:
        return socket_ioctl(&s->sock, request, ap);
    }
}

/* Must fit in a u8_t, because it may be used as backlog value for tcp_listen_with_backlog(). */
#define SOCK_QUEUE_LEN 255

closure_func_basic(fdesc_close, sysreturn, socket_close,
                   context ctx, io_completion completion)
{
    netsock s = struct_from_field(closure_self(), netsock, close);
    net_debug("sock %d, type %d\n", s->sock.fd, s->sock.type);
    struct tcp_pcb *tcp_lw;
    switch (s->sock.type) {
    case SOCK_STREAM:
        /* tcp_close() doesn't really stop everything synchronously; in order to
         * prevent any lwIP callback that might be called after tcp_close() from
         * using a stale reference to the socket structure, set the callback
         * argument to NULL. */
        tcp_lw = netsock_tcp_get(s);
        if (tcp_lw) {
            netsock_tcp_close(s, tcp_lw);
            netsock_tcp_put(tcp_lw);
            tcp_unref(tcp_lw);
            netsock_check_loop();
        }
        break;
    case SOCK_DGRAM:
        udp_remove(s->info.udp.lw);
        break;
    }
    void *p;
    while ((p = dequeue(s->incoming)) != INVALID_ADDRESS) {
        switch (s->sock.type) {
        case SOCK_STREAM:
            if (s->info.tcp.state == TCP_SOCK_LISTENING)
                apply(((netsock)p)->sock.f.close, 0, io_completion_ignore);
            else
                pbuf_free((struct pbuf *)p);
            break;
        case SOCK_DGRAM:
            pbuf_free(((struct udp_entry *)p)->pbuf);
            deallocate(s->sock.h, p, sizeof(struct udp_entry));
            break;
        }
    }
    deallocate_queue(s->incoming);
    socket_deinit(&s->sock);
    unix_cache_free(s->p->uh, socket, s);
    return io_complete(completion, 0);
}

static sysreturn netsock_shutdown(struct sock *sock, int how)
{
    int shut_rx = 0, shut_tx = 0;
    netsock s = (netsock) sock;
    sysreturn rv;

    switch (how) {
    case SHUT_RD:
        shut_rx = 1;
        break;
    case SHUT_WR:
        shut_tx = 1;
        break;
    case SHUT_RDWR:
        shut_rx = 1;
        shut_tx = 1;
        break;
    default:
        msg_warn("Wrong value passed for direction sock %d, type %d\n", sock->fd, s->sock.type);
        rv = -EINVAL;
        goto out;
    }
    switch (s->sock.type) {
    case SOCK_STREAM:
        netsock_lock(s);
        if (s->info.tcp.state != TCP_SOCK_OPEN) {
            netsock_unlock(s);
            rv = -ENOTCONN;
            goto out;
        }
        struct tcp_pcb *tcp_lw = s->info.tcp.lw;
        tcp_ref(tcp_lw);
        netsock_unlock(s);
        tcp_lock(tcp_lw);

        /* Determine whether TX or RX has been shut down during previous calls to this function. */
        if (!shut_rx && tcp_is_flag_set(tcp_lw, TF_RXCLOSED))
            shut_rx = 1;
        if (!shut_tx && (tcp_lw->state != ESTABLISHED) && (tcp_lw->state != CLOSE_WAIT))
            shut_tx = 1;

        if (shut_rx && shut_tx)
            /* Shutting down both TX and RX is equivalent to calling tcp_close(). */
            netsock_tcp_close(s, tcp_lw);
        else
            tcp_shutdown(tcp_lw, shut_rx, shut_tx);
        tcp_unlock(tcp_lw);
        tcp_unref(tcp_lw);
        netsock_check_loop();
        break;
    case SOCK_DGRAM:
        if (shut_rx)
            s->info.udp.state = UDP_SOCK_SHUTDOWN;
        rv = -ENOTCONN;
        goto out;
    }

    rv = 0;
  out:
    /* Wake up any blockers waiting on the socket */
    if (shut_rx)
        blockq_flush(sock->rxbq);
    if (shut_tx)
        blockq_flush(sock->txbq);
    socket_release(sock);
    return rv;
}

sysreturn shutdown(int sockfd, int how)
{
    struct sock *s = resolve_socket(current->p, sockfd);

    net_debug("sock %d, type %d, how %d\n", sockfd, s->type, how);
    if (!s->shutdown) {
        socket_release(s);
        return -EOPNOTSUPP;
    }
    return s->shutdown(s, how);
}

static void udp_input_lower(void *z, struct udp_pcb *pcb, struct pbuf *p,
                            struct ip_globals *ip_data, u16 port)
{
    netsock s = z;
#ifdef NETSYSCALL_DEBUG
    u8 *n = (u8 *)(&ip_data->current_iphdr_src);
#endif
    net_debug("sock %d, pcb %p, buf %p, src addr %d.%d.%d.%d, port %d\n",
	      s->sock.fd, pcb, p, n[0], n[1], n[2], n[3], port);
    assert(pcb == s->info.udp.lw);
    if (p) {
	netsock_lock(s);
	if ((s->sock.rx_len + p->tot_len > so_rcvbuf) || queue_full(s->incoming)) {
	    netsock_unlock(s);
	    pbuf_free(p);
	    return;
	}
	/* could make a cache if we care to */
	struct udp_entry * e = allocate(s->sock.h, sizeof(*e));
	assert(e != INVALID_ADDRESS);
	e->pbuf = p;
	runtime_memcpy(&e->raddr, &ip_data->current_iphdr_src, sizeof(ip_addr_t));
	e->rport = port;
	assert(enqueue(s->incoming, e));
	s->sock.rx_len += p->tot_len;
	wakeup_sock(s, WAKEUP_SOCK_RX);
    } else {
	msg_err("null pbuf\n");
    }
}

static int allocate_sock(process p, int af, int type, u32 flags, boolean alloc_fd, netsock *rs)
{
    netsock s;
    int fd;

    s = unix_cache_alloc(p->uh, socket);
    if (s == INVALID_ADDRESS) {
	msg_err("failed to allocate struct sock\n");
        goto err_sock;
    }

    heap h = heap_locked(get_kernel_heaps());
    if (socket_init(h, af, type, flags, &s->sock) < 0)
        goto err_sock_init;
    s->sock.f.read = init_closure_func(&s->read, file_io, socket_read);
    s->sock.f.write = init_closure_func(&s->write, file_io, socket_write);
    s->sock.f.writev = init_closure_func(&s->writev, file_iov, socket_writev);
    s->sock.f.close = init_closure_func(&s->close, fdesc_close, socket_close);
    s->sock.f.events = init_closure_func(&s->events, fdesc_events, socket_events);
    s->sock.f.ioctl = init_closure_func(&s->ioctl, fdesc_ioctl, netsock_ioctl);
    s->p = p;

    s->incoming = allocate_queue(h, SOCK_QUEUE_LEN);
    if (s->incoming == INVALID_ADDRESS) {
        msg_err("failed to allocate queue\n");
        goto err_queue;
    }

    s->sock.bind = netsock_bind;
    s->sock.listen = netsock_listen;
    s->sock.connect = netsock_connect;
    s->sock.accept4 = netsock_accept4;
    s->sock.getsockname = netsock_getsockname;
    s->sock.getsockopt = netsock_getsockopt;
    s->sock.setsockopt = netsock_setsockopt;
    s->sock.sendto = netsock_sendto;
    s->sock.recvfrom = netsock_recvfrom;
    s->sock.sendmsg = netsock_sendmsg;
    s->sock.recvmsg = netsock_recvmsg;
    s->sock.shutdown = netsock_shutdown;
    s->ipv6only = 0;
    set_lwip_error(s, ERR_OK);
    if (alloc_fd) {
        fd = s->sock.fd = allocate_fd(p, s);
        if (fd == INVALID_PHYSICAL) {
            apply(s->sock.f.close, 0, io_completion_ignore);
            return -ENFILE;
        }
    } else {
        fd = 0;
    }
    *rs = s;
    return fd;

err_queue:
    socket_deinit(&s->sock);
err_sock_init:
    unix_cache_free(p->uh, socket, s);
err_sock:
    return -ENOMEM;
}

static int allocate_tcp_sock(process p, int af, struct tcp_pcb *pcb, u32 flags)
{
    netsock s;
    int fd = allocate_sock(p, af, SOCK_STREAM, flags, true, &s);
    if (fd >= 0) {
	s->info.tcp.lw = pcb;
	s->info.tcp.flags = pcb->flags & SOCK_TCP_CFG_FLAGS;
	s->info.tcp.state = TCP_SOCK_CREATED;
	tcp_ref(pcb);
    }
    return fd;
}

static int allocate_udp_sock(process p, int af, struct udp_pcb *pcb, u32 flags)
{
    netsock s;
    int fd = allocate_sock(p, af, SOCK_DGRAM, flags, true, &s);
    if (fd >= 0) {
        s->info.udp.lw = pcb;
        s->info.udp.state = UDP_SOCK_CREATED;
        udp_recv(pcb, udp_input_lower, s);
    }
    return fd;
}

sysreturn socket(int domain, int type, int protocol)
{
    switch (domain) {
    case AF_INET:
    case AF_INET6:
        /* Validate protocol/type combination */
        if (protocol) {
            if ((type == SOCK_STREAM && protocol != IP_PROTO_TCP) ||
                (type == SOCK_DGRAM && protocol != IP_PROTO_UDP))
                return -EPROTONOSUPPORT;
        }
        break;
    case AF_UNIX:
        return unixsock_open(type, protocol);
    case AF_NETLINK:
        return netlink_open(type, protocol);
    case AF_VSOCK:
        return vsock_open(type, protocol);
    default:
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
        /* In case of AF_INET6, listen to IPv4 and IPv6 (dual-stack)
         * connections. */
        struct tcp_pcb *p = tcp_new_ip_type((domain == AF_INET) ?
                                            IPADDR_TYPE_V4: IPADDR_TYPE_ANY);
        if (!p)
            return -ENOMEM;

        int fd = allocate_tcp_sock(current->p, domain, p,
            nonblock ? SOCK_NONBLOCK : 0);
        net_debug("new tcp fd %d, pcb %p\n", fd, p);
        return fd;
    } else if (type == SOCK_DGRAM) {
        struct udp_pcb *p = udp_new_ip_type((domain == AF_INET) ?
                                            IPADDR_TYPE_V4: IPADDR_TYPE_ANY);
        if (!p)
            return -ENOMEM;

        int fd = allocate_udp_sock(current->p, domain, p,
            nonblock ? SOCK_NONBLOCK : 0);
        net_debug("new udp fd %d, pcb %p\n", fd, p);
        return fd;
    }
    msg_warn("unsupported socket type %d\n", type);
    return -EINVAL;
}

static err_t tcp_input_lower(void *z, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
    if (!z) {
        return err;
    }
    netsock s = z;
    net_debug("sock %d, pcb %p, buf %p, err %d\n", s->sock.fd, pcb, p, err);

    if (err != ERR_OK) {
        /* shouldn't happen according to lwIP sources; just report */
        msg_err("Unexpected error from lwIP: %d\n", err);
    }

    /* A null pbuf indicates connection closed. */
    netsock_lock(s);
    if (p) {
        if ((s->sock.rx_len + p->tot_len > so_rcvbuf) || !enqueue(s->incoming, p)) {
	    netsock_unlock(s);
	    msg_err("incoming queue full\n");
            return ERR_BUF;     /* XXX verify */
        }
        s->sock.rx_len += p->tot_len;
    }
    wakeup_sock(s, WAKEUP_SOCK_RX);

    return ERR_OK;
}

static sysreturn netsock_bind(struct sock *sock, struct sockaddr *addr,
        socklen_t addrlen)
{
    netsock s = (netsock) sock;
    ip_addr_t ipaddr;
    u16 port;
    sysreturn ret;
    context ctx = get_current_context(current_cpu());
    if (!context_set_err(ctx)) {
        ret = sockaddr_to_addrport(s, addr, addrlen, &ipaddr, &port);
        context_clear_err(ctx);
    } else {
        ret = -EFAULT;
    }
    if (ret)
        goto out;
    if ((s->sock.domain == AF_INET6) && ip6_addr_isany(&ipaddr.u_addr.ip6) &&
            !s->ipv6only)
        /* Allow receiving both IPv4 and IPv6 packets (dual-stack support). */
        IP_SET_TYPE(&ipaddr, IPADDR_TYPE_ANY);
    err_t err;
    netsock_lock(s);
    if (sock->type == SOCK_STREAM) {
	if (!s->info.tcp.lw || (s->info.tcp.lw->local_port != 0)) {
	    ret = -EINVAL;	/* shut down or already bound */
	    goto unlock_out;
	}
	net_debug("calling tcp_bind, pcb %p, port %d\n", s->info.tcp.lw, port);
	err = tcp_bind(s->info.tcp.lw, &ipaddr, port);
    } else {
        if (s->info.udp.lw->local_port != 0) {
            ret = -EINVAL; /* already bound */
            goto unlock_out;
        }
        net_debug("calling udp_bind, pcb %p, port %d\n", s->info.udp.lw, port);
        err = udp_bind(s->info.udp.lw, &ipaddr, port);
    }
    ret = lwip_to_errno(err);
  unlock_out:
    netsock_unlock(s);
  out:
    socket_release(sock);
    return ret;
}

sysreturn bind(int sockfd, struct sockaddr *addr, socklen_t addrlen)
{
    if (!validate_user_memory(addr, addrlen, false))
        return -EFAULT;
    struct sock *s = resolve_socket(current->p, sockfd);
    net_debug("sock %d, type %d\n", sockfd, s->type);
    if (!s->bind) {
        socket_release(s);
        return -EOPNOTSUPP;
    }
    return s->bind(s, addr, addrlen);
}

static void lwip_tcp_conn_err(void * z, err_t err) {
    if (!z) {
        return;
    }
    netsock s = z;
    net_debug("sock %d, err %d\n", s->sock.fd, err);
    netsock_lock(s);
    s->info.tcp.state = TCP_SOCK_UNDEFINED;
    set_lwip_error(s, err);
    wakeup_sock(s, WAKEUP_SOCK_EXCEPT);
}

static err_t lwip_tcp_sent(void * arg, struct tcp_pcb * pcb, u16 len)
{
    if (!arg) {
        return ERR_OK;
    }
    netsock s = (netsock)arg;
    net_debug("fd %d, pcb %p, len %d\n", s->sock.fd, pcb, len);
    netsock_lock(s);
    wakeup_sock(s, WAKEUP_SOCK_TX);
    return ERR_OK;
}

closure_function(2, 1, sysreturn, connect_tcp_bh,
                 netsock, s, thread, t,
                 u64 flags)
{
    sysreturn rv = 0;
    netsock s = bound(s);
    thread t = bound(t);
    if (flags & BLOCKQ_ACTION_BLOCKED)
        netsock_lock(s);
    err_t err = get_lwip_error(s);

    net_debug("sock %d, tcp state %d, thread %ld, lwip_status %d, flags 0x%lx\n",
              s->sock.fd, s->info.tcp.state, t->tid, err, flags);

    rv = lwip_to_errno(err);
    if (flags & BLOCKQ_ACTION_NULLIFY) {
        if (rv == 0) {
            if (s->info.tcp.state == TCP_SOCK_OPEN) {
                /* The connection opened before we could abort; close it. */
                struct tcp_pcb *tcp_lw = s->info.tcp.lw;
                tcp_ref(tcp_lw);
                tcp_arg(tcp_lw, 0);
                s->info.tcp.lw = 0;
                s->info.tcp.state = TCP_SOCK_CREATED;
                netsock_unlock(s);
                tcp_lock(tcp_lw);
                tcp_shutdown(tcp_lw, 1, 1);
                tcp_unlock(tcp_lw);
                tcp_unref(tcp_lw);
                goto out;
            } else {
                assert(s->info.tcp.state == TCP_SOCK_IN_CONNECTION);
                s->info.tcp.state = TCP_SOCK_ABORTING_CONNECTION;
            }
            rv = -ERESTARTSYS;
        }
        goto unlock_out;
    }

    if (s->info.tcp.state == TCP_SOCK_IN_CONNECTION) {
        if (s->sock.f.flags & SOCK_NONBLOCK) {
            rv = -EINPROGRESS;
            goto unlock_out;
        }
        netsock_unlock(s);
        return blockq_block_required(&t->syscall->uc, flags);
    }
    assert(s->info.tcp.state == TCP_SOCK_OPEN);
  unlock_out:
    if (flags & BLOCKQ_ACTION_BLOCKED)
        netsock_unlock(s);
  out:
    if (flags & BLOCKQ_ACTION_BLOCKED)
        socket_release(&s->sock);
    closure_finish();
    return syscall_return(t, rv);
}

static err_t connect_tcp_complete(void* arg, struct tcp_pcb* tpcb, err_t err)
{
   if (!arg)
      return ERR_OK;
   netsock s = (netsock)arg;
   netsock_lock(s);
   net_debug("sock %d, tcp state %d, pcb %p, err %d\n", s->sock.fd,
           s->info.tcp.state, tpcb, err);
   if (s->info.tcp.state == TCP_SOCK_ABORTING_CONNECTION) {
       s->info.tcp.state = TCP_SOCK_CREATED;
       netsock_unlock(s);
       return ERR_ABRT;
   }
   assert(s->info.tcp.state == TCP_SOCK_IN_CONNECTION);
   s->info.tcp.state = TCP_SOCK_OPEN;
   set_lwip_error(s, err);
   wakeup_sock(s, WAKEUP_SOCK_TX);
   return ERR_OK;
}

static inline sysreturn connect_tcp(netsock s, const ip_addr_t* address,
                                    unsigned short port)
{
    sysreturn rv;
    net_debug("sock %d, tcp state %d, port %d\n", s->sock.fd,
            s->info.tcp.state, port);
    struct tcp_pcb * lw = s->info.tcp.lw;
    switch (s->info.tcp.state) {
    case TCP_SOCK_IN_CONNECTION:
    case TCP_SOCK_ABORTING_CONNECTION:
        rv = -EALREADY;
        goto out;
    case TCP_SOCK_OPEN:
        rv = -EISCONN;
        goto out;
    case TCP_SOCK_CREATED:
        break;
    default:
        rv = -EINVAL;
        goto out;
    }
    tcp_lock(lw);
    tcp_arg(lw, s);
    tcp_recv(lw, tcp_input_lower);
    tcp_err(lw, lwip_tcp_conn_err);
    tcp_sent(lw, lwip_tcp_sent);
    s->info.tcp.state = TCP_SOCK_IN_CONNECTION;
    set_lwip_error(s, ERR_OK);
    err_t err = tcp_connect(lw, address, port, connect_tcp_complete);
    tcp_unlock(lw);
    if (err != ERR_OK)
        return lwip_to_errno(err);
    netsock_check_loop();

    return blockq_check(s->sock.txbq,
                        contextual_closure(connect_tcp_bh, s, current), false);
  out:
    return rv;
}

static sysreturn netsock_connect(struct sock *sock, struct sockaddr *addr,
        socklen_t addrlen)
{
    netsock s = (netsock) sock;
    ip_addr_t ipaddr;
    u16 port;
    sysreturn ret;
    context ctx = get_current_context(current_cpu());
    if (!context_set_err(ctx)) {
        ret = sockaddr_to_addrport(s, addr, addrlen, &ipaddr, &port);
        context_clear_err(ctx);
    } else {
        ret = -EFAULT;
    }
    if (ret)
        goto out;
    netsock_lock(s);
    if (s->sock.type == SOCK_STREAM) {
        if (s->info.tcp.state == TCP_SOCK_IN_CONNECTION) {
            ret = -EALREADY;
        } else if (s->info.tcp.state == TCP_SOCK_OPEN) {
            ret = -EISCONN;
        } else if (s->info.tcp.state == TCP_SOCK_LISTENING) {
            msg_warn("attempt to connect on listening socket fd = %d; ignored\n", sock->fd);
            ret = -EINVAL;
        } else {
            ret = connect_tcp(s, &ipaddr, port);
        }
    } else {
        /* Set remote endpoint */
        ret = lwip_to_errno(udp_connect(s->info.udp.lw, &ipaddr, port));
    }
    netsock_unlock(s);
  out:
    socket_release(sock);
    return ret;
}

sysreturn connect(int sockfd, struct sockaddr *addr, socklen_t addrlen)
{
    if (!validate_user_memory(addr, addrlen, false))
        return -EFAULT;
    struct sock *sock = resolve_socket(current->p, sockfd);
    if (!sock->connect) {
        socket_release(sock);
        return -EOPNOTSUPP;
    }
    return sock->connect(sock, addr, addrlen);
}

static sysreturn sendto_prepare(struct sock *sock, int flags)
{
    /* Process flags */
    if (flags & MSG_CONFIRM)
	msg_warn("MSG_CONFIRM unimplemented; ignored\n");

    if (flags & MSG_DONTROUTE)
	msg_warn("MSG_DONTROUTE unimplemented; ignored\n");

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

    return 0;
}

static sysreturn netsock_sendto(struct sock *sock, void *buf, u64 len,
                                int flags, struct sockaddr *dest_addr, socklen_t addrlen,
                                context ctx, boolean in_bh, io_completion completion)
{
    sysreturn rv = sendto_prepare(sock, flags);
    if (rv < 0) {
        return io_complete(completion, rv);
    }
    return socket_write_internal(sock, buf, 0, len, flags, dest_addr, addrlen,
                                 ctx, in_bh, completion);
}

sysreturn sendto(int sockfd, void *buf, u64 len, int flags,
		 struct sockaddr *dest_addr, socklen_t addrlen)
{
    if (!validate_user_memory(buf, len, false) ||
            (dest_addr && !validate_user_memory(dest_addr, addrlen, false)))
        return -EFAULT;
    struct sock *sock = resolve_socket(current->p, sockfd);
    net_debug("sendto %d, buf %p, len %ld, flags %x, dest_addr %p, addrlen %d\n",
              sockfd, buf, len, flags, dest_addr, addrlen);

    if (!sock->sendto) {
        socket_release(sock);
        return -EOPNOTSUPP;
    }
    context ctx = get_current_context(current_cpu());
    io_completion completion = (io_completion)&sock->f.io_complete;
    return sock->sendto(sock, buf, len, flags, dest_addr, addrlen, ctx, false, completion);
}

sysreturn socket_send(fdesc f, void *buf, u64 len, context ctx, boolean in_bh,
                      io_completion completion)
{
    if (f->type != FDESC_TYPE_SOCKET)
        return io_complete(completion, -ENOTSOCK);
    if (!validate_user_memory(buf, len, false))
        return io_complete(completion, -EFAULT);
    struct sock *sock = struct_from_field(f, struct sock *, f);
    return sock->sendto(sock, buf, len, 0, 0, 0, ctx, in_bh, completion);
}

static sysreturn netsock_sendmsg(struct sock *s, const struct msghdr *msg, int flags,
                                 boolean in_bh, io_completion completion)
{
    sysreturn rv = sendto_prepare(s, flags);
    if (rv < 0)
        goto out;
    return socket_write_internal(s, 0, msg->msg_iov, msg->msg_iovlen, flags,
                                 msg->msg_name, msg->msg_namelen,
                                 get_current_context(current_cpu()), in_bh, completion);
  out:
    return io_complete(completion, rv);
}

sysreturn sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
    if (!validate_msghdr(msg, false))
        return -EFAULT;
    struct sock *s = resolve_socket(current->p, sockfd);
    net_debug("sock %d, type %d, msg %p, flags 0x%x\n", s->fd, s->type, msg, flags);
    if (!s->sendmsg) {
        socket_release(s);
        return -EOPNOTSUPP;
    }
    return s->sendmsg(s, msg, flags, false, (io_completion)&s->f.io_complete);
}

declare_closure_struct(0, 0, void, sendmmsg_next);

closure_function(6, 1, void, sendmmsg_complete,
                 struct sock *, s, struct mmsghdr *, msgvec, unsigned int, vlen, int, flags, unsigned int, index, closure_struct_type(sendmmsg_next), next,
                 sysreturn rv)
{
    struct sock *s = bound(s);
    if (rv < 0)
        goto out;
    struct mmsghdr *hdr = &bound(msgvec)[bound(index)];
    int msg_len = rv;
    if (!set_user_value(&hdr->msg_len, msg_len)) {
        rv = -EFAULT;
        goto out;
    }
    bound(index)++;
    if (bound(index) < bound(vlen)) {
        enqueue(runqueue, &bound(next));
        return;
    }
  out:
    if (bound(index) > 0)
        rv = bound(index);
    closure_finish();
    socket_release(s);
    apply(syscall_io_complete, rv);
}

define_closure_function(0, 0, void, sendmmsg_next)
{
    closure_ref(sendmmsg_complete, completion) =
        struct_from_field(closure_self(), closure_struct_type(sendmmsg_complete) *, next);
    struct mmsghdr *hdr = &completion->msgvec[completion->index];
    completion->s->sendmsg(completion->s, &hdr->msg_hdr, completion->flags, true,
        (io_completion)completion);
}

sysreturn sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen,
        int flags)
{
    if (vlen == 0)
        return 0;
    if (!validate_user_memory(msgvec, vlen * sizeof(struct mmsghdr), true))
        return -EFAULT;
    for (int i = 0; i < vlen; i++) {
        if (!validate_msghdr(&msgvec[i].msg_hdr, false))
            return -EFAULT;
    }
    thread t = current;
    struct sock *s = resolve_socket(t->p, sockfd);

    net_debug("sock %d, type %d, flags 0x%x, vlen %d\n", s->fd, s->type, flags, vlen);
    closure_struct(sendmmsg_next, next);
    contextual_closure_init(sendmmsg_next, &next);
    io_completion completion = contextual_closure(sendmmsg_complete,
                                                  s, msgvec, vlen, flags, 0, next);
    if (completion == INVALID_ADDRESS) {
        socket_release(s);
        return -ENOMEM;
    }
    s->sendmsg(s, &msgvec->msg_hdr, flags, false, completion);
    return thread_maybe_sleep_uninterruptible(t);
}

static sysreturn netsock_recvfrom(struct sock *sock, void *buf, u64 len,
                                  int flags, struct sockaddr *src_addr, socklen_t *addrlen,
                                  context ctx, boolean in_bh, io_completion completion)
{
    netsock s = (netsock) sock;
    sysreturn rv;
    if (sock->type == SOCK_STREAM && s->info.tcp.state != TCP_SOCK_OPEN) {
        rv = (s->info.tcp.state == TCP_SOCK_UNDEFINED) ? 0 : -ENOTCONN;
        goto out;
    }

    if (len == 0) {
        rv = 0;
        goto out;
    }

    blockq_action ba = closure_from_context(ctx, sock_read_bh, s, buf, len, flags,
                                            src_addr, addrlen, completion);
    if (ba == INVALID_ADDRESS) {
        rv = -ENOMEM;
        goto out;
    }
    return blockq_check(sock->rxbq, ba, in_bh);
  out:
    return io_complete(completion, rv);
}

sysreturn recvfrom(int sockfd, void * buf, u64 len, int flags,
		   struct sockaddr *src_addr, socklen_t *addrlen)
{
    /* Use a dummy value for the address length, instead of reading it from addrlen (the value
     * pointed to by addrlen might change before this syscall completes). */
    if (src_addr && (!validate_user_memory(addrlen, sizeof(socklen_t), true) ||
                     !validate_user_memory(src_addr, PAGESIZE, true)))
        return -EFAULT;

    struct sock *sock = resolve_socket(current->p, sockfd);
    net_debug("sock %d, type %d, thread %ld, buf %p, len %ld\n", sock->fd,
            sock->type, current->tid, buf, len);

    if (!sock->recvfrom) {
        socket_release(sock);
        return -EOPNOTSUPP;
    }
    context ctx = get_current_context(current_cpu());
    io_completion completion = (io_completion)&sock->f.io_complete;
    return sock->recvfrom(sock, buf, len, flags, src_addr, addrlen, ctx, false, completion);
}

sysreturn socket_recv(fdesc f, void *buf, u64 len, context ctx, boolean in_bh,
                      io_completion completion)
{
    if (f->type != FDESC_TYPE_SOCKET)
        return io_complete(completion, -ENOTSOCK);
    if (!validate_user_memory(buf, len, true))
        return io_complete(completion, -EFAULT);
    struct sock *sock = struct_from_field(f, struct sock *, f);
    return sock->recvfrom(sock, buf, len, 0, 0, 0, ctx, in_bh, completion);
}

static sysreturn netsock_recvmsg(struct sock *sock, struct msghdr *msg,
                                 int flags, boolean in_bh, io_completion completion)
{
    netsock s = (netsock) sock;
    sysreturn rv;

    if ((sock->type == SOCK_STREAM) && (s->info.tcp.state != TCP_SOCK_OPEN)) {
        rv = (s->info.tcp.state == TCP_SOCK_UNDEFINED) ? 0 : -ENOTCONN;
        goto out;
    }
    blockq_action ba = contextual_closure(recvmsg_bh, s, msg, flags, completion);
    return blockq_check(sock->rxbq, ba, in_bh);
  out:
    return io_complete(completion, rv);
}

sysreturn recvmsg(int sockfd, struct msghdr *msg, int flags)
{
    if (!validate_msghdr(msg, true))
        return -EFAULT;
    struct sock *s = resolve_socket(current->p, sockfd);
    net_debug("sock %d, type %d, thread %ld\n", s->fd, s->type, current->tid);
    if (!s->recvmsg) {
        socket_release(s);
        return -EOPNOTSUPP;
    }
    return s->recvmsg(s, msg, flags, false, (io_completion)&s->f.io_complete);
}

declare_closure_struct(0, 0, void, recvmmsg_next);

closure_function(6, 1, void, recvmmsg_complete,
                 struct sock *, s, struct mmsghdr *, msgvec, unsigned int, vlen, int, flags, unsigned int, index, closure_struct_type(recvmmsg_next), next,
                 sysreturn rv)
{
    struct sock *s = bound(s);
    if (rv < 0)
        goto out;
    struct mmsghdr *msgvec = bound(msgvec);
    struct mmsghdr *hdr = &msgvec[bound(index)];
    int msg_len = rv;
    if (!set_user_value(&hdr->msg_len, msg_len)) {
        rv = -EFAULT;
        goto out;
    }
    bound(index)++;
    if (bound(index) < bound(vlen)) {
        if (bound(flags) & MSG_WAITFORONE)
            bound(flags) = (bound(flags) & ~MSG_WAITFORONE) | MSG_DONTWAIT;
        enqueue(runqueue, &bound(next));
        return;
    }
  out:
    if (bound(index) > 0)
        rv = bound(index);
    closure_finish();
    socket_release(s);
    apply(syscall_io_complete, rv);
}

define_closure_function(0, 0, void, recvmmsg_next)
{
    closure_ref(recvmmsg_complete, completion) =
        struct_from_field(closure_self(), closure_struct_type(recvmmsg_complete) *, next);
    struct mmsghdr *hdr = &completion->msgvec[completion->index];
    completion->s->recvmsg(completion->s, &hdr->msg_hdr, completion->flags, true,
        (io_completion)completion);
}

sysreturn recvmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags,
                   struct timespec *timeout)
{
    if (!validate_user_memory(msgvec, vlen * sizeof(struct mmsghdr), true))
        return -EFAULT;
    for (int i = 0; i < vlen; i++) {
        if (!validate_msghdr(&msgvec[i].msg_hdr, true))
            return -EFAULT;
    }
    if (vlen == 0)
        return 0;
    if (timeout)
        return -EOPNOTSUPP;
    thread t = current;
    struct sock *s = resolve_socket(t->p, sockfd);
    net_debug("sock %d, type %d, flags 0x%x, vlen %d\n", s->fd, s->type, flags, vlen);
    closure_struct(recvmmsg_next, next);
    contextual_closure_init(recvmmsg_next, &next);
    io_completion completion = contextual_closure(recvmmsg_complete,
                                                  s, msgvec, vlen, flags, 0, next);
    if (completion == INVALID_ADDRESS) {
        socket_release(s);
        return -ENOMEM;
    }
    s->recvmsg(s, &msgvec->msg_hdr, flags & ~MSG_WAITFORONE, false, completion);
    return thread_maybe_sleep_uninterruptible(t);
}

static err_t accept_tcp_from_lwip(void * z, struct tcp_pcb * lw, err_t err)
{
    if (!z) {
        return ERR_CLSD;
    }
    netsock s = z;
    netsock_lock(s);

    if (err == ERR_MEM) {
        set_lwip_error(s, err);
        wakeup_sock(s, WAKEUP_SOCK_EXCEPT);
        return err;               /* lwIP doesn't care */
    }

    netsock sn;
    int rv = allocate_sock(s->p, s->sock.domain, SOCK_STREAM, 0, false, &sn);
    if (rv < 0) {
        err = ERR_MEM;
        goto unlock_out;
    }

    net_debug("new socket %p, pcb %p\n", sn, lw);
    sn->info.tcp.lw = lw;
    tcp_ref(lw);
    sn->info.tcp.state = TCP_SOCK_OPEN;
    set_lwip_error(s, ERR_OK);
    tcp_arg(lw, sn);
    tcp_recv(lw, tcp_input_lower);
    tcp_err(lw, lwip_tcp_conn_err);
    tcp_sent(lw, lwip_tcp_sent);
    if (!enqueue(s->incoming, sn)) {
        msg_err("queue overrun; shouldn't happen with lwIP listen backlog\n");
        err = ERR_BUF;      /* lwIP will do tcp_abort */
        goto unlock_out;
    }

    /* consume a slot in the lwIP listen backlog */
    tcp_backlog_delayed(lw);

    wakeup_sock(s, WAKEUP_SOCK_RX);
    return ERR_OK;
  unlock_out:
    netsock_unlock(s);
    return err;
}

static sysreturn netsock_listen(struct sock *sock, int backlog)
{
    netsock s = (netsock) sock;
    sysreturn rv;
    netsock_lock(s);
    backlog = MIN(backlog, SOCK_QUEUE_LEN);
    if (s->sock.type != SOCK_STREAM) {
        rv = -EOPNOTSUPP;
        goto unlock_out;
    }
    if (s->info.tcp.state != TCP_SOCK_CREATED) {
        if (s->info.tcp.state == TCP_SOCK_LISTENING) {
            tcp_backlog_set(s->info.tcp.lw, backlog);
            rv = 0;
        } else {
            rv = -EINVAL;
        }
        goto unlock_out;
    }
    err_t err;
    struct tcp_pcb * lw = tcp_listen_with_backlog_and_err(s->info.tcp.lw, backlog, &err);
    if (!lw) {
        rv = lwip_to_errno(err);
        goto unlock_out;
    }
    tcp_unref(s->info.tcp.lw);
    tcp_ref(lw);
    s->info.tcp.lw = lw;
    s->info.tcp.state = TCP_SOCK_LISTENING;
    set_lwip_error(s, ERR_OK);
    tcp_arg(lw, s);
    tcp_accept(lw, accept_tcp_from_lwip);
    rv = 0;
  unlock_out:
    netsock_unlock(s);
    socket_release(sock);
    return rv;
}

sysreturn listen(int sockfd, int backlog)
{
    net_debug("sock %d, backlog %d\n", sockfd, backlog);
    struct sock *sock = resolve_socket(current->p, sockfd);
    if (!sock->listen) {
        socket_release(sock);
        return -EOPNOTSUPP;
    }
    return sock->listen(sock, backlog);
}

closure_function(5, 1, sysreturn, accept_bh,
                 netsock, s, struct sockaddr *, addr, socklen_t *, addrlen, int, flags, io_completion, completion,
                 u64 bqflags)
{
    netsock s = bound(s);
    netsock child = INVALID_ADDRESS;
    sysreturn rv = 0;

    err_t err = get_lwip_error(s);
    net_debug("sock %d, lwip err %d\n", s->sock.fd,
            err);

    if (err != ERR_OK) {
        rv = lwip_to_errno(err);
        goto out;
    }

    if (bqflags & BLOCKQ_ACTION_NULLIFY) {
        rv = -ERESTARTSYS;
        goto out;
    }

    context ctx = context_from_closure(closure_self());
    child = dequeue(s->incoming);
    if (child == INVALID_ADDRESS) {
        if (s->sock.f.flags & SOCK_NONBLOCK) {
            rv = -EAGAIN;
            goto out;
        }
        return blockq_block_required((unix_context)ctx, bqflags);   /* block */
    }

    if (bound(addr) &&
        (!fault_in_memory(bound(addrlen), sizeof(socklen_t)) ||
         !fault_in_memory(bound(addr), *bound(addrlen)))) {
        rv = -EFAULT;
        goto out;
    }
    netsock_lock(child);
    child->sock.f.flags |= bound(flags);
    if (bound(addr)) {
        if (context_set_err(ctx)) {
            netsock_unlock(child);
            rv = -EFAULT;
            goto out;
        }
        if (child->info.tcp.state == TCP_SOCK_OPEN)
            remote_sockaddr(child, bound(addr), bound(addrlen));
        else
            /* The new socket is disconnected already, we can't retrieve the address of the remote
             * peer. */
            addrport_to_sockaddr(child->sock.domain, (ip_addr_t *)IP_ADDR_ANY, 0,
                bound(addr), bound(addrlen));
        context_clear_err(ctx);
    }

    /* report falling edge in case of edge trigger */
    if (queue_length(s->incoming) == 0)
        fdesc_notify_events(&s->sock.f);

    /* TCP flags are inherited from listen socket. */
    child->info.tcp.flags = s->info.tcp.flags;

    struct tcp_pcb *tcp_lw = child->info.tcp.lw;
    if (tcp_lw)
        tcp_ref(tcp_lw);
    netsock_unlock(child);

    /* release slot in lwIP listen backlog */
    if (tcp_lw) {
        tcp_lock(tcp_lw);
        tcp_backlog_accepted(tcp_lw);
        tcp_lw->flags = (tcp_lw->flags & ~SOCK_TCP_CFG_FLAGS) |
                        (child->info.tcp.flags & SOCK_TCP_CFG_FLAGS);
        tcp_unlock(tcp_lw);
        tcp_unref(tcp_lw);
    }

    rv = allocate_fd(child->p, child);
    if (rv == INVALID_PHYSICAL)
        rv = -ENFILE;
    else
        child->sock.fd = rv;
  out:
    if ((rv < 0) && (child != INVALID_ADDRESS))
        apply(child->sock.f.close, 0, io_completion_ignore);
    apply(bound(completion), rv);

    closure_finish();
    return rv;
}

static sysreturn netsock_accept4(struct sock *sock, struct sockaddr *addr,
                                 socklen_t *addrlen, int flags, context ctx, boolean in_bh,
                                 io_completion completion)
{
    netsock s = (netsock) sock;
    sysreturn rv;
    if (sock->type != SOCK_STREAM) {
        rv = -EOPNOTSUPP;
        goto out;
    }

    if ((s->info.tcp.state != TCP_SOCK_LISTENING) ||
        (flags & ~SOCK_FLAGS_MASK)) {
        rv = -EINVAL;
        goto out;
    }

    blockq_action ba = closure_from_context(ctx, accept_bh, s, addr, addrlen, flags, completion);
    if (ba == INVALID_ADDRESS) {
        rv = -ENOMEM;
        goto out;
    }
    return blockq_check(sock->rxbq, ba, in_bh);
  out:
    return io_complete(completion, rv);
}

sysreturn accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen,
        int flags)
{
    net_debug("sock %d, addr %p, addrlen %p, flags %x\n", sockfd, addr, addrlen,
            flags);
    fdesc f = resolve_fd(current->p, sockfd);
    context ctx = get_current_context(current_cpu());
    return socket_accept4(f, addr, addrlen, flags, ctx, false, (io_completion)&f->io_complete);
}

sysreturn socket_accept4(fdesc f, struct sockaddr *addr, socklen_t *addrlen, int flags, context ctx,
                         boolean in_bh, io_completion completion)
{
    if (f->type != FDESC_TYPE_SOCKET)
        return io_complete(completion, -ENOTSOCK);

    /* Use a dummy value for the address length, instead of reading it from addrlen (the value
     * pointed to by addrlen might change before this syscall completes). */
    if (addr && (!validate_user_memory(addrlen, sizeof(socklen_t), true) ||
                 !validate_user_memory(addr, PAGESIZE, true)))
        return io_complete(completion, -EFAULT);

    struct sock *sock = struct_from_field(f, struct sock *, f);
    if (!sock->accept4) {
        return io_complete(completion, -EOPNOTSUPP);
    }
    return sock->accept4(sock, addr, addrlen, flags, ctx, in_bh, completion);
}

sysreturn accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    return accept4(sockfd, addr, addrlen, 0);
}

static sysreturn netsock_getsockname(struct sock *sock, struct sockaddr *addr, socklen_t *addrlen)
{
    netsock s = get_netsock(sock);
    struct tcp_pcb *tcp_lw = 0;
    ip_addr_t *ip_addr;
    u16_t port;
    sysreturn rv;
    if (s->sock.type == SOCK_STREAM) {
        tcp_lw = netsock_tcp_get(s);
        if (tcp_lw) {
            port = tcp_lw->local_port;
            ip_addr = &tcp_lw->local_ip;
        } else {
            /* The socket has been shut down; since we can't retrieve its local address, pretend
             * it's not bound to any address. */
            port = 0;
            ip_addr = (ip_addr_t *)IP_ADDR_ANY;
        }
    } else {
        netsock_lock(s);
        port = s->info.udp.lw->local_port;
        ip_addr = &s->info.udp.lw->local_ip;
    }
    addrport_to_sockaddr(s->sock.domain, ip_addr, port, addr, addrlen);
    rv = 0;
    if (s->sock.type == SOCK_STREAM) {
        if (tcp_lw)
            netsock_tcp_put(tcp_lw);
    } else {
        netsock_unlock(s);
    }
    socket_release(sock);
    return rv;
}

sysreturn getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    net_debug("sock %d, addr %p, addrlen %p\n", sockfd, addr, addrlen);
    if (!fault_in_user_memory(addrlen, sizeof(socklen_t), true) ||
        !fault_in_user_memory(addr, *addrlen, true))
        return -EFAULT;
    struct sock *sock = resolve_socket(current->p, sockfd);
    if (!sock->getsockname) {
        socket_release(sock);
        return -EOPNOTSUPP;
    }
    return sock->getsockname(sock, addr, addrlen);
}

sysreturn getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    if (!fault_in_user_memory(addrlen, sizeof(socklen_t), true) ||
        !fault_in_user_memory(addr, *addrlen, true))
        return -EFAULT;
    struct sock *sock = resolve_socket(current->p, sockfd);
    sysreturn rv = 0;
    netsock s = get_netsock(sock);
    if (!s) {
        rv = -EOPNOTSUPP;
    } else {
        netsock_lock(s);
        if ((s->sock.type == SOCK_STREAM) && (s->info.tcp.state != TCP_SOCK_OPEN))
            rv = -ENOTCONN;
        else
            remote_sockaddr(s, addr, addrlen);
        netsock_unlock(s);
    }
    socket_release(sock);
    return rv;
}

static sysreturn netsock_setsockopt(struct sock *sock, int level,
                                    int optname, void *optval, socklen_t optlen)
{
    netsock s = (netsock)sock;
    int int_optval;
    sysreturn rv;
    switch (level) {
    case IPPROTO_IP:
        switch (optname) {
        case IP_MTU_DISCOVER:
            rv = sockopt_copy_from_user(optval, optlen, &int_optval, sizeof(int));
            if (rv)
                goto out;
            if (s->sock.type == SOCK_STREAM) {
                struct tcp_pcb *tcp_lw = netsock_tcp_get(s);
                tcp_lw->pmtudisc = int_optval;
                netsock_tcp_put(tcp_lw);
            } else {
                s->info.udp.lw->pmtudisc = int_optval;
            }
            break;
        default:
            goto unimplemented;
        }
        break;
    case IPPROTO_IPV6:
        switch (optname) {
        case IPV6_V6ONLY:
            rv = sockopt_copy_from_user(optval, optlen, &int_optval, sizeof(int));
            if (rv)
                goto out;
            s->ipv6only = int_optval;
            break;
        default:
            goto unimplemented;
        }
        break;
    case SOL_SOCKET:
        switch (optname) {
        case SO_REUSEADDR:
        case SO_KEEPALIVE:
        case SO_BROADCAST:
            rv = sockopt_copy_from_user(optval, optlen, &int_optval, sizeof(int));
            if (rv)
                goto out;
            u8 so_option = (optname == SO_REUSEADDR ? SOF_REUSEADDR :
                            (optname == SO_KEEPALIVE ? SOF_KEEPALIVE : SOF_BROADCAST));
            if (s->sock.type == SOCK_STREAM) {
                struct tcp_pcb *tcp_lw = netsock_tcp_get(s);
                if (tcp_lw) {
                    if (int_optval)
                        ip_set_option(tcp_lw, so_option);
                    else
                        ip_reset_option(tcp_lw, so_option);
                    netsock_tcp_put(tcp_lw);
                } else {
                    rv = -EINVAL;
                    goto out;
                }
            } else if (s->sock.type == SOCK_DGRAM) {
                netsock_lock(s);
                if (int_optval)
                    ip_set_option(s->info.udp.lw, so_option);
                else
                    ip_reset_option(s->info.udp.lw, so_option);
                netsock_unlock(s);
            }
            break;
        case SO_REUSEPORT:
            goto unimplemented;
        default:
            goto unimplemented;
        }
        break;
    case SOL_TCP:
        switch (optname) {
        case TCP_NODELAY:
            if ((s->sock.type != SOCK_STREAM)) {
                rv = -EINVAL;
                goto out;
            }
            rv = sockopt_copy_from_user(optval, optlen, &int_optval, sizeof(int));
            if (rv)
                goto out;
            netsock_lock(s);
            struct tcp_pcb *tcp_lw = s->info.tcp.lw;
            if (tcp_lw && (s->info.tcp.state != TCP_SOCK_LISTENING)) {
                tcp_ref(tcp_lw);
                netsock_unlock(s);
                tcp_lock(tcp_lw);
                if (int_optval)
                    tcp_nagle_disable(tcp_lw);
                else
                    tcp_nagle_enable(tcp_lw);
                tcp_unlock(tcp_lw);
                tcp_unref(tcp_lw);
            } else {
                if (int_optval)
                    s->info.tcp.flags |= TF_NODELAY;
                else
                    s->info.tcp.flags &= ~TF_NODELAY;
                netsock_unlock(s);
            }
            break;
        default:
            goto unimplemented;
        }
        break;
    default:
        goto unimplemented;
    }
    rv = 0;
    goto out;
unimplemented:
    msg_warn("setsockopt unimplemented: fd %d, level %d, optname %d\n",
             sock->fd, level, optname);
    rv = 0;
out:
    socket_release(sock);
    return rv;
}

static void netsock_get_tcpinfo(netsock s, struct tcp_info *info)
{
    zero(info, sizeof(*info));
    struct tcp_pcb *lw = s->info.tcp.lw;
    tcp_lock(lw);
    u8 *state = &info->tcpi_state;
    switch (lw->state) {
    case CLOSED:
        *state = TCP_CLOSE;
        break;
    case LISTEN:
        *state = TCP_LISTEN;
        info->tcpi_unacked = ((struct tcp_pcb_listen *)lw)->accepts_pending;
        info->tcpi_sacked = ((struct tcp_pcb_listen *)lw)->backlog;
        tcp_unlock(lw);
        return;
    case SYN_SENT:
        *state = TCP_SYN_SENT;
        break;
    case SYN_RCVD:
        *state = TCP_SYN_RECV;
        break;
    case ESTABLISHED:
        *state = TCP_ESTABLISHED;
        break;
    case FIN_WAIT_1:
        *state = TCP_FIN_WAIT1;
        break;
    case FIN_WAIT_2:
        *state = TCP_FIN_WAIT2;
        break;
    case CLOSE_WAIT:
        *state = TCP_CLOSE_WAIT;
        break;
    case CLOSING:
        *state = TCP_CLOSING;
        break;
    case LAST_ACK:
        *state = TCP_LAST_ACK;
        break;
    case TIME_WAIT:
        *state = TCP_TIME_WAIT;
        break;
    }
    info->tcpi_ca_state = (lw->flags & TF_INFR) ? TCP_CA_Recovery : TCP_CA_Open;
    info->tcpi_retransmits = lw->nrtx;
    info->tcpi_probes = lw->persist_probe;
    info->tcpi_backoff = lw->persist_backoff;
#if LWIP_TCP_TIMESTAMPS
    if (lw->flags & TF_TIMESTAMP)
        info->tcpi_options |= TCPI_OPT_TIMESTAMPS;
#endif
#if LWIP_TCP_SACK_OUT
    if (lw->flags & TF_SACK)
        info->tcpi_options |= TCPI_OPT_SACK;
#endif
    if (lw->flags & TF_WND_SCALE)
        info->tcpi_options |= TCPI_OPT_WSCALE;
    info->tcpi_snd_wscale = lw->snd_scale;
    info->tcpi_rcv_wscale = lw->rcv_scale;
    info->tcpi_rto = lw->rto * TCP_SLOW_INTERVAL * 1000;    /* microseconds */
    info->tcpi_snd_mss = info->tcpi_rcv_mss = tcp_mss(lw);
    struct tcp_seg *unacked = lw->unacked;
    while (unacked) {
        info->tcpi_unacked++;
        unacked = unacked->next;
    }
#if LWIP_TCP_SACK_OUT
    struct tcp_sack_range *sacks = *lw->rcv_sacks;
    for (int i = 0; (i < LWIP_TCP_MAX_SACK_NUM) && LWIP_TCP_SACK_VALID(lw, i); i++)
        info->tcpi_sacked += sacks[i].right - sacks[i].left;
#endif
    info->tcpi_retrans = lw->nrtx;
    info->tcpi_rcv_ssthresh = info->tcpi_snd_ssthresh = lw->ssthresh;
    info->tcpi_rtt = info->tcpi_rcv_rtt = info->tcpi_min_rtt =
            lw->rttest * TCP_SLOW_INTERVAL * 1000;  /* microseconds */
    info->tcpi_snd_cwnd = lw->cwnd;
    info->tcpi_advmss = lw->mss;
    info->tcpi_rcv_space = so_rcvbuf - s->sock.rx_len;
    info->tcpi_notsent_bytes = lw->snd_lbb - lw->snd_nxt;
    struct tcp_seg *ooo = lw->ooseq;
    while (ooo) {
        info->tcpi_rcv_ooopack++;
        ooo = ooo->next;
    }
    info->tcpi_snd_wnd = lw->snd_wnd_max;
    tcp_unlock(lw);
}

static sysreturn netsock_getsockopt(struct sock *sock, int level,
                                    int optname, void *optval, socklen_t *optlen)
{
    netsock s = (netsock)sock;
    sysreturn rv;
    net_debug("sock %d, type %d, thread %ld, level %d, optname %d\n, optlen %d\n",
        s->sock.fd, s->sock.type, current->tid, level, optname,
        optlen ? *optlen : -1);

    union {
        int val;
        struct linger linger;
        char str[16];
        struct tcp_info tcp_info;
    } ret_optval;
    int ret_optlen = sizeof(ret_optval.val);

    switch (level) {
    case SOL_SOCKET:
        switch (optname) {
        case SO_TYPE:
            ret_optval.val = s->sock.type;
            break;
        case SO_ERROR:
            ret_optval.val = -lwip_to_errno(get_and_clear_lwip_error(s));
            break;
        case SO_SNDBUF:
            ret_optval.val = (s->sock.type == SOCK_STREAM) ? TCP_SND_BUF : 0;
            break;
        case SO_RCVBUF:
            ret_optval.val = so_rcvbuf;
            break;
        case SO_PRIORITY:
            ret_optval.val = 0; /* default value in Linux */
            break;
        case SO_LINGER:
            ret_optval.linger.l_onoff = 0;
            ret_optval.linger.l_linger = 0;
            ret_optlen = sizeof(ret_optval.linger);
            break;
        case SO_ACCEPTCONN:
            ret_optval.val = (s->sock.type == SOCK_STREAM) && (s->info.tcp.state == TCP_SOCK_LISTENING);
            break;
        case SO_REUSEADDR:
        case SO_KEEPALIVE:
        case SO_BROADCAST: {
            u8 so_option = (optname == SO_REUSEADDR ? SOF_REUSEADDR :
                            (optname == SO_KEEPALIVE ? SOF_KEEPALIVE : SOF_BROADCAST));
            netsock_lock(s);
            if ((s->sock.type == SOCK_STREAM) && s->info.tcp.lw) {
                ret_optval.val = !!ip_get_option(s->info.tcp.lw, so_option);
            } else if (s->sock.type == SOCK_DGRAM) {
                ret_optval.val = !!ip_get_option(s->info.udp.lw, so_option);
            } else {
                netsock_unlock(s);
                rv = -EINVAL;
                goto out;
            }
            netsock_unlock(s);
            break;
        }
        case SO_REUSEPORT:
            ret_optval.val = 0;
            break;
        case SO_PROTOCOL:
            ret_optval.val = s->sock.type == SOCK_STREAM ? IP_PROTO_TCP : IP_PROTO_UDP;
            break;
        case SO_DOMAIN:
            ret_optval.val = s->sock.domain;
            break;
        default:
            goto unimplemented;
        }
        break;
    case SOL_TCP:
        if (s->sock.type != SOCK_STREAM) {
            rv = -EOPNOTSUPP;
            goto out;
        }
        switch (optname) {
        case TCP_NODELAY:
            netsock_lock(s);
            if (s->info.tcp.lw && (s->info.tcp.state != TCP_SOCK_LISTENING))
                ret_optval.val = tcp_nagle_disabled(s->info.tcp.lw);
            else
                ret_optval.val = ((s->info.tcp.flags & TF_NODELAY) != 0);
            netsock_unlock(s);
            break;
        case TCP_MAXSEG:
            netsock_lock(s);
            if (s->info.tcp.lw && (s->info.tcp.state != TCP_SOCK_LISTENING))
                ret_optval.val = s->info.tcp.lw->mss;
            else
                ret_optval.val = TCP_MSS;
            netsock_unlock(s);
            break;
        case TCP_SYNCNT:
            ret_optval.val = TCP_SYNMAXRTX;
            break;
        case TCP_LINGER2:
            ret_optval.val = TCP_FIN_WAIT_TIMEOUT / THOUSAND;
            break;
        case TCP_WINDOW_CLAMP:
            ret_optval.val = TCP_WND_MAX(s->info.tcp.lw);
            break;
        case TCP_INFO:
            netsock_get_tcpinfo(s, &ret_optval.tcp_info);
            ret_optlen = sizeof(ret_optval.tcp_info);
            break;
        case TCP_CONGESTION:
            zero(ret_optval.str, sizeof(ret_optval.str));
            runtime_memcpy(ret_optval.str, TCP_CONG_CTRL_ALGO, sizeof(TCP_CONG_CTRL_ALGO));
            ret_optlen = sizeof(ret_optval.str);
            break;
        case TCP_CORK:
        case TCP_DEFER_ACCEPT:
        case TCP_QUICKACK:
        case TCP_FASTOPEN:
            ret_optval.val = 0; /* unsupported options */
            break;
        default:
            goto unimplemented;
        }
        break;
    case IPPROTO_IP:
        switch (optname) {
        case IP_MTU_DISCOVER:
            if (s->sock.type == SOCK_STREAM) {
                struct tcp_pcb *tcp_lw = netsock_tcp_get(s);
                ret_optval.val = tcp_lw->pmtudisc;
                netsock_tcp_put(tcp_lw);
            } else {
                ret_optval.val = s->info.udp.lw->pmtudisc;
            }
            break;
        default:
            goto unimplemented;
        }
        break;
    case IPPROTO_IPV6:
        switch (optname) {
        case IPV6_V6ONLY:
            ret_optval.val = s->ipv6only;
            break;
        default:
            goto unimplemented;
        }
        break;
    default:
        rv = -EOPNOTSUPP;
        goto out;
    }
    rv = sockopt_copy_to_user(optval, optlen, &ret_optval, ret_optlen);
    goto out;
unimplemented:
    msg_err("getsockopt unimplemented optname: fd %d, level %d, optname %d\n",
            sock->fd, level, optname);
    rv = -ENOPROTOOPT;
out:
    socket_release(sock);
    return rv;
}

sysreturn setsockopt(int sockfd, int level, int optname, void *optval, socklen_t optlen)
{
    struct sock *sock = resolve_socket(current->p, sockfd);
    if (!sock->setsockopt) {
        socket_release(sock);
        return -EOPNOTSUPP;
    }
    return sock->setsockopt(sock, level, optname, optval, optlen);
}

sysreturn getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen)
{
    struct sock *sock = resolve_socket(current->p, sockfd);
    if (!sock->getsockopt) {
        socket_release(sock);
        return -EOPNOTSUPP;
    }
    return sock->getsockopt(sock, level, optname, optval, optlen);
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
    register_syscall(map, sendmsg, sendmsg);
    register_syscall(map, sendmmsg, sendmmsg);
    register_syscall(map, recvfrom, recvfrom);
    register_syscall(map, recvmsg, recvmsg);
    register_syscall(map, recvmmsg, recvmmsg);
    register_syscall(map, setsockopt, setsockopt);
    register_syscall(map, getsockname, getsockname);
    register_syscall(map, getpeername, getpeername);
    register_syscall(map, getsockopt, getsockopt);
    register_syscall(map, shutdown, shutdown);
}

boolean netsyscall_init(unix_heaps uh, tuple cfg)
{
    u64 rcvbuf;
    if (get_u64(cfg, sym(so_rcvbuf), &rcvbuf))
        so_rcvbuf = MIN(MAX(rcvbuf, 256), MASK(sizeof(so_rcvbuf) * 8 - 1));
    else
        so_rcvbuf = DEFAULT_SO_RCVBUF;
    kernel_heaps kh = get_kernel_heaps();
    heap h = heap_locked(kh);
    caching_heap socket_cache = allocate_objcache(h, (heap)heap_page_backed(kh),
                                                  sizeof(struct netsock), PAGESIZE, true);
    if (socket_cache == INVALID_ADDRESS)
	return false;
    uh->socket_cache = socket_cache;
    net_loop_poll = closure(h, netsock_poll);
    netlink_init();
    vsock_init();
    return true;
}
