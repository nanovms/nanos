/* TODO

   - consider switching on blockq timeout
   - check err handling of tcp_output
   - do udp tx bottom half
*/

#include <unix_internal.h>
#include <lwip.h>
#include <lwip/udp.h>
#include <net_system_structs.h>
#include <socket.h>

//#define NETSYSCALL_DEBUG
#ifdef NETSYSCALL_DEBUG
#define net_debug(x, ...) do {log_printf(" NET", "%s: " x, __func__, ##__VA_ARGS__);} while(0)
#else
#define net_debug(x, ...)
#endif

#define SIOCGIFCONF 0x8912
#define SIOCGIFFLAGS    0x8913
#define SIOCSIFFLAGS    0x8914
#define SIOCGIFADDR 0x8915
#define SIOCSIFADDR     0x8916
#define SIOCGIFNETMASK  0x891B
#define SIOCSIFNETMASK  0x891C
#define SIOCGIFMTU      0x8921
#define SIOCSIFMTU      0x8922
#define SIOCGIFINDEX    0x8933

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

struct mmsghdr {
    struct msghdr msg_hdr;
    unsigned int msg_len;
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
	    enum tcp_socket_state state; // half open?
	} tcp;
	struct {
	    struct udp_pcb *lw;
	    enum udp_socket_state state;
	} udp;
    } info;
} *netsock;

static sysreturn netsock_bind(struct sock *sock, struct sockaddr *addr,
        socklen_t addrlen);
static sysreturn netsock_listen(struct sock *sock, int backlog);
static sysreturn netsock_connect(struct sock *sock, struct sockaddr *addr,
        socklen_t addrlen);
static sysreturn netsock_accept4(struct sock *sock, struct sockaddr *addr,
        socklen_t *addrlen, int flags);
static sysreturn netsock_getsockname(struct sock *sock, struct sockaddr *addr, socklen_t *addrlen);
static sysreturn netsock_sendto(struct sock *sock, void *buf, u64 len,
        int flags, struct sockaddr *dest_addr, socklen_t addrlen);
static sysreturn netsock_recvfrom(struct sock *sock, void *buf, u64 len,
        int flags, struct sockaddr *src_addr, socklen_t *addrlen);
static sysreturn netsock_sendmsg(struct sock *sock, const struct msghdr *msg,
                                 int flags);
static sysreturn netsock_recvmsg(struct sock *sock, struct msghdr *msg,
                                 int flags);

static thunk net_loop_poll;
static boolean net_loop_poll_queued;

closure_function(0, 0, void, netsock_poll) {
    net_loop_poll_queued = false;
    lwip_lock();
    netif_poll_all();
    lwip_unlock();
}

static void netsock_check_loop(void)
{
    /* Not race-free, but the worst that can happen is that the thunk is
     * enqueued more than once. */
    if (!net_loop_poll_queued) {
        net_loop_poll_queued = true;
        enqueue_irqsafe(runqueue, net_loop_poll);
    }
}

static netsock get_netsock(struct sock *sock)
{
    if ((sock->domain != AF_INET) && (sock->domain != AF_INET6))
        return 0;
    return (netsock)sock;
}

closure_function(1, 1, u32, socket_events,
                 netsock, s,
                 thread, t /* ignore */)
{
    netsock s = bound(s);
    boolean in = !queue_empty(s->incoming);
    sysreturn rv;
    if (s->sock.type == SOCK_STREAM) {
        if (s->info.tcp.state == TCP_SOCK_LISTENING) {
            rv = in ? EPOLLIN : 0;
        } else if (s->info.tcp.state == TCP_SOCK_OPEN) {
            /* We can't take the lwIP lock here given that notifies are
               triggered by lwIP callbackes, but the lwIP state read is atomic
               as is the TCP sendbuf size read. */
            rv = (in ? EPOLLIN | EPOLLRDNORM : 0) |
                (s->info.tcp.lw->state == ESTABLISHED ?
                 (tcp_sndbuf(s->info.tcp.lw) ? EPOLLOUT | EPOLLWRNORM : 0) :
                 EPOLLIN | EPOLLHUP);
        } else if (s->info.tcp.state == TCP_SOCK_UNDEFINED ||
                   s->info.tcp.state == TCP_SOCK_CREATED) {
            rv = EPOLLHUP;
        } else {
            rv = 0;
        }
    } else {
        assert(s->sock.type == SOCK_DGRAM);
        rv = (in ? EPOLLIN | EPOLLRDNORM : 0) | EPOLLOUT | EPOLLWRNORM;
    }
    return rv;
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
    return __atomic_exchange_n(&s->lwip_error, ERR_OK, __ATOMIC_ACQUIRE);
}

#define WAKEUP_SOCK_RX          0x00000001
#define WAKEUP_SOCK_TX          0x00000002
#define WAKEUP_SOCK_EXCEPT      0x00000004 /* flush, and thus implies rx & tx */

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
    fdesc_notify_events(&s->sock.f);
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

static void remote_sockaddr(netsock s, struct sockaddr *addr, socklen_t *len, boolean lwip_locked)
{
    ip_addr_t *ip_addr;
    u16_t port;
    if (!lwip_locked)
        lwip_lock();
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
    if (!lwip_locked)
        lwip_unlock();
    addrport_to_sockaddr(s->sock.domain, ip_addr, port, addr, len);
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
    case ERR_ALREADY: return -EALREADY;
    case ERR_ISCONN: return -EISCONN;
    case ERR_CONN: return -ENOTCONN;
    case ERR_IF: return -EINVAL;
    case ERR_ABRT: return -EINVAL;
    case ERR_RST: return -ECONNRESET;
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
    ip_addr_t raddr;
    u16 rport;
};

static sysreturn sock_read_bh_internal(netsock s, thread t, void * dest,
                                       u64 length, int flags, struct sockaddr *src_addr,
                                       socklen_t *addrlen, io_completion completion, u64 bqflags)
{
    /* called with corresponding blockq lock held */
    sysreturn rv = 0;
    err_t err = get_lwip_error(s);
    net_debug("sock %d, thread %ld, dest %p, len %ld, flags 0x%x, bqflags 0x%lx, lwip err %d\n",
	      s->sock.fd, t->tid, dest, length, flags, bqflags, err);
    assert(length > 0);
    assert(s->sock.type == SOCK_STREAM || s->sock.type == SOCK_DGRAM);

    if (s->sock.type == SOCK_STREAM && s->info.tcp.state != TCP_SOCK_OPEN) {
        rv = 0;
        goto out;
    }

    if (err != ERR_OK) {
        rv = lwip_to_errno(err);
        goto out;
    }

    if (bqflags & BLOCKQ_ACTION_NULLIFY) {
        rv = -ERESTARTSYS;
        goto out;
    }

    /* If we're blocked and not a nullify, we know that we were woken up from
       an lwIP callback, and thus the lwIP lock is held. Otherwise we are in a
       syscall top half or continuation, and must grab the lwIP lock here. */
    boolean blocked = (bqflags & BLOCKQ_ACTION_BLOCKED) != 0;
    if (!blocked)
        lwip_lock();

    /* check if we actually have data */
    void * p = queue_peek(s->incoming);
    if (p == INVALID_ADDRESS) {
        if (!blocked)
            lwip_unlock();
        if (s->sock.type == SOCK_STREAM &&
            s->info.tcp.lw->state != ESTABLISHED) {
            rv = 0;
            goto out;
        }
        if ((s->sock.f.flags & SOCK_NONBLOCK) || (flags & MSG_DONTWAIT)) {
            rv = -EAGAIN;
            goto out;
        }
        return blockq_block_required(t, bqflags); /* back to chewing more cud */
    }

    if (src_addr) {
        if (s->sock.type == SOCK_STREAM) {
            remote_sockaddr(s, src_addr, addrlen, blocked);
        } else {
            struct udp_entry * e = p;
            addrport_to_sockaddr(s->sock.domain, &e->raddr, e->rport, src_addr,
                                 addrlen);
        }
    }

    u64 xfer_total = 0;
    u32 pbuf_idx = 0;

    /* TCP: consume multiple buffers to fill request, if available. */
    do {
        struct pbuf * pbuf = s->sock.type == SOCK_STREAM ? (struct pbuf *)p :
            ((struct udp_entry *)p)->pbuf;
        struct pbuf *cur_buf = pbuf;

        do {
            if (cur_buf->len > 0) {
                u64 xfer = MIN(length, cur_buf->len);
                runtime_memcpy(dest, cur_buf->payload, xfer);
                if (!(flags & MSG_PEEK))
                    pbuf_consume(cur_buf, xfer);
                length -= xfer;
                xfer_total += xfer;
                dest = (char *) dest + xfer;
                if ((s->sock.type == SOCK_STREAM) && !(flags & MSG_PEEK))
                    tcp_recved(s->info.tcp.lw, xfer);
            }
            if ((cur_buf->len == 0) || (flags & MSG_PEEK))
                cur_buf = cur_buf->next;
        } while ((length > 0) && cur_buf);

        if (flags & MSG_PEEK) {
            if (!cur_buf)
                p = queue_peek_at(s->incoming, ++pbuf_idx);
        } else if (!cur_buf || (s->sock.type == SOCK_DGRAM)) {
            assert(dequeue(s->incoming) == p);
            if (s->sock.type == SOCK_DGRAM)
                deallocate(s->sock.h, p, sizeof(struct udp_entry));
            pbuf_free(pbuf);
            p = queue_peek(s->incoming);
            if (p == INVALID_ADDRESS)
                fdesc_notify_events(&s->sock.f); /* reset a triggered EPOLLIN condition */
        }
    } while(s->sock.type == SOCK_STREAM && length > 0 && p != INVALID_ADDRESS); /* XXX simplify expression */

    if (!blocked)
        lwip_unlock();

    if (s->sock.type == SOCK_STREAM)
        /* Calls to tcp_recved() may have enqueued new packets in the loopback interface. */
        netsock_check_loop();

    rv = xfer_total;
  out:
    net_debug("   completion %p, rv %ld\n", completion, rv);
    apply(completion, t, rv);
    return rv;
}

closure_function(8, 1, sysreturn, sock_read_bh,
                 netsock, s, thread, t, void *, dest, u64, length, int, flags, struct sockaddr *, src_addr, socklen_t *, addrlen, io_completion, completion,
                 u64, flags)
{
    thread_resume(bound(t));
    sysreturn rv = sock_read_bh_internal(bound(s), bound(t), bound(dest), bound(length),
        bound(flags), bound(src_addr), bound(addrlen), bound(completion), flags);
    if (rv != BLOCKQ_BLOCK_REQUIRED)
        closure_finish();
    return rv;
}

static void recvmsg_complete_internal(netsock s, struct msghdr * msg, void * dest, u64 length,
                                      thread t, sysreturn rv)
{
    s64 offset = 0;
    int iv = 0;
    while (offset < rv) {
        struct iovec *iov = &msg->msg_iov[iv];

        runtime_memcpy(iov->iov_base, dest + offset,
                MIN(iov->iov_len, rv - offset));
        offset += iov->iov_len;
        iv++;
    }
    deallocate(s->sock.h, dest, length);
    msg->msg_controllen = 0;
    msg->msg_flags = 0;
    apply(syscall_io_complete, t, rv);
}

closure_function(4, 2, void, recvmsg_complete,
                 netsock, s, struct msghdr *, msg, void *, dest, u64, length,
                 thread, t, sysreturn, rv)
{
    recvmsg_complete_internal(bound(s), bound(msg), bound(dest), bound(length), t, rv);
    closure_finish();
}

closure_function(6, 1, sysreturn, recvmsg_bh,
                 netsock, s, thread, t, void *, dest, u64, length, int, flags, struct msghdr *, msg,
                 u64, flags)
{
    thread_resume(bound(t));
    io_completion completion = closure(bound(s)->sock.h, recvmsg_complete,
                                       bound(s), bound(msg), bound(dest),
                                       bound(length));
    sysreturn rv = sock_read_bh_internal(bound(s), bound(t), bound(dest), bound(length),
                                         bound(flags), bound(msg)->msg_name,
                                         &bound(msg)->msg_namelen, completion, flags);
    if (rv != BLOCKQ_BLOCK_REQUIRED) {
        socket_release(&bound(s)->sock);
        closure_finish();
    }
    return rv;
}

closure_function(1, 6, sysreturn, socket_read,
                 netsock, s,
                 void *, dest, u64, length, u64, offset, thread, t, boolean, bh, io_completion, completion)
{
    netsock s = bound(s);
    net_debug("sock %d, type %d, thread %ld, dest %p, length %ld, offset %ld\n",
	      s->sock.fd, s->sock.type, t->tid, dest, length, offset);
    if (s->sock.type == SOCK_STREAM && s->info.tcp.state != TCP_SOCK_OPEN)
        return io_complete(completion, t,
            (s->info.tcp.state == TCP_SOCK_UNDEFINED) ? 0 : -ENOTCONN);

    blockq_action ba = closure(s->sock.h, sock_read_bh, s, t, dest, length, 0, 0,
            0, completion);
    return blockq_check(s->sock.rxbq, t, ba, bh);
}

static sysreturn socket_write_tcp_bh_internal(netsock s, thread t, void * buf,
                                              u64 remain, int flags, io_completion completion,
                                              u64 bqflags)
{
    sysreturn rv = 0;
    err_t err = get_lwip_error(s);
    net_debug("fd %d, thread %ld, buf %p, remain %ld, flags 0x%x, bqflags 0x%lx, lwip err %d\n",
              s->sock.fd, t->tid, buf, remain, flags, bqflags, err);
    assert(remain > 0);

    if (err != ERR_OK) {
        rv = lwip_to_errno(err);
        goto out;
    }

    if (s->sock.type == SOCK_STREAM && s->info.tcp.state != TCP_SOCK_OPEN) {
        rv = -ENOTCONN;
        goto out;
    }

    if (bqflags & BLOCKQ_ACTION_NULLIFY) {
        rv = -ERESTARTSYS;
        goto out;
    }

    boolean blocked = (bqflags & BLOCKQ_ACTION_BLOCKED) != 0;
    /* Note that the actual transmit window size is truncated to 16
       bits here (and tcp_write() doesn't accept more than 2^16
       anyway), so even if we have a large transmit window due to
       LWIP_WND_SCALE, we still can't write more than 2^16. Sigh... */
    if (!blocked)
        lwip_lock();
    u64 avail = tcp_sndbuf(s->info.tcp.lw);
    if (avail == 0) {
      full:
        if (!blocked)
            lwip_unlock();
        if ((bqflags & BLOCKQ_ACTION_BLOCKED) == 0 &&
                ((s->sock.f.flags & SOCK_NONBLOCK) || (flags & MSG_DONTWAIT))) {
            net_debug(" send buf full and non-blocking, return EAGAIN\n");
            rv = -EAGAIN;
            goto out;
        } else {
            net_debug(" send buf full, sleep\n");
            return blockq_block_required(t, bqflags); /* block again */
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

    err = tcp_write(s->info.tcp.lw, buf, n, apiflags);
    if (err == ERR_OK) {
        /* XXX prob add a flag to determine whether to continuously
           post data, e.g. if used by send/sendto... */
        err = tcp_output(s->info.tcp.lw);
        if (!blocked)
            lwip_unlock();
        if (err == ERR_OK) {
            net_debug(" tcp_write and tcp_output successful for %ld bytes\n", n);
            netsock_check_loop();
            rv = n;
            if (n == avail) {
                fdesc_notify_events(&s->sock.f); /* reset a triggered EPOLLOUT condition */
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
        if (!blocked)
            lwip_unlock();
        net_debug(" tcp_write() lwip error: %d\n", err);
        rv = lwip_to_errno(err);
    }
  out:
    net_debug("   completion %p, rv %ld\n", completion, rv);
    apply(completion, t, rv);
    return rv;
}

closure_function(6, 1, sysreturn, socket_write_tcp_bh,
                 netsock, s, thread, t, void *, buf, u64, remain, int, flags, io_completion, completion,
                 u64, bqflags)
{
    thread_resume(bound(t));
    sysreturn rv = socket_write_tcp_bh_internal(bound(s), bound(t), bound(buf), bound(remain),
        bound(flags), bound(completion), bqflags);
    if (rv != BLOCKQ_BLOCK_REQUIRED)
        closure_finish();
    return rv;
}

static sysreturn socket_write_udp(netsock s, void *source, u64 length,
                                  struct sockaddr *dest_addr, socklen_t addrlen)
{
    ip_addr_t ipaddr;
    u16 port = 0;
    if (dest_addr) {
        sysreturn ret = sockaddr_to_addrport(s, dest_addr, addrlen,
            &ipaddr, &port);
        if (ret)
            return ret;
    }
    err_t err = ERR_OK;

    /* XXX check how much we can queue, maybe make udp bh */
    /* XXX check if remote endpoint set? let LWIP check? */
    lwip_lock();
    struct pbuf * pbuf = pbuf_alloc(PBUF_TRANSPORT, length, PBUF_RAM);
    if (!pbuf) {
        lwip_unlock();
        msg_err("failed to allocate pbuf for udp_send()\n");
        return -ENOBUFS;
    }
    runtime_memcpy(pbuf->payload, source, length);
    if (dest_addr)
        err = udp_sendto(s->info.udp.lw, pbuf, &ipaddr, port);
    else
        err = udp_send(s->info.udp.lw, pbuf);
    pbuf_free(pbuf);
    lwip_unlock();
    if (err != ERR_OK) {
        net_debug("lwip error %d\n", err);
        return lwip_to_errno(err);
    }
    netsock_check_loop();
    return length;
}

static sysreturn socket_write_internal(struct sock *sock, void *source,
                                       u64 length, int flags,
                                       struct sockaddr *dest_addr, socklen_t addrlen,
                                       thread t, boolean bh, io_completion completion)
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
        blockq_action ba = closure(sock->h, socket_write_tcp_bh, s, t,
                                   source, length, flags, completion);
        return blockq_check(sock->txbq, t, ba, bh);
    } else if (sock->type == SOCK_DGRAM) {
        rv = socket_write_udp(s, source, length, dest_addr, addrlen);
    } else {
	msg_err("socket type %d unsupported\n", sock->type);
	rv = -EINVAL;
    }
    net_debug("completed\n");
out:
    apply(completion, t, rv);
    return rv;
}

closure_function(1, 6, sysreturn, socket_write,
                 netsock, s,
                 void *, source, u64, length, u64, offset, thread, t, boolean, bh, io_completion, completion)
{
    struct sock *s = (struct sock *) bound(s);
    net_debug("sock %d, type %d, thread %ld, source %p, length %ld, offset %ld\n",
	      s->fd, s->type, t->tid, source, length, offset);
    return socket_write_internal(s, source, length, 0, 0, 0, t, bh, completion);
}

closure_function(1, 2, sysreturn, netsock_ioctl,
                 netsock, s,
                 unsigned long, request, vlist, ap)
{
    netsock s = bound(s);
    net_debug("sock %d, request 0x%x\n", s->sock.fd, request);
    switch (request) {
    case SIOCGIFCONF: {
        struct ifconf *ifconf = varg(ap, struct ifconf *);
        if (!validate_user_memory(ifconf, sizeof(struct ifconf), true))
            return -EFAULT;
        if (ifconf->ifc.ifc_req == NULL) {
            ifconf->ifc_len = 0;
            lwip_lock();
            for (struct netif *netif = netif_list; netif != NULL;
                    netif = netif->next) {
                if (netif_is_up(netif) && netif_is_link_up(netif) &&
                        !ip4_addr_isany(netif_ip4_addr(netif))) {
                    ifconf->ifc_len += sizeof(struct ifreq);
                }
            }
            lwip_unlock();
        }
        else {
            int len = 0;
            int iface = 0;
            lwip_lock();
            for (struct netif *netif = netif_list; (netif != NULL) &&
                    (len + sizeof(ifconf->ifc) <= ifconf->ifc_len);
                    netif = netif->next) {
                if (netif_is_up(netif) && netif_is_link_up(netif) &&
                        !ip4_addr_isany(netif_ip4_addr(netif))) {
                    netif_name_cpy(ifconf->ifc.ifc_req[iface].ifr_name, netif);
                    struct sockaddr_in *addr = (struct sockaddr_in *)
                            &ifconf->ifc.ifc_req[iface].ifr.ifr_addr;
                    addr->family = AF_INET;
                    runtime_memcpy(&addr->address, netif_ip4_addr(netif),
                            sizeof(ip4_addr_t));
                    len += sizeof(struct ifreq);
                    iface++;
                }
            }
            lwip_unlock();
            ifconf->ifc_len = len;
        }
        return 0;
    }
    case SIOCGIFFLAGS: {
        struct ifreq *ifreq = varg(ap, struct ifreq *);
        if (!validate_user_memory(ifreq, sizeof(struct ifreq), true))
            return -EFAULT;
        lwip_lock();
        struct netif *netif = netif_find(ifreq->ifr_name);
        lwip_unlock();
        if (!netif) {
            return -ENODEV;
        }
        ifreq->ifr.ifr_flags = ifflags_from_netif(netif);
        return 0;
    }
    case SIOCSIFFLAGS: {
        struct ifreq *ifreq = varg(ap, struct ifreq *);
        if (!validate_user_memory(ifreq, sizeof(struct ifreq), false))
            return -EFAULT;
        lwip_lock();
        struct netif *netif = netif_find(ifreq->ifr_name);
        lwip_unlock();
        if (!netif)
            return -ENODEV;
        return (ifflags_to_netif(netif, ifreq->ifr.ifr_flags) ? 0 : -EINVAL);
    }
    case SIOCGIFADDR: {
        struct ifreq *ifreq = varg(ap, struct ifreq *);
        if (!validate_user_memory(ifreq, sizeof(struct ifreq), true))
            return -EFAULT;
        lwip_lock();
        struct netif *netif = netif_find(ifreq->ifr_name);
        lwip_unlock();
        if (!netif) {
            return -ENODEV;
        }
        struct sockaddr_in *addr = (struct sockaddr_in *)&ifreq->ifr.ifr_addr;
        addr->family = AF_INET;
        runtime_memcpy(&addr->address, netif_ip4_addr(netif),
                sizeof(ip4_addr_t));
        return 0;
    }
    case SIOCSIFADDR: {
        struct ifreq *ifreq = varg(ap, struct ifreq *);
        if (!validate_user_memory(ifreq, sizeof(struct ifreq), false))
            return -EFAULT;
        lwip_lock();
        struct netif *netif = netif_find(ifreq->ifr_name);
        lwip_unlock();
        if (!netif)
            return -ENODEV;
        struct sockaddr_in *addr = (struct sockaddr_in *)&ifreq->ifr.ifr_addr;
        if (addr->family != AF_INET)
            return -EINVAL;
        ip4_addr_t lwip_addr = {
                .addr = addr->address,
        };
        lwip_lock();
        netif_set_ipaddr(netif, &lwip_addr);
        lwip_unlock();
        return 0;
    }
    case SIOCGIFNETMASK: {
        struct ifreq *ifreq = varg(ap, struct ifreq *);
        if (!validate_user_memory(ifreq, sizeof(struct ifreq), true))
            return -EFAULT;
        lwip_lock();
        struct netif *netif = netif_find(ifreq->ifr_name);
        lwip_unlock();
        if (!netif) {
            return -ENODEV;
        }
        struct sockaddr_in *addr =
                (struct sockaddr_in *)&ifreq->ifr.ifr_netmask;
        addr->family = AF_INET;
        runtime_memcpy(&addr->address, netif_ip4_netmask(netif),
                sizeof(ip4_addr_t));
        return 0;
    }
    case SIOCSIFNETMASK: {
        struct ifreq *ifreq = varg(ap, struct ifreq *);
        if (!validate_user_memory(ifreq, sizeof(struct ifreq), false))
            return -EFAULT;
        lwip_lock();
        struct netif *netif = netif_find(ifreq->ifr_name);
        lwip_unlock();
        if (!netif)
            return -ENODEV;
        struct sockaddr_in *addr =
                (struct sockaddr_in *)&ifreq->ifr.ifr_netmask;
        if (addr->family != AF_INET)
            return -EINVAL;
        ip4_addr_t lwip_addr = {
                .addr = addr->address,
        };
        lwip_lock();
        netif_set_netmask(netif, &lwip_addr);
        lwip_unlock();
        return 0;
    }
    case SIOCGIFMTU: {
        struct ifreq *ifreq = varg(ap, struct ifreq *);
        if (!validate_user_memory(ifreq, sizeof(struct ifreq), true))
            return -EFAULT;
        lwip_lock();
        struct netif *netif = netif_find(ifreq->ifr_name);
        lwip_unlock();
        if (!netif)
            return -ENODEV;
        ifreq->ifr.ifr_mtu = netif->mtu;
        return 0;
    }
    case SIOCSIFMTU: {
        struct ifreq *ifreq = varg(ap, struct ifreq *);
        if (!validate_user_memory(ifreq, sizeof(struct ifreq), false))
            return -EFAULT;
        if ((ifreq->ifr.ifr_mtu <= 0) || (ifreq->ifr.ifr_mtu > MTU_MAX))
            return -EINVAL;
        lwip_lock();
        struct netif *netif = netif_find(ifreq->ifr_name);
        lwip_unlock();
        if (!netif)
            return -ENODEV;
        netif->mtu = ifreq->ifr.ifr_mtu;
        return 0;
    }
    case SIOCGIFINDEX: {
        struct ifreq *ifreq = varg(ap, struct ifreq *);
        if (!validate_user_memory(ifreq, sizeof(struct ifreq), true))
            return -EFAULT;
        lwip_lock();
        struct netif *netif = netif_find(ifreq->ifr_name);
        lwip_unlock();
        if (!netif)
            return -ENODEV;
        ifreq->ifr.ifr_ivalue = netif->num;
        return 0;
    }
    case FIONREAD: {
        int *nbytes = varg(ap, int *);
        *nbytes = 0;
        lwip_lock();
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
                *nbytes += (int)buf->len;
                buf = buf->next;
            }
        }
        lwip_unlock();
        return 0;
    }
    default:
        return socket_ioctl(&s->sock, request, ap);
    }
}

#define SOCK_QUEUE_LEN 128

closure_function(1, 2, sysreturn, socket_close,
                 netsock, s,
                 thread, t, io_completion, completion)
{
    netsock s = bound(s);
    net_debug("sock %d, type %d\n", s->sock.fd, s->sock.type);
    switch (s->sock.type) {
    case SOCK_STREAM:
        /* tcp_close() doesn't really stop everything synchronously; in order to
         * prevent any lwIP callback that might be called after tcp_close() from
         * using a stale reference to the socket structure, set the callback
         * argument to NULL. */
        lwip_lock();
        if (s->info.tcp.lw) {
            tcp_close(s->info.tcp.lw);
            tcp_arg(s->info.tcp.lw, 0);
            netsock_check_loop();
        }
        lwip_unlock();
        break;
    case SOCK_DGRAM:
        lwip_lock();
        udp_remove(s->info.udp.lw);
        lwip_unlock();
        break;
    }
    deallocate_queue(s->incoming);
    deallocate_closure(s->sock.f.read);
    deallocate_closure(s->sock.f.write);
    deallocate_closure(s->sock.f.close);
    deallocate_closure(s->sock.f.events);
    deallocate_closure(s->sock.f.ioctl);
    socket_deinit(&s->sock);
    unix_cache_free(s->p->uh, socket, s);
    return io_complete(completion, t, 0);
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
        if (s->info.tcp.state != TCP_SOCK_OPEN) {
            rv = -ENOTCONN;
            goto out;
        }
        lwip_lock();
        if (shut_rx && shut_tx) {
            tcp_arg(s->info.tcp.lw, 0);
        }
        tcp_shutdown(s->info.tcp.lw, shut_rx, shut_tx);
        if (shut_rx && shut_tx) {
            /* Shutting down both TX and RX is equivalent to calling
             * tcp_close(), so the pcb should not be referenced anymore. */
            s->info.tcp.lw = 0;
            s->info.tcp.state = TCP_SOCK_UNDEFINED;
        }
        lwip_unlock();
        netsock_check_loop();
        break;
    case SOCK_DGRAM:
        rv = -ENOTCONN;
        goto out;
    }
    
    rv = 0;
  out:
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
			    const ip_addr_t * addr, u16 port)
{
    netsock s = z;
#ifdef NETSYSCALL_DEBUG
    u8 *n = (u8 *)addr;
#endif
    net_debug("sock %d, pcb %p, buf %p, src addr %d.%d.%d.%d, port %d\n",
	      s->sock.fd, pcb, p, n[0], n[1], n[2], n[3], port);
    assert(pcb == s->info.udp.lw);
    if (p) {
	/* could make a cache if we care to */
	struct udp_entry * e = allocate(s->sock.h, sizeof(*e));
	assert(e != INVALID_ADDRESS);
	e->pbuf = p;
	runtime_memcpy(&e->raddr, addr, sizeof(ip_addr_t));
	e->rport = port;
	if (!enqueue(s->incoming, e))
	    msg_err("incoming queue full\n");
    } else {
	msg_err("null pbuf\n");
    }
    wakeup_sock(s, WAKEUP_SOCK_RX);
}

static int allocate_sock(process p, int af, int type, u32 flags, netsock *rs)
{
    netsock s;
    int fd;

    s = unix_cache_alloc(p->uh, socket);
    if (s == INVALID_ADDRESS) {
	msg_err("failed to allocate struct sock\n");
        goto err_sock;
    }

    heap h = heap_locked((kernel_heaps)p->uh);
    if (socket_init(p, h, af, type, flags, &s->sock) < 0)
        goto err_sock_init;
    s->sock.f.read = closure(h, socket_read, s);
    s->sock.f.write = closure(h, socket_write, s);
    s->sock.f.close = closure(h, socket_close, s);
    s->sock.f.events = closure(h, socket_events, s);
    s->sock.f.ioctl = closure(h, netsock_ioctl, s);
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
    s->sock.sendto = netsock_sendto;
    s->sock.recvfrom = netsock_recvfrom;
    s->sock.sendmsg = netsock_sendmsg;
    s->sock.recvmsg = netsock_recvmsg;
    s->sock.shutdown = netsock_shutdown;
    s->ipv6only = 0;
    set_lwip_error(s, ERR_OK);
    fd = s->sock.fd = allocate_fd(p, s);
    if (fd == INVALID_PHYSICAL) {
        apply(s->sock.f.close, 0, io_completion_ignore);
        return -EMFILE;
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
    int fd = allocate_sock(p, af, SOCK_STREAM, flags, &s);
    if (fd >= 0) {
	s->info.tcp.lw = pcb;
	s->info.tcp.state = TCP_SOCK_CREATED;
    }
    return fd;
}

static int allocate_udp_sock(process p, int af, struct udp_pcb *pcb, u32 flags)
{
    netsock s;
    int fd = allocate_sock(p, af, SOCK_DGRAM, flags, &s);
    if (fd >= 0) {
        s->info.udp.lw = pcb;
        s->info.udp.state = UDP_SOCK_CREATED;
        lwip_lock();
        udp_recv(pcb, udp_input_lower, s);
        lwip_unlock();
    }
    return fd;
}

sysreturn socket(int domain, int type, int protocol)
{
    switch (domain) {
    case AF_INET:
    case AF_INET6:
        break;
    case AF_UNIX:
        return unixsock_open(type, protocol);
    case AF_NETLINK:
        return netlink_open(type, protocol);
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
        lwip_lock();
        struct tcp_pcb *p = tcp_new_ip_type((domain == AF_INET) ?
                                            IPADDR_TYPE_V4: IPADDR_TYPE_ANY);
        lwip_unlock();
        if (!p)
            return -ENOMEM;

        int fd = allocate_tcp_sock(current->p, domain, p,
            nonblock ? SOCK_NONBLOCK : 0);
        net_debug("new tcp fd %d, pcb %p\n", fd, p);
        return fd;
    } else if (type == SOCK_DGRAM) {
        lwip_lock();
        struct udp_pcb *p = udp_new();
        lwip_unlock();
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
    if (p) {
        if (!enqueue(s->incoming, p)) {
	    msg_err("incoming queue full\n");
            return ERR_BUF;     /* XXX verify */
        }
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
    sysreturn ret = sockaddr_to_addrport(s, addr, addrlen, &ipaddr,
        &port);
    if (ret)
        goto out;
    if ((s->sock.domain == AF_INET6) && ip6_addr_isany(&ipaddr.u_addr.ip6) &&
            !s->ipv6only)
        /* Allow receiving both IPv4 and IPv6 packets (dual-stack support). */
        IP_SET_TYPE(&ipaddr, IPADDR_TYPE_ANY);
    err_t err;
    if (sock->type == SOCK_STREAM) {
	if (!s->info.tcp.lw || (s->info.tcp.lw->local_port != 0)) {
	    ret = -EINVAL;	/* shut down or already bound */
	    goto out;
	}
	net_debug("calling tcp_bind, pcb %p, port %d\n", s->info.tcp.lw, port);
        lwip_lock();
	err = tcp_bind(s->info.tcp.lw, &ipaddr, port);
        lwip_unlock();
    } else if (sock->type == SOCK_DGRAM) {
        if (s->info.udp.lw->local_port != 0) {
            ret = -EINVAL; /* already bound */
            goto out;
        }
        net_debug("calling udp_bind, pcb %p, port %d\n", s->info.udp.lw, port);
        lwip_lock();
        err = udp_bind(s->info.udp.lw, &ipaddr, port);
        lwip_unlock();
    } else {
        msg_warn("unsupported socket type %d\n", s->sock.type);
        ret = -EINVAL;
        goto out;
    }
    ret = lwip_to_errno(err);
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
    s->info.tcp.state = TCP_SOCK_UNDEFINED;
    set_lwip_error(s, err);

    /* Don't try to use the pcb, it may have been deallocated already. */
    s->info.tcp.lw = 0;

    wakeup_sock(s, WAKEUP_SOCK_EXCEPT);
}

static err_t lwip_tcp_sent(void * arg, struct tcp_pcb * pcb, u16 len)
{
    if (!arg) {
        return ERR_OK;
    }
    netsock s = (netsock)arg;
    net_debug("fd %d, pcb %p, len %d\n", s->sock.fd, pcb, len);
    wakeup_sock(s, WAKEUP_SOCK_TX);
    return ERR_OK;
}

closure_function(2, 1, sysreturn, connect_tcp_bh,
                 netsock, s, thread, t,
                 u64, flags)
{
    sysreturn rv = 0;
    netsock s = bound(s);
    thread t = bound(t);
    err_t err = get_lwip_error(s);

    net_debug("sock %d, tcp state %d, thread %ld, lwip_status %d, flags 0x%lx\n",
              s->sock.fd, s->info.tcp.state, t->tid, err, flags);

    thread_resume(bound(t));
    rv = lwip_to_errno(err);
    if (flags & BLOCKQ_ACTION_NULLIFY) {
        if (rv == 0) {
            /* We can assume a nullify will not happen on an lwIP callback. */
            lwip_lock();
            if (s->info.tcp.state == TCP_SOCK_OPEN) {
                /* The connection opened before we could abort; close it. */
                tcp_arg(s->info.tcp.lw, 0);
                tcp_shutdown(s->info.tcp.lw, 1, 1);
                s->info.tcp.lw = 0;
                s->info.tcp.state = TCP_SOCK_CREATED;
            } else {
                assert(s->info.tcp.state == TCP_SOCK_IN_CONNECTION);
                s->info.tcp.state = TCP_SOCK_ABORTING_CONNECTION;
            }
            lwip_unlock();
            rv = -ERESTARTSYS;
        }
        goto out;
    }

    if (s->info.tcp.state == TCP_SOCK_IN_CONNECTION) {
        if (s->sock.f.flags & SOCK_NONBLOCK) {
            rv = -EINPROGRESS;
            goto out;
        }
        return blockq_block_required(t, flags);
    }
    assert(s->info.tcp.state == TCP_SOCK_OPEN);
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
   net_debug("sock %d, tcp state %d, pcb %p, err %d\n", s->sock.fd,
           s->info.tcp.state, tpcb, err);
   if (s->info.tcp.state == TCP_SOCK_ABORTING_CONNECTION) {
       s->info.tcp.state = TCP_SOCK_CREATED;
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
    /* Force exclusion in case - for whatever odd reason - there's a race with
       another thread trying to connect on the same socket. */
    lwip_lock();
    struct tcp_pcb * lw = s->info.tcp.lw;
    switch (s->info.tcp.state) {
    case TCP_SOCK_IN_CONNECTION:
    case TCP_SOCK_ABORTING_CONNECTION:
        rv = -EALREADY;
        goto unlock_out;
    case TCP_SOCK_OPEN:
        rv = -EISCONN;
        goto unlock_out;
    case TCP_SOCK_CREATED:
        break;
    default:
        rv = -EINVAL;
        goto unlock_out;
    }
    tcp_arg(lw, s);
    tcp_recv(lw, tcp_input_lower);
    tcp_err(lw, lwip_tcp_conn_err);
    tcp_sent(lw, lwip_tcp_sent);
    s->info.tcp.state = TCP_SOCK_IN_CONNECTION;
    set_lwip_error(s, ERR_OK);
    err_t err = tcp_connect(lw, address, port, connect_tcp_complete);
    lwip_unlock();
    if (err != ERR_OK)
        return lwip_to_errno(err);
    netsock_check_loop();

    return blockq_check(s->sock.txbq, current,
                        closure(s->sock.h, connect_tcp_bh, s, current), false);
  unlock_out:
    lwip_unlock();
    return rv;
}

static sysreturn netsock_connect(struct sock *sock, struct sockaddr *addr,
        socklen_t addrlen)
{
    netsock s = (netsock) sock;
    ip_addr_t ipaddr;
    u16 port;
    sysreturn ret = sockaddr_to_addrport(s, addr, addrlen, &ipaddr,
        &port);
    if (ret)
        goto out;
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
    } else if (s->sock.type == SOCK_DGRAM) {
        /* Set remote endpoint */
        lwip_lock();
        ret = lwip_to_errno(udp_connect(s->info.udp.lw, &ipaddr, port));
        lwip_unlock();
    } else {
        msg_err("can't connect on socket type %d\n", s->sock.type);
        ret = -EINVAL;
    }
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
        int flags, struct sockaddr *dest_addr, socklen_t addrlen)
{
    sysreturn rv = sendto_prepare(sock, flags);
    if (rv < 0) {
        socket_release(sock);
        return set_syscall_return(current, rv);
    }
    return socket_write_internal(sock, buf, len, flags, dest_addr, addrlen, current, false,
            (io_completion)&sock->f.io_complete);
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
    return sock->sendto(sock, buf, len, flags, dest_addr, addrlen);
}

static sysreturn sendmsg_prepare(struct sock *s, const struct msghdr *msg,
        int flags,
        void **buf, u64 *len)
{
    sysreturn rv;
    size_t i;

    rv = sendto_prepare(s, flags);
    if (rv < 0) {
        return rv;
    }
    *len = 0;
    for (i = 0; i < msg->msg_iovlen; i++) {
        *len += msg->msg_iov[i].iov_len;
    }
    if (*len == 0) {
        return 0;
    }
    *buf = allocate(s->h, *len);
    if (*buf == INVALID_ADDRESS) {
        return -ENOMEM;
    }
    s64 offset = 0;
    for (i = 0; i < msg->msg_iovlen; i++) {
        struct iovec *iov = &msg->msg_iov[i];

        runtime_memcpy(*buf + offset, iov->iov_base, iov->iov_len);
        offset += iov->iov_len;
    }
    return *len;
}

static void sendmsg_complete_internal(struct sock *s, void * buf, u64 len,
                                      thread t, sysreturn rv)
{
    deallocate(s->h, buf, len);
    socket_release(s);
    apply(syscall_io_complete, t, rv);
}

closure_function(3, 2, void, sendmsg_complete,
                 struct sock *, s, void *, buf, u64, len,
                 thread, t, sysreturn, rv)
{
    sendmsg_complete_internal(bound(s), bound(buf), bound(len), t, rv);
    closure_finish();
}

static sysreturn netsock_sendmsg(struct sock *s, const struct msghdr *msg,
                                 int flags)
{
    void *buf;
    u64 len;
    sysreturn rv;

    rv = sendmsg_prepare(s, msg, flags, &buf, &len);
    if (rv <= 0) {
        socket_release(s);
        return set_syscall_return(current, rv);
    }
    io_completion completion = closure(s->h, sendmsg_complete, s, buf, len);
    return socket_write_internal(s, buf, len, flags, msg->msg_name, msg->msg_namelen,
        current, false, completion);
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
    return s->sendmsg(s, msg, flags);
}

closure_function(3, 2, void, sendmmsg_buf_complete,
                 netsock, s, void *, buf, u64, len,
                 thread, t, sysreturn, rv)
{
    deallocate(bound(s)->sock.h, bound(buf), bound(len));
    closure_finish();
}

closure_function(7, 1, sysreturn, sendmmsg_tcp_bh,
                 netsock, s, thread, t, void *, buf, u64, len, int, flags, struct mmsghdr *, msgvec, unsigned int, vlen,
                 u64, bqflags)
{
    netsock s = bound(s);
    thread t = bound(t);
    void * buf = bound(buf);
    u64 len = bound(len);
    struct mmsghdr * msgvec = bound(msgvec);
    thread_resume(bound(t));

    io_completion completion = closure(s->sock.h, sendmmsg_buf_complete, s, buf,
            len);
    sysreturn rv = socket_write_tcp_bh_internal(s, t, buf, len, bound(flags), completion,
        bqflags | BLOCKQ_ACTION_BLOCKED);

    while (true) {
        if (rv == BLOCKQ_BLOCK_REQUIRED) {
            return rv;
        }
        else if (rv <= 0) {
            if (s->sock.msg_count > 0) {
                rv = s->sock.msg_count;
            }
            break;
        }
        msgvec[s->sock.msg_count++].msg_len = rv;
        if (s->sock.msg_count == bound(vlen)) {
            break;
        }
        rv = sendmsg_prepare(&s->sock, &msgvec[s->sock.msg_count].msg_hdr,
                bound(flags), &buf, &len);
        if (rv > 0) {
            completion = closure(s->sock.h, sendmmsg_buf_complete, s, buf, len);
            rv = socket_write_tcp_bh_internal(s, t, buf, len, bound(flags), completion,
                bqflags | BLOCKQ_ACTION_BLOCKED);
        }
    }

    if (bqflags & BLOCKQ_ACTION_BLOCKED)
        socket_release(&s->sock);
    closure_finish();
    return syscall_return(t, rv);
}

sysreturn sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen,
        int flags)
{
    if (!validate_user_memory(msgvec, vlen * sizeof(struct mmsghdr), true))
        return -EFAULT;
    for (int i = 0; i < vlen; i++) {
        if (!validate_msghdr(&msgvec[i].msg_hdr, false))
            return -EFAULT;
    }

    void *buf;
    u64 len;
    sysreturn rv = 0;
    struct sock *sock = resolve_socket(current->p, sockfd);
    netsock s = get_netsock(sock);
    if (!s) {
        rv = -EOPNOTSUPP;
        goto out;
    }

    net_debug("sock %d, type %d, flags 0x%x, vlen %d\n", sock->fd, sock->type,
            flags,
            vlen);

    for (sock->msg_count = 0; sock->msg_count < vlen; sock->msg_count++) {
        struct msghdr *msg_hdr = &msgvec[sock->msg_count].msg_hdr;

        rv = sendmsg_prepare(sock, msg_hdr, flags, &buf, &len);
        if (rv < 0) {
            break;
        }
        else if (rv == 0) {
            msgvec[sock->msg_count].msg_len = 0;
            continue;
        }
        switch (sock->type) {
        case SOCK_STREAM:
            if (s->info.tcp.state != TCP_SOCK_OPEN) {
                rv = -EPIPE;
                break;
            }
            blockq_action ba = closure(sock->h, sendmmsg_tcp_bh, s, current,
                    buf, len, flags, msgvec, vlen);
            rv = blockq_check(sock->txbq, current, ba, false);
            break;
        case SOCK_DGRAM:
            rv = socket_write_udp(s, buf, len, msg_hdr->msg_name,
                msg_hdr->msg_namelen);
            break;
        }
        deallocate(sock->h, buf, len);
        if (rv < 0) {
            break;
        }
        msgvec[sock->msg_count].msg_len = rv;
    }
    if (sock->msg_count > 0) {
        rv = sock->msg_count;
    }
  out:
    socket_release(sock);
    return set_syscall_return(current, rv);
}

static sysreturn netsock_recvfrom(struct sock *sock, void *buf, u64 len,
        int flags, struct sockaddr *src_addr, socklen_t *addrlen)
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

    blockq_action ba = closure(sock->h, sock_read_bh, s, current, buf, len, flags,
                               src_addr, addrlen, (io_completion)&sock->f.io_complete);
    return blockq_check(sock->rxbq, current, ba, false);
  out:
    socket_release(sock);
    return rv;
}

sysreturn recvfrom(int sockfd, void * buf, u64 len, int flags,
		   struct sockaddr *src_addr, socklen_t *addrlen)
{
    if (src_addr && (!validate_user_memory(addrlen, sizeof(socklen_t), true) ||
                     !validate_user_memory(src_addr, *addrlen, true)))
        return -EFAULT;
    struct sock *sock = resolve_socket(current->p, sockfd);
    net_debug("sock %d, type %d, thread %ld, buf %p, len %ld\n", sock->fd,
            sock->type, current->tid, buf, len);

    if (!sock->recvfrom) {
        socket_release(sock);
        return -EOPNOTSUPP;
    }
    return sock->recvfrom(sock, buf, len, flags, src_addr, addrlen);
}

static sysreturn netsock_recvmsg(struct sock *sock, struct msghdr *msg,
                                 int flags)
{
    u64 total_len;
    u8 *buf;
    netsock s = (netsock) sock;
    sysreturn rv;

    if ((sock->type == SOCK_STREAM) && (s->info.tcp.state != TCP_SOCK_OPEN)) {
        rv = (s->info.tcp.state == TCP_SOCK_UNDEFINED) ? 0 : -ENOTCONN;
        goto out;
    }
    total_len = 0;
    for (int i = 0; i < msg->msg_iovlen; i++) {
        total_len += msg->msg_iov[i].iov_len;
    }
    if (total_len == 0) {
        rv = 0;
        goto out;
    }
    buf = allocate(sock->h, total_len);
    if (buf == INVALID_ADDRESS) {
        rv = -ENOMEM;
        goto out;
    }
    blockq_action ba = closure(sock->h, recvmsg_bh, s, current, buf, total_len, flags,
            msg);
    return blockq_check(sock->rxbq, current, ba, false);
  out:
    socket_release(sock);
    return rv;
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
    return s->recvmsg(s, msg, flags);
}

static err_t accept_tcp_from_lwip(void * z, struct tcp_pcb * lw, err_t err)
{
    if (!z) {
        return ERR_CLSD;
    }
    netsock s = z;

    if (err == ERR_MEM) {
        set_lwip_error(s, err);
        wakeup_sock(s, WAKEUP_SOCK_EXCEPT);
        return err;               /* lwIP doesn't care */
    }

    /* XXX such a thing as nonblock inherited from listen socket? */
    int fd = allocate_tcp_sock(s->p, s->sock.domain, lw, 0);
    if (fd < 0)
	return ERR_MEM;

    // XXX - what if this has been closed in the meantime?
    // refcnt

    net_debug("new fd %d, pcb %p\n", fd, lw);
    netsock sn = (netsock)fdesc_get(s->p, fd);
    sn->info.tcp.state = TCP_SOCK_OPEN;
    sn->sock.fd = fd;
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

static sysreturn netsock_listen(struct sock *sock, int backlog)
{
    netsock s = (netsock) sock;
    sysreturn rv;
    lwip_lock();
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
    struct tcp_pcb * lw = tcp_listen_with_backlog(s->info.tcp.lw, backlog);
    s->info.tcp.lw = lw;
    s->info.tcp.state = TCP_SOCK_LISTENING;
    set_lwip_error(s, ERR_OK);
    tcp_arg(lw, s);
    tcp_accept(lw, accept_tcp_from_lwip);
    rv = 0;
  unlock_out:
    lwip_unlock();
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
                 netsock, s, thread, t, struct sockaddr *, addr, socklen_t *, addrlen, int, flags,
                 u64, bqflags)
{
    netsock s = bound(s);
    thread t = bound(t);
    sysreturn rv = 0;
    thread_resume(bound(t));

    err_t err = get_lwip_error(s);
    net_debug("sock %d, target thread %ld, lwip err %d\n", s->sock.fd, t->tid,
            err);

    if (err != ERR_OK) {
        rv = lwip_to_errno(err);
        goto out;
    }

    if (bqflags & BLOCKQ_ACTION_NULLIFY) {
        rv = -ERESTARTSYS;
        goto out;
    }

    netsock child = dequeue(s->incoming);
    if (child == INVALID_ADDRESS) {
        if (s->sock.f.flags & SOCK_NONBLOCK) {
            rv = -EAGAIN;
            goto out;
        }
        return blockq_block_required(t, bqflags);               /* block */
    }

    boolean blocked = (bqflags & BLOCKQ_ACTION_BLOCKED);
    child->sock.f.flags |= bound(flags);
    if (bound(addr)) {
        if (child->info.tcp.state == TCP_SOCK_OPEN)
            remote_sockaddr(child, bound(addr), bound(addrlen), blocked);
        else
            /* The new socket is disconnected already, we can't retrieve the address of the remote
             * peer. */
            addrport_to_sockaddr(child->sock.domain, (ip_addr_t *)IP_ADDR_ANY, 0,
                bound(addr), bound(addrlen));
    }

    /* report falling edge in case of edge trigger */
    if (queue_length(s->incoming) == 0)
        fdesc_notify_events(&s->sock.f);

    /* release slot in lwIP listen backlog */
    if (child->info.tcp.lw) {
        if (!blocked)
            lwip_lock();
        tcp_backlog_accepted(child->info.tcp.lw);
        if (!blocked)
            lwip_unlock();
    }

    rv = child->sock.fd;
    fdesc_put(&child->sock.f);
  out:
    syscall_return(t, rv);

    socket_release(&s->sock);
    closure_finish();
    return rv;
}

static sysreturn netsock_accept4(struct sock *sock, struct sockaddr *addr,
        socklen_t *addrlen, int flags)
{
    netsock s = (netsock) sock;
    sysreturn rv;
    if (sock->type != SOCK_STREAM) {
        rv = -EOPNOTSUPP;
        goto out;
    }

    if ((s->info.tcp.state != TCP_SOCK_LISTENING) ||
            (flags & ~(SOCK_NONBLOCK | SOCK_CLOEXEC))) {
        rv = -EINVAL;
        goto out;
    }

    blockq_action ba = closure(sock->h, accept_bh, s, current, addr, addrlen,
            flags);
    return blockq_check(sock->rxbq, current, ba, false);
  out:
    socket_release(sock);
    return rv;
}

sysreturn accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen,
        int flags)
{
    net_debug("sock %d, addr %p, addrlen %p, flags %x\n", sockfd, addr, addrlen,
            flags);
    if (addr && (!validate_user_memory(addrlen, sizeof(socklen_t), true) ||
                 !validate_user_memory(addr, *addrlen, true)))
        return -EFAULT;
    struct sock *sock = resolve_socket(current->p, sockfd);
    if (!sock->accept4) {
        socket_release(sock);
        return -EOPNOTSUPP;
    }
    return sock->accept4(sock, addr, addrlen, flags);
}

sysreturn accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    return accept4(sockfd, addr, addrlen, 0);
}

static sysreturn netsock_getsockname(struct sock *sock, struct sockaddr *addr, socklen_t *addrlen)
{
    netsock s = get_netsock(sock);
    ip_addr_t *ip_addr;
    u16_t port;
    sysreturn rv;
    lwip_lock();
    if (s->sock.type == SOCK_STREAM) {
        if (s->info.tcp.lw) {
            port = s->info.tcp.lw->local_port;
            ip_addr = &s->info.tcp.lw->local_ip;
        } else {
            /* The socket has been shut down; since we can't retrieve its local address, pretend
             * it's not bound to any address. */
            port = 0;
            ip_addr = (ip_addr_t *)IP_ADDR_ANY;
        }
    } else if (s->sock.type == SOCK_DGRAM) {
        port = s->info.udp.lw->local_port;
        ip_addr = &s->info.udp.lw->local_ip;
    } else {
        msg_warn("not supported for socket type %d\n", s->sock.type);
        rv = -EINVAL;
        goto unlock_out;
    }
    addrport_to_sockaddr(s->sock.domain, ip_addr, port, addr, addrlen);
    rv = 0;
  unlock_out:
    lwip_unlock();
    socket_release(sock);
    return rv;
}

sysreturn getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    net_debug("sock %d, addr %p, addrlen %p\n", sockfd, addr, addrlen);
    if (!validate_user_memory(addrlen, sizeof(socklen_t), true) ||
        !validate_user_memory(addr, *addrlen, true))
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
    if (!validate_user_memory(addrlen, sizeof(socklen_t), true) ||
        !validate_user_memory(addr, *addrlen, true))
        return -EFAULT;
    struct sock *sock = resolve_socket(current->p, sockfd);
    sysreturn rv = 0;
    netsock s = get_netsock(sock);
    if (!s)
        rv = -EOPNOTSUPP;
    else if ((s->sock.type == SOCK_STREAM) && (s->info.tcp.state != TCP_SOCK_OPEN))
        rv = -ENOTCONN;
    else
        remote_sockaddr(s, addr, addrlen, false);
    socket_release(sock);
    return rv;
}

sysreturn setsockopt(int sockfd,
                     int level,
                     int optname,
                     void *optval,
                     socklen_t optlen)
{
    if (!validate_user_memory(optval, optlen, false))
        return -EFAULT;
    struct sock *sock = resolve_socket(current->p, sockfd);
    netsock s = get_netsock(sock);
    sysreturn rv;
    if (!s) {
        rv = -EOPNOTSUPP;
        goto out;
    }
    switch (level) {
    case IPPROTO_IPV6:
        switch (optname) {
        case IPV6_V6ONLY:
            if (optlen != sizeof(int)) {
                rv = -EINVAL;
                goto out;
            }
            s->ipv6only = *((int *)optval);
            break;
        default:
            goto unimplemented;
        }
        break;
    case SOL_SOCKET:
        switch (optname) {
        case SO_REUSEADDR:
            if (optlen != sizeof(int)) {
                rv = -EINVAL;
                goto out;
            }
            lwip_lock();
            if ((s->sock.type == SOCK_STREAM) && s->info.tcp.lw) {
                if (*((int *)optval))
                    ip_set_option(s->info.tcp.lw, SOF_REUSEADDR);
                else
                    ip_reset_option(s->info.tcp.lw, SOF_REUSEADDR);
            } else if (s->sock.type == SOCK_DGRAM){
                if (*((int *)optval))
                    ip_set_option(s->info.udp.lw, SOF_REUSEADDR);
                else
                    ip_reset_option(s->info.udp.lw, SOF_REUSEADDR);
            } else {
                lwip_unlock();
                rv = -EINVAL;
                goto out;
            }
            lwip_unlock();
            break;
        default:
            goto unimplemented;
        }
        break;
    case SOL_TCP:
        switch (optname) {
        case TCP_NODELAY:
            if ((optlen != sizeof(int)) || (s->sock.type != SOCK_STREAM) || !s->info.tcp.lw) {
                rv = -EINVAL;
                goto out;
            }
            lwip_lock();
            if (*((int *)optval))
                tcp_nagle_enable(s->info.tcp.lw);
            else
                tcp_nagle_disable(s->info.tcp.lw);
            lwip_unlock();
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
	    sockfd, level, optname);
    rv = 0;
out:
    socket_release(sock);
    return rv;
}

sysreturn getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen)
{
    if (!validate_user_memory(optlen, sizeof(socklen_t), true) ||
            !validate_user_memory(optval, *optlen, true))
        return -EFAULT;
    struct sock *sock = resolve_socket(current->p, sockfd);
    netsock s = get_netsock(sock);
    sysreturn rv;
    if (!s) {
        rv = -EOPNOTSUPP;
        goto out;
    }
    net_debug("sock %d, type %d, thread %ld, level %d, optname %d\n, optlen %d\n",
        s->sock.fd, s->sock.type, current->tid, level, optname,
        optlen ? *optlen : -1);

    union {
        int val;
        struct linger linger;
    } ret_optval;
    int ret_optlen;

    switch (level) {
    case SOL_SOCKET:
        switch (optname) {
        case SO_TYPE:
            ret_optval.val = s->sock.type;
            ret_optlen = sizeof(ret_optval.val);
            break;
        case SO_ERROR:
            ret_optval.val = -lwip_to_errno(get_and_clear_lwip_error(s));
            ret_optlen = sizeof(ret_optval.val);
            break;
        case SO_SNDBUF:
        case SO_RCVBUF:
            ret_optval.val = 2048;  /* minimum value for this option in Linux */
            ret_optlen = sizeof(ret_optval.val);
            break;
        case SO_PRIORITY:
            ret_optval.val = 0; /* default value in Linux */
            ret_optlen = sizeof(ret_optval.val);
            break;
        case SO_LINGER:
            ret_optval.linger.l_onoff = 0;
            ret_optval.linger.l_linger = 0;
            ret_optlen = sizeof(ret_optval.linger);
            break;
        case SO_ACCEPTCONN:
            ret_optval.val = (s->sock.type == SOCK_STREAM) && (s->info.tcp.state == TCP_SOCK_LISTENING);
            ret_optlen = sizeof(ret_optval.val);
            break;
        default:
            goto unimplemented;
        }
        break;
    case IPPROTO_IPV6:
        switch (optname) {
        case IPV6_V6ONLY:
            ret_optval.val = s->ipv6only;
            ret_optlen = sizeof(ret_optval.val);
            break;
        default:
            goto unimplemented;
        }
        break;
    default:
        rv = -EOPNOTSUPP;
        goto out;
    }
    if (optval && optlen) {
        ret_optlen = MIN(*optlen, ret_optlen);
        runtime_memcpy(optval, &ret_optval, ret_optlen);
        *optlen = ret_optlen;
    }

    rv = 0;
    goto out;
unimplemented:
    msg_err("getsockopt unimplemented optname: fd %d, level %d, optname %d\n",
        sockfd, level, optname);
    rv = -ENOPROTOOPT;
out:
    socket_release(sock);
    return rv;
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
    register_syscall(map, setsockopt, setsockopt);
    register_syscall(map, getsockname, getsockname);
    register_syscall(map, getpeername, getpeername);
    register_syscall(map, getsockopt, getsockopt);
    register_syscall(map, shutdown, shutdown);
}

boolean netsyscall_init(unix_heaps uh)
{
    kernel_heaps kh = (kernel_heaps)uh;
    heap socket_cache = locking_heap_wrapper(heap_general(kh), allocate_objcache(heap_general(kh),
        (heap)heap_linear_backed(kh), sizeof(struct netsock), PAGESIZE));
    if (socket_cache == INVALID_ADDRESS)
	return false;
    uh->socket_cache = socket_cache;
    net_loop_poll = closure(heap_general(kh), netsock_poll);
    netlink_init();
    return true;
}
