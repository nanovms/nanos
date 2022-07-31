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

#define SIOCGIFNAME    0x8910
#define SIOCGIFCONF    0x8912
#define SIOCGIFFLAGS   0x8913
#define SIOCSIFFLAGS   0x8914
#define SIOCGIFADDR    0x8915
#define SIOCSIFADDR    0x8916
#define SIOCGIFNETMASK 0x891B
#define SIOCSIFNETMASK 0x891C
#define SIOCGIFMTU     0x8921
#define SIOCSIFMTU     0x8922
#define SIOCGIFINDEX   0x8933

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
	    tcpflags_t flags;
	    enum tcp_socket_state state; // half open?
	} tcp;
	struct {
	    struct udp_pcb *lw;
	    enum udp_socket_state state;
	} udp;
    } info;
} *netsock;

#define DEFAULT_SO_RCVBUF   0x34000 /* same as Linux */

int so_rcvbuf;

static sysreturn netsock_bind(struct sock *sock, struct sockaddr *addr,
        socklen_t addrlen);
static sysreturn netsock_listen(struct sock *sock, int backlog);
static sysreturn netsock_connect(struct sock *sock, struct sockaddr *addr,
        socklen_t addrlen);
static sysreturn netsock_accept4(struct sock *sock, struct sockaddr *addr,
        socklen_t *addrlen, int flags);
static sysreturn netsock_getsockname(struct sock *sock, struct sockaddr *addr, socklen_t *addrlen);
static sysreturn netsock_getsockopt(struct sock *sock, int level,
                                    int optname, void *optval, socklen_t *optlen);
static sysreturn netsock_setsockopt(struct sock *sock, int level,
                                    int optname, void *optval, socklen_t optlen);
static sysreturn netsock_sendto(struct sock *sock, void *buf, u64 len,
        int flags, struct sockaddr *dest_addr, socklen_t addrlen);
static sysreturn netsock_recvfrom(struct sock *sock, void *buf, u64 len,
        int flags, struct sockaddr *src_addr, socklen_t *addrlen);
static sysreturn netsock_sendmsg(struct sock *sock, const struct msghdr *msg,
                                 int flags, boolean in_bh, io_completion completion);
static sysreturn netsock_recvmsg(struct sock *sock, struct msghdr *msg,
                                 int flags, boolean in_bh, io_completion completion);

BSS_RO_AFTER_INIT static thunk net_loop_poll;
static boolean net_loop_poll_queued;

closure_function(0, 0, void, netsock_poll) {
    /* taking the lock here can block, so clear the flag after acquiring */
    lwip_lock();
    net_loop_poll_queued = false;
    netif_poll_all();
    lwip_unlock();
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

closure_function(1, 1, u32, socket_events,
                 netsock, s,
                 thread, t /* ignore */)
{
    netsock s = bound(s);
    boolean in = !queue_empty(s->incoming);
    sysreturn rv;
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
    lwip_lock();
    e = s->lwip_error;
    s->lwip_error = ERR_OK;
    lwip_unlock();
    return e;
#else
    return __atomic_exchange_n(&s->lwip_error, ERR_OK, __ATOMIC_ACQUIRE);
#endif
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

static void remote_sockaddr(netsock s, struct sockaddr *addr, socklen_t *len)
{
    ip_addr_t *ip_addr;
    u16_t port;
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

static sysreturn sock_read_bh_internal(netsock s, struct msghdr *msg, int flags,
                                       io_completion completion, u64 bqflags)
{
    lwip_lock();

    thread t = current;
    sysreturn rv = 0;
    err_t err = get_lwip_error(s);
    iovec iov = msg->msg_iov;
    u64 length = msg->msg_iovlen;
    net_debug("sock %d, thread %ld, iov %p, len %ld, flags 0x%x, bqflags 0x%lx, lwip err %d\n",
	      s->sock.fd, t->tid, iov, length, flags, bqflags, err);
    assert(s->sock.type == SOCK_STREAM || s->sock.type == SOCK_DGRAM);

    if (s->sock.type == SOCK_STREAM && s->info.tcp.state != TCP_SOCK_OPEN) {
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
        lwip_unlock();
        return blockq_block_required(t, bqflags);
    }

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
    u64 xfer_total = 0;
    u32 pbuf_idx = 0;

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
                if ((s->sock.type == SOCK_STREAM) && !(flags & MSG_PEEK))
                    tcp_recved(s->info.tcp.lw, xfer);
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
                fdesc_notify_events(&s->sock.f); /* reset a triggered EPOLLIN condition */
        }
    } while(s->sock.type == SOCK_STREAM && length > 0 && p != INVALID_ADDRESS); /* XXX simplify expression */

    if (s->sock.type == SOCK_STREAM)
        /* Calls to tcp_recved() may have enqueued new packets in the loopback interface. */
        netsock_check_loop();

    rv = xfer_total;
  out_unlock:
    lwip_unlock();
    net_debug("   completion %p, rv %ld\n", completion, rv);
    apply(completion, t, rv);
    return rv;
}

closure_function(8, 1, sysreturn, sock_read_bh,
                 netsock, s, thread, t, void *, dest, u64, length, int, flags, struct sockaddr *, src_addr, socklen_t *, addrlen, io_completion, completion,
                 u64, flags)
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
    if (msg.msg_name)
        msg.msg_namelen = *bound(addrlen);
    sysreturn rv = sock_read_bh_internal(bound(s), &msg, bound(flags), bound(completion), flags);
    if (rv != BLOCKQ_BLOCK_REQUIRED) {
        if (msg.msg_name)
            *bound(addrlen) = msg.msg_namelen;
        closure_finish();
    }
    return rv;
}

closure_function(4, 1, sysreturn, recvmsg_bh,
                 netsock, s, struct msghdr *, msg, int, flags, io_completion, completion,
                 u64, flags)
{
    sysreturn rv = sock_read_bh_internal(bound(s), bound(msg), bound(flags), bound(completion),
                                        flags);
    if (rv != BLOCKQ_BLOCK_REQUIRED)
        closure_finish();
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

    blockq_action ba = contextual_closure(sock_read_bh, s, t, dest, length, 0, 0,
                                          0, completion);
    return blockq_check(s->sock.rxbq, t, ba, bh);
}

closure_function(6, 1, sysreturn, socket_write_tcp_bh,
                 netsock, s, void *, buf, iovec, iov, u64, length, int, flags, io_completion, completion,
                 u64, bqflags)
{
    lwip_lock();

    netsock s = bound(s);
    void *buf = bound(buf);
    u64 remain = bound(length);
    int flags = bound(flags);
    thread t = current;
    sysreturn rv = 0;
    io_completion completion = bound(completion);
    err_t err = get_lwip_error(s);
    net_debug("fd %d, thread %ld, buf %p, remain %ld, flags 0x%x, bqflags 0x%lx, lwip err %d\n",
              s->sock.fd, t->tid, buf, remain, flags, bqflags, err);
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

    /* Note that the actual transmit window size is truncated to 16
       bits here (and tcp_write() doesn't accept more than 2^16
       anyway), so even if we have a large transmit window due to
       LWIP_WND_SCALE, we still can't write more than 2^16. Sigh... */
    u64 avail = tcp_sndbuf(s->info.tcp.lw);
    if (avail == 0) {
        /* directly poll for loopback traffic in case the enqueued netsock_poll is backed up */
        netif_poll_all();
        avail = tcp_sndbuf(s->info.tcp.lw);
        if (avail == 0) {
          full:
            if ((bqflags & BLOCKQ_ACTION_BLOCKED) == 0 &&
                ((s->sock.f.flags & SOCK_NONBLOCK) || (flags & MSG_DONTWAIT))) {
                net_debug(" send buf full and non-blocking, return EAGAIN\n");
                rv = -EAGAIN;
                goto out_unlock;
            }
            net_debug(" send buf full, sleep\n");
            lwip_unlock();
            return blockq_block_required(t, bqflags); /* block again */
        }
    }
    iovec iov = bound(iov);
    struct iovec iov_internal;
    if (!iov) {
        iov = &iov_internal;
        iov->iov_base = buf;
        iov->iov_len = remain;
        remain = 1;
    }

    /* Figure actual length and flags */
    u64 n;
    for (u64 i = 0; i < remain; i++) {
        u8 apiflags = TCP_WRITE_FLAG_COPY;
        n = iov[i].iov_len;
        if (avail < rv + n) {
            n = avail - rv;
            apiflags |= TCP_WRITE_FLAG_MORE;
        } else if (i < remain) {
            apiflags |= TCP_WRITE_FLAG_MORE;
        }

        err = tcp_write(s->info.tcp.lw, iov[i].iov_base, n, apiflags);
        if (err == ERR_OK) {
            rv += n;
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
    if (err == ERR_OK) {
        /* XXX prob add a flag to determine whether to continuously
           post data, e.g. if used by send/sendto... */
        err = tcp_output(s->info.tcp.lw);
        lwip_unlock();
        if (err == ERR_OK) {
            net_debug(" tcp_write and tcp_output successful for %ld bytes\n", rv);
            netsock_check_loop();
            if (rv == avail) {
                fdesc_notify_events(&s->sock.f); /* reset a triggered EPOLLOUT condition */
            }
        } else {
            net_debug(" tcp_output() lwip error: %d\n", err);
            rv = lwip_to_errno(err);
            /* XXX map error to socket tcp state */
        }
        goto out;
    }
  out_unlock:
    lwip_unlock();
  out:
    closure_finish();
    net_debug("   completion %p, rv %ld\n", completion, rv);
    apply(completion, t, rv);
    return rv;
}

static sysreturn socket_write_udp(netsock s, void *source, iovec iov, u64 length,
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
    lwip_lock();
    if (!dest_addr && !udp_is_flag_set(s->info.udp.lw, UDP_FLAGS_CONNECTED)) {
        lwip_unlock();
        return -EDESTADDRREQ;
    }

    struct iovec iov_internal;
    if (!iov) {
        iov = &iov_internal;
        iov->iov_base = source;
        iov->iov_len = length;
        length = 1;
    }
    u64 total_len = iov_total_len(iov, length);
    struct pbuf *pbuf = pbuf_alloc(PBUF_TRANSPORT, total_len, PBUF_RAM);
    if (!pbuf) {
        lwip_unlock();
        msg_err("failed to allocate pbuf for udp_send()\n");
        return -ENOBUFS;
    }
    for (u64 i = 0, offset = 0; i < length; offset += iov[i].iov_len, i++)
        runtime_memcpy(pbuf->payload + offset, iov[i].iov_base, iov[i].iov_len);
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
    return total_len;
}

static sysreturn socket_write_internal(struct sock *sock, void *source, iovec iov,
                                       u64 length, int flags,
                                       struct sockaddr *dest_addr, socklen_t addrlen,
                                       boolean bh, io_completion completion)
{
    netsock s = (netsock) sock;
    thread t = current;
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
        blockq_action ba = contextual_closure(socket_write_tcp_bh, s, source, iov, length, flags,
                                              completion);
        return blockq_check(sock->txbq, t, ba, bh);
    } else if (sock->type == SOCK_DGRAM) {
        rv = socket_write_udp(s, source, iov, length, dest_addr, addrlen);
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
    return socket_write_internal(s, source, 0, length, 0, 0, 0, bh, completion);
}

/* socket configuration controls; not netsock specific, but reliant on lwIP calls */
sysreturn socket_ioctl(struct sock *s, unsigned long request, vlist ap)
{
    net_debug("sock %d, request 0x%x\n", s->sock.fd, request);
    switch (request) {
    case SIOCGIFNAME: {
        struct ifreq *ifreq = varg(ap, struct ifreq *);
        if (!validate_user_memory(ifreq, sizeof(struct ifreq), true))
            return -EFAULT;
        lwip_lock();
        struct netif *netif = netif_get_by_index(ifreq->ifr.ifr_ivalue);
        lwip_unlock();
        ifreq->ifr_name[IFNAMSIZ-1] = '\0';
        netif_name_cpy(ifreq->ifr_name, netif);
        return 0;
    }
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
    default:
        return ioctl_generic(&s->f, request, ap);
    }
}

closure_function(1, 2, sysreturn, netsock_ioctl,
                 netsock, s,
                 unsigned long, request, vlist, ap)
{
    netsock s = bound(s);
    net_debug("sock %d, request 0x%x\n", s->sock.fd, request);
    switch (request) {
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

/* Must fit in a u8_t, because it may be used as backlog value for tcp_listen_with_backlog(). */
#define SOCK_QUEUE_LEN 255

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
	if ((s->sock.rx_len + p->tot_len > so_rcvbuf) || queue_full(s->incoming)) {
	    pbuf_free(p);
	    return;
	}
	/* could make a cache if we care to */
	struct udp_entry * e = allocate(s->sock.h, sizeof(*e));
	assert(e != INVALID_ADDRESS);
	e->pbuf = p;
	runtime_memcpy(&e->raddr, addr, sizeof(ip_addr_t));
	e->rport = port;
	assert(enqueue(s->incoming, e));
	s->sock.rx_len += p->tot_len;
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
    s->sock.getsockopt = netsock_getsockopt;
    s->sock.setsockopt = netsock_setsockopt;
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
	s->info.tcp.flags = pcb->flags;
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
        if ((s->sock.rx_len + p->tot_len > so_rcvbuf) || !enqueue(s->incoming, p)) {
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
                        contextual_closure(connect_tcp_bh, s, current), false);
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
    return socket_write_internal(sock, buf, 0, len, flags, dest_addr, addrlen, false,
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

static sysreturn netsock_sendmsg(struct sock *s, const struct msghdr *msg, int flags,
                                 boolean in_bh, io_completion completion)
{
    sysreturn rv = sendto_prepare(s, flags);
    if (rv < 0)
        return io_complete(completion, current, rv);
    return socket_write_internal(s, 0, msg->msg_iov, msg->msg_iovlen, flags,
                                 msg->msg_name, msg->msg_namelen, in_bh, completion);
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

closure_function(6, 2, void, sendmmsg_complete,
                 struct sock *, s, struct mmsghdr *, msgvec, unsigned int, vlen, int, flags, unsigned int, index, closure_struct_type(sendmmsg_next), next,
                 thread, t, sysreturn, rv)
{
    struct sock *s = bound(s);
    if (rv < 0)
        goto out;
    struct mmsghdr *hdr = &bound(msgvec)[bound(index)];
    hdr->msg_len = rv;
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
    apply(syscall_io_complete, t, rv);
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

    blockq_action ba = contextual_closure(sock_read_bh, s, current, buf, len, flags,
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
                                 int flags, boolean in_bh, io_completion completion)
{
    thread t = current;
    netsock s = (netsock) sock;
    sysreturn rv;

    if ((sock->type == SOCK_STREAM) && (s->info.tcp.state != TCP_SOCK_OPEN)) {
        rv = (s->info.tcp.state == TCP_SOCK_UNDEFINED) ? 0 : -ENOTCONN;
        goto out;
    }
    msg->msg_controllen = 0;
    msg->msg_flags = 0;
    blockq_action ba = contextual_closure(recvmsg_bh, s, msg, flags, completion);
    return blockq_check(sock->rxbq, t, ba, in_bh);
  out:
    return io_complete(completion, t, rv);
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

closure_function(6, 2, void, recvmmsg_complete,
                 struct sock *, s, struct mmsghdr *, msgvec, unsigned int, vlen, int, flags, unsigned int, index, closure_struct_type(recvmmsg_next), next,
                 thread, t, sysreturn, rv)
{
    struct sock *s = bound(s);
    if (rv < 0)
        goto out;
    struct mmsghdr *msgvec = bound(msgvec);
    struct mmsghdr *hdr = &msgvec[bound(index)];
    hdr->msg_len = rv;
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
    apply(syscall_io_complete, t, rv);
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

    if (err == ERR_MEM) {
        set_lwip_error(s, err);
        wakeup_sock(s, WAKEUP_SOCK_EXCEPT);
        return err;               /* lwIP doesn't care */
    }

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

    child->sock.f.flags |= bound(flags);
    if (bound(addr)) {
        if (child->info.tcp.state == TCP_SOCK_OPEN)
            remote_sockaddr(child, bound(addr), bound(addrlen));
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
        lwip_lock();
        tcp_backlog_accepted(child->info.tcp.lw);
        /* TCP flags are inherited from listen socket. */
        child->info.tcp.flags = child->info.tcp.lw->flags = s->info.tcp.flags;
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

    blockq_action ba = contextual_closure(accept_bh, s, current, addr, addrlen, flags);
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
        remote_sockaddr(s, addr, addrlen);
    socket_release(sock);
    return rv;
}

static sysreturn netsock_setsockopt(struct sock *sock, int level,
                                    int optname, void *optval, socklen_t optlen)
{
    netsock s = (netsock)sock;
    sysreturn rv;
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
        case SO_KEEPALIVE:
        case SO_BROADCAST:
            if (optlen != sizeof(int)) {
                rv = -EINVAL;
                goto out;
            }
            u8 so_option = (optname == SO_REUSEADDR ? SOF_REUSEADDR :
                            (optname == SO_KEEPALIVE ? SOF_KEEPALIVE : SOF_BROADCAST));
            lwip_lock();
            if ((s->sock.type == SOCK_STREAM) && s->info.tcp.lw) {
                if (*((int *)optval))
                    ip_set_option(s->info.tcp.lw, so_option);
                else
                    ip_reset_option(s->info.tcp.lw, so_option);
            } else if (s->sock.type == SOCK_DGRAM) {
                if (*((int *)optval))
                    ip_set_option(s->info.udp.lw, so_option);
                else
                    ip_reset_option(s->info.udp.lw, so_option);
            } else {
                lwip_unlock();
                rv = -EINVAL;
                goto out;
            }
            lwip_unlock();
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
            if ((optlen != sizeof(int)) || (s->sock.type != SOCK_STREAM)) {
                rv = -EINVAL;
                goto out;
            }
            lwip_lock();
            if (s->info.tcp.lw && (s->info.tcp.state != TCP_SOCK_LISTENING)) {
                if (*((int *)optval))
                    tcp_nagle_disable(s->info.tcp.lw);
                else
                    tcp_nagle_enable(s->info.tcp.lw);
            } else {
                if (*((int *)optval))
                    s->info.tcp.flags |= TF_NODELAY;
                else
                    s->info.tcp.flags &= ~TF_NODELAY;
            }
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
             sock->fd, level, optname);
    rv = 0;
out:
    socket_release(sock);
    return rv;
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
            ret_optval.val = (s->sock.type == SOCK_STREAM) ? TCP_SND_BUF : 0;
            ret_optlen = sizeof(ret_optval.val);
            break;
        case SO_RCVBUF:
            ret_optval.val = so_rcvbuf;
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
        case SO_REUSEADDR:
        case SO_KEEPALIVE:
        case SO_BROADCAST: {
            u8 so_option = (optname == SO_REUSEADDR ? SOF_REUSEADDR :
                            (optname == SO_KEEPALIVE ? SOF_KEEPALIVE : SOF_BROADCAST));
            lwip_lock();
            if ((s->sock.type == SOCK_STREAM) && s->info.tcp.lw) {
                ret_optval.val = !!ip_get_option(s->info.tcp.lw, so_option);
            } else if (s->sock.type == SOCK_DGRAM) {
                ret_optval.val = !!ip_get_option(s->info.udp.lw, so_option);
            } else {
                lwip_unlock();
                rv = -EINVAL;
                goto out;
            }
            ret_optlen = sizeof(ret_optval.val);
            lwip_unlock();
            break;
        }
        case SO_REUSEPORT:
            ret_optval.val = 0;
            ret_optlen = sizeof(ret_optval.val);
            break;
        default:
            goto unimplemented;
        }
        break;
    case SOL_TCP:
        switch (optname) {
        case TCP_NODELAY:
            lwip_lock();
            if (s->info.tcp.lw && (s->info.tcp.state != TCP_SOCK_LISTENING))
                ret_optval.val = tcp_nagle_disabled(s->info.tcp.lw);
            else
                ret_optval.val = ((s->info.tcp.flags & TF_NODELAY) != 0);
            ret_optlen = sizeof(ret_optval.val);
            lwip_unlock();
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
            sock->fd, level, optname);
    rv = -ENOPROTOOPT;
out:
    socket_release(sock);
    return rv;
}

sysreturn setsockopt(int sockfd, int level, int optname, void *optval, socklen_t optlen)
{
    if (!validate_user_memory(optval, optlen, false))
        return -EFAULT;
    struct sock *sock = resolve_socket(current->p, sockfd);
    if (!sock->setsockopt) {
        socket_release(sock);
        return -EOPNOTSUPP;
    }
    return sock->setsockopt(sock, level, optname, optval, optlen);
}

sysreturn getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen)
{
    if (!validate_user_memory(optlen, sizeof(socklen_t), true) ||
            !validate_user_memory(optval, *optlen, true))
        return -EFAULT;
    struct sock *sock = resolve_socket(current->p, sockfd);
    if (!sock->getsockopt) {
        socket_release(sock);
        return -EOPNOTSUPP;
    }
    return sock->getsockopt(sock, level, optname, optval, optlen);
}

void register_net_syscalls(struct syscall *map)
{
    register_syscall(map, socket, socket, SYSCALL_F_SET_NET);
    register_syscall(map, bind, bind, SYSCALL_F_SET_NET);
    register_syscall(map, listen, listen, SYSCALL_F_SET_NET);
    register_syscall(map, accept, accept, SYSCALL_F_SET_NET);
    register_syscall(map, accept4, accept4, SYSCALL_F_SET_NET);
    register_syscall(map, connect, connect, SYSCALL_F_SET_NET);
    register_syscall(map, sendto, sendto, SYSCALL_F_SET_NET);
    register_syscall(map, sendmsg, sendmsg, SYSCALL_F_SET_NET);
    register_syscall(map, sendmmsg, sendmmsg, SYSCALL_F_SET_NET);
    register_syscall(map, recvfrom, recvfrom, SYSCALL_F_SET_NET);
    register_syscall(map, recvmsg, recvmsg, SYSCALL_F_SET_NET);
    register_syscall(map, recvmmsg, recvmmsg, SYSCALL_F_SET_NET);
    register_syscall(map, setsockopt, setsockopt, SYSCALL_F_SET_NET);
    register_syscall(map, getsockname, getsockname, SYSCALL_F_SET_NET);
    register_syscall(map, getpeername, getpeername, SYSCALL_F_SET_NET);
    register_syscall(map, getsockopt, getsockopt, SYSCALL_F_SET_NET);
    register_syscall(map, shutdown, shutdown, SYSCALL_F_SET_NET);
}

boolean netsyscall_init(unix_heaps uh, tuple cfg)
{
    u64 rcvbuf;
    if (get_u64(cfg, sym(so_rcvbuf), &rcvbuf))
        so_rcvbuf = MIN(MAX(rcvbuf, 256), MASK(sizeof(so_rcvbuf) * 8 - 1));
    else
        so_rcvbuf = DEFAULT_SO_RCVBUF;
    kernel_heaps kh = (kernel_heaps)uh;
    caching_heap socket_cache = allocate_objcache(heap_general(kh), (heap)heap_linear_backed(kh),
                                                  sizeof(struct netsock), PAGESIZE, true);
    if (socket_cache == INVALID_ADDRESS)
	return false;
    uh->socket_cache = socket_cache;
    net_loop_poll = closure(heap_general(kh), netsock_poll);
    netlink_init();
    return true;
}
