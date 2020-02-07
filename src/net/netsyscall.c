/* TODO

   - consider switching on blockq timeout
   - check err handling of tcp_output
   - do udp tx bottom half
*/

#include <unix_internal.h>
#include <lwip.h>
#include <lwip/udp.h>
#include <net_system_structs.h>

//#define NETSYSCALL_DEBUG
#ifdef NETSYSCALL_DEBUG
#define net_debug(x, ...) do {log_printf(" NET", "%s: " x, __func__, ##__VA_ARGS__);} while(0)
#else
#define net_debug(x, ...)
#endif

#define SIOCGIFCONF 0x8912
#define SIOCGIFADDR 0x8915

#define IFNAMSIZ    16

#define resolve_socket(__p, __fd) ({fdesc f = resolve_fd(__p, __fd); \
    if (f->type != FDESC_TYPE_SOCKET) \
        return set_syscall_error(current, ENOTSOCK); \
    (sock)f;})

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

struct msghdr {
    void *msg_name;
    socklen_t msg_namelen;
    struct iovec *msg_iov;
    size_t msg_iovlen;
    void *msg_control;
    size_t msg_controllen;
    int msg_flags;
};

struct mmsghdr {
    struct msghdr msg_hdr;
    unsigned int msg_len;
};

struct ifmap {
    unsigned long mem_start;
    unsigned long mem_end;
    unsigned short base_addr;
    unsigned char irq;
    unsigned char dma;
    unsigned char port;
};

struct ifreq {
    char ifr_name[IFNAMSIZ];
    union {
        struct sockaddr ifr_addr;
        struct sockaddr ifr_dstaddr;
        struct sockaddr ifr_broadaddr;
        struct sockaddr ifr_netmask;
        struct sockaddr ifr_hwaddr;
        short ifr_flags;
        int ifr_ivalue;
        int ifr_mtu;
        struct ifmap ifru_map;
        char ifr_slave[IFNAMSIZ];
        char ifr_newname[IFNAMSIZ];
        void *ifr_data;
    } ifr;
};

struct ifconf {
    int ifc_len;
    union {
        char *ifc_buf;
        struct ifreq *ifc_req;
    } ifc;
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

typedef struct sock {
    struct fdesc f;              /* must be first */
    int type;
    process p;
    heap h;
    blockq rxbq;                 /* for incoming queue */
    queue incoming;
    blockq txbq;                 /* for lwip protocol tx buffer */
    int fd;
    err_t lwip_error;           /* lwIP error code; ERR_OK if normal */
    unsigned int msg_count;
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

closure_function(1, 1, u32, socket_events,
                 sock, s,
                 thread, t /* ignore */)
{
    sock s = bound(s);
    boolean in = !queue_empty(s->incoming);

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
    u32 events = apply(s->f.events, 0);
    net_debug("sock %d, events %lx\n", s->fd, events);
    notify_dispatch(s->f.ns, events);
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

static err_t get_and_clear_lwip_error(sock s)
{
    return __atomic_exchange_n(&s->lwip_error, ERR_OK, __ATOMIC_ACQUIRE);
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

static void remote_sockaddr_in(sock s, struct sockaddr_in *sin)
{
    sin->family = AF_INET;
    if (s->type == SOCK_STREAM) {
	struct tcp_pcb * lw = s->info.tcp.lw;
        assert(lw);
	sin->port = ntohs(lw->remote_port);
	sin->address = ip4_addr_get_u32(&lw->remote_ip);
    } else {
	assert(s->type == SOCK_DGRAM);
	struct udp_pcb * lw = s->info.udp.lw;
        assert(lw);
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
    case ERR_ALREADY: return -EALREADY;
    case ERR_ISCONN: return -EISCONN;
    case ERR_CONN: return -ENOTCONN;
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

static sysreturn sock_read_bh_internal(sock s, thread t, void * dest, u64 length, struct sockaddr * src_addr,
                                       socklen_t * addrlen, io_completion completion, u64 flags)
{
    /* called with corresponding blockq lock held */
    sysreturn rv = 0;
    err_t err = get_lwip_error(s);
    net_debug("sock %d, thread %ld, dest %p, len %ld, flags 0x%lx, lwip err %d\n",
	      s->fd, t->tid, dest, length, flags, err);
    assert(length > 0);
    assert(s->type == SOCK_STREAM || s->type == SOCK_DGRAM);

    if (flags & BLOCKQ_ACTION_NULLIFY) {
        rv = -EINTR;
        goto out;
    }

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
    if (p == INVALID_ADDRESS) {
        assert(p);
        if (s->type == SOCK_STREAM && s->info.tcp.lw->state != ESTABLISHED) {
            rv = 0;
            goto out;
        }
        if ((s->f.flags & SOCK_NONBLOCK)) {
            rv = -EAGAIN;
            goto out;
        }
        return BLOCKQ_BLOCK_REQUIRED;               /* back to chewing more cud */
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
        struct pbuf *cur_buf = pbuf;

        do {
            if (cur_buf->len > 0) {
                u64 xfer = MIN(length, cur_buf->len);
                runtime_memcpy(dest, cur_buf->payload, xfer);
                pbuf_consume(cur_buf, xfer);
                length -= xfer;
                xfer_total += xfer;
                dest = (char *) dest + xfer;
                if (s->type == SOCK_STREAM)
                    tcp_recved(s->info.tcp.lw, xfer);
            }
            if (cur_buf->len == 0)
                cur_buf = cur_buf->next;
        } while ((length > 0) && cur_buf);

        if (!cur_buf || (s->type == SOCK_DGRAM)) {
            assert(dequeue(s->incoming) == p);
            if (s->type == SOCK_DGRAM)
                deallocate(s->h, p, sizeof(struct udp_entry));
            pbuf_free(pbuf);
            p = queue_peek(s->incoming);
            if (p == INVALID_ADDRESS)
                notify_sock(s); /* reset a triggered EPOLLIN condition */
        }
    } while(s->type == SOCK_STREAM && length > 0 && p != INVALID_ADDRESS); /* XXX simplify expression */

    rv = xfer_total;
  out:
    net_debug("   completion %p, rv %ld\n", completion, rv);
    blockq_handle_completion(s->rxbq, flags, completion, t, rv);
    return rv;
}

closure_function(7, 1, sysreturn, sock_read_bh,
                 sock, s, thread, t, void *, dest, u64, length, struct sockaddr *, src_addr, socklen_t *, addrlen, io_completion, completion,
                 u64, flags)
{
    sysreturn rv = sock_read_bh_internal(bound(s), bound(t), bound(dest), bound(length), bound(src_addr), bound(addrlen), bound(completion), flags);
    if (rv != BLOCKQ_BLOCK_REQUIRED)
        closure_finish();
    return rv;
}

static void recvmsg_complete_internal(sock s, struct msghdr * msg, void * dest, u64 length, boolean blocked,
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
    deallocate(s->h, dest, length);
    msg->msg_controllen = 0;
    msg->msg_flags = 0;
    set_syscall_return(t, rv);
    if (blocked)
        thread_wakeup(t);
}

closure_function(5, 2, void, recvmsg_complete,
                 sock, s, struct msghdr *, msg, void *, dest, u64, length, boolean, blocked,
                 thread, t, sysreturn, rv)
{
    recvmsg_complete_internal(bound(s), bound(msg), bound(dest), bound(length), bound(blocked), t, rv);
    closure_finish();
}

closure_function(5, 1, sysreturn, recvmsg_bh,
                 sock, s, thread, t, void *, dest, u64, length, struct msghdr *, msg,
                 u64, flags)
{
    io_completion completion = closure(bound(s)->h, recvmsg_complete, bound(s), bound(msg), bound(dest),
                                       bound(length), true);
    sysreturn rv = sock_read_bh_internal(bound(s), bound(t), bound(dest), bound(length), bound(msg)->msg_name,
                                         &bound(msg)->msg_namelen, completion, flags);
    if (rv != BLOCKQ_BLOCK_REQUIRED)
        closure_finish();
    return rv;
}

closure_function(1, 6, sysreturn, socket_read,
                 sock, s,
                 void *, dest, u64, length, u64, offset, thread, t, boolean, bh, io_completion, completion)
{
    sock s = bound(s);
    net_debug("sock %d, type %d, thread %ld, dest %p, length %ld, offset %ld\n",
	      s->fd, s->type, t->tid, dest, length, offset);
    if (s->type == SOCK_STREAM && s->info.tcp.state != TCP_SOCK_OPEN)
        return -ENOTCONN;

    blockq_action ba = closure(s->h, sock_read_bh, s, t, dest, length, 0,
            0, completion);
    return blockq_check(s->rxbq, t, ba, bh);
}

static sysreturn socket_write_tcp_bh_internal(sock s, thread t, void * buf, u64 remain, io_completion completion, u64 flags)
{
    sysreturn rv = 0;
    err_t err = get_lwip_error(s);
    net_debug("fd %d, thread %ld, buf %p, remain %ld, flags 0x%lx, lwip err %d\n",
              s->fd, t->tid, buf, remain, flags, err);
    assert(remain > 0);

    if (flags & BLOCKQ_ACTION_NULLIFY) {
        rv = -EINTR;
        goto out;
    }

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
        if ((flags & BLOCKQ_ACTION_BLOCKED) == 0 && (s->f.flags & SOCK_NONBLOCK)) {
            net_debug(" send buf full and non-blocking, return EAGAIN\n");
            rv = -EAGAIN;
            goto out;
        } else {
            net_debug(" send buf full, sleep\n");
            return BLOCKQ_BLOCK_REQUIRED;           /* block again */
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
    net_debug("   completion %p, rv %ld\n", completion, rv);
    blockq_handle_completion(s->txbq, flags, completion, t, rv);
    return rv;
}

closure_function(5, 1, sysreturn, socket_write_tcp_bh,
                 sock, s, thread, t, void *, buf, u64, remain, io_completion, completion,
                 u64, flags)
{
    sysreturn rv = socket_write_tcp_bh_internal(bound(s), bound(t), bound(buf), bound(remain), bound(completion), flags);
    if (rv != BLOCKQ_BLOCK_REQUIRED)
        closure_finish();
    return rv;
}

static sysreturn socket_write_udp(sock s, void *source, u64 length)
{
    err_t err = ERR_OK;

    /* XXX check how much we can queue, maybe make udp bh */
    /* XXX check if remote endpoint set? let LWIP check? */
    struct pbuf * pbuf = pbuf_alloc(PBUF_TRANSPORT, length, PBUF_RAM);

    if (!pbuf) {
        msg_err("failed to allocate pbuf for udp_send()\n");
        return -ENOBUFS;
    }
    runtime_memcpy(pbuf->payload, source, length);
    err = udp_send(s->info.udp.lw, pbuf);
    if (err != ERR_OK) {
        net_debug("lwip error %d\n", err);
        return lwip_to_errno(err);
    }
    return length;
}

static sysreturn socket_write_internal(sock s, void *source, u64 length,
                                       thread t, boolean bh, io_completion completion)
{
    sysreturn rv;

    if (s->type == SOCK_STREAM) {
	if (s->info.tcp.state != TCP_SOCK_OPEN) 		/* XXX maybe defer to lwip for connect state */
	    return -EPIPE;
        if (length == 0) {
            rv = 0;
            goto out;
        }
        blockq_action ba = closure(s->h, socket_write_tcp_bh, s, t,
                                   source, length, completion);
        rv = blockq_check(s->txbq, t, ba, bh);
    } else if (s->type == SOCK_DGRAM) {
        rv = socket_write_udp(s, source, length);
    } else {
	msg_err("socket type %d unsupported\n", s->type);
	rv = -EINVAL;
    }
    net_debug("completed\n");
out:
    return rv;
}

closure_function(1, 6, sysreturn, socket_write,
                 sock, s,
                 void *, source, u64, length, u64, offset, thread, t, boolean, bh, io_completion, completion)
{
    sock s = bound(s);
    net_debug("sock %d, type %d, thread %ld, source %p, length %ld, offset %ld\n",
	      s->fd, s->type, t->tid, source, length, offset);
    return socket_write_internal(s, source, length, t, bh, completion);
}

closure_function(1, 2, sysreturn, socket_ioctl,
                 sock, s,
                 unsigned long, request, vlist, ap)
{
    sock s = bound(s);
    net_debug("sock %d, request 0x%x\n", s->fd, request);
    switch (request) {
    case SIOCGIFCONF: {
        struct ifconf *ifconf = varg(ap, struct ifconf *);
        if (ifconf->ifc.ifc_req == NULL) {
            ifconf->ifc_len = 0;
            for (struct netif *netif = netif_list; netif != NULL;
                    netif = netif->next) {
                if (netif_is_up(netif) && netif_is_link_up(netif) &&
                        !ip4_addr_isany(netif_ip4_addr(netif))) {
                    ifconf->ifc_len += sizeof(struct ifreq);
                }
            }
        }
        else {
            int len = 0;
            int iface = 0;
            for (struct netif *netif = netif_list; (netif != NULL) &&
                    (len + sizeof(ifconf->ifc) <= ifconf->ifc_len);
                    netif = netif->next) {
                if (netif_is_up(netif) && netif_is_link_up(netif) &&
                        !ip4_addr_isany(netif_ip4_addr(netif))) {
                    runtime_memcpy(ifconf->ifc.ifc_req[iface].ifr_name,
                            netif->name, sizeof(netif->name));
                    ifconf->ifc.ifc_req[iface].ifr_name[sizeof(netif->name)] =
                            '0' + netif->num;
                    ifconf->ifc.ifc_req[iface].ifr_name[sizeof(netif->name) + 1]
                             = '\0';
                    struct sockaddr_in *addr = (struct sockaddr_in *)
                            &ifconf->ifc.ifc_req[iface].ifr.ifr_addr;
                    addr->family = AF_INET;
                    runtime_memcpy(&addr->address, netif_ip4_addr(netif),
                            sizeof(ip4_addr_t));
                    len += sizeof(ifconf->ifc);
                    iface++;
                }
            }
            ifconf->ifc_len = len;
        }
        return 0;
    }
    case SIOCGIFADDR: {
        struct ifreq *ifreq = varg(ap, struct ifreq *);
        struct netif *netif = netif_find(ifreq->ifr_name);
        if (!netif) {
            return -ENODEV;
        }
        struct sockaddr_in *addr = (struct sockaddr_in *)&ifreq->ifr.ifr_addr;
        addr->family = AF_INET;
        runtime_memcpy(&addr->address, netif_ip4_addr(netif),
                sizeof(ip4_addr_t));
        return 0;
    }
    case FIONBIO: {
        int opt = varg(ap, int);
        if (opt) {
            s->f.flags |= SOCK_NONBLOCK;
        }
        else {
            s->f.flags &= ~SOCK_NONBLOCK;
        }
        return 0;
    }
    default:
        return -ENOSYS;
    }
}

#define SOCK_QUEUE_LEN 128

closure_function(1, 0, sysreturn, socket_close,
                 sock, s)
{
    sock s = bound(s);
    net_debug("sock %d, type %d\n", s->fd, s->type);
    switch (s->type) {
    case SOCK_STREAM:
        /* tcp_close() doesn't really stop everything synchronously; in order to
         * prevent any lwIP callback that might be called after tcp_close() from
         * using a stale reference to the socket structure, set the callback
         * argument to NULL. */
        if (s->info.tcp.lw) {
            tcp_close(s->info.tcp.lw);
            tcp_arg(s->info.tcp.lw, 0);
        }
        break;
    case SOCK_DGRAM:
        udp_remove(s->info.udp.lw);
        break;
    }
    deallocate_blockq(s->txbq);
    deallocate_blockq(s->rxbq);
    deallocate_queue(s->incoming);
    deallocate_closure(s->f.read);
    deallocate_closure(s->f.write);
    deallocate_closure(s->f.close);
    deallocate_closure(s->f.events);
    deallocate_closure(s->f.ioctl);
    release_fdesc(&s->f);
    unix_cache_free(s->p->uh, socket, s);
    return 0;
}

sysreturn shutdown(int sockfd, int how)
{
    int shut_rx = 0, shut_tx = 0;
    sock s = resolve_socket(current->p, sockfd);
		
    net_debug("sock %d, type %d, how %d\n", sockfd, s->type, how);

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
        msg_warn("Wrong value passed for direction sock %d, type %d\n", sockfd, s->type);
        return -EINVAL;
    }
    switch (s->type) {
    case SOCK_STREAM:
        if (s->info.tcp.state != TCP_SOCK_OPEN) {
            return -ENOTCONN;
        }
        tcp_shutdown(s->info.tcp.lw, shut_rx, shut_tx);
        break;
    case SOCK_DGRAM:
        return -ENOTCONN;
    }
    
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

static int allocate_sock(process p, int type, u32 flags, sock * rs)
{
    sock s;
    int fd;

    s = unix_cache_alloc(p->uh, socket);
    if (s == INVALID_ADDRESS) {
	msg_err("failed to allocate struct sock\n");
        goto err_sock;
    }

    fd = allocate_fd(p, s);
    if (fd == INVALID_PHYSICAL) {
        msg_err("failed to allocate fd\n");
        goto err_fd;
    }

    heap h = heap_general((kernel_heaps)p->uh);
    init_fdesc(h, &s->f, FDESC_TYPE_SOCKET);
    s->f.read = closure(h, socket_read, s);
    s->f.write = closure(h, socket_write, s);
    s->f.close = closure(h, socket_close, s);
    s->f.events = closure(h, socket_events, s);
    s->f.ioctl = closure(h, socket_ioctl, s);
    s->f.flags = flags;
    s->type = type;
    s->p = p;
    s->h = h;
    s->fd = fd;

    s->incoming = allocate_queue(h, SOCK_QUEUE_LEN);
    if (s->incoming == INVALID_ADDRESS) {
        msg_err("failed to allocate queue\n");
        goto err_queue;
    }

    s->rxbq = allocate_blockq(h, "sock receive");
    if (s->rxbq == INVALID_ADDRESS) {
        msg_err("failed to allocate blockq\n");
        goto err_rx;
    }
    s->txbq = allocate_blockq(h, "sock transmit");
    if (s->txbq == INVALID_ADDRESS) {
        msg_err("failed to allocate blockq\n");
        goto err_tx;
    }

    set_lwip_error(s, ERR_OK);
    *rs = s;
    return fd;

err_tx:
    deallocate_blockq(s->rxbq);
err_rx:
    deallocate_queue(s->incoming);
err_queue:
    deallocate_fd(p, fd);
err_fd:
    unix_cache_free(p->uh, socket, s);
err_sock:
    return -ENOMEM;
}

static int allocate_tcp_sock(process p, struct tcp_pcb *pcb, u32 flags)
{
    sock s;
    int fd = allocate_sock(p, SOCK_STREAM, flags, &s);
    if (fd >= 0) {
	s->info.tcp.lw = pcb;
	s->info.tcp.state = TCP_SOCK_CREATED;
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
    if (!z) {
        return err;
    }
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

static void lwip_tcp_conn_err(void * z, err_t err) {
    if (!z) {
        return;
    }
    sock s = z;
    net_debug("sock %d, err %d\n", s->fd, err);
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
    sock s = (sock)arg;
    net_debug("fd %d, pcb %p, len %d\n", s->fd, pcb, len);
    wakeup_sock(s, WAKEUP_SOCK_TX);
    return ERR_OK;
}

closure_function(2, 1, sysreturn, connect_tcp_bh,
                 sock, s, thread, t,
                 u64, flags)
{
    sysreturn rv = 0;
    sock s = bound(s);
    thread t = bound(t);
    err_t err = get_lwip_error(s);

    net_debug("sock %d, tcp state %d, thread %ld, lwip_status %d, flags 0x%lx\n",
              s->fd, s->info.tcp.state, t->tid, err, flags);

    if (flags & BLOCKQ_ACTION_NULLIFY) {
        /* XXX spinlock */
        s->info.tcp.state = TCP_SOCK_ABORTING_CONNECTION;
        rv = -EINTR;
        goto out;
    }

    if (s->info.tcp.state == TCP_SOCK_IN_CONNECTION)
        return BLOCKQ_BLOCK_REQUIRED;
    assert(s->info.tcp.state == TCP_SOCK_OPEN);
    rv = lwip_to_errno(err);
  out:
    if (flags & BLOCKQ_ACTION_BLOCKED)
        thread_wakeup(t);
    closure_finish();
    return set_syscall_return(t, rv);
}

static err_t connect_tcp_complete(void* arg, struct tcp_pcb* tpcb, err_t err)
{
   if (!arg)
      return ERR_OK;
   sock s = (sock)arg;
   net_debug("sock %d, tcp state %d, pcb %p, err %d\n", s->fd, s->info.tcp.state, tpcb, err);
   if (s->info.tcp.state == TCP_SOCK_ABORTING_CONNECTION) {
       s->info.tcp.state = TCP_SOCK_CREATED;
       return ERR_ABRT;
   }
   assert(s->info.tcp.state == TCP_SOCK_IN_CONNECTION);
   s->info.tcp.state = TCP_SOCK_OPEN; /* XXX state handling needs fixing; this could indicate an error as well */
   set_lwip_error(s, err);
   blockq_wake_one(s->rxbq);
   return ERR_OK;
}

static inline err_t connect_tcp(sock s, const ip_addr_t* address, unsigned short port)
{
    net_debug("sock %d, tcp state %d, addr %x, port %d\n", s->fd, s->info.tcp.state, address->addr, port);
    switch (s->info.tcp.state) {
    case TCP_SOCK_IN_CONNECTION:
    case TCP_SOCK_ABORTING_CONNECTION:
        return ERR_ALREADY;
    case TCP_SOCK_OPEN:
        return ERR_ISCONN;
    case TCP_SOCK_CREATED:
        break;
    default:
        msg_err("connect attempt while in state %d\n", s->info.tcp.state);
        return ERR_VAL;
    }
    struct tcp_pcb * lw = s->info.tcp.lw;
    tcp_arg(lw, s);
    tcp_recv(lw, tcp_input_lower);
    tcp_err(lw, lwip_tcp_conn_err);
    tcp_sent(lw, lwip_tcp_sent);
    s->info.tcp.state = TCP_SOCK_IN_CONNECTION;
    set_lwip_error(s, ERR_OK);
    err_t err = tcp_connect(lw, address, port, connect_tcp_complete);
    if (err != ERR_OK)
        return err;

    sysreturn rv = blockq_check(s->rxbq, current, closure(s->h, connect_tcp_bh, s, current), false);
    /* should not return under normal cirucmstances */
    msg_err("blockq check error: %ld\n", rv);
    return ERR_OK;
}

sysreturn connect(int sockfd, struct sockaddr * addr, socklen_t addrlen)
{
    err_t err = ERR_OK;
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

static sysreturn sendto_prepare(sock s, int flags, struct sockaddr *dest_addr,
        socklen_t addrlen)
{
    int err = ERR_OK;

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

    return 0;
}

sysreturn sendto(int sockfd, void * buf, u64 len, int flags,
		 struct sockaddr *dest_addr, socklen_t addrlen)
{
    sock s = resolve_fd(current->p, sockfd);
    net_debug("sendto %d, buf %p, len %ld, flags %x, dest_addr %p, addrlen %d\n",
              sockfd, buf, len, flags, dest_addr, addrlen);

    sysreturn rv = sendto_prepare(s, flags, dest_addr, addrlen);
    if (rv < 0) {
        return set_syscall_return(current, rv);
    }
    return socket_write_internal(s, buf, len, current, false, syscall_io_complete);
}

static sysreturn sendmsg_prepare(sock s, const struct msghdr *msg, int flags,
        void **buf, u64 *len)
{
    sysreturn rv;
    size_t i;

    rv = sendto_prepare(s, flags, msg->msg_name, msg->msg_namelen);
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

static void sendmsg_complete_internal(sock s, void * buf, u64 len, boolean blocked,
                                      thread t, sysreturn rv)
{
    deallocate(s->h, buf, len);
    set_syscall_return(t, rv);
    if (blocked)
        thread_wakeup(t);
}

closure_function(4, 2, void, sendmsg_complete,
                 sock, s, void *, buf, u64, len, boolean, blocked,
                 thread, t, sysreturn, rv)
{
    sendmsg_complete_internal(bound(s), bound(buf), bound(len), bound(blocked), t, rv);
    closure_finish();
}

sysreturn sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
    sock s = resolve_socket(current->p, sockfd);
    void *buf;
    u64 len;
    sysreturn rv;

    net_debug("sock %d, type %d, flags 0x%x\n", s->fd, s->type, flags);
    rv = sendmsg_prepare(s, msg, flags, &buf, &len);
    if (rv <= 0) {
        return set_syscall_return(current, rv);
    }
    io_completion completion = closure(s->h, sendmsg_complete, s, buf, len,
            true);
    rv = socket_write_internal(s, buf, len, current, false, completion);
    sendmsg_complete_internal(s, buf, len, false, current, rv);
    return rv;
}

closure_function(3, 2, void, sendmmsg_buf_complete,
                 sock, s, void *, buf, u64, len,
                 thread, t, sysreturn, rv)
{
    deallocate(bound(s)->h, bound(buf), bound(len));
    closure_finish();
}

closure_function(7, 1, sysreturn, sendmmsg_tcp_bh,
                 sock, s, thread, t, void *, buf, u64, len, int, flags, struct mmsghdr *, msgvec, unsigned int, vlen,
                 u64, bqflags)
{
    sock s = bound(s);
    thread t = bound(t);
    void * buf = bound(buf);
    u64 len = bound(len);
    struct mmsghdr * msgvec = bound(msgvec);

    io_completion completion = closure(s->h, sendmmsg_buf_complete, s, buf, len);
    sysreturn rv = socket_write_tcp_bh_internal(s, t, buf, len, completion, bqflags | BLOCKQ_ACTION_BLOCKED);

    while (true) {
        if (rv == BLOCKQ_BLOCK_REQUIRED) {
            return rv;
        }
        else if (rv <= 0) {
            if (s->msg_count > 0) {
                rv = s->msg_count;
            }
            break;
        }
        msgvec[s->msg_count++].msg_len = rv;
        if (s->msg_count == bound(vlen)) {
            break;
        }
        rv = sendmsg_prepare(s, &msgvec[s->msg_count].msg_hdr, bound(flags), &buf, &len);
        if (rv > 0) {
            completion = closure(s->h, sendmmsg_buf_complete, s, buf, len);
            rv = socket_write_tcp_bh_internal(s, t, buf, len, completion, bqflags | BLOCKQ_ACTION_BLOCKED);
        }
    }

    if (bqflags & BLOCKQ_ACTION_BLOCKED)
        thread_wakeup(t);

    closure_finish();
    return set_syscall_return(t, rv);
}

sysreturn sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen,
        int flags)
{
    void *buf;
    u64 len;
    sysreturn rv = 0;
    sock s = resolve_socket(current->p, sockfd);

    net_debug("sock %d, type %d, flags 0x%x, vlen %d\n", s->fd, s->type, flags,
            vlen);
    for (s->msg_count = 0; s->msg_count < vlen; s->msg_count++) {
        struct msghdr *msg_hdr = &msgvec[s->msg_count].msg_hdr;

        rv = sendmsg_prepare(s, msg_hdr, flags, &buf, &len);
        if (rv < 0) {
            break;
        }
        else if (rv == 0) {
            msgvec[s->msg_count].msg_len = 0;
            continue;
        }
        switch (s->type) {
        case SOCK_STREAM:
            if (s->info.tcp.state != TCP_SOCK_OPEN) {
                rv = -EPIPE;
                break;
            }
            blockq_action ba = closure(s->h, sendmmsg_tcp_bh, s, current,
                    buf, len, flags, msgvec, vlen);
            rv = blockq_check(s->txbq, current, ba, false);
            break;
        case SOCK_DGRAM:
            rv = socket_write_udp(s, buf, len);
            break;
        }
        deallocate(s->h, buf, len);
        if (rv < 0) {
            break;
        }
        msgvec[s->msg_count].msg_len = rv;
    }
    if (s->msg_count > 0) {
        rv = s->msg_count;
    }
    return set_syscall_return(current, rv);
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

    blockq_action ba = closure(s->h, sock_read_bh, s, current, buf, len,
                               src_addr, addrlen, syscall_io_complete);
    return blockq_check(s->rxbq, current, ba, false);
}

sysreturn recvmsg(int sockfd, struct msghdr *msg, int flags)
{
    u64 total_len;
    u8 *buf;
    sock s = resolve_socket(current->p, sockfd);

    net_debug("sock %d, type %d, thread %ld\n", s->fd, s->type, current->tid);
    if ((s->type == SOCK_STREAM) && (s->info.tcp.state != TCP_SOCK_OPEN)) {
        return set_syscall_error(current, ENOTCONN);
    }
    total_len = 0;
    for (int i = 0; i < msg->msg_iovlen; i++) {
        total_len += msg->msg_iov[i].iov_len;
    }
    if (total_len == 0) {
        return 0;
    }
    buf = allocate(s->h, total_len);
    if (buf == INVALID_ADDRESS) {
        return set_syscall_error(current, ENOMEM);
    }
    blockq_action ba = closure(s->h, recvmsg_bh, s, current, buf, total_len,
            msg);
    sysreturn rv = blockq_check(s->rxbq, current, ba, false);
    recvmsg_complete_internal(s, msg, buf, total_len, false, current, rv);
    return rv;
}

static err_t accept_tcp_from_lwip(void * z, struct tcp_pcb * lw, err_t err)
{
    if (!z) {
        return ERR_CLSD;
    }
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

closure_function(5, 1, sysreturn, accept_bh,
                 sock, s, thread, t, struct sockaddr *, addr, socklen_t *, addrlen, int, flags,
                 u64, bqflags)
{
    sock s = bound(s);
    thread t = bound(t);
    sysreturn rv = 0;

    if (bqflags & BLOCKQ_ACTION_NULLIFY) {
        rv = -EINTR;
        goto out;
    }

    err_t err = get_lwip_error(s);
    net_debug("sock %d, target thread %ld, lwip err %d\n", s->fd, t->tid, err);

    if (err != ERR_OK) {
        rv = lwip_to_errno(err);
        goto out;
    }

    sock child = dequeue(s->incoming);
    if (child == INVALID_ADDRESS) {
        if (s->f.flags & SOCK_NONBLOCK) {
            rv = -EAGAIN;
            goto out;
        }
        return BLOCKQ_BLOCK_REQUIRED;               /* block */
    }

    err_t child_err = get_lwip_error(child);
    if (child_err != ERR_OK) {
        rv = lwip_to_errno(child_err);
        goto out;
    }

    child->f.flags = bound(flags);
    if (bound(addr))
        remote_sockaddr_in(child, (struct sockaddr_in *)bound(addr));
    if (bound(addrlen))
        *bound(addrlen) = sizeof(struct sockaddr);

    /* report falling edge in case of edge trigger */
    if (queue_length(s->incoming) == 0)
        notify_sock(s);

    /* release slot in lwIP listen backlog */
    tcp_backlog_accepted(child->info.tcp.lw);

    rv = child->fd;
  out:
    set_syscall_return(t, rv);
    if (bqflags & BLOCKQ_ACTION_BLOCKED)
        thread_wakeup(t);

    closure_finish();
    return rv;
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
    return blockq_check(s->rxbq, current, ba, false);
}

sysreturn accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    return accept4(sockfd, addr, addrlen, 0);
}

sysreturn getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    net_debug("sock %d, addr %p, addrlen %p\n", sockfd, addr, addrlen);
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
        s->fd, s->type, current->tid, level, optname, optlen ? *optlen : -1);

    union {
        int val;
    } ret_optval;

    /* Only socket options supported at the moment... */
    if (level != 1)
        return -EOPNOTSUPP;

    switch (optname) {
    case SO_TYPE:
        ret_optval.val = s->type;
        break;
    case SO_ERROR:
        ret_optval.val = -lwip_to_errno(get_and_clear_lwip_error(s));
        break;
    case SO_SNDBUF:
        ret_optval.val = 2048;  /* minimum value for this option in Linux */
        break;
    default:
        msg_err("getsockopt unimplemented optname: fd %d, level %d, optname %d\n",
            sockfd, level, optname);
        return -ENOPROTOOPT;
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
    heap socket_cache = allocate_objcache(heap_general(kh), heap_backed(kh),
					  sizeof(struct sock), PAGESIZE);
    if (socket_cache == INVALID_ADDRESS)
	return false;
    uh->socket_cache = socket_cache;
    return true;
}
