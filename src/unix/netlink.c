#include <net_system_structs.h>
#include <unix_internal.h>
#include <lwip.h>
#include <socket.h>

#define NL_PID_KERNEL   0

struct sockaddr_nl {
    u16 nl_family;  /* AF_NETLINK */
    u16 nl_pad;     /* zero */
    u32 nl_pid;     /* port ID */
    u32 nl_groups;  /* multicast groups mask */
};

struct nlmsghdr {
    u32 nlmsg_len;      /* length of message including header */
    u16 nlmsg_type;     /* message content */
    u16 nlmsg_flags;    /* additional flags */
    u32 nlmsg_seq;      /* sequence number */
    u32 nlmsg_pid;      /* sender port ID */
};

/* Generic message types */
#define NLMSG_NOOP  1
#define NLMSG_ERROR 2
#define NLMSG_DONE  3 /* end of multipart message */

/* Generic message flags */
#define NLM_F_REQUEST   (1 << 0)    /* this is a request message */
#define NLM_F_MULTI     (1 << 1)    /* multipart message, terminated by NLMSG_DONE */
#define NLM_F_ACK       (1 << 2)    /* reply with ack message */
#define NLM_F_ECHO      (1 << 3)    /* echo this request */

/* Message flags for GET requests */
#define NLM_F_ROOT      (1 << 8)    /* return complete table instead of a single entry */
#define NLM_F_MATCH     (1 << 9)    /* return all matching entries */
#define NLM_F_ATOMIC    (1 << 10)   /* return atomic snapshot of table */
#define NLM_F_DUMP      (NLM_F_ROOT | NLM_F_MATCH)

#define NLMSG_ALIGNMENT     4
#define NLMSG_ALIGN(len)    pad(len, NLMSG_ALIGNMENT)
#define NLMSG_HDRLEN        NLMSG_ALIGN(sizeof(struct nlmsghdr))
#define NLMSG_DATA(nlh)     ((void *)(((u8 *)nlh) + NLMSG_HDRLEN))

struct nlmsgerr {
    int error;
    struct nlmsghdr msg;
};

#define NETLINK_ROUTE   0

/* NETLINK_ROUTE multicast groups */
#define RTMGRP_LINK         (1 << 0)
#define RTMGRP_NOTIFY       (1 << 1)
#define RTMGRP_NEIGH        (1 << 2)
#define RTMGRP_TC           (1 << 3)
#define RTMGRP_IPV4_IFADDR  (1 << 4)
#define RTMGRP_IPV4_MROUTE  (1 << 5)
#define RTMGRP_IPV4_ROUTE   (1 << 6)
#define RTMGRP_IPV4_RULE    (1 << 7)
#define RTMGRP_IPV6_IFADDR  (1 << 8)
#define RTMGRP_IPV6_MROUTE  (1 << 9)
#define RTMGRP_IPV6_ROUTE   (1 << 10)
#define RTMGRP_IPV6_IFINFO  (1 << 11)

/* NETLINK_ROUTE message types */
enum {
    RTM_NEWLINK = 16,
    RTM_DELLINK,
    RTM_GETLINK,
    RTM_SETLINK,
    RTM_NEWADDR = 20,
    RTM_DELADDR,
    RTM_GETADDR,
    RTM_NEWROUTE = 24,
    RTM_DELROUTE,
    RTM_GETROUTE,
    RTM_NEWNEIGH = 28,
    RTM_DELNEIGH,
    RTM_GETNEIGH,
    RTM_NEWRULE = 32,
    RTM_DELRULE,
    RTM_GETRULE,
    RTM_NEWQDISC = 36,
    RTM_DELQDISC,
    RTM_GETQDISC,
    RTM_NEWTCLASS = 40,
    RTM_DELTCLASS,
    RTM_GETTCLASS,
    RTM_NEWTFILTER = 44,
    RTM_DELTFILTER,
    RTM_GETTFILTER,
    RTM_NEWACTION = 48,
    RTM_DELACTION,
    RTM_GETACTION,
    RTM_NEWPREFIX = 52,
    RTM_GETMULTICAST = 58,
    RTM_GETANYCAST  = 62,
    RTM_NEWNEIGHTBL = 64,
    RTM_GETNEIGHTBL = 66,
    RTM_SETNEIGHTBL,
    RTM_NEWNDUSEROPT = 68,
    RTM_NEWADDRLABEL = 72,
    RTM_DELADDRLABEL,
    RTM_GETADDRLABEL,
    RTM_GETDCB = 78,
    RTM_SETDCB,
    RTM_NEWNETCONF = 80,
    RTM_GETNETCONF = 82,
    RTM_NEWMDB = 84,
    RTM_DELMDB,
    RTM_GETMDB,
    RTM_NEWNSID = 88,
    RTM_DELNSID,
    RTM_GETNSID,
};

/* RTM_* generic message payload */
struct rtgenmsg {
    u8 rtgen_family;
};

/* NETLINK_ROUTE attributes */
struct rtattr {
    u16 rta_len;
    u16 rta_type;
};

#define RTA_ALIGNMENT           4
#define RTA_ALIGN(len)          pad(len, RTA_ALIGNMENT)
#define RTA_LENGTH(data_len)    (RTA_ALIGN(sizeof(struct rtattr)) + (data_len))
#define RTA_SPACE(data_len)     RTA_ALIGN(RTA_LENGTH(data_len))
#define RTA_DATA(rta)           ((void *)(((u8 *)rta) + RTA_LENGTH(0)))
#define RTA_NEXT(rta)           ((struct rtattr *)(((u8 *)(rta)) + RTA_ALIGN((rta)->rta_len)))

/* RTM_*LINK message payload */
struct ifinfomsg {
    u8 ifi_family;              /* AF_UNSPEC */
    u16 ifi_type;               /* device type */
    int ifi_index;              /* 1-based interface index */
    unsigned int ifi_flags;     /* device flags */
    unsigned int ifi_change;    /* change mask */
};

/* RTM_*LINK attribute types */
enum {
    IFLA_UNSPEC,
    IFLA_ADDRESS,
    IFLA_BROADCAST,
    IFLA_IFNAME,
    IFLA_MTU,
};

/* RTM_*ADDR message payload */
struct ifaddrmsg {
    u8 ifa_family;
    u8 ifa_prefixlen;
    u8 ifa_flags;
    u8 ifa_scope;
    u32 ifa_index;  /* 1-based interface index */
};

/* ifaddrmsg.ifa_scope values */
enum rt_scope_t {
    RT_SCOPE_UNIVERSE = 0,
    RT_SCOPE_SITE = 200,
    RT_SCOPE_LINK = 253,
    RT_SCOPE_HOST = 254,
    RT_SCOPE_NOWHERE = 255
};

/* RTM_*ADDR attribute types */
enum {
    IFA_UNSPEC,
    IFA_ADDRESS,
    IFA_LOCAL,
    IFA_LABEL,
    IFA_BROADCAST,
    IFA_ANYCAST,
    IFA_CACHEINFO,
    IFA_MULTICAST,
    IFA_FLAGS,
};

#define NL_QUEUE_MAX_LEN    64

//#define NETLINK_DEBUG
#ifdef NETLINK_DEBUG
#define nl_debug(x, ...)    rprintf("NL: " x "\n", ##__VA_ARGS__)
#else
#define nl_debug(x, ...)
#endif

static struct {
    id_heap pids;
    vector sockets;
    struct spinlock lock;
} netlink;

typedef struct nlsock {
    struct sock sock;   /* must be first */
    int family;
    struct sockaddr_nl addr;
    queue data;
} *nlsock;

#define nl_lock(s)      spin_lock(&(s)->sock.f.lock)
#define nl_unlock(s)    spin_unlock(&(s)->sock.f.lock)

static void nl_enqueue(nlsock s, void *msg, u64 msg_len)
{
    if ((s->sock.rx_len + msg_len < so_rcvbuf) && enqueue(s->data, msg)) {
        s->sock.rx_len += msg_len;
        blockq_wake_one(s->sock.rxbq);
        fdesc_notify_events(&s->sock.f);
    } else {
        msg_err("failed to enqueue message\n");
        deallocate(s->sock.h, msg, msg_len);
    }
}

static void nl_enqueue_ifinfo(nlsock s, u16 type, u16 flags, u32 seq, u32 pid, struct netif *netif)
{
    int resp_len = NLMSG_ALIGN(sizeof(struct nlmsghdr) + sizeof(struct ifinfomsg) +
        RTA_SPACE(sizeof(netif->name) + 2) + RTA_SPACE(sizeof(u32) /* MTU */));
    if (netif->hwaddr_len != 0)
        resp_len += RTA_SPACE(netif->hwaddr_len);
    struct nlmsghdr *hdr = allocate(s->sock.h, resp_len);
    if (hdr == INVALID_ADDRESS) {
        msg_err("failed to allocate message\n");
        return;
    }
    hdr->nlmsg_len = resp_len;
    hdr->nlmsg_type = type;
    hdr->nlmsg_flags = flags;
    hdr->nlmsg_seq = seq;
    hdr->nlmsg_pid = pid;
    struct ifinfomsg *ifi = (struct ifinfomsg *)NLMSG_DATA(hdr);
    ifi->ifi_family = AF_UNSPEC;
    ifi->ifi_type = netif_is_loopback(netif) ? ARPHRD_LOOPBACK : ARPHRD_ETHER;
    ifi->ifi_index = 1 + netif->num;
    ifi->ifi_flags = ifflags_from_netif(netif);
    ifi->ifi_change = (u32)-1;
    struct rtattr *rta = (void*)ifi + NLMSG_ALIGN(sizeof(*ifi));
    if (netif->hwaddr_len != 0) {
        rta->rta_len = RTA_LENGTH(netif->hwaddr_len);
        rta->rta_type = IFLA_ADDRESS;
        runtime_memcpy(RTA_DATA(rta), netif->hwaddr, netif->hwaddr_len);
        rta = RTA_NEXT(rta);
    }
    rta->rta_len = RTA_LENGTH(sizeof(netif->name) + 2);
    rta->rta_type = IFLA_IFNAME;
    netif_name_cpy(RTA_DATA(rta), netif);
    rta = RTA_NEXT(rta);
    rta->rta_len = RTA_LENGTH(sizeof(u32));
    rta->rta_type = IFLA_MTU;
    *(u32 *)(RTA_DATA(rta)) = netif->mtu;
    nl_enqueue(s, hdr, resp_len);
}

static void nl_enqueue_ifaddr(nlsock s, u16 type, u16 flags, u32 seq, u32 pid, struct netif *netif,
                              ip4_addr_t addr, ip4_addr_t netmask)
{
    int resp_len = NLMSG_ALIGN(sizeof(struct nlmsghdr) + sizeof(struct ifaddrmsg) +
        RTA_SPACE(sizeof(ip4_addr_t)) + RTA_SPACE(sizeof(netif->name) + 2));
    struct nlmsghdr *hdr = allocate(s->sock.h, resp_len);
    if (hdr == INVALID_ADDRESS) {
        msg_err("failed to allocate message\n");
        return;
    }
    hdr->nlmsg_len = resp_len;
    hdr->nlmsg_type = type;
    hdr->nlmsg_flags = flags;
    hdr->nlmsg_seq = seq;
    hdr->nlmsg_pid = pid;
    struct ifaddrmsg *ifa = (struct ifaddrmsg *)NLMSG_DATA(hdr);
    ifa->ifa_family = AF_INET;
    ifa->ifa_prefixlen = 32 - lsb(ntohl(netmask.addr));
    ifa->ifa_flags = 0;
    ifa->ifa_scope = netif_is_loopback(netif) ? RT_SCOPE_HOST : RT_SCOPE_UNIVERSE;
    ifa->ifa_index = 1 + netif->num;
    struct rtattr *rta = (void*)ifa + NLMSG_ALIGN(sizeof(*ifa));
    rta->rta_len = RTA_LENGTH(sizeof(ip4_addr_t));
    rta->rta_type = IFA_ADDRESS;
    runtime_memcpy(RTA_DATA(rta), &addr, sizeof(addr));
    rta = RTA_NEXT(rta);
    rta->rta_len = RTA_LENGTH(sizeof(netif->name) + 2);
    rta->rta_type = IFA_LABEL;
    netif_name_cpy(RTA_DATA(rta), netif);
    nl_enqueue(s, hdr, resp_len);
}

static void nl_enqueue_done(nlsock s, struct nlmsghdr *req)
{
    struct nlmsghdr *hdr = allocate(s->sock.h, NLMSG_HDRLEN);
    if (hdr == INVALID_ADDRESS) {
        msg_err("failed to allocate message\n");
        return;
    }
    hdr->nlmsg_len = NLMSG_HDRLEN;
    hdr->nlmsg_type = NLMSG_DONE;
    hdr->nlmsg_flags = 0;
    hdr->nlmsg_seq = req->nlmsg_seq;
    hdr->nlmsg_pid = s->addr.nl_pid;
    nl_enqueue(s, hdr, NLMSG_HDRLEN);
}

static void nl_enqueue_error(nlsock s, struct nlmsghdr *msg, int errno)
{
    int errmsg_len = NLMSG_ALIGN(sizeof(struct nlmsghdr) + sizeof(struct nlmsgerr));
    struct nlmsghdr *hdr = allocate(s->sock.h, errmsg_len);
    if (hdr == INVALID_ADDRESS) {
        msg_err("failed to allocate message\n");
        return;
    }
    hdr->nlmsg_len = errmsg_len;
    hdr->nlmsg_type = NLMSG_ERROR;
    hdr->nlmsg_flags = 0;
    hdr->nlmsg_seq = msg->nlmsg_seq;
    hdr->nlmsg_pid = s->addr.nl_pid;
    struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(hdr);
    err->error = errno;
    runtime_memcpy(&err->msg, msg, sizeof(*msg));
    nl_enqueue(s, hdr, errmsg_len);
}

static void nl_route_req(nlsock s, struct nlmsghdr *hdr)
{
    int errno = 0;
    switch (hdr->nlmsg_type) {
    case RTM_GETLINK: {
        struct rtgenmsg *msg = (struct rtgenmsg *)NLMSG_DATA(hdr);
        if ((hdr->nlmsg_len < NLMSG_HDRLEN + sizeof(*msg)) || (msg->rtgen_family != AF_UNSPEC)) {
            errno = EINVAL;
            break;
        }
        if (hdr->nlmsg_flags & NLM_F_DUMP) {
            lwip_lock();
            for (struct netif *netif = netif_list; netif; netif = netif->next)
                nl_enqueue_ifinfo(s, RTM_NEWLINK, NLM_F_MULTI, hdr->nlmsg_seq, s->addr.nl_pid,
                    netif);
            lwip_unlock();
            nl_enqueue_done(s, hdr);
        } else {    /* Return a single entry. */
            struct ifinfomsg *ifi = (struct ifinfomsg *)NLMSG_DATA(hdr);
            if ((hdr->nlmsg_len < NLMSG_HDRLEN + sizeof(*ifi)) || (ifi->ifi_index == 0)) {
                errno = EINVAL;
                break;
            }
            struct netif *netif = 0;
            lwip_lock();
            for (netif = netif_list; netif; netif = netif->next) {
                if (netif->num + 1 == ifi->ifi_index) {
                    nl_enqueue_ifinfo(s, RTM_NEWLINK, 0, hdr->nlmsg_seq, s->addr.nl_pid, netif);
                    break;
                }
            }
            lwip_unlock();
            if (!netif)
                errno = EINVAL;
        }
        break;
    }
    case RTM_GETADDR: {
        struct rtgenmsg *msg = (struct rtgenmsg *)NLMSG_DATA(hdr);
        if (hdr->nlmsg_len < NLMSG_HDRLEN + sizeof(*msg))
            break;
        if (hdr->nlmsg_flags & NLM_F_DUMP) {
            u8 af = msg->rtgen_family;
            if (af != AF_INET6) {   /* retrieve IPv4 addresses */
                lwip_lock();
                for (struct netif *netif = netif_list; netif; netif = netif->next)
                    nl_enqueue_ifaddr(s, RTM_NEWADDR, NLM_F_MULTI, hdr->nlmsg_seq, s->addr.nl_pid,
                        netif, *netif_ip4_addr(netif), *netif_ip4_netmask(netif));
                lwip_unlock();
            }
            nl_enqueue_done(s, hdr);
        } else {
            errno = EOPNOTSUPP;
        }
        break;
    }
    default:
        errno = EOPNOTSUPP;
        break;
    }
    if (errno)
        nl_enqueue_error(s, hdr, -errno);
}

static void nl_route_msg(nlsock s, struct nlmsghdr *hdr)
{
    if (hdr->nlmsg_flags & NLM_F_REQUEST)
        nl_route_req(s, hdr);
}

static sysreturn nl_check_dest(struct sockaddr *addr, socklen_t addrlen)
{
    if (addr) {
        struct sockaddr_nl *nl_addr = (struct sockaddr_nl *)addr;

        if (addrlen < sizeof(*nl_addr))
            return -EINVAL;
        if (nl_addr->nl_pid != NL_PID_KERNEL)
            return -EPERM;
    }
    return 0;
}

static sysreturn nl_write_internal(nlsock s, void * src, u64 len)
{
    nl_debug("write_internal: len %ld", len);
    struct nlmsghdr *hdr;
    u64 offset = 0;
    while (offset + sizeof(*hdr) <= len) {
        hdr = (struct nlmsghdr *)(src + offset);
        if ((u64_from_pointer(hdr) & (NLMSG_ALIGNMENT - 1)) || (len - offset < hdr->nlmsg_len))
            break;  /* Refuse to process unaligned or incomplete messages. */
        nl_debug(" msg len %d, type %d, flags 0x%x, seq %d, pid %d", hdr->nlmsg_len,
                 hdr->nlmsg_type, hdr->nlmsg_flags, hdr->nlmsg_seq, hdr->nlmsg_pid);
        if (hdr->nlmsg_len < sizeof(*hdr))
            break;
        switch (s->family) {
        case NETLINK_ROUTE:
            nl_route_msg(s, hdr);
            break;
        }
        offset += MIN(NLMSG_ALIGN(hdr->nlmsg_len), len - offset);
    }
    return (sysreturn)offset;
}

closure_function(7, 1, sysreturn, nl_read_bh,
                 nlsock, s, thread, t, void *, dest, u64, length, struct msghdr *, msg, int, flags, io_completion, completion,
                 u64, bqflags)
{
    nlsock s = bound(s);
    void *dest = bound(dest);
    u64 length = bound(length);
    struct msghdr *msg = bound(msg);
    sysreturn rv;
    if (bqflags & BLOCKQ_ACTION_NULLIFY) {
        rv = -ERESTARTSYS;
        goto out;
    }
    boolean lock = !(bqflags & BLOCKQ_ACTION_BLOCKED);
    if (lock)
        nl_lock(s);
    struct nlmsghdr *hdr = dequeue(s->data);
    if (hdr == INVALID_ADDRESS) {
        if (s->sock.f.flags & SOCK_NONBLOCK) {
            rv = -EAGAIN;
            goto unlock;
        }
        if (lock)
            nl_unlock(s);
        return BLOCKQ_BLOCK_REQUIRED;
    }
    rv = 0;
    struct iovec *iov = 0;
    u64 iov_len = 0;
    void *iov_buf;
    if (!dest) {
        iov = msg->msg_iov;
        length = msg->msg_iovlen;
    }
    u64 dest_len;
    do {
        nl_debug("read_bh: msg len %d, type %d, flags 0x%x, seq %d, pid %d", hdr->nlmsg_len,
                 hdr->nlmsg_type, hdr->nlmsg_flags, hdr->nlmsg_seq, hdr->nlmsg_pid);
        if (dest) {
            u64 xfer = MIN(hdr->nlmsg_len, length);
            runtime_memcpy(dest, hdr, xfer);
            dest += xfer;
            length -= xfer;
            rv += xfer;
            dest_len = length;
        } else {
            u64 msg_offset = 0;
            do {
                while ((iov_len == 0) && (length > 0)) {
                    iov_len = iov->iov_len;
                    iov_buf = iov->iov_base;
                    iov++;
                    length--;
                }
                if (iov_len == 0)
                    break;
                u64 xfer = MIN(hdr->nlmsg_len - msg_offset, iov_len);
                runtime_memcpy(iov_buf, hdr + msg_offset, xfer);
                iov_buf += xfer;
                iov_len -= xfer;
                rv += xfer;
                msg_offset += xfer;
            } while (msg_offset < hdr->nlmsg_len);
            if (msg_offset < hdr->nlmsg_len)
                msg->msg_flags |= MSG_TRUNC;
            dest_len = iov_len + iov_total_len(iov, length);
        }
        if ((rv < hdr->nlmsg_len) && (bound(flags) & MSG_TRUNC))
            rv = hdr->nlmsg_len;
        s->sock.rx_len -= hdr->nlmsg_len;
        deallocate(s->sock.h, hdr, hdr->nlmsg_len);
        hdr = queue_peek(s->data);
        if (hdr == INVALID_ADDRESS) { /* no more data available to read */
            fdesc_notify_events(&s->sock.f);
            break;
        }
        if (hdr->nlmsg_len > dest_len)
            break;
        dequeue(s->data);
    } while (dest_len > 0);
unlock:
    if (lock)
        nl_unlock(s);
out:
    blockq_handle_completion(s->sock.rxbq, bqflags, bound(completion), bound(t), rv);
    closure_finish();
    return rv;
}

closure_function(1, 6, sysreturn, nl_read,
                 nlsock, s,
                 void *, dest, u64, length, u64, offset_arg, thread, t, boolean, bh, io_completion, completion)
{
    nl_debug("read len %ld", length);
    nlsock s = bound(s);
    blockq_action ba = closure(s->sock.h, nl_read_bh, s, current, dest, length, 0, 0,
        completion);
    if (ba == INVALID_ADDRESS)
        return io_complete(completion, t, -ENOMEM);
    return blockq_check(s->sock.rxbq, current, ba, false);
}

closure_function(1, 6, sysreturn, nl_write,
                 nlsock, s,
                 void *, src, u64, length, u64, offset, thread, t, boolean, bh, io_completion, completion)
{
    nl_debug("write len %ld", length);
    nlsock s = bound(s);
    nl_lock(s);
    sysreturn rv = nl_write_internal(s, src, length);
    nl_unlock(s);
    return io_complete(completion, t, rv);
}

closure_function(1, 1, u32, nl_events,
                 nlsock, s,
                 thread, t /* ignore */)
{
    nlsock s = bound(s);
    u32 events = EPOLLOUT;
    if (!queue_empty(s->data))
        events |= EPOLLIN;
    return events;
}

closure_function(1, 2, sysreturn, nl_close,
                 nlsock, s,
                 thread, t, io_completion, completion)
{
    nlsock s = bound(s);
    nl_debug("close, pid %d", s->addr.nl_pid);
    socket_flush_q(&s->sock);
    struct nlmsghdr *hdr = dequeue(s->data);
    while (hdr != INVALID_ADDRESS) {
        deallocate(s->sock.h, hdr, hdr->nlmsg_len);
        hdr = dequeue(s->data);
    }
    deallocate_queue(s->data);
    spin_lock(&netlink.lock);
    nlsock sock;
    vector_foreach(netlink.sockets, sock) {
        if (sock == s) {
            vector_delete(netlink.sockets, _i);
            break;
        }
    }
    deallocate_closure(s->sock.f.read);
    deallocate_closure(s->sock.f.write);
    deallocate_closure(s->sock.f.events);
    deallocate_closure(s->sock.f.close);
    socket_deinit(&s->sock);
    if (s->addr.nl_pid != 0)
        deallocate_u64((heap)netlink.pids, s->addr.nl_pid, 1);
    spin_unlock(&netlink.lock);
    deallocate(s->sock.h, s, sizeof(*s));
    return io_complete(completion, t, 0);
}

static sysreturn nl_bind(struct sock *sock, struct sockaddr *addr, socklen_t addrlen)
{
    nlsock s = (nlsock)sock;
    sysreturn rv;
    struct sockaddr_nl *nl_addr = (struct sockaddr_nl *)addr;
    if ((addrlen != sizeof(*nl_addr)) || (nl_addr->nl_family != AF_NETLINK)) {
        rv = -EINVAL;
        goto out;
    }
    nl_debug("bind to pid %d, multicast 0x%x", nl_addr->nl_pid, nl_addr->nl_groups);
    spin_lock(&netlink.lock);
    nl_lock(s);
    if (s->addr.nl_pid != 0) {  /* already bound */
        if (nl_addr->nl_pid == s->addr.nl_pid)
            rv = 0;
        else
            rv = -EINVAL;
        goto unlock;
    }
    runtime_memcpy(&s->addr, nl_addr, addrlen);
    if (nl_addr->nl_pid == 0) {
        u64 pid = allocate_u64((heap)netlink.pids, 1);
        if (pid == INVALID_PHYSICAL) {
            rv = -ENOMEM;
            goto unlock;
        }
        nl_debug(" allocated pid %d", pid);
        s->addr.nl_pid = pid;
    } else {
        u64 pid = id_heap_alloc_gte(netlink.pids, 1, nl_addr->nl_pid);
        if (pid != nl_addr->nl_pid) {
            deallocate_u64((heap)netlink.pids, pid, 1);
            s->addr.nl_pid = 0;
            rv = -EADDRINUSE;
            goto unlock;
        }
    }
    rv = 0;
  unlock:
    nl_unlock(s);
    spin_unlock(&netlink.lock);
  out:
    socket_release(sock);
    return rv;
}

static sysreturn nl_getsockname(struct sock *sock, struct sockaddr *addr, socklen_t *addrlen)
{
    nlsock s = (nlsock)sock;
    nl_lock(s);
    runtime_memcpy(addr, &s->addr, MIN(sizeof(s->addr), *addrlen));
    nl_unlock(s);
    *addrlen = sizeof(s->addr);
    socket_release(sock);
    return 0;
}

static sysreturn nl_sendto(struct sock *sock, void *buf, u64 len, int flags,
        struct sockaddr *dest_addr, socklen_t addrlen)
{
    nl_debug("sendto: len %ld, flags 0x%x", len, flags);
    sysreturn rv = nl_check_dest(dest_addr, addrlen);
    if (rv) {
        socket_release(sock);
        return rv;
    }
    return apply(sock->f.write, buf, len, 0, current, false, (io_completion)&sock->f.io_complete);
}

static sysreturn nl_recvfrom(struct sock *sock, void *buf, u64 len, int flags,
                             struct sockaddr *src_addr, socklen_t *addrlen)
{
    nl_debug("recvfrom: len %ld, flags 0x%x", len, flags);
    nlsock s = (nlsock)sock;
    blockq_action ba = closure(s->sock.h, nl_read_bh, s, current, buf, len, 0, flags,
        (io_completion)&sock->f.io_complete);
    if (ba == INVALID_ADDRESS) {
        socket_release(sock);
        return -ENOMEM;
    }
    if (addrlen) {
        if (src_addr && (*addrlen >= sizeof(struct sockaddr_nl))) {
            struct sockaddr_nl *addr = (struct sockaddr_nl *)src_addr;
            addr->nl_family = AF_NETLINK;
            addr->nl_pad = 0;
            addr->nl_pid = NL_PID_KERNEL;
            addr->nl_groups = 0;
        }
        *addrlen = sizeof(struct sockaddr_nl);
    }
    return blockq_check(s->sock.rxbq, current, ba, false);
}

static sysreturn nl_sendmsg(struct sock *sock, const struct msghdr *msg, int flags)
{
    nl_debug("sendmsg: iovlen %ld, flags 0x%x", msg->msg_iovlen, flags);
    nlsock s = (nlsock)sock;
    sysreturn rv = nl_check_dest(msg->msg_name, msg->msg_namelen);
    if (rv)
        goto out;
    u64 written = 0;
    nl_lock(s);
    for (u64 i = 0; i < msg->msg_iovlen; i++) {
        rv = nl_write_internal(s, msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len);
        if (rv > 0)
            written += rv;
        else
            break;
    }
    nl_unlock(s);
    rv = (written > 0) ? written : rv;
  out:
    socket_release(sock);
    return rv;
}

static sysreturn nl_recvmsg(struct sock *sock, struct msghdr *msg, int flags)
{
    nl_debug("recvmsg: iovlen %ld, flags 0x%x", msg->msg_iovlen, flags);
    nlsock s = (nlsock)sock;
    blockq_action ba = closure(s->sock.h, nl_read_bh, s, current, 0, 0, msg, flags,
        (io_completion)&sock->f.io_complete);
    if (ba == INVALID_ADDRESS) {
        socket_release(sock);
        return -ENOMEM;
    }
    if (msg->msg_name && (msg->msg_namelen >= sizeof(struct sockaddr_nl))) {
        struct sockaddr_nl *addr = msg->msg_name;
        addr->nl_family = AF_NETLINK;
        addr->nl_pad = 0;
        addr->nl_pid = NL_PID_KERNEL;
        addr->nl_groups = 0;
    }
    msg->msg_namelen = sizeof(struct sockaddr_nl);
    msg->msg_controllen = 0;
    msg->msg_flags = 0;
    return blockq_check(s->sock.rxbq, current, ba, false);
}

static void nl_lwip_ext_callback(struct netif* netif, netif_nsc_reason_t reason,
                               const netif_ext_callback_args_t* args)
{
    nl_debug("lwIP callback, reason 0x%x", reason);
    nlsock s;
    if (reason & (LWIP_NSC_NETIF_ADDED | LWIP_NSC_NETIF_REMOVED | LWIP_NSC_LINK_CHANGED)) {
        spin_lock(&netlink.lock);
        vector_foreach(netlink.sockets, s) {
            if (s->addr.nl_groups & RTMGRP_LINK) {
                nl_lock(s);
                nl_enqueue_ifinfo(s, (reason == LWIP_NSC_NETIF_REMOVED) ? RTM_DELLINK : RTM_NEWLINK,
                        0, 0, NL_PID_KERNEL, netif);
                nl_unlock(s);
            }
        }
        spin_unlock(&netlink.lock);
    }
    if (reason & LWIP_NSC_IPV4_SETTINGS_CHANGED) {
        spin_lock(&netlink.lock);
        vector_foreach(netlink.sockets, s) {
            if (s->addr.nl_groups & RTMGRP_IPV4_IFADDR) {
                if ((reason & LWIP_NSC_IPV4_ADDRESS_CHANGED) &&
                        !ip4_addr_isany(ip_2_ip4(args->ipv4_changed.old_address))) {
                    nl_lock(s);
                    nl_enqueue_ifaddr(s, RTM_DELADDR, 0, 0, NL_PID_KERNEL, netif,
                        args->ipv4_changed.old_address->u_addr.ip4,
                        (reason & LWIP_NSC_IPV4_NETMASK_CHANGED) ?
                                *ip_2_ip4(args->ipv4_changed.old_netmask) :
                                *ip_2_ip4(&netif->netmask));
                    nl_unlock(s);
                }
                if (!ip4_addr_isany(netif_ip4_addr(netif))) {
                    nl_lock(s);
                    nl_enqueue_ifaddr(s, RTM_NEWADDR, 0, 0, NL_PID_KERNEL, netif,
                        *netif_ip4_addr(netif), *netif_ip4_netmask(netif));
                    nl_unlock(s);
                }
            }
        }
        spin_unlock(&netlink.lock);
    }
}

sysreturn netlink_open(int type, int family)
{
    nl_debug("open: type %d, family %d", type, family);
    int flags = type & ~SOCK_TYPE_MASK;
    if (flags & ~(SOCK_NONBLOCK | SOCK_CLOEXEC))
        return -EINVAL;
    type &= SOCK_TYPE_MASK;
    if ((type != SOCK_DGRAM) && (type != SOCK_RAW))
        return -ESOCKTNOSUPPORT;
    switch (family) {
    case NETLINK_ROUTE:
        break;
    default:
        return -EPROTONOSUPPORT;
    }
    heap h = heap_locked(&get_unix_heaps()->kh);
    nlsock s = allocate(h, sizeof(*s));
    if (s == INVALID_ADDRESS)
        return -ENOMEM;
    if (socket_init(current->p, h, AF_NETLINK, type, flags, &s->sock) < 0)
        goto err_socket;
    s->data = allocate_queue(h, NL_QUEUE_MAX_LEN);
    if (s->data == INVALID_ADDRESS)
        goto err_queue;
    spin_lock(&netlink.lock);
    vector_push(netlink.sockets, s);
    spin_unlock(&netlink.lock);
    s->family = family;
    zero(&s->addr, sizeof(s->addr));
    s->sock.f.read = closure(h, nl_read, s);
    s->sock.f.write = closure(h, nl_write, s);
    s->sock.f.events = closure(h, nl_events, s);
    s->sock.f.close = closure(h, nl_close, s);
    s->sock.bind = nl_bind;
    s->sock.getsockname = nl_getsockname;
    s->sock.sendto = nl_sendto;
    s->sock.recvfrom = nl_recvfrom;
    s->sock.sendmsg = nl_sendmsg;
    s->sock.recvmsg = nl_recvmsg;
    s->sock.fd = allocate_fd(current->p, s);
    if (s->sock.fd == INVALID_PHYSICAL) {
        apply(s->sock.f.close, 0, io_completion_ignore);
        return -EMFILE;
    }
    return s->sock.fd;
  err_queue:
    socket_deinit(&s->sock);
  err_socket:
    deallocate(h, s, sizeof(*s));
    return -ENOMEM;
}

void netlink_init(void)
{
    heap h = heap_locked(&get_unix_heaps()->kh);
    netlink.pids = create_id_heap(h, h, 1, U32_MAX, 1, false);
    assert(netlink.pids != INVALID_ADDRESS);
    netlink.sockets = allocate_vector(h, 8);
    assert(netlink.sockets != INVALID_ADDRESS);
    spin_lock_init(&netlink.lock);
    lwip_lock();
    NETIF_DECLARE_EXT_CALLBACK(netif_callback);
    netif_add_ext_callback(&netif_callback, nl_lwip_ext_callback);
    lwip_unlock();
}
