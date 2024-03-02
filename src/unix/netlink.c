#include <net_system_structs.h>
#include <unix_internal.h>
#include <lwip.h>
#include <socket.h>

//#define NETLINK_DEBUG
#ifdef NETLINK_DEBUG
#define nl_debug(x, ...) do {tprintf(sym(netlink), 0, ss(x "\n"), ##__VA_ARGS__);} while(0)
#else
#define nl_debug(x, ...)
#endif

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

/* RTM_*ROUTE message payload */
struct rtmsg {
    u8 rtm_family;
    u8 rtm_dst_len;
    u8 rtm_src_len;
    u8 rtm_tos;
    u8 rtm_table;
    u8 rtm_protocol;
    u8 rtm_scope;
    u8 rtm_type;
    u32 rtm_flags;
};

/* rtmsg.rtm_table */
enum {
    RT_TABLE_UNSPEC = 0,
    RT_TABLE_COMPAT = 252,
    RT_TABLE_DEFAULT = 253,
    RT_TABLE_MAIN = 254,
    RT_TABLE_LOCAL = 255,
};

/* rtmsg.rtm_protocol */
enum {
    RTPROT_UNSPEC,
    RTPROT_REDIRECT,
    RTPROT_KERNEL,
    RTPROT_BOOT,
    RTPROT_STATIC,
};

/* rtmsg.rtm_type */
enum {
    RTN_UNSPEC,
    RTN_UNICAST,
    RTN_LOCAL,
    RTN_BROADCAST,
    RTN_ANYCAST,
    RTN_MULTICAST,
    RTN_BLACKHOLE,
    RTN_UNREACHABLE,
    RTN_PROHIBIT,
    RTN_THROW,
    RTN_NAT,
    RTN_XRESOLVE,
};

/* rtmsg attributes */
enum {
    RTA_UNSPEC,
    RTA_DST,
    RTA_SRC,
    RTA_IIF,
    RTA_OIF,
    RTA_GATEWAY,
    RTA_PRIORITY,
    RTA_PREFSRC,
    RTA_METRICS,
    RTA_MULTIPATH,
    RTA_PROTOINFO,
    RTA_FLOW,
    RTA_CACHEINFO,
    RTA_SESSION,
    RTA_MP_ALGO,
    RTA_TABLE,
    RTA_MARK,
    RTA_MFC_STATS,
    RTA_VIA,
    RTA_NEWDST,
    RTA_PREF,
    RTA_ENCAP_TYPE,
    RTA_ENCAP,
    RTA_EXPIRES,
    RTA_PAD,
    RTA_UID,
    RTA_TTL_PROPAGATE,
    RTA_IP_PROTO,
    RTA_SPORT,
    RTA_DPORT,
    RTA_NH_ID
};

/* rtmsg.rtm_flags */
#define RTM_F_NOTIFY	   0x100
#define RTM_F_CLONED	   0x200
#define RTM_F_EQUALIZE	   0x400
#define RTM_F_PREFIX	   0x800
#define RTM_F_LOOKUP_TABLE 0x1000
#define RTM_F_FIB_MATCH	   0x2000
#define RTM_F_OFFLOAD	   0x4000
#define RTM_F_TRAP	   0x8000

#define NL_QUEUE_MAX_LEN    64

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
    closure_struct(file_io, read);
    closure_struct(file_io, write);
    closure_struct(fdesc_events, events);
    closure_struct(fdesc_close, close);
} *nlsock;

#define nl_lock(s)      spin_lock(&(s)->sock.f.lock)
#define nl_unlock(s)    spin_unlock(&(s)->sock.f.lock)

typedef struct nl_rtm_netif_priv {
    nlsock s;
    struct nlmsghdr *hdr;
    int if_index;
    struct netif *netif_default;
    boolean found;
} *nl_rtm_netif_priv;

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
    ifi->ifi_type = netif_get_type(netif);
    ifi->ifi_index = netif_get_index(netif);
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
                              int family, void *addr, int addr_len, int prefix_len)
{
    int resp_len = NLMSG_ALIGN(sizeof(struct nlmsghdr) + sizeof(struct ifaddrmsg) +
        RTA_SPACE(addr_len) + RTA_SPACE(sizeof(netif->name) + 2));
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
    ifa->ifa_family = family;
    ifa->ifa_prefixlen = prefix_len;
    ifa->ifa_flags = 0;
    ifa->ifa_scope = netif_is_loopback(netif) ? RT_SCOPE_HOST : RT_SCOPE_UNIVERSE;
    ifa->ifa_index = netif_get_index(netif);
    struct rtattr *rta = (void*)ifa + NLMSG_ALIGN(sizeof(*ifa));
    rta->rta_len = RTA_LENGTH(addr_len);
    rta->rta_type = IFA_ADDRESS;
    runtime_memcpy(RTA_DATA(rta), addr, addr_len);
    rta = RTA_NEXT(rta);
    rta->rta_len = RTA_LENGTH(sizeof(netif->name) + 2);
    rta->rta_type = IFA_LABEL;
    netif_name_cpy(RTA_DATA(rta), netif);
    nl_enqueue(s, hdr, resp_len);
}

static inline void nl_enqueue_ifaddr4(nlsock s, u16 type, u16 flags, u32 seq, u32 pid,
                                      struct netif *netif, ip4_addr_t addr, ip4_addr_t netmask)
{
    nl_enqueue_ifaddr(s, type, flags, seq, pid, netif, AF_INET, &addr, sizeof(ip4_addr_t),
                      32 - lsb(ntohl(netmask.addr)));
}

static inline void nl_enqueue_ifaddr6(nlsock s, u16 type, u16 flags, u32 seq, u32 pid,
                                      struct netif *netif, ip6_addr_t addr)
{
    nl_enqueue_ifaddr(s, type, flags, seq, pid, netif, AF_INET6, &addr.addr, sizeof(addr.addr),
                      netif_is_loopback(netif) ? 128 : 64);
}

enum {
    RTMSG_TYPE_IF,
    RTMSG_TYPE_GW
};

static void nl_enqueue_rtmsg(nlsock s, u16 type, u16 flags, u32 seq, u32 pid, struct netif *netif,
                             struct netif *netif_default, int rmtype)
{
    int resp_len;
    boolean is_default = netif_default == netif;
    const ip4_addr_t *addr = netif_ip4_addr(netif);
    const ip4_addr_t *netmask = netif_ip4_netmask(netif);

    switch (rmtype) {
    case RTMSG_TYPE_IF:
        resp_len = NLMSG_ALIGN(sizeof(struct nlmsghdr) + sizeof(struct rtmsg) +
                               (RTA_SPACE(4) /* table */ +
                                RTA_SPACE(sizeof(ip4_addr_t)) /* dst */ +
                                RTA_SPACE(4) /* priority */ +
                                RTA_SPACE(4) /* prefsrc */ +
                                RTA_SPACE(4) /* oif */));
        break;
    case RTMSG_TYPE_GW:
        resp_len = NLMSG_ALIGN(sizeof(struct nlmsghdr) + sizeof(struct rtmsg) +
                               (RTA_SPACE(4) /* table */ +
                                RTA_SPACE(4) /* priority */ +
                                RTA_SPACE(sizeof(ip4_addr_t)) /* gateway */ +
                                (is_default ? 0 : RTA_SPACE(sizeof(ip4_addr_t)) /* dst */) +
                                RTA_SPACE(4) /* oif */));
        break;
    }
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
    struct rtmsg *rtm = (struct rtmsg *)NLMSG_DATA(hdr);
    rtm->rtm_family = AF_INET;
    rtm->rtm_table = RT_TABLE_MAIN;
    rtm->rtm_src_len = 0;
    rtm->rtm_tos = 0;
    rtm->rtm_protocol = (is_default && rmtype == RTMSG_TYPE_GW) ? RTPROT_STATIC : RTPROT_KERNEL;
    rtm->rtm_scope = rmtype == RTMSG_TYPE_IF ? RT_SCOPE_LINK : RT_SCOPE_UNIVERSE;
    rtm->rtm_type = RTN_UNICAST;
    rtm->rtm_flags = 0;
    rtm->rtm_dst_len = rmtype == RTMSG_TYPE_IF ? 32 - lsb(ntohl(netif->netmask.u_addr.ip4.addr)) :
        (is_default ? 0 : 32);

    struct rtattr *rta = (void*)rtm + NLMSG_ALIGN(sizeof(*rtm));
    rta->rta_len = RTA_LENGTH(4);
    rta->rta_type = RTA_TABLE;
    *(u32 *)RTA_DATA(rta) = rtm->rtm_table;

    if (!(rmtype == RTMSG_TYPE_GW && is_default)) {
        rta = RTA_NEXT(rta);
        rta->rta_len = RTA_LENGTH(sizeof(ip4_addr_t));
        rta->rta_type = RTA_DST;
        ip4_addr_t dest;
        dest.addr = addr->addr & netmask->addr;
        ip4_addr_copy(*(ip4_addr_t *)RTA_DATA(rta), dest);
    }

    rta = RTA_NEXT(rta);
    rta->rta_len = RTA_LENGTH(4);
    rta->rta_type = RTA_PRIORITY;
    *(u32 *)RTA_DATA(rta) = 100;

    if (rmtype == RTMSG_TYPE_GW) {
        rta = RTA_NEXT(rta);
        rta->rta_len = RTA_LENGTH(sizeof(ip4_addr_t));
        rta->rta_type = RTA_GATEWAY;
        ip4_addr_copy(*(ip4_addr_t *)RTA_DATA(rta), *(ip_2_ip4(&netif->gw)));
    }

    if (rmtype == RTMSG_TYPE_IF) {
        rta = RTA_NEXT(rta);
        rta->rta_len = RTA_LENGTH(sizeof(ip4_addr_t));
        rta->rta_type = RTA_PREFSRC;
        ip4_addr_copy(*(ip4_addr_t *)RTA_DATA(rta), *addr);
    }

    rta = RTA_NEXT(rta);
    rta->rta_len = RTA_LENGTH(4);
    rta->rta_type = RTA_OIF;
    *(u32 *)RTA_DATA(rta) = netif_get_index(netif);
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

static boolean nl_rtm_getlink(struct netif *n, void *priv)
{
    nl_rtm_netif_priv data = priv;
    nlsock s = data->s;
    nl_enqueue_ifinfo(s, RTM_NEWLINK, NLM_F_MULTI, data->hdr->nlmsg_seq, s->addr.nl_pid, n);
    return false;
}

static boolean nl_rtm_getlink_single(struct netif *n, void *priv)
{
    nl_rtm_netif_priv data = priv;
    if (netif_get_index(n) == data->if_index) {
        nlsock s = data->s;
        nl_enqueue_ifinfo(s, RTM_NEWLINK, 0, data->hdr->nlmsg_seq, s->addr.nl_pid, n);
        data->found = true;
        return true;
    }
    return false;
}

static boolean nl_rtm_getaddr(struct netif *n, void *priv)
{
    nl_rtm_netif_priv data = priv;
    nlsock s = data->s;
    nl_enqueue_ifaddr4(s, RTM_NEWADDR, NLM_F_MULTI, data->hdr->nlmsg_seq, s->addr.nl_pid, n,
                       *netif_ip4_addr(n), *netif_ip4_netmask(n));
    return false;
}

static boolean nl_rtm_getaddr6(struct netif *n, void *priv)
{
    nl_rtm_netif_priv data = priv;
    nlsock s = data->s;
    for (int i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
        if (!ip6_addr_isinvalid(netif_ip6_addr_state(n, i))) {
            nl_enqueue_ifaddr6(s, RTM_NEWADDR, NLM_F_MULTI, data->hdr->nlmsg_seq, s->addr.nl_pid, n,
                               *netif_ip6_addr(n, i));
        }
    }
    return false;
}

static boolean nl_rtm_getroute(struct netif *n, void *priv)
{
    /* No loopback reporting for main table. */
    if (n->name[0] == 'l' && n->name[1] == 'o')
        return false;

    nl_rtm_netif_priv data = priv;
    nlsock s = data->s;
    struct nlmsghdr *hdr = data->hdr;
    struct netif *n_default = data->netif_default;
    if (!ip4_addr_cmp(ip_2_ip4(&n->gw), IP4_ADDR_ANY4))
        nl_enqueue_rtmsg(s, RTM_NEWROUTE, NLM_F_MULTI, hdr->nlmsg_seq, s->addr.nl_pid, n, n_default,
                         RTMSG_TYPE_GW);
    nl_enqueue_rtmsg(s, RTM_NEWROUTE, NLM_F_MULTI, hdr->nlmsg_seq, s->addr.nl_pid, n, n_default,
                     RTMSG_TYPE_IF);
    return false;
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
            struct nl_rtm_netif_priv priv = {
                .s = s,
                .hdr = hdr,
            };
            netif_iterate(nl_rtm_getlink, &priv);
            nl_enqueue_done(s, hdr);
        } else {    /* Return a single entry. */
            struct ifinfomsg *ifi = (struct ifinfomsg *)NLMSG_DATA(hdr);
            if ((hdr->nlmsg_len < NLMSG_HDRLEN + sizeof(*ifi)) || (ifi->ifi_index == 0)) {
                errno = EINVAL;
                break;
            }
            struct nl_rtm_netif_priv priv = {
                .s = s,
                .hdr = hdr,
                .if_index = ifi->ifi_index,
                .found = false,
            };
            netif_iterate(nl_rtm_getlink_single, &priv);
            if (!priv.found)
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
            if (af == AF_INET || af == AF_UNSPEC) {   /* retrieve IPv4 addresses */
                struct nl_rtm_netif_priv priv = {
                    .s = s,
                    .hdr = hdr,
                };
                netif_iterate(nl_rtm_getaddr, &priv);
            }
            if (af == AF_INET6 || af == AF_UNSPEC) {  /* IPv6 */
                struct nl_rtm_netif_priv priv = {
                    .s = s,
                    .hdr = hdr,
                };
                netif_iterate(nl_rtm_getaddr6, &priv);
            }
            nl_enqueue_done(s, hdr);
        } else {
            errno = EOPNOTSUPP;
        }
        break;
    }
    case RTM_GETROUTE: {
        struct rtgenmsg *msg = (struct rtgenmsg *)NLMSG_DATA(hdr);
        if (hdr->nlmsg_len < NLMSG_HDRLEN + sizeof(*msg)) {
            errno = EINVAL;
            break;
        }
        u8 af = msg->rtgen_family;
        if (hdr->nlmsg_flags & NLM_F_DUMP) {
            /* Presently only reporting IPv4 routes on the "main" table. */
            if (af != AF_INET6) {
                struct nl_rtm_netif_priv priv = {
                    .s = s,
                    .hdr = hdr,
                    .netif_default = netif_get_default(),
                };
                netif_iterate(nl_rtm_getroute, &priv);
                if (priv.netif_default)
                    netif_unref(priv.netif_default);
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
        u32 pid;
        if (!get_user_value(&nl_addr->nl_pid, &pid))
            return -EFAULT;
        if (pid != NL_PID_KERNEL)
            return -EPERM;
    }
    return 0;
}

static sysreturn nl_write_internal(nlsock s, void * src, u64 len)
{
    nl_debug("write_internal: len %ld", len);
    struct nlmsghdr *hdr;
    u64 offset = 0;
    buffer kbuf = allocate_buffer(s->sock.h, sizeof(struct nlmsghdr));
    if (kbuf == INVALID_ADDRESS)
        return -ENOMEM;
    context ctx = get_current_context(current_cpu());
    if (context_set_err(ctx)) {
        if (offset == 0)
            offset = -EFAULT;
        goto out;
    }
    while (offset + sizeof(*hdr) <= len) {
        hdr = (struct nlmsghdr *)(src + offset);
        if (len - offset < hdr->nlmsg_len)
            break;  /* Refuse to process incomplete messages. */
        nl_debug(" msg len %d, type %d, flags 0x%x, seq %d, pid %d", hdr->nlmsg_len,
                 hdr->nlmsg_type, hdr->nlmsg_flags, hdr->nlmsg_seq, hdr->nlmsg_pid);
        if (hdr->nlmsg_len < sizeof(*hdr))
            break;
        buffer_clear(kbuf);
        if (!buffer_write(kbuf, hdr, hdr->nlmsg_len)) {
            if (offset == 0)
                offset = -ENOMEM;
            break;
        }
        switch (s->family) {
        case NETLINK_ROUTE:
            nl_route_msg(s, buffer_ref(kbuf, 0));
            break;
        }
        offset += MIN(NLMSG_ALIGN(hdr->nlmsg_len), len - offset);
    }
    context_clear_err(ctx);
  out:
    deallocate_buffer(kbuf);
    return (sysreturn)offset;
}

closure_function(8, 1, sysreturn, nl_read_bh,
                 nlsock, s, void *, dest, u64, length, struct msghdr *, msg, int, flags, struct sockaddr *, from, socklen_t *, from_len, io_completion, completion,
                 u64 bqflags)
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
    context ctx = get_current_context(current_cpu());
    nl_lock(s);
    struct nlmsghdr *hdr = dequeue(s->data);
    if (hdr == INVALID_ADDRESS) {
        if (s->sock.f.flags & SOCK_NONBLOCK) {
            rv = -EAGAIN;
            goto unlock;
        }
        nl_unlock(s);
        return blockq_block_required((unix_context)ctx, bqflags);
    }
    rv = 0;
    struct iovec *iov = 0;
    u64 iov_len = 0;
    void *iov_buf;
    if (context_set_err(ctx)) {
        if (rv == 0)
            rv = -EFAULT;
        deallocate(s->sock.h, hdr, hdr->nlmsg_len);
        goto unlock;
    }
    if (!dest) {
        iov = msg->msg_iov;
        length = msg->msg_iovlen;
        msg->msg_controllen = 0;
        msg->msg_flags = 0;
    }
    struct sockaddr *from = bound(from);
    socklen_t *from_len = bound(from_len);
    if (from_len) {
        if (from && (*from_len >= sizeof(struct sockaddr_nl))) {
            struct sockaddr_nl *addr = (struct sockaddr_nl *)from;
            addr->nl_family = AF_NETLINK;
            addr->nl_pad = 0;
            addr->nl_pid = NL_PID_KERNEL;
            addr->nl_groups = 0;
        }
        *from_len = sizeof(struct sockaddr_nl);
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
    context_clear_err(ctx);
unlock:
    nl_unlock(s);
out:
    apply(bound(completion), rv);
    closure_finish();
    return rv;
}

closure_func_basic(file_io, sysreturn, nl_read,
                   void *dest, u64 length, u64 offset_arg, context ctx, boolean bh, io_completion completion)
{
    nl_debug("read len %ld", length);
    nlsock s = struct_from_closure(nlsock, read);
    blockq_action ba = closure_from_context(ctx, nl_read_bh, s, dest, length, 0, 0, 0, 0, completion);
    if (ba == INVALID_ADDRESS)
        return io_complete(completion, -ENOMEM);
    return blockq_check(s->sock.rxbq, ba, false);
}

closure_func_basic(file_io, sysreturn, nl_write,
                   void *src, u64 length, u64 offset, context ctx, boolean bh, io_completion completion)
{
    nl_debug("write len %ld", length);
    nlsock s = struct_from_closure(nlsock, write);
    nl_lock(s);
    sysreturn rv = nl_write_internal(s, src, length);
    nl_unlock(s);
    return io_complete(completion, rv);
}

closure_func_basic(fdesc_events, u32, nl_events,
                 thread t)
{
    nlsock s = struct_from_closure(nlsock, events);
    u32 events = EPOLLOUT;
    if (!queue_empty(s->data))
        events |= EPOLLIN;
    return events;
}

closure_func_basic(fdesc_close, sysreturn, nl_close,
                   context ctx, io_completion completion)
{
    nlsock s = struct_from_closure(nlsock, close);
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
    socket_deinit(&s->sock);
    if (s->addr.nl_pid != 0)
        deallocate_u64((heap)netlink.pids, s->addr.nl_pid, 1);
    spin_unlock(&netlink.lock);
    deallocate(s->sock.h, s, sizeof(*s));
    return io_complete(completion, 0);
}

static sysreturn nl_bind(struct sock *sock, struct sockaddr *addr, socklen_t addrlen)
{
    nlsock s = (nlsock)sock;
    sysreturn rv;
    struct sockaddr_nl *nl_addr = (struct sockaddr_nl *)addr;
    if (addrlen != sizeof(*nl_addr)) {
        rv = -EINVAL;
        goto out;
    }
    if (!fault_in_memory(addr, addrlen)) {
        rv = -EFAULT;
        goto out;
    }
    if (nl_addr->nl_family != AF_NETLINK) {
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
    context ctx = get_current_context(current_cpu());
    return apply(sock->f.write, buf, len, 0, ctx, false, (io_completion)&sock->f.io_complete);
}

static sysreturn nl_recvfrom(struct sock *sock, void *buf, u64 len, int flags,
                             struct sockaddr *src_addr, socklen_t *addrlen)
{
    nl_debug("recvfrom: len %ld, flags 0x%x", len, flags);
    nlsock s = (nlsock)sock;
    blockq_action ba = contextual_closure(nl_read_bh, s, buf, len, 0, flags, src_addr, addrlen,
                                          (io_completion)&sock->f.io_complete);
    if (ba == INVALID_ADDRESS) {
        socket_release(sock);
        return -ENOMEM;
    }
    return blockq_check(s->sock.rxbq, ba, false);
}

static sysreturn nl_sendmsg(struct sock *sock, const struct msghdr *msg, int flags, boolean in_bh,
                            io_completion completion)
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
    return io_complete(completion, rv);
}

static sysreturn nl_recvmsg(struct sock *sock, struct msghdr *msg, int flags, boolean in_bh,
                            io_completion completion)
{
    nl_debug("recvmsg: iovlen %ld, flags 0x%x", msg->msg_iovlen, flags);
    nlsock s = (nlsock)sock;
    blockq_action ba = contextual_closure(nl_read_bh, s, 0, 0, msg, flags,
                                          msg->msg_name, &msg->msg_namelen, completion);
    if (ba == INVALID_ADDRESS)
        return io_complete(completion, -ENOMEM);
    return blockq_check(s->sock.rxbq, ba, in_bh);
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
                    nl_enqueue_ifaddr4(s, RTM_DELADDR, 0, 0, NL_PID_KERNEL, netif,
                        args->ipv4_changed.old_address->u_addr.ip4,
                        (reason & LWIP_NSC_IPV4_NETMASK_CHANGED) ?
                                *ip_2_ip4(args->ipv4_changed.old_netmask) :
                                *ip_2_ip4(&netif->netmask));
                    nl_unlock(s);
                }
                if (!ip4_addr_isany(netif_ip4_addr(netif))) {
                    nl_lock(s);
                    nl_enqueue_ifaddr4(s, RTM_NEWADDR, 0, 0, NL_PID_KERNEL, netif,
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
    if (flags & ~SOCK_FLAGS_MASK)
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
    if (socket_init(h, AF_NETLINK, type, flags, &s->sock) < 0)
        goto err_socket;
    s->data = allocate_queue(h, NL_QUEUE_MAX_LEN);
    if (s->data == INVALID_ADDRESS)
        goto err_queue;
    spin_lock(&netlink.lock);
    vector_push(netlink.sockets, s);
    spin_unlock(&netlink.lock);
    s->family = family;
    zero(&s->addr, sizeof(s->addr));
    s->sock.f.read = init_closure_func(&s->read, file_io, nl_read);
    s->sock.f.write = init_closure_func(&s->write, file_io, nl_write);
    s->sock.f.events = init_closure_func(&s->events, fdesc_events, nl_events);
    s->sock.f.close = init_closure_func(&s->close, fdesc_close, nl_close);
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
    BSS_RO_AFTER_INIT NETIF_DECLARE_EXT_CALLBACK(netif_callback);
    netif_add_ext_callback(&netif_callback, nl_lwip_ext_callback);
}
