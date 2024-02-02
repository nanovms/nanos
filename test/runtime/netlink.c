#include <errno.h>
#include <ifaddrs.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "../test_utils.h"

#define DUMP_ROUTES
//#define DEBUG_NETLINK

#ifdef DUMP_ROUTES
#define dump_routes(x, ...) do {printf(x, ##__VA_ARGS__);} while(0)
#else
#define dump_routes(x, ...)
#endif

#ifdef DEBUG_NETLINK
#define debug_netlink(x, ...) do {printf(x, ##__VA_ARGS__);} while(0)
#else
#define debug_netlink(x, ...)
#endif

static int netlink_open(struct sockaddr_nl *nladdr, unsigned int pid)
{
    int fd;
    socklen_t addr_len;

    fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    test_assert(fd >= 0);
    memset(nladdr, '\0', sizeof(*nladdr));
    nladdr->nl_pid = pid;
    nladdr->nl_family = AF_NETLINK;
    test_assert(bind(fd, (struct sockaddr *)nladdr, sizeof(*nladdr)) == 0);
    addr_len = sizeof(*nladdr);
    test_assert(getsockname(fd, (struct sockaddr *)nladdr, &addr_len) == 0);
    test_assert(addr_len == sizeof(*nladdr));
    return fd;
}

static void assert_resp(struct nlmsghdr *resp_hdr, unsigned int len, unsigned int type,
                        unsigned int flags)
{
    test_assert(resp_hdr->nlmsg_len >= NLMSG_LENGTH(len));
    test_assert(resp_hdr->nlmsg_type == type);
    test_assert(resp_hdr->nlmsg_flags == flags);
}

static int recv_resp(int fd, struct msghdr *resp, unsigned int len, unsigned int type,
                     unsigned int flags)
{
    int ret;
    struct sockaddr_nl *addr = (struct sockaddr_nl *)resp->msg_name;

    ret = recvmsg(fd, resp, 0);
    test_assert(ret >= NLMSG_LENGTH(len));
    test_assert(resp->msg_namelen == sizeof(*addr));
    test_assert((addr->nl_family == AF_NETLINK) && (addr->nl_pid == 0));
    assert_resp((struct nlmsghdr *)resp->msg_iov[0].iov_base, len, type, flags);
    return ret;
}

static void recv_resp_error(int fd, struct msghdr *resp, int err_number)
{
    int ret;
    struct nlmsghdr *resp_hdr;
    struct nlmsgerr *err;

    ret = recvmsg(fd, resp, 0);
    test_assert(ret >= NLMSG_LENGTH(sizeof(struct nlmsgerr)));
    resp_hdr = (struct nlmsghdr *)resp->msg_iov[0].iov_base;
    test_assert(resp_hdr->nlmsg_len >= NLMSG_LENGTH(sizeof(struct nlmsgerr)));
    test_assert(resp_hdr->nlmsg_type == NLMSG_ERROR);
    err = (struct nlmsgerr *)NLMSG_DATA(resp_hdr);
    test_assert(err->error == -err_number);
}

static void test_basic(void)
{
    int fd;
    struct ifaddrs *ifaddr, *ifa;
    int inet_addrs = 0;

    /* invalid socket type */
    fd = socket(PF_NETLINK, SOCK_STREAM, NETLINK_ROUTE);
    test_assert((fd == -1) && (errno == ESOCKTNOSUPPORT));

    /* invalid protocol */
    fd = socket(PF_NETLINK, SOCK_DGRAM, -1);
    test_assert((fd == -1) && (errno == EPROTONOSUPPORT));

    test_assert(getifaddrs(&ifaddr) == 0);
    for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;
        if (ifa->ifa_addr->sa_family == AF_INET)
            inet_addrs++;
    }
    /* Expect at least an ethernet-like interface, plus the loopback interface. */
    test_assert(inet_addrs >= 2);
    freeifaddrs(ifaddr);
}

static void test_fault(void)
{
    int fd;
    struct sockaddr_nl nladdr;
    socklen_t len;
    struct nlmsghdr nlh;
    uint8_t buf[512];
    void *fault_addr = FAULT_ADDR;

    fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    test_assert(fd >= 0);
    test_assert(bind(fd, (struct sockaddr *)fault_addr, sizeof(nladdr)) == -1);
    test_assert(errno == EFAULT);
    test_assert(close(fd) == 0);

    fd = netlink_open(&nladdr, 0);
    test_assert((write(fd, fault_addr, sizeof(nlh)) == -1) && (errno == EFAULT));

    nlh.nlmsg_type = -1;    /* invalid header type, should generate an error message */
    nlh.nlmsg_flags = NLM_F_REQUEST;
    nlh.nlmsg_pid = nladdr.nl_pid;
    nlh.nlmsg_seq = 1;
    nlh.nlmsg_len = sizeof(nlh);
    test_assert(write(fd, &nlh, sizeof(nlh)) == sizeof(nlh));
    test_assert((read(fd, fault_addr, sizeof(nlh)) == -1) && (errno == EFAULT));

    test_assert(write(fd, &nlh, sizeof(nlh)) == sizeof(nlh));
    len = sizeof(nladdr);
    test_assert((recvfrom(fd, buf, sizeof(buf), 0, fault_addr, &len) == -1) && (errno == EFAULT));

    test_assert(write(fd, &nlh, sizeof(nlh)) == sizeof(nlh));
    test_assert(recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&nladdr, fault_addr) == -1);
    test_assert(errno == EFAULT);

    test_assert(close(fd) == 0);
}

static void test_bind(void)
{
    int fd, fd1;
    struct sockaddr_nl nladdr;
    socklen_t addr_len;
    int ret;

    fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    test_assert(fd >= 0);
    memset(&nladdr, '\0', sizeof(nladdr));
    ret = bind(fd, (struct sockaddr *)&nladdr, sizeof(nladdr)); /* invalid address family */
    test_assert((ret == -1) && (errno == EINVAL));
    nladdr.nl_family = AF_NETLINK;
    ret = bind(fd, (struct sockaddr *)&nladdr, sizeof(nladdr) - 1); /* invalid address length */
    test_assert((ret == -1) && (errno == EINVAL));
    test_assert(bind(fd, (struct sockaddr *)&nladdr, sizeof(nladdr)) == 0);
    addr_len = sizeof(nladdr);
    test_assert(getsockname(fd, (struct sockaddr *)&nladdr, &addr_len) == 0);
    test_assert(addr_len == sizeof(nladdr));

    /* Try to bind to another address. */
    nladdr.nl_pid++;
    ret = bind(fd, (struct sockaddr *)&nladdr, sizeof(nladdr));
    test_assert((ret == -1) && (errno == EINVAL));

    /* Re-bind to the already bound address (no-op). */
    nladdr.nl_pid--;
    test_assert(bind(fd, (struct sockaddr *)&nladdr, sizeof(nladdr)) == 0);

    /* Try to bind another socket to the same address. */
    fd1 = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    test_assert(fd1 >= 0);
    ret = bind(fd1, (struct sockaddr *)&nladdr, sizeof(nladdr));
    test_assert((ret == -1) && (errno == EADDRINUSE));
    test_assert(close(fd1) == 0);

    test_assert(close(fd) == 0);
}

static void test_getlink(void)
{
    int fd;
    struct sockaddr_nl nladdr;
    struct req {
        struct nlmsghdr nlh;
        struct ifinfomsg ifi;
    } req;
    uint8_t buf[4096];
    struct iovec iov;
    struct msghdr resp;
    struct ifinfomsg *ifi;
    int ret;

    fd = netlink_open(&nladdr, 0);
    memset(&req, '\0', sizeof(req));
    req.nlh.nlmsg_type = RTM_GETLINK;
    req.nlh.nlmsg_flags = NLM_F_REQUEST;
    req.nlh.nlmsg_pid = nladdr.nl_pid;
    req.nlh.nlmsg_seq = 1;
    iov.iov_base = buf;
    iov.iov_len = sizeof(buf);
    resp.msg_name = &nladdr;
    resp.msg_namelen =  sizeof(nladdr);
    resp.msg_iov = &iov;
    resp.msg_iovlen = 1;
    resp.msg_control = NULL;
    resp.msg_controllen = 0;
    resp.msg_flags = 0;

    /* non-allowed destination PID */
    ret = sendto(fd, &req, sizeof(req), 0, (struct sockaddr *)&nladdr, sizeof(nladdr));
    test_assert((ret == -1) && (errno == EPERM));
    ret = sendmsg(fd, &resp, 0);
    test_assert((ret == -1) && (errno == EPERM));

    /* invalid address size */
    nladdr.nl_pid = 0;
    ret = sendto(fd, &req, sizeof(req), 0, (struct sockaddr *)&nladdr, sizeof(nladdr) - 1);
    test_assert((ret == -1) && (errno == EINVAL));

    /* invalid length in request header */
    req.nlh.nlmsg_len = sizeof(req) - 1;
    req.ifi.ifi_index = 1;
    ret = sendto(fd, &req, sizeof(req), 0, (struct sockaddr *)&nladdr, sizeof(nladdr));
    test_assert(ret == sizeof(req));
    recv_resp_error(fd, &resp, EINVAL);

    /* invalid interface index */
    req.nlh.nlmsg_len = sizeof(req);
    req.ifi.ifi_index = 0;
    ret = sendto(fd, &req, sizeof(req), 0, (struct sockaddr *)&nladdr, sizeof(nladdr));
    test_assert(ret == sizeof(req));
    recv_resp_error(fd, &resp, EINVAL);

    /* valid request */
    req.ifi.ifi_index = 1;
    ret = sendto(fd, &req, sizeof(req), 0, (struct sockaddr *)&nladdr, sizeof(nladdr));
    test_assert(ret == sizeof(req));
    recv_resp(fd, &resp, sizeof(struct ifinfomsg), RTM_NEWLINK, 0);
    ifi = (struct ifinfomsg *)NLMSG_DATA(buf);
    test_assert(ifi->ifi_index == req.ifi.ifi_index);

    test_assert(close(fd) == 0);
}

static void test_getaddr(void)
{
    int fd;
    struct sockaddr_nl nladdr;
    struct req {
        struct nlmsghdr nlh;
        struct rtgenmsg msg;
    } req;
    uint8_t buf[4096];
    struct iovec iov;
    struct msghdr msg;
    socklen_t addr_len;
    struct ifaddrmsg *ifa;
    int ret;

    const int afs[3] = { AF_INET, AF_INET6, AF_UNSPEC };
    for (int i = 0; i < 3; i++) {
        fd = netlink_open(&nladdr, 0);
        nladdr.nl_pid = 0;
        memset(&req, '\0', sizeof(req));
        req.nlh.nlmsg_len = sizeof(req);
        req.nlh.nlmsg_type = RTM_GETADDR;
        req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
        req.nlh.nlmsg_pid = nladdr.nl_pid;
        req.nlh.nlmsg_seq = 2;
        iov.iov_base = buf;
        msg.msg_name = &nladdr;
        msg.msg_namelen = sizeof(nladdr);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
        msg.msg_flags = 0;
        req.msg.rtgen_family = afs[i];
        memcpy(iov.iov_base, &req, sizeof(req));
        iov.iov_len = sizeof(req);
        ret = sendmsg(fd, &msg, 0);
        test_assert(ret == sizeof(req));
        iov.iov_len = sizeof(buf);
        recv_resp(fd, &msg, sizeof(struct ifaddrmsg), RTM_NEWADDR, NLM_F_MULTI);
        ifa = (struct ifaddrmsg *)NLMSG_DATA(buf);
        test_assert(afs[i] != AF_UNSPEC ? (ifa->ifa_family == afs[i]) :
                    (ifa->ifa_family == AF_INET || ifa->ifa_family == AF_INET6));
        test_assert(close(fd) == 0);
    }

    fd = netlink_open(&nladdr, 0);
    ret = send(fd, &req, sizeof(req), 0);
    test_assert(ret == sizeof(req));
    iov.iov_len = sizeof(struct nlmsghdr);  /* truncated response */
    ret = recvmsg(fd, &msg, 0);
    test_assert((ret == iov.iov_len) && (msg.msg_flags & MSG_TRUNC));
    test_assert(close(fd) == 0);

    fd = netlink_open(&nladdr, 0);
    ret = send(fd, &req, sizeof(req), 0);
    test_assert(ret == sizeof(req));
    msg.msg_flags = 0;
    ret = recvmsg(fd, &msg, MSG_TRUNC);    /* return non-truncated message length */
    test_assert((ret > iov.iov_len) && (msg.msg_flags & MSG_TRUNC));
    test_assert(close(fd) == 0);

    fd = netlink_open(&nladdr, getpid());
    ret = write(fd, &req, sizeof(req));
    test_assert(ret == sizeof(req));
    addr_len = 0;   /* Should be adjusted by recvfrom() to the actual address size. */
    ret = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&nladdr, &addr_len);
    test_assert(addr_len == sizeof(nladdr));
    assert_resp((struct nlmsghdr *)buf, sizeof(struct ifaddrmsg), RTM_NEWADDR, NLM_F_MULTI);
    test_assert(close(fd) == 0);

    fd = netlink_open(&nladdr, getpid());
    ret = write(fd, &req, sizeof(req));
    test_assert(ret == sizeof(req));
    memset(buf, 0, sizeof(buf));
    ret = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&nladdr, &addr_len);
    test_assert(ret >= NLMSG_LENGTH(sizeof(struct ifaddrmsg)));
    test_assert(addr_len == sizeof(nladdr));
    test_assert((nladdr.nl_family == AF_NETLINK) && (nladdr.nl_pid == 0));
    assert_resp((struct nlmsghdr *)buf, sizeof(struct ifaddrmsg), RTM_NEWADDR, NLM_F_MULTI);
    test_assert(close(fd) == 0);
}

static void test_nonblocking(void)
{
    int fd;
    uint8_t buf[4096];
    int ret;

    fd = socket(PF_NETLINK, SOCK_RAW | SOCK_NONBLOCK, NETLINK_ROUTE);
    test_assert(fd >= 0);
    ret = read(fd, buf, sizeof(buf));
    test_assert((ret == -1) && (errno == EAGAIN));
    test_assert(close(fd) == 0);
}

static void test_getroute(int family)
{
    /* There is no guarantee that interfaces have been configured by the time
       this runs, so just validate that we can walk the table without issues. */
    int fd;
    struct sockaddr_nl nladdr;
    struct req {
        struct nlmsghdr nlh;
        struct rtgenmsg msg;
    } req;
    uint8_t buf[4096];
    struct iovec iov;
    struct msghdr msg;
    int ret;

    fd = netlink_open(&nladdr, 0);
    nladdr.nl_pid = 0;
    memset(&req, '\0', sizeof(req));
    req.nlh.nlmsg_len = sizeof(req);
    req.nlh.nlmsg_type = RTM_GETROUTE;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_pid = nladdr.nl_pid;
    req.nlh.nlmsg_seq = 3;
    iov.iov_base = buf;
    msg.msg_name = &nladdr;
    msg.msg_namelen = sizeof(nladdr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    req.msg.rtgen_family = family;
    memcpy(iov.iov_base, &req, sizeof(req));
    iov.iov_len = sizeof(req);
    ret = sendmsg(fd, &msg, 0);
    test_assert(ret == sizeof(req));
    iov.iov_len = sizeof(buf);
    int avail = recv_resp(fd, &msg, sizeof(struct rtmsg), RTM_NEWROUTE, NLM_F_MULTI);

    char ifname[IF_NAMESIZE];
    char dest[INET_ADDRSTRLEN];
    char gwaddr[INET_ADDRSTRLEN];

    dump_routes("Kernel %s routing table\n", family == AF_INET ? "IP" : "IPv6");
    dump_routes("%-16s%-16s%-16s\n", "Destination", "Gateway", "Iface");
    for (struct nlmsghdr *nlh = (struct nlmsghdr *)buf; NLMSG_OK(nlh, avail);
         nlh = NLMSG_NEXT(nlh, avail)) {
        debug_netlink("nlmsg: len %d, type %d, flags %d, seq %d, pid %d\n",
                      nlh->nlmsg_len, nlh->nlmsg_type, nlh->nlmsg_flags, nlh->nlmsg_seq, nlh->nlmsg_pid);
        if (nlh->nlmsg_type == NLMSG_DONE)
            break;
        ifname[0] = '\0';
        dest[0] = '\0';
        gwaddr[0] = '\0';
        struct rtmsg *rtm = (struct rtmsg *)NLMSG_DATA(nlh);
        debug_netlink("family %d, dst_len %d, src_len %d, tos %d, table %d, "
                      "protocol %d, scope %d, type %d, flags 0x%x\n",
                      rtm->rtm_family, rtm->rtm_dst_len, rtm->rtm_src_len, rtm->rtm_tos, rtm->rtm_table,
                      rtm->rtm_protocol, rtm->rtm_scope, rtm->rtm_type, rtm->rtm_flags);
        test_assert(rtm->rtm_family == family);
        int rta_len = RTM_PAYLOAD(nlh);
        for (struct rtattr *rta = (struct rtattr *)RTM_RTA(rtm); RTA_OK(rta, rta_len);
             rta = RTA_NEXT(rta, rta_len)) {
            debug_netlink(" -> type %d, len %d\n", rta->rta_type, rta->rta_len);
            debug_netlink("    %d %d %d %d\n", *(unsigned char *)RTA_DATA(rta),
                          *(unsigned char *)(RTA_DATA(rta) + 1),
                          *(unsigned char *)(RTA_DATA(rta) + 2),
                          *(unsigned char *)(RTA_DATA(rta) + 3));
            switch (rta->rta_type) {
            case RTA_OIF:
                test_assert(if_indextoname(*(unsigned int *)RTA_DATA(rta), ifname));
                break;
            case RTA_GATEWAY:
                test_assert(inet_ntop(family, RTA_DATA(rta), gwaddr, sizeof(gwaddr)));
                break;
            case RTA_DST:
                test_assert(inet_ntop(family, RTA_DATA(rta), dest, sizeof(dest)));
                break;
            }
        }
        dump_routes("%-16s%-16s%-16s\n", dest[0] ? dest : "default", gwaddr[0] ? gwaddr : "0.0.0.0", ifname);
    }
    dump_routes("\n");
    test_assert(close(fd) == 0);
}

int main(int argc, char *argv[])
{
    test_basic();
    test_fault();
    test_bind();
    test_getlink();
    test_getaddr();
    test_nonblocking();
    test_getroute(AF_INET);
    /* test_getroute(AF_INET6); */
    return 0;
}
