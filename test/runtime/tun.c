#include <errno.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <poll.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <runtime.h>

#include "../test_utils.h"

#define TUN_ADDR    0x0a0b0c0d

#define TUN_PEER_ADDR   (TUN_ADDR + 1)
#define TUN_PEER_PORT   1234

static int tun_setup(int flags, char *ifname)
{
    int tun_fd, sock_fd;
    struct pollfd pfd;
    u64 dummy_buf;
    struct ifreq ifr;
    struct sockaddr_in addr;

    tun_fd = open("/dev/net/tun", O_RDWR);
    test_assert(tun_fd > 0);

    /* A file descriptor not attached to a tun interface cannot be read from or written to. */
    pfd.fd = tun_fd;
    pfd.events = POLLIN | POLLOUT;
    test_assert((poll(&pfd, 1, 0) == 1) && (pfd.revents == POLLERR));
    test_assert((read(tun_fd, &dummy_buf, sizeof(dummy_buf)) == -1) && (errno == EBADFD));
    test_assert((write(tun_fd, &dummy_buf, sizeof(dummy_buf)) == -1) && (errno == EBADFD));

    test_assert((ioctl(tun_fd, TUNSETIFF, NULL) == -1) && (errno == EFAULT));
    test_assert((ioctl(tun_fd, TUNSETIFF, FAULT_ADDR) == -1) && (errno == EFAULT));
    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, ifname);
    ifr.ifr_flags = flags;
    test_assert((ioctl(tun_fd, TUNGETIFF, &ifr) == -1) && (errno == EBADFD));
    test_assert(ioctl(tun_fd, TUNSETIFF, &ifr) == 0);

    /* Try to re-attach to the interface when already attached. */
    test_assert((ioctl(tun_fd, TUNSETIFF, &ifr) == -1) && (errno == EINVAL));

    sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    test_assert(sock_fd > 0);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(TUN_ADDR);
    memcpy(&ifr.ifr_addr, &addr, sizeof(addr));
    test_assert(ioctl(sock_fd, SIOCSIFADDR, &ifr) == 0);
    addr.sin_addr.s_addr = htonl(0xffffff00);
    memcpy(&ifr.ifr_addr, &addr, sizeof(addr));
    test_assert(ioctl(sock_fd, SIOCSIFNETMASK, &ifr) == 0);
    test_assert((ioctl(sock_fd, SIOCGIFFLAGS, &ifr) == 0) && !(ifr.ifr_flags & IFF_UP));
    ifr.ifr_flags |= IFF_UP;
    test_assert(ioctl(sock_fd, SIOCSIFFLAGS, &ifr) == 0);
    test_assert(close(sock_fd) == 0);
    strcpy(ifname, ifr.ifr_name);
    return tun_fd;
}

static void tun_test_basic(void)
{
    int tun_fd, sock_fd;
    struct ifreq ifr;
    struct sockaddr_in addr;
    socklen_t addr_len;
    int mtu, hdr_len, pkt_len;
    struct pollfd pfd;
    int nbio;
    uint8_t buf[64 * KB];
    struct iphdr *ip_hdr = (struct iphdr *)buf;
    struct udphdr *udp_hdr = (struct udphdr *)(ip_hdr + 1);

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_name[0] = ifr.ifr_name[1] = 't';
    tun_fd = tun_setup(IFF_TUN | IFF_NO_PI, ifr.ifr_name);

    /* Check that the request for a given interface name is honored. */
    test_assert((ifr.ifr_name[0] == 't') && (ifr.ifr_name[1] == 't'));

    test_assert((ioctl(tun_fd, TUNGETIFF, NULL) == -1) && (errno == EFAULT));
    memset(&ifr, 0, sizeof(ifr));
    test_assert(ioctl(tun_fd, TUNGETIFF, &ifr) == 0);
    test_assert((ifr.ifr_name[0] == 't') && (ifr.ifr_name[1] == 't'));
    test_assert(ifr.ifr_flags == (IFF_TUN | IFF_NO_PI));

    /* A newly attached file descriptor can be written to but not read from (until a packet arrives
     * at the tun interface). */
    pfd.fd = tun_fd;
    pfd.events = POLLIN | POLLOUT;
    test_assert((poll(&pfd, 1, 0) == 1) && (pfd.revents == POLLOUT));
    nbio = 1;
    test_assert(ioctl(tun_fd, FIONBIO, &nbio) == 0);
    test_assert((read(tun_fd, buf, sizeof(buf)) == -1) && (errno == EAGAIN));
    nbio = 0;
    test_assert(ioctl(tun_fd, FIONBIO, &nbio) == 0);

    /* Try to send a zero-sized packet. */
    test_assert((write(tun_fd, buf, 0) == -1) && (errno == EINVAL));

    /* Send an MTU-sized packet. */
    sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    test_assert(sock_fd > 0);
    test_assert((ioctl(sock_fd, SIOCGIFMTU, &ifr) == 0) && (ifr.ifr_mtu > 1));
    if (ifr.ifr_mtu >= sizeof(buf)) {
        ifr.ifr_mtu = sizeof(buf) - 1;
        test_assert(ioctl(sock_fd, SIOCSIFMTU, &ifr) == 0);
    }
    mtu = ifr.ifr_mtu;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(TUN_PEER_ADDR);
    addr.sin_port = htons(TUN_PEER_PORT);
    test_assert(connect(sock_fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    hdr_len = sizeof(struct iphdr) + sizeof(struct udphdr);
    pkt_len = mtu - hdr_len;
    for (int i = 0; i < pkt_len; i++)
        buf[i] = i;
    test_assert(send(sock_fd, buf, pkt_len, 0) == pkt_len);
    test_assert((poll(&pfd, 1, 0) == 1) && (pfd.revents == (POLLIN | POLLOUT)));
    test_assert(read(tun_fd, buf, sizeof(buf)) == mtu);
    for (int i = 0; i < pkt_len; i++)
        test_assert(buf[hdr_len + i] == (uint8_t)i);

    /* Try to operate on tun_fd using an invalid buffer. */
    test_assert(send(sock_fd, buf, pkt_len, 0) == pkt_len);
    test_assert((read(tun_fd, FAULT_ADDR, PAGESIZE) == -1) && (errno == EFAULT));
    test_assert((write(tun_fd, FAULT_ADDR, PAGESIZE) == -1) && (errno == EFAULT));
    test_assert((ioctl(tun_fd, TUNGETIFF, FAULT_ADDR) == -1) && (errno == EFAULT));
    test_assert((ioctl(tun_fd, TUNSETQUEUE, FAULT_ADDR) == -1) && (errno == EFAULT));

    /* Swap source and destination, and receive an MTU-sized packet. */
    ip_hdr->saddr = htonl(TUN_PEER_ADDR);
    ip_hdr->daddr = htonl(TUN_ADDR);
    udp_hdr->source = htons(TUN_PEER_PORT);
    addr_len = sizeof(addr);
    test_assert(getsockname(sock_fd, (struct sockaddr *)&addr, &addr_len) == 0);
    udp_hdr->dest = addr.sin_port;
    test_assert(write(tun_fd, buf, mtu) == mtu);
    test_assert(recv(sock_fd, buf, sizeof(buf), 0) == pkt_len);
    for (int i = 0; i < pkt_len; i++)
        test_assert(buf[i] == (uint8_t)i);

    test_assert(close(tun_fd) == 0);

    /* Check that network interface is removed when file descriptor is closed. */
    test_assert((ioctl(sock_fd, SIOCGIFMTU, &ifr) == -1) && (errno == ENODEV));

    test_assert(close(sock_fd) == 0);
}

/* Test packet sending and receiving with packet information enabled in interface options. */
static void tun_test_pi(void)
{
    int tun_fd, sock_fd;
    struct ifreq ifr;
    struct sockaddr_in addr;
    socklen_t addr_len;
    uint8_t buf[KB];
    const int pkt_len = sizeof(buf) / 2;
    const int tot_len =
            sizeof(struct tun_pi) + sizeof(struct iphdr) + sizeof(struct udphdr) + pkt_len;
    const struct tun_pi *pi = (struct tun_pi *)buf;
    struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(*pi));
    struct udphdr *udp_hdr = (struct udphdr *)(ip_hdr + 1);

    memset(&ifr, 0, sizeof(ifr));
    tun_fd = tun_setup(IFF_TUN, ifr.ifr_name);
    sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    test_assert(sock_fd > 0);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(TUN_PEER_ADDR);
    addr.sin_port = htons(TUN_PEER_PORT);
    test_assert(connect(sock_fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);

    /* Try to receive a packet with a buffer too small. */
    test_assert(send(sock_fd, buf, 1, 0) == 1);
    test_assert((read(tun_fd, buf, sizeof(struct tun_pi) - 1) == -1) && (errno == EINVAL));

    for (int i = 0; i < pkt_len; i++)
        buf[i] = i;
    test_assert(send(sock_fd, buf, pkt_len, 0) == pkt_len);
    test_assert(read(tun_fd, buf, sizeof(buf)) == tot_len);
    test_assert(pi->proto == htons(ETH_P_IP));
    test_assert(!(pi->flags & TUN_PKT_STRIP));
    for (int i = 0; i < pkt_len; i++)
        test_assert(buf[tot_len - pkt_len + i] == (uint8_t)i);

    /* Receive a packet with a buffer smaller than what is required to hold the entire packet. */
    for (int i = 0; i < pkt_len; i++)
        buf[i] = i;
    test_assert(send(sock_fd, buf, pkt_len, 0) == pkt_len);
    test_assert(read(tun_fd, buf, tot_len - 1) == tot_len - 1);
    test_assert(pi->flags & TUN_PKT_STRIP);

    /* Try to send a packet with a buffer too small. */
    test_assert((write(tun_fd, buf, sizeof(struct tun_pi) - 1) == -1) && (errno == EINVAL));

    /* Send an empty packet. */
    test_assert(write(tun_fd, buf, sizeof(struct tun_pi)) == sizeof(struct tun_pi));

    /* Swap source and destination, and receive a packet. */
    ip_hdr->saddr = htonl(TUN_PEER_ADDR);
    ip_hdr->daddr = htonl(TUN_ADDR);
    udp_hdr->source = htons(TUN_PEER_PORT);
    addr_len = sizeof(addr);
    test_assert(getsockname(sock_fd, (struct sockaddr *)&addr, &addr_len) == 0);
    udp_hdr->dest = addr.sin_port;
    test_assert(write(tun_fd, buf, tot_len) == tot_len);
    test_assert(recv(sock_fd, buf, sizeof(buf), 0) == pkt_len);
    for (int i = 0; i < pkt_len; i++)
        test_assert(buf[i] == (uint8_t)i);

    test_assert(close(sock_fd) == 0);
    test_assert(close(tun_fd) == 0);
}

static int tun_set_queue(int fd, int enable)
{
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));

    if (enable > 0)
        ifr.ifr_flags = IFF_ATTACH_QUEUE;
    else if (enable == 0)
        ifr.ifr_flags = IFF_DETACH_QUEUE;
    else
        ifr.ifr_flags = IFF_ATTACH_QUEUE|IFF_DETACH_QUEUE;

    return ioctl(fd, TUNSETQUEUE, (void *)&ifr);
}

#define MQ_COUNT 4
/* Test the multi-queue option when creating an interface */
static void tun_test_multiqueue(void)
{
    int fds[MQ_COUNT], sock_fd;
    struct ifreq ifr;
    struct sockaddr_in addr;

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_name[0] = 'm';
    ifr.ifr_name[1] = 'q';
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;
    for (int i = 0; i < MQ_COUNT; i++) {
        fds[i] = open("/dev/net/tun", O_RDWR);
        test_assert(fds[i] > 0);
        test_assert(ioctl(fds[i], TUNSETIFF, &ifr) == 0);
    }

    sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    test_assert(sock_fd > 0);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(TUN_ADDR);
    memcpy(&ifr.ifr_addr, &addr, sizeof(addr));
    test_assert(ioctl(sock_fd, SIOCSIFADDR, &ifr) == 0);
    addr.sin_addr.s_addr = htonl(0xffffff00);
    memcpy(&ifr.ifr_addr, &addr, sizeof(addr));
    test_assert(ioctl(sock_fd, SIOCSIFNETMASK, &ifr) == 0);
    test_assert((ioctl(sock_fd, SIOCGIFFLAGS, &ifr) == 0) && !(ifr.ifr_flags & IFF_UP));
    ifr.ifr_flags |= IFF_UP;
    test_assert(ioctl(sock_fd, SIOCSIFFLAGS, &ifr) == 0);
    test_assert(close(sock_fd) == 0);

    test_assert(tun_set_queue(fds[0], -1) == -1);
    for (int i = 0; i < MQ_COUNT; i++)
        test_assert(tun_set_queue(fds[i], 0) == 0);
    for (int i = 0; i < MQ_COUNT; i++)
        test_assert(tun_set_queue(fds[i], 1) == 0);
    for (int i = 0; i < MQ_COUNT; i++)
        test_assert(close(fds[i]) == 0);
}

int main(int argc, char **argv)
{
    tun_test_basic();
    tun_test_pi();
    tun_test_multiqueue();
    printf("Tun interface tests OK\n");
    return EXIT_SUCCESS;
}
