#define _GNU_SOURCE
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <poll.h>
#include <pthread.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <sys/epoll.h>

#include <runtime.h>

#include "../test_utils.h"

#define NETSOCK_TEST_BASIC_PORT 1233
#define NETSOCK_TEST_FAULT_PORT 1237

#define NETSOCK_TEST_FIO_COUNT  8

#define NETSOCK_TEST_PEEK_COUNT 8

static inline void timespec_sub(struct timespec *a, struct timespec *b, struct timespec *r)
{
    r->tv_sec = a->tv_sec - b->tv_sec;
    r->tv_nsec = a->tv_nsec - b->tv_nsec;
    if (a->tv_nsec < b->tv_nsec) {
        r->tv_sec--;
        r->tv_nsec += 1000000000ull;
    }
}

static void *netsock_test_basic_thread(void *arg)
{
    int sock_type = (long)arg;
    int fd;
    struct sockaddr_in addr;
    uint8_t rx_buf[8 * KB];
    int rx;

    fd = socket(AF_INET, sock_type, 0);
    test_assert(fd > 0);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(NETSOCK_TEST_BASIC_PORT);
    test_assert(connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    do {
        rx = read(fd, rx_buf, sizeof(rx_buf));
        test_assert(rx >= 0);
    } while (rx > 0);
    test_assert(close(fd) == 0);
    if (sock_type == SOCK_STREAM) {
        /* Create a new connection to the server, to test resource deallocation for the new
         * connection when the server socket is closed without an accept() call. */
        fd = socket(AF_INET, sock_type, 0);
        test_assert(fd > 0);
        test_assert(connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
        test_assert(close(fd) == 0);
    }
    return NULL;
}

static inline void netsock_toggle_and_check_sockopt(int fd, int level, int optname, int val)
{
    int v;
    socklen_t len = sizeof(v);
    test_assert(getsockopt(fd, level, optname, &v, &len) == 0 && v == !val);
    v = val;
    test_assert(setsockopt(fd, level, optname, &v, len) == 0);
    test_assert(getsockopt(fd, level, optname, &v, &len) == 0 && v == val);
}

static void netsock_test_basic(int sock_type)
{
    int fd, tx_fd;
    struct pollfd pfd;
    struct sockaddr_in addr;
    socklen_t addr_len;
    pthread_t pt;
    int ret;
    struct timespec start, end, elapsed;
    const int tx_total = 8 * MB;
    uint8_t tx_buf[32 * KB];
    int tx = 0;
    unsigned long long ns;

    fd = socket(AF_INET, sock_type, 0);
    test_assert(fd > 0);
    pfd.fd = fd;
    pfd.events = POLLIN | POLLOUT;
    ret = poll(&pfd, 1, -1);
    test_assert(ret == 1);
    test_assert(pfd.revents == ((sock_type == SOCK_STREAM) ? (POLLHUP | POLLOUT) : POLLOUT));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(NETSOCK_TEST_BASIC_PORT);
    test_assert(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    if (sock_type == SOCK_STREAM) {
        int val;
        socklen_t len = sizeof(val);
        test_assert(getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &val, &len) == 0 && val == 0);
        netsock_toggle_and_check_sockopt(fd, SOL_SOCKET, SO_REUSEADDR, 1);
        netsock_toggle_and_check_sockopt(fd, SOL_SOCKET, SO_KEEPALIVE, 1);
        test_assert(listen(fd, 1) == 0);
        test_assert(listen(fd, 1) == 0);    /* test listen() call on already listening socket */
        test_assert(getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &val, &len) == 0 && val == 1);
        ret = pthread_create(&pt, NULL, netsock_test_basic_thread, (void *)(long)sock_type);
        test_assert(ret == 0);

        /* Change a TCP option on the listening socket and verify that the option is inherited by
         * the accepted socket. */
        netsock_toggle_and_check_sockopt(fd, IPPROTO_TCP, TCP_NODELAY, 1);
        tx_fd = accept(fd, NULL, NULL);
        test_assert(tx_fd > 0);
        test_assert(getsockopt(tx_fd, IPPROTO_TCP, TCP_NODELAY, &val, &len) == 0 && val == 1);

        /* Also validate that SO_REUSEADDR and SO_KEEPALIVE are inherited. Linux follows this
         * behavior, and it is explicitly supported by lwIP (see SOF_INHERITED). */
        test_assert(getsockopt(tx_fd, SOL_SOCKET, SO_REUSEADDR, &val, &len) == 0 && val == 1);
        test_assert(getsockopt(tx_fd, SOL_SOCKET, SO_KEEPALIVE, &val, &len) == 0 && val == 1);
        val = 0;
        test_assert(setsockopt(tx_fd, IPPROTO_TCP, TCP_NODELAY, &val, len) == 0);

        test_assert(getsockopt(tx_fd, SOL_SOCKET, SO_ACCEPTCONN, &val, &len) == 0 && val == 0);
        test_assert(getsockopt(tx_fd, IPPROTO_TCP, TCP_MAXSEG, &val, &len) == 0 && val > 0);
    } else {
        netsock_toggle_and_check_sockopt(fd, SOL_SOCKET, SO_BROADCAST, 1);
        netsock_toggle_and_check_sockopt(fd, SOL_SOCKET, SO_BROADCAST, 0);
        tx_fd = fd;
        /* Test that writing to an unconnected datagram socket gives an error. */
        test_assert(write(tx_fd, &ret, sizeof(ret)) < 0 && errno == EDESTADDRREQ);
        test_assert(connect(tx_fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    }
    addr_len = sizeof(addr);
    test_assert((getpeername(tx_fd, FAULT_ADDR, &addr_len) == -1) && (errno == EFAULT));
    test_assert((getpeername(tx_fd, &addr, FAULT_ADDR) == -1) && (errno == EFAULT));
    test_assert((write(tx_fd, FAULT_ADDR, sizeof(tx_buf)) == -1) && (errno == EFAULT));
    test_assert((recv(tx_fd, tx_buf, sizeof(tx_buf), MSG_DONTWAIT) == -1) && (errno == EAGAIN));
    test_assert(clock_gettime(CLOCK_MONOTONIC, &start) == 0);
    do {
        ret = write(tx_fd, tx_buf, sizeof(tx_buf));
        test_assert(ret > 0);
        tx += ret;
    } while (tx < tx_total);
    test_assert(clock_gettime(CLOCK_MONOTONIC, &end) == 0);
    timespec_sub(&end, &start, &elapsed);
    ns = elapsed.tv_sec * 1000000000ull + elapsed.tv_nsec;
    printf("%s(%d): transmitted %d bytes in %ld.%.9ld seconds (%lld KB/s)\n", __func__, sock_type,
           tx_total, elapsed.tv_sec, elapsed.tv_nsec, (1000000000ull / KB) * tx_total / ns);
    test_assert(close(tx_fd) == 0);
    if (sock_type == SOCK_STREAM) {
        test_assert(pthread_join(pt, NULL) == 0);
        /* close() should clean up a pending connection that has not been accept()ed */
        test_assert(close(fd) == 0);
    }
}

static void *netsock_test_fionread_thread(void *arg)
{
    int port = (long)arg;
    int fd;
    struct sockaddr_in addr;
    uint8_t buf[NETSOCK_TEST_FIO_COUNT];

    fd = socket(AF_INET, SOCK_STREAM, 0);
    test_assert(fd > 0);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    test_assert(connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    test_assert(write(fd, buf, sizeof(buf)) == sizeof(buf));
    return (void *)(long)fd;
}

static void netsock_test_fionread(void)
{
    int fd, conn_fd;
    int nbytes;
    struct sockaddr_in addr;
    const int port = 1234;
    pthread_t pt;
    int ret;
    void *thread_ret;
    uint8_t buf[NETSOCK_TEST_FIO_COUNT];

    fd = socket(AF_INET, SOCK_STREAM, 0);
    test_assert(fd > 0);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    test_assert(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    test_assert((ioctl(fd, FIONREAD, &nbytes) == 0) && (nbytes == 0));
    test_assert(listen(fd, 1) == 0);
    ret = pthread_create(&pt, NULL, netsock_test_fionread_thread,
        (void *)(long)port);
    test_assert(ret == 0);

    /* Wait for client to connect. */
    conn_fd = accept(fd, NULL, NULL);
    test_assert(conn_fd > 0);

    /* Wait for client to send data. */
    test_assert(pthread_join(pt, &thread_ret) == 0);

    test_assert(ioctl(conn_fd, FIONREAD, &nbytes) == 0);
    test_assert(nbytes == NETSOCK_TEST_FIO_COUNT);
    test_assert(close((long)thread_ret) == 0);  /* TCP client socket */
    test_assert(close(conn_fd) == 0);
    test_assert(close(fd) == 0);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    test_assert(fd > 0);
    test_assert(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    test_assert((ioctl(fd, FIONREAD, &nbytes) == 0) && (nbytes == 0));
    ret = sendto(fd, buf, sizeof(buf), 0, (struct sockaddr *)&addr,
        sizeof(addr));
    test_assert(ret == sizeof(buf));
    test_assert((ioctl(fd, FIONREAD, &nbytes) == 0) && (nbytes == sizeof(buf)));
    test_assert(close(fd) == 0);
}

/* Connect to TCP server and then close connection right away. */
static void *netsock_test_connclose_thread(void *arg)
{
    int port = (long)arg;
    int fd;
    struct sockaddr_in addr;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    test_assert(fd > 0);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    test_assert(connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    test_assert(close(fd) == 0);
    return NULL;
}

/* Connect to TCP server and wait for connection to be closed. */
static void *netsock_test_connwait_thread(void *arg)
{
    int port = (long)arg;
    int fd;
    struct sockaddr_in addr;
    uint8_t buf[8];

    fd = socket(AF_INET, SOCK_STREAM, 0);
    test_assert(fd > 0);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    test_assert(connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    test_assert(read(fd, buf, sizeof(buf)) == 0);
    test_assert(close(fd) == 0);
    return NULL;
}

/* Tests behavior of syscalls invoked on a socket after the connection has been closed. */
static void netsock_test_connclosed(void)
{
    int fd, conn_fd;
    struct sockaddr_in addr;
    socklen_t addr_len;
    const int port = 1234;
    struct pollfd pfd;
    pthread_t pt;
    uint8_t buf[8];
    struct iovec iov;
    struct msghdr msg;
    int ret;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    test_assert(fd > 0);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    test_assert(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    test_assert(listen(fd, 1) == 0);

    /* Test connection closed by peer. */
    ret = pthread_create(&pt, NULL, netsock_test_connclose_thread,
        (void *)(long)port);
    test_assert(ret == 0);
    conn_fd = accept(fd, NULL, NULL);
    test_assert(conn_fd > 0);
    test_assert(read(conn_fd, buf, sizeof(buf)) == 0);
    test_assert(recv(conn_fd, buf, sizeof(buf), 0) == 0);
    test_assert(recvfrom(conn_fd, buf, sizeof(buf), 0, NULL, 0) == 0);
    memset(&iov, 0, sizeof(iov));
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    test_assert(recvmsg(conn_fd, &msg, 0) == 0);
    pfd.fd = conn_fd;
    pfd.events = POLLIN | POLLOUT;
    ret = poll(&pfd, 1, -1);
    test_assert((ret == 1) && (pfd.revents == (POLLIN | POLLOUT)));
    test_assert(pthread_join(pt, NULL) == 0);
    test_assert(close(conn_fd) == 0);

    /* Test connection closed via shutdown(). */
    ret = pthread_create(&pt, NULL, netsock_test_connwait_thread,
        (void *)(long)port);
    test_assert(ret == 0);
    conn_fd = accept(fd, NULL, NULL);
    test_assert(conn_fd > 0);
    test_assert(shutdown(conn_fd, SHUT_RDWR) == 0);
    test_assert(read(conn_fd, buf, sizeof(buf)) == 0);
    test_assert(recv(conn_fd, buf, sizeof(buf), 0) == 0);
    test_assert(recvfrom(conn_fd, buf, sizeof(buf), 0, NULL, 0) == 0);
    memset(&iov, 0, sizeof(iov));
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    test_assert(recvmsg(conn_fd, &msg, 0) == 0);
    test_assert(pthread_join(pt, NULL) == 0);
    test_assert((listen(conn_fd, 1) == -1) && (errno == EINVAL));
    addr_len = sizeof(addr);
    test_assert(getsockname(conn_fd, (struct sockaddr *)&addr, &addr_len) == 0);
    test_assert(addr_len == sizeof(addr));
    test_assert(getpeername(conn_fd, (struct sockaddr *)&addr, &addr_len) == -1);
    test_assert(errno == ENOTCONN);
    test_assert(close(conn_fd) == 0);

    test_assert(close(fd) == 0);
}

static void *netsock_test_udpblock(void *arg)
{
    int fd;
    struct sockaddr_in addr;
    const int port = 1237;
    u8 buf[1];
    fd = (int)(long)arg;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    test_assert(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    test_assert(recv(fd, &buf, 1, 0) == 0);
    return 0;
}

static void netsock_test_udpshutdown(void)
{
    pthread_t pt;
    int ret;
    struct timespec ts;
    int fd;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    test_assert(fd > 0);
    ret = pthread_create(&pt, NULL, netsock_test_udpblock, (void *)(long)fd);
    /* allow time for the child thread to block on recv */
    usleep(1000 * 50);
    shutdown(fd, SHUT_RDWR);
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += 1;
    test_assert(pthread_timedjoin_np(pt, (void *)&ret, &ts) == 0);
    test_assert(close(fd) == 0);
}

static void *netsock_test_nonblocking_connect_thread(void *arg)
{
    int port = (long)arg;
    int fd, efd, err;
    socklen_t slen;
    struct sockaddr_in addr;
    struct epoll_event event;
    struct epoll_event events[1];

    /* Connect with SOCK_NONBLOCK and verify that EINPROGRESS is returned. */
    fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    test_assert(fd > 0);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    test_assert((connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1 && errno == EINPROGRESS));

    /* Validate reporting of EPOLLOUT. */
    efd = epoll_create1(0);
    test_assert(efd > 0);
    event.data.fd = fd;
    event.events = EPOLLOUT;
    test_assert(epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event) == 0);
    test_assert(epoll_wait(efd, events, 1, 1000 /* 1s */) == 1);
    test_assert((events[0].events & EPOLLOUT));

    slen = sizeof(err);
    test_assert(getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &slen) == 0);
    test_assert(slen == sizeof(err) && err == 0);
    test_assert(close(fd) == 0);
    test_assert(close(efd) == 0);
    return EXIT_SUCCESS;
}

static void netsock_test_nonblocking_connect(void)
{
    int fd, conn_fd;
    struct sockaddr_in addr;
    const int port = 1235;
    pthread_t pt;
    int ret;
    void *thread_ret;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    test_assert(fd > 0);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    test_assert(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    test_assert(listen(fd, 1) == 0);
    ret = pthread_create(&pt, NULL, netsock_test_nonblocking_connect_thread,
        (void *)(long)port);
    test_assert(ret == 0);

    /* Wait for client to connect and return. */
    conn_fd = accept(fd, NULL, NULL);
    test_assert(conn_fd > 0);
    test_assert(pthread_join(pt, &thread_ret) == 0);
    if (thread_ret != EXIT_SUCCESS)
        exit((long)thread_ret);
    test_assert(close(fd) == 0);
}

static void *netsock_test_peek_thread(void *arg)
{
    int port = (long)arg;
    int fd;
    struct sockaddr_in addr;
    uint8_t buf[NETSOCK_TEST_PEEK_COUNT];

    fd = socket(AF_INET, SOCK_STREAM, 0);
    test_assert(fd > 0);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    test_assert(connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    for (int i = 0; i < sizeof(buf); i++)
        buf[i] = i;
    test_assert(write(fd, buf, sizeof(buf)) == sizeof(buf));
    return (void *)(long)fd;
}

static void netsock_test_peek(void)
{
    int fd, conn_fd;
    struct sockaddr_in addr;
    const int port = 1236;
    pthread_t pt;
    void *thread_ret;
    uint8_t buf[NETSOCK_TEST_PEEK_COUNT];

    fd = socket(AF_INET, SOCK_STREAM, 0);
    test_assert(fd > 0);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    test_assert(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    test_assert(listen(fd, 1) == 0);
    test_assert(pthread_create(&pt, NULL, netsock_test_peek_thread, (void *)(long)port) == 0);

    /* Wait for client to connect. */
    conn_fd = accept(fd, NULL, NULL);
    test_assert(conn_fd > 0);

    /* Wait for client to send data. */
    test_assert(pthread_join(pt, &thread_ret) == 0);

    /* Read client data twice, the first time without removing it from the socket incoming data. */
    test_assert(recv(conn_fd, buf, sizeof(buf), MSG_PEEK) == sizeof(buf));
    for (int i = 0; i < sizeof(buf); i++)
        test_assert(buf[i] == i);
    memset(buf, 0, sizeof(buf));
    test_assert(read(conn_fd, buf, sizeof(buf)) == sizeof(buf));
    for (int i = 0; i < sizeof(buf); i++)
        test_assert(buf[i] == i);

    test_assert(close((long)thread_ret) == 0);  /* TCP client socket */
    test_assert(close(conn_fd) == 0);
    test_assert(close(fd) == 0);
}

static void netsock_test_rcvbuf(void)
{
    int tx_fd, rx_fd;
    struct sockaddr_in addr;
    int rcvbuf;
    socklen_t optval;
    uint8_t pkt[KB];
    const int xfer_size = 80 * KB;
    const int pkt_count = xfer_size / sizeof(pkt);
    int rx_avail, rx_count;

    tx_fd = socket(AF_INET, SOCK_DGRAM, 0);
    test_assert(tx_fd > 0);
    rx_fd = socket(AF_INET, SOCK_DGRAM, 0);
    test_assert(rx_fd > 0);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(1234);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    test_assert(bind(rx_fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    optval = sizeof(rcvbuf);
    test_assert(getsockopt(rx_fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, &optval) == 0);
    test_assert((optval == sizeof(rcvbuf)) && (rcvbuf > 0));
    test_assert(connect(tx_fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    for (int i = 0; i < pkt_count; i++)
        test_assert(send(tx_fd, pkt, sizeof(pkt), 0) == sizeof(pkt));
    rx_count = 0;
    do {
        test_assert(recv(rx_fd, pkt, sizeof(pkt), 0) == sizeof(pkt));
        rx_count += sizeof(pkt);
        test_assert(ioctl(rx_fd, FIONREAD, &rx_avail) == 0);
    } while (rx_avail > 0);
    test_assert(rx_count == MIN(xfer_size, rcvbuf));
    test_assert((close(tx_fd) == 0) && (close(rx_fd) == 0));
}

static void netsock_test_netconf(void)
{
    /* SIOC?IF* ioctls aren't netsock-specific - in fact, netdevice(7)
       declares that they may be performed on any socket "regardless of the
       family or type" (and we'll use AF_UNIX here just to test this
       assertion) - but here is as good a place as any to stash tests for
       them. */
    struct ifreq ifr;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    test_assert(fd > 0);
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_ifindex = 1;
    test_assert(ioctl(fd, SIOCGIFNAME, &ifr) == 0);
    test_assert(ioctl(fd, SIOCGIFHWADDR, &ifr) == 0);
    close(fd);
}

static int iov_compare(struct iovec *iov1, unsigned int len1,
                        struct iovec *iov2, unsigned int len2, unsigned int total_len)
{
    unsigned int offset = 0;
    unsigned int index1 = 0, index2 = 0;
    unsigned int offset1 = 0, offset2 = 0;

    while ((offset < total_len) && (index1 < len1) && (index2 < len2)) {
        unsigned int l = MIN(iov1[index1].iov_len - offset1, iov2[index2].iov_len - offset2);
        int cmp = memcmp(iov1[index1].iov_base + offset1, iov2[index2].iov_base + offset2, l);

        if (cmp)
            return cmp;
        offset += l;
        offset1 += l;
        if (offset1 == iov1[index1].iov_len) {
            index1++;
            offset1 = 0;
        }
        offset2 += l;
        if (offset2 == iov2[index2].iov_len) {
            index2++;
            offset2 = 0;
        }
    }
    if (offset == total_len)
        return 0;
    else if (index1 == len1)
        return -1;
    else
        return 1;
}

static void netsock_test_msg(int sock_type)
{
    int listen_fd = -1, tx_fd, rx_fd;
    struct sockaddr_in addr;
    struct iovec iov1[2], iov2[2], iov3[2], iov4[2];
    struct msghdr msg1, msg2;
    struct mmsghdr mmsg1[2], mmsg2[2];
    int total_len;
    char tx_buf[4 * KB], rx_buf[4 * KB];

    tx_fd = socket(AF_INET, sock_type, 0);
    test_assert(tx_fd > 0);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(1236);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (sock_type == SOCK_STREAM) {
        listen_fd = socket(AF_INET, sock_type, 0);
        test_assert(listen_fd > 0);
        test_assert(bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
        test_assert(listen(listen_fd, 1) == 0);
    } else {
        rx_fd = socket(AF_INET, sock_type, 0);
        test_assert(rx_fd > 0);
        test_assert(bind(rx_fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    }
    test_assert(connect(tx_fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    if (sock_type == SOCK_STREAM) {
        rx_fd = accept(listen_fd, NULL, NULL);
        test_assert(rx_fd > 0);
    }

    memset(&msg1, 0, sizeof(msg1));
    iov1[0].iov_base = "abc";
    iov1[0].iov_len = 3;
    iov1[1].iov_base = "de";
    iov1[1].iov_len = 2;
    msg1.msg_iov = iov1;
    msg1.msg_iovlen = 2;
    total_len = iov1[0].iov_len + iov1[1].iov_len;
    test_assert(sendmsg(tx_fd, &msg1, 0) == total_len);

    memset(&msg2, 0, sizeof(msg2));
    iov2[0].iov_base = rx_buf;
    iov2[0].iov_len = 2;
    iov2[1].iov_base = rx_buf + sizeof(rx_buf) / 2;
    iov2[1].iov_len = sizeof(rx_buf) / 2;
    msg2.msg_iov = iov2;
    msg2.msg_iovlen = 2;
    test_assert((recvmsg(rx_fd, &msg2, 0) == total_len) && (msg2.msg_flags == 0));
    test_assert(!iov_compare(iov1, 2, iov2, 2, total_len));

    test_assert(sendmmsg(tx_fd, mmsg1, 0, 0) == 0); /* dummy sendmmsg() */
    test_assert(recvmmsg(rx_fd, mmsg2, 0, 0, NULL) == 0);   /* dummy recvmmsg() */

    if (sock_type == SOCK_DGRAM) {
        /* test reception of truncated messages */
        test_assert(sendmsg(tx_fd, &msg1, 0) == total_len);
        test_assert(sendmsg(tx_fd, &msg1, 0) == total_len);
        msg2.msg_iovlen = 1;
        test_assert(recvmsg(rx_fd, &msg2, 0) == msg2.msg_iov[0].iov_len);
        test_assert(msg2.msg_flags == MSG_TRUNC);
        test_assert(recvmsg(rx_fd, &msg2, MSG_TRUNC) == total_len);
        test_assert(msg2.msg_flags == MSG_TRUNC);
    }

    memset(&mmsg1, 0, sizeof(mmsg1));
    iov1[0].iov_base = tx_buf;
    iov1[0].iov_len = 4;
    iov1[1].iov_base = tx_buf + 4;
    iov1[1].iov_len = sizeof(tx_buf) / 2 - 4;
    mmsg1[0].msg_hdr.msg_iov = iov1;
    mmsg1[0].msg_hdr.msg_iovlen = 2;
    iov2[0].iov_base = tx_buf + sizeof(tx_buf) / 2;
    iov2[0].iov_len = 6;
    iov2[1].iov_base = tx_buf + sizeof(tx_buf) / 2 + 6;
    iov2[1].iov_len = sizeof(tx_buf) / 2 - 6;
    mmsg1[1].msg_hdr.msg_iov = iov2;
    mmsg1[1].msg_hdr.msg_iovlen = 2;
    test_assert(sendmmsg(tx_fd, mmsg1, 2, 0) == 2);
    test_assert(mmsg1[0].msg_len == iov1[0].iov_len + iov1[1].iov_len);
    test_assert(mmsg1[1].msg_len == iov2[0].iov_len + iov2[1].iov_len);
    total_len = mmsg1[0].msg_len + mmsg1[1].msg_len;

    if (sock_type == SOCK_STREAM) {
        /* test a dummy recvmsg(), which should not consume any data available in the socket */
        msg2.msg_iovlen = 0;
        test_assert(recvmsg(rx_fd, &msg2, 0) == 0);
    }

    memset(&mmsg2, 0, sizeof(mmsg2));
    iov3[0].iov_base = rx_buf;
    iov3[0].iov_len = 1;
    iov3[1].iov_base = rx_buf + 1;
    iov3[1].iov_len = sizeof(rx_buf) / 2 - 1;
    mmsg2[0].msg_hdr.msg_iov = iov3;
    mmsg2[0].msg_hdr.msg_iovlen = 2;
    iov4[0].iov_base = rx_buf + sizeof(rx_buf) / 2;
    iov4[0].iov_len = 9;
    iov4[1].iov_base = rx_buf + sizeof(rx_buf) / 2 + 9;
    iov4[1].iov_len = sizeof(rx_buf) / 2 - 9;
    mmsg2[1].msg_hdr.msg_iov = iov4;
    mmsg2[1].msg_hdr.msg_iovlen = 2;
    test_assert(recvmmsg(rx_fd, mmsg2, 2, 0, NULL) == 2);
    test_assert(mmsg2[0].msg_len == iov3[0].iov_len + iov3[1].iov_len);
    test_assert(!iov_compare(iov1, 2, iov3, 2, mmsg2[0].msg_len));
    test_assert(mmsg2[1].msg_len == iov4[0].iov_len + iov4[1].iov_len);
    test_assert(!iov_compare(iov2, 2, iov4, 2, mmsg2[1].msg_len));
    test_assert(mmsg2[0].msg_len + mmsg2[1].msg_len == total_len);

    test_assert(sendmmsg(tx_fd, mmsg1, 1, 0) == 1);
    test_assert(recvmmsg(rx_fd, mmsg2, 2, MSG_WAITFORONE, NULL) == 1);

    test_assert((close(tx_fd) == 0) && (close(rx_fd) == 0));
    if (sock_type == SOCK_STREAM)
        test_assert(close(listen_fd) == 0);
}

static void *netsock_test_fault_udp_thread(void *arg)
{
    int fd;
    struct sockaddr_in addr;
    u8 buf[8];

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    test_assert(fd > 0);
    test_assert(connect(fd, (struct sockaddr *)FAULT_ADDR, sizeof(addr)) == -1);
    test_assert(errno == EFAULT);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(NETSOCK_TEST_FAULT_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    test_assert(connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    usleep(1000 * 10);  /* wait for the main thread to block */
    test_assert(munmap(arg, PAGESIZE) == 0);
    test_assert(write(fd, buf, sizeof(buf)) == sizeof(buf));
    close(fd);
    return NULL;
}

static int netsock_test_fault_udp_setup(pthread_t *pt, void **fault_addr)
{
    int fd;
    struct sockaddr_in addr;

    *fault_addr = mmap(0, PAGESIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    test_assert(*fault_addr != MAP_FAILED);
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    test_assert(fd > 0);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(NETSOCK_TEST_FAULT_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    test_assert((bind(fd, (struct sockaddr *)FAULT_ADDR, sizeof(addr)) == -1) && (errno == EFAULT));
    test_assert(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    test_assert(pthread_create(pt, NULL, netsock_test_fault_udp_thread, *fault_addr) == 0);
    return fd;
}

static void *netsock_test_fault_tcp_thread(void *arg)
{
    int fd;
    struct sockaddr_in addr;

    fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    test_assert(fd > 0);
    usleep(1000 * 10);  /* wait for the main thread to block */
    test_assert(munmap(arg, PAGESIZE) == 0);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(NETSOCK_TEST_FAULT_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    close(fd);
    return NULL;
}

static void netsock_test_fault(void)
{
    int fd;
    void *fault_addr;
    u8 buf[KB];
    struct iovec iov;
    struct msghdr *msg;
    struct mmsghdr *mmsg;
    struct sockaddr_in addr;
    socklen_t len;
    pthread_t pt;
    struct ifconf ifconf;

    /* recvmsg()/sendmsg() with faulting struct msghdr */
    fd = netsock_test_fault_udp_setup(&pt, &fault_addr);
    iov.iov_base = buf;
    iov.iov_len = sizeof(buf);
    msg = fault_addr;
    memset(msg, 0, sizeof(*msg));
    msg->msg_iov = &iov;
    msg->msg_iovlen = 1;
    test_assert((recvmsg(fd, msg, 0) == -1) && (errno == EFAULT));
    test_assert(pthread_join(pt, NULL) == 0);
    test_assert((sendmsg(fd, msg, 0) == -1) && (errno == EFAULT));
    close(fd);

    /* recvmmsg()/sendmmsg() with faulting struct mmsghdr */
    fd = netsock_test_fault_udp_setup(&pt, &fault_addr);
    mmsg = fault_addr;
    mmsg->msg_hdr.msg_iov = &iov;
    mmsg->msg_hdr.msg_iovlen = 1;
    test_assert((recvmmsg(fd, mmsg, 1, 0, NULL) == -1) && (errno == EFAULT));
    test_assert(pthread_join(pt, NULL) == 0);
    test_assert((sendmmsg(fd, mmsg, 1, 0) == -1) && (errno == EFAULT));
    close(fd);

    /* read() with faulting buffer */
    fd = netsock_test_fault_udp_setup(&pt, &fault_addr);
    test_assert((read(fd, fault_addr, PAGESIZE) == -1) && (errno == EFAULT));
    test_assert(pthread_join(pt, NULL) == 0);
    close(fd);

    /* recvfrom()/sendto() with faulting address */
    fd = netsock_test_fault_udp_setup(&pt, &fault_addr);
    len = sizeof(addr);
    test_assert((recvfrom(fd, buf, sizeof(buf), 0, fault_addr, &len) == -1) && (errno == EFAULT));
    test_assert(pthread_join(pt, NULL) == 0);
    test_assert(sendto(fd, buf, sizeof(buf), 0, fault_addr, sizeof(addr)) == -1);
    test_assert(errno == EFAULT);
    close(fd);

    /* recvfrom() with faulting address length */
    fd = netsock_test_fault_udp_setup(&pt, &fault_addr);
    *(socklen_t *)fault_addr = sizeof(addr);
    test_assert((recvfrom(fd, buf, sizeof(buf), 0, &addr, fault_addr) == -1) && (errno == EFAULT));
    test_assert(pthread_join(pt, NULL) == 0);

    test_assert((ioctl(fd, SIOCGIFCONF, fault_addr) == -1) && (errno == EFAULT));
    ifconf.ifc_len = sizeof(struct ifreq);
    ifconf.ifc_req = fault_addr;
    test_assert((ioctl(fd, SIOCGIFCONF, &ifconf) == -1) && (errno == EFAULT));
    test_assert((ioctl(fd, SIOCGIFNAME, fault_addr) == -1) && (errno == EFAULT));
    test_assert((ioctl(fd, SIOCGIFFLAGS, fault_addr) == -1) && (errno == EFAULT));
    test_assert((ioctl(fd, SIOCSIFFLAGS, fault_addr) == -1) && (errno == EFAULT));
    test_assert((ioctl(fd, SIOCGIFADDR, fault_addr) == -1) && (errno == EFAULT));
    test_assert((ioctl(fd, SIOCSIFADDR, fault_addr) == -1) && (errno == EFAULT));
    test_assert((ioctl(fd, SIOCGIFNETMASK, fault_addr) == -1) && (errno == EFAULT));
    test_assert((ioctl(fd, SIOCSIFNETMASK, fault_addr) == -1) && (errno == EFAULT));
    test_assert((ioctl(fd, SIOCGIFMTU, fault_addr) == -1) && (errno == EFAULT));
    test_assert((ioctl(fd, SIOCSIFMTU, fault_addr) == -1) && (errno == EFAULT));
    test_assert((ioctl(fd, SIOCGIFINDEX, fault_addr) == -1) && (errno == EFAULT));
    test_assert((ioctl(fd, FIONREAD, fault_addr) == -1) && (errno == EFAULT));
    len = sizeof(addr);
    test_assert((getsockname(fd, fault_addr, &len) == -1) && (errno == EFAULT));
    test_assert((getsockname(fd, &addr, fault_addr) == -1) && (errno == EFAULT));
    test_assert(setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, fault_addr, sizeof(int)) == -1);
    test_assert(errno == EFAULT);
    len = sizeof(int);
    test_assert((getsockopt(fd, SOL_SOCKET, SO_TYPE, fault_addr, &len) == -1) && (errno == EFAULT));

    close(fd);

    /* accept() with faulting address */
    fault_addr = mmap(0, PAGESIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    test_assert(fault_addr != MAP_FAILED);
    fd = socket(AF_INET, SOCK_STREAM, 0);
    test_assert(fd > 0);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(NETSOCK_TEST_FAULT_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    test_assert(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    test_assert(listen(fd, 1) == 0);
    test_assert(pthread_create(&pt, NULL, netsock_test_fault_tcp_thread, fault_addr) == 0);
    len = sizeof(addr);
    test_assert((accept(fd, fault_addr, &len) == -1) && (errno == EFAULT));
    test_assert(pthread_join(pt, NULL) == 0);
    close(fd);
}

int main(int argc, char **argv)
{
    netsock_test_basic(SOCK_STREAM);
    netsock_test_basic(SOCK_DGRAM);
    netsock_test_fionread();
    netsock_test_connclosed();
    netsock_test_udpshutdown();
    netsock_test_nonblocking_connect();
    netsock_test_peek();
    netsock_test_rcvbuf();
    netsock_test_netconf();
    netsock_test_msg(SOCK_STREAM);
    netsock_test_msg(SOCK_DGRAM);
    netsock_test_fault();
    printf("Network socket tests OK\n");
    return EXIT_SUCCESS;
}
