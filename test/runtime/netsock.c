#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <sys/epoll.h>

#include <runtime.h>

#define NETSOCK_TEST_BASIC_PORT 1233

#define NETSOCK_TEST_FIO_COUNT  8

#define NETSOCK_TEST_PEEK_COUNT 8

#define test_assert(expr) do { \
    if (!(expr)) { \
        printf("Error: %s -- failed at %s:%d\n", #expr, __FILE__, __LINE__); \
        exit(EXIT_FAILURE); \
    } \
} while (0)

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
    return NULL;
}

static void netsock_test_basic(int sock_type)
{
    int fd, tx_fd;
    struct sockaddr_in addr;
    pthread_t pt;
    int ret;
    struct timespec start, end, elapsed;
    const int tx_total = 8 * MB;
    uint8_t tx_buf[32 * KB];
    int tx = 0;
    unsigned long long ns;

    fd = socket(AF_INET, sock_type, 0);
    test_assert(fd > 0);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(NETSOCK_TEST_BASIC_PORT);
    test_assert(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    if (sock_type == SOCK_STREAM) {
        int val;
        socklen_t len = sizeof(val);
        test_assert(getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &val, &len) == 0 && val == 0);
        test_assert(listen(fd, 1) == 0);
        test_assert(listen(fd, 1) == 0);    /* test listen() call on already listening socket */
        test_assert(getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &val, &len) == 0 && val == 1);
        ret = pthread_create(&pt, NULL, netsock_test_basic_thread, (void *)(long)sock_type);
        test_assert(ret == 0);
        tx_fd = accept(fd, NULL, NULL);
        test_assert(tx_fd > 0);
        test_assert(getsockopt(tx_fd, SOL_SOCKET, SO_ACCEPTCONN, &val, &len) == 0 && val == 0);
        test_assert(close(fd) == 0);
    } else {
        tx_fd = fd;
    }
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
    if (sock_type == SOCK_STREAM)
        test_assert(pthread_join(pt, NULL) == 0);
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

int main(int argc, char **argv)
{
    setbuf(stdout, NULL);

    netsock_test_basic(SOCK_STREAM);
    netsock_test_basic(SOCK_DGRAM);
    netsock_test_fionread();
    netsock_test_connclosed();
    netsock_test_nonblocking_connect();
    netsock_test_peek();
    netsock_test_rcvbuf();
    printf("Network socket tests OK\n");
    return EXIT_SUCCESS;
}
