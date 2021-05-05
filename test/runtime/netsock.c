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

#define NETSOCK_TEST_FIO_COUNT  8

#define test_assert(expr) do { \
    if (!(expr)) { \
        printf("Error: %s -- failed at %s:%d\n", #expr, __FILE__, __LINE__); \
        exit(EXIT_FAILURE); \
    } \
} while (0)

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

int main(int argc, char **argv)
{
    setbuf(stdout, NULL);

    netsock_test_fionread();
    netsock_test_connclosed();
    netsock_test_nonblocking_connect();
    printf("Network socket tests OK\n");
    return EXIT_SUCCESS;
}
