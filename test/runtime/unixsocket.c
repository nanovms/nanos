#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#define CLIENT_SOCKET_PATH "/client_socket"
#define SERVER_SOCKET_PATH "/server_socket"

#define SMALLBUF_SIZE    8
#define LARGEBUF_SIZE    8192

#define test_assert(expr) do { \
    if (!(expr)) { \
        printf("Error: %s -- failed at %s:%d\n", #expr, __FILE__, __LINE__); \
        exit(EXIT_FAILURE); \
    } \
} while (0)

static void *uds_stream_server(void *arg)
{
    int fd = (long) arg;
    struct sockaddr_un addr;
    socklen_t addr_len = sizeof(addr);
    int client_fd;
    uint8_t readBuf[LARGEBUF_SIZE];
    ssize_t nbytes, total;

    test_assert(accept(fd, (struct sockaddr *) &addr, NULL) == -1);
    test_assert(errno == EFAULT);
    client_fd = accept(fd, (struct sockaddr *) &addr, &addr_len);
    test_assert(client_fd >= 0);
    test_assert(addr_len == sizeof(addr.sun_family));
    test_assert(addr.sun_family == AF_UNIX);
    total = 0;
    do {
        nbytes = recv(client_fd, readBuf + total, LARGEBUF_SIZE - total, 0);
        test_assert(nbytes > 0);
        total += nbytes;
    } while (total < LARGEBUF_SIZE);
    for (int i = 0; i < LARGEBUF_SIZE; i++) {
        test_assert(readBuf[i] == (i & 0xFF));
    }
    for (int i = 0; i < LARGEBUF_SIZE; i++) {
        test_assert(recv(client_fd, readBuf, 1, 0) == 1);
        test_assert(readBuf[0] == (i & 0xFF));
    }
    test_assert(close(client_fd) == 0);
    return NULL;
}

static void uds_stream_test(void)
{
    int s1, s2;
    struct sockaddr_un addr;
    socklen_t addr_len = sizeof(addr);
    struct stat s;
    pthread_t pt;
    uint8_t writeBuf[LARGEBUF_SIZE];
    ssize_t nbytes, total;

    s1 = socket(AF_UNIX, SOCK_STREAM, 0);
    test_assert(s1 >= 0);
    addr.sun_family = AF_UNIX;

    test_assert((bind(s1, NULL, addr_len) == -1) && (errno == EFAULT));
    test_assert(bind(s1, (struct sockaddr *) &addr, 0) == -1);
    test_assert(errno == EINVAL);

    strcpy(addr.sun_path, "/nonexistent/socket");
    test_assert(bind(s1, (struct sockaddr *) &addr, addr_len) == -1);
    test_assert(errno == ENOENT);
    test_assert(connect(s1, (struct sockaddr *) &addr, addr_len) == -1);
    test_assert(errno == ECONNREFUSED);

    strcpy(addr.sun_path, "/unixsocket");
    test_assert(bind(s1, (struct sockaddr *) &addr, addr_len) == -1);
    test_assert(errno == EADDRINUSE);
    test_assert(connect(s1, (struct sockaddr *) &addr, addr_len) == -1);
    test_assert(errno == ECONNREFUSED);

    strcpy(addr.sun_path, SERVER_SOCKET_PATH);
    test_assert(bind(s1, (struct sockaddr *) &addr, addr_len) == 0);
    test_assert(stat(SERVER_SOCKET_PATH, &s) == 0);
    test_assert((s.st_mode & S_IFMT) == S_IFSOCK);
    test_assert((bind(s1, (struct sockaddr *) &addr, addr_len) == -1) &&
            (errno == EINVAL));

    s2 = socket(AF_UNIX, SOCK_STREAM, 0);
    test_assert(s2 >= 0);
    test_assert(bind(s2, (struct sockaddr *) &addr, addr_len) == -1);
    test_assert(errno == EADDRINUSE);
    test_assert(connect(s2, (struct sockaddr *) &addr, addr_len) == -1);
    test_assert(errno == ECONNREFUSED);

    test_assert(accept(s1, (struct sockaddr *) &addr, &addr_len) == -1);
    test_assert(errno == EINVAL);

    test_assert(listen(s1, 1) == 0);
    test_assert(pthread_create(&pt, NULL, uds_stream_server, (void *)(long) s1)
            == 0);

    test_assert(connect(s2, (struct sockaddr *) &addr, addr_len) == 0);
    test_assert(connect(s2, (struct sockaddr *) &addr, addr_len) == -1);
    test_assert(errno == EISCONN);

    for (int i = 0; i < LARGEBUF_SIZE; i++) {
        writeBuf[i] = i;
        test_assert(send(s2, writeBuf + i, 1, 0) == 1);
    }
    total = 0;
    do {
        nbytes = send(s2, writeBuf + total, LARGEBUF_SIZE - total, 0);
        test_assert(nbytes > 0);
        total += nbytes;
    } while (total < LARGEBUF_SIZE);
    test_assert(pthread_join(pt, NULL) == 0);

    test_assert(recv(s2, writeBuf, 1, 0) == 0);
    test_assert((send(s2, writeBuf, 1, 0) == -1) && (errno == EPIPE));

    test_assert(close(s1) == 0);
    test_assert(connect(s2, (struct sockaddr *) &addr, addr_len) == -1);
    test_assert(errno == ECONNREFUSED);

    test_assert(close(s2) == 0);
    test_assert(unlink(SERVER_SOCKET_PATH) == 0);
}

static void *uds_dgram_server(void *arg)
{
    int fd = (long) arg;
    struct sockaddr_un addr;
    socklen_t addr_len = sizeof(addr);
    int client_fd;
    uint8_t readBuf[SMALLBUF_SIZE];

    client_fd = accept(fd, (struct sockaddr *) &addr, &addr_len);
    test_assert(client_fd >= 0);
    test_assert(addr_len > sizeof(addr.sun_family));
    test_assert(addr_len <= sizeof(addr));
    test_assert(addr.sun_family == AF_UNIX);
    test_assert(!strcmp(addr.sun_path, CLIENT_SOCKET_PATH));

    test_assert(recv(client_fd, readBuf, SMALLBUF_SIZE / 2, 0) ==
            SMALLBUF_SIZE / 2);
    for (int i = 0; i < SMALLBUF_SIZE / 2; i++) {
        test_assert(readBuf[i] == i);
    }
    test_assert(recv(client_fd, readBuf, SMALLBUF_SIZE, 0) == 1);
    test_assert(readBuf[0] == 0);

    /* zero-length datagram */
    test_assert(recv(client_fd, readBuf, SMALLBUF_SIZE, 0) == 0);

    test_assert(close(client_fd) == 0);
    return NULL;
}

static void uds_dgram_test(void)
{
    int s1, s2;
    struct sockaddr_un client_addr, server_addr;
    socklen_t addr_len = sizeof(struct sockaddr_un);
    pthread_t pt;
    uint8_t writeBuf[SMALLBUF_SIZE];

    s1 = socket(AF_UNIX, SOCK_DGRAM, 0);
    test_assert(s1 >= 0);
    client_addr.sun_family = server_addr.sun_family = AF_UNIX;
    strcpy(client_addr.sun_path, CLIENT_SOCKET_PATH);
    strcpy(server_addr.sun_path, SERVER_SOCKET_PATH);
    test_assert(bind(s1, (struct sockaddr *) &server_addr, addr_len) == 0);
    test_assert(listen(s1, 1) == 0);

    s2 = socket(AF_UNIX, SOCK_DGRAM, 0);
    test_assert(s2 >= 0);
    test_assert(bind(s2, (struct sockaddr *) &client_addr, addr_len) == 0);

    test_assert(pthread_create(&pt, NULL, uds_dgram_server, (void *)(long) s1)
            == 0);
    test_assert(connect(s2, (struct sockaddr *) &server_addr, addr_len) == 0);
    for (int i = 0; i < SMALLBUF_SIZE; i++) {
        writeBuf[i] = i;
    }
    test_assert(send(s2, writeBuf, SMALLBUF_SIZE, 0) == SMALLBUF_SIZE);
    test_assert(send(s2, writeBuf, 1, 0) == 1);

    /* zero-length datagram */
    test_assert(send(s2, writeBuf, 0, 0) == 0);

    test_assert(pthread_join(pt, NULL) == 0);
    test_assert(close(s1) == 0);
    test_assert(close(s2) == 0);
    test_assert(unlink(SERVER_SOCKET_PATH) == 0);
    test_assert(unlink(CLIENT_SOCKET_PATH) == 0);
}

static void *uds_nonblocking_server(void *arg)
{
    int fd = (long) arg;
    struct sockaddr_un addr;
    socklen_t addr_len = sizeof(addr);
    int client_fd;

    client_fd = accept(fd, (struct sockaddr *) &addr, &addr_len);
    if (client_fd < 0) {
        test_assert(errno == EAGAIN);
        struct pollfd fds;
        fds.fd = fd;
        fds.events = POLLIN | POLLOUT;
        test_assert((poll(&fds, 1, -1) == 1) && (fds.revents == POLLIN));
        client_fd = accept(fd, (struct sockaddr *) &addr, &addr_len);
        test_assert(client_fd >= 0);
    }
    test_assert(addr_len == sizeof(addr.sun_family));
    test_assert(addr.sun_family == AF_UNIX);
    test_assert(close(client_fd) == 0);
    return NULL;
}

static void uds_nonblocking_test(void)
{
    int s1, s2;
    struct sockaddr_un addr;
    socklen_t addr_len = sizeof(addr);
    pthread_t pt;
    struct pollfd fds;

    s1 = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
    test_assert(s1 >= 0);
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, SERVER_SOCKET_PATH);
    test_assert(bind(s1, (struct sockaddr *) &addr, addr_len) == 0);
    test_assert(listen(s1, 1) == 0);

    s2 = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
    test_assert(s2 >= 0);
    test_assert(connect(s2, (struct sockaddr *) &addr, addr_len) == -1);
    test_assert(errno == EINPROGRESS);
    test_assert(connect(s2, (struct sockaddr *) &addr, addr_len) == -1);
    test_assert(errno == EALREADY);

    test_assert(pthread_create(&pt, NULL, uds_nonblocking_server,
            (void *)(long) s1) == 0);
    fds.fd = s2;
    fds.events = POLLIN | POLLOUT;
    test_assert((poll(&fds, 1, -1) == 1) && (fds.revents == POLLOUT));
    test_assert(connect(s2, (struct sockaddr *) &addr, addr_len) == 0);
    test_assert(pthread_join(pt, NULL) == 0);
    test_assert(close(s2) == 0);

    s2 = socket(AF_UNIX, SOCK_STREAM, 0);
    test_assert(s2 >= 0);
    test_assert(pthread_create(&pt, NULL, uds_nonblocking_server,
            (void *)(long) s1) == 0);
    usleep(100 * 1000);
    test_assert(connect(s2, (struct sockaddr *) &addr, addr_len) == 0);
    test_assert(pthread_join(pt, NULL) == 0);

    test_assert(close(s1) == 0);
    fds.fd = s2;
    test_assert((poll(&fds, 1, -1) == 1) && (fds.revents == POLLHUP));
    test_assert(close(s2) == 0);
    test_assert(unlink(SERVER_SOCKET_PATH) == 0);
}

int main(int argc, char **argv)
{
    setbuf(stdout, NULL);
    uds_stream_test();
    uds_dgram_test();
    uds_nonblocking_test();
    printf("Unix domain socket tests OK\n");
    return EXIT_SUCCESS;
}
