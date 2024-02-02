#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <semaphore.h>

#include "../test_utils.h"

#define CLIENT_SOCKET_PATH "client_socket"
#define SERVER_SOCKET_PATH "server_socket"

#define SMALLBUF_SIZE    8
#define LARGEBUF_SIZE    8192
#define IOV_LEN          8
#define CLIENT_COUNT     8
#define DGRAM_COUNT      128

static void test_getsockopt(int fd, int type)
{
    int opt;
    socklen_t optlen = sizeof(int);
    test_assert(getsockopt(fd, SOL_SOCKET, SO_TYPE, &opt, &optlen) == 0);
    test_assert(opt == type);
}

static void *uds_stream_server(void *arg)
{
    int fd = (long) arg;
    struct sockaddr_un addr;
    socklen_t addr_len = sizeof(addr);
    int client_fd;
    uint8_t readBuf[LARGEBUF_SIZE];
    struct iovec iov[IOV_LEN];
    struct msghdr msg;
    ssize_t nbytes, total;

    /* on linux, generates SIGPIPE */
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

    for (int i = 0; i < IOV_LEN; i++) {
        iov[i].iov_base = &readBuf[i * LARGEBUF_SIZE / IOV_LEN];
        iov[i].iov_len = LARGEBUF_SIZE / IOV_LEN;
    }
    memset(&msg, 0, sizeof(msg));
    for (int i = 0; i < IOV_LEN; i += 2) {
        msg.msg_iov = iov + i;
        msg.msg_iovlen = 0;
        test_assert(recvmsg(client_fd, &msg, 0) == 0);
        msg.msg_iovlen = 2;
        test_assert(recvmsg(client_fd, &msg, 0) == LARGEBUF_SIZE * 2 / IOV_LEN);
    }
    for (int i = 0; i < IOV_LEN; i++)
        for (int j = 0; j < iov[i].iov_len; j++)
            test_assert(*((uint8_t *)(iov[i].iov_base) + j) == (i & 0xFF));

    usleep(100 * 1000); /* to make the sender block */
    test_assert(close(client_fd) == 0);
    return NULL;
}

/* Closes server socket after a delay. */
static void *uds_stream_dummy_server(void *arg)
{
    int fd = (long) arg;

    usleep(100 * 1000); /* to make the client thread block */
    test_assert(close(fd) == 0);
    return NULL;
}

/* Closes server socket after accepting a connection. */
static void *uds_stream_closing_server(void *arg)
{
    int fd = (long) arg;
    int client_fd = accept(fd, NULL, 0);

    test_assert(client_fd >= 0);
    usleep(100 * 1000); /* to make the client thread block */
    test_assert(close(client_fd) == 0);
    test_assert(close(fd) == 0);
    return NULL;
}

static void uds_stream_test(void)
{
    int s1, s2;
    int s3[CLIENT_COUNT];
    struct sockaddr_un addr;
    socklen_t addr_len = sizeof(addr);
    struct sockaddr_un ret_addr;
    struct stat s;
    pthread_t pt;
    uint8_t writeBuf[LARGEBUF_SIZE];
    struct iovec iov[IOV_LEN];
    struct msghdr msg;
    ssize_t nbytes, total;
    struct pollfd fds;

    s1 = socket(AF_UNIX, SOCK_STREAM, 0);
    test_assert(s1 >= 0);

    addr.sun_family = AF_UNIX + 1;
    test_assert((bind(s1, (struct sockaddr *) &addr, addr_len) == -1) && (errno == EINVAL));
    addr.sun_family = AF_UNIX;

    test_getsockopt(s1, SOCK_STREAM);
    test_assert((bind(s1, NULL, addr_len) == -1) && (errno == EFAULT));
    test_assert(bind(s1, (struct sockaddr *) &addr, 0) == -1);
    test_assert(errno == EINVAL);

    strcpy(addr.sun_path, "/nonexistent/socket");
    test_assert(bind(s1, (struct sockaddr *) &addr, addr_len) == -1);
    test_assert(errno == ENOENT);
    test_assert(connect(s1, (struct sockaddr *) &addr, addr_len) == -1);
    test_assert(errno == ENOENT);

    strcpy(addr.sun_path, "unixsocket");
    test_assert(bind(s1, (struct sockaddr *) &addr, addr_len) == -1);
    test_assert(errno == EADDRINUSE);
    test_assert(connect(s1, (struct sockaddr *) &addr, addr_len) == -1);
    test_assert(errno == ECONNREFUSED);

    strcpy(addr.sun_path, SERVER_SOCKET_PATH);
    test_assert(bind(s1, (struct sockaddr *) &addr, addr_len) == 0);
    test_assert(stat(SERVER_SOCKET_PATH, &s) == 0);
    test_assert((s.st_mode & S_IFMT) == S_IFSOCK);
    test_assert(getsockname(s1, (struct sockaddr *) &ret_addr, &addr_len) == 0);
    test_assert(addr_len == offsetof(struct sockaddr_un, sun_path) + sizeof(SERVER_SOCKET_PATH));
    test_assert(!strcmp(addr.sun_path, ret_addr.sun_path));
    test_assert(bind(s1, (struct sockaddr *) &addr, addr_len) == -1);
    test_assert(errno == EADDRINUSE);

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

    test_assert(sendto(s2, writeBuf, sizeof(writeBuf), 0, (struct sockaddr *)&addr,
        addr_len) == -1);
    test_assert(errno == EOPNOTSUPP);
    test_assert((send(s2, writeBuf, sizeof(writeBuf), 0) == -1) && (errno == ENOTCONN));

    test_assert(connect(s2, (struct sockaddr *) &addr, addr_len) == 0);
    test_assert(connect(s2, (struct sockaddr *) &addr, addr_len) == -1);
    test_assert(errno == EISCONN);

    fds.fd = s2;
    fds.events = POLLIN | POLLOUT | POLLHUP;
    test_assert((poll(&fds, 1, -1) == 1) && (fds.revents == POLLOUT));

    test_assert(sendto(s2, writeBuf, sizeof(writeBuf), 0, (struct sockaddr *)&addr,
        addr_len) == -1);
    test_assert(errno == EISCONN);
    test_assert(send(s2, writeBuf, 0, 0) == 0);

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

    for (int i = 0; i < IOV_LEN; i++) {
        iov[i].iov_base = &writeBuf[i * LARGEBUF_SIZE / IOV_LEN];
        iov[i].iov_len = LARGEBUF_SIZE / IOV_LEN;
        memset(iov[i].iov_base, i & 0xFF, iov[i].iov_len);
    }
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = iov;
    msg.msg_iovlen = 0;
    test_assert(sendmsg(s2, &msg, 0) == 0);
    msg.msg_iovlen = IOV_LEN;
    test_assert(sendmsg(s2, &msg, 0) == LARGEBUF_SIZE);

    /* Close receiving socket (in the server thread) during blocking send. */
    while (1) {
        nbytes = send(s2, writeBuf, 1, 0);
        if (nbytes != 1) {
            test_assert(nbytes == -1);
            break;
        }
    }

    test_assert(pthread_join(pt, NULL) == 0);

    test_assert((poll(&fds, 1, -1) == 1) && (fds.revents & POLLHUP));
    test_assert(recv(s2, writeBuf, 1, 0) == 0);
    /* on linux, this generates SIGPIPE instead of returning */
    test_assert((send(s2, writeBuf, 1, 0) == -1) && (errno == EPIPE));

    test_assert(close(s1) == 0);
    test_assert(connect(s2, (struct sockaddr *) &addr, addr_len) == -1);
    test_assert(errno == ECONNREFUSED);

    test_assert(close(s2) == 0);
    test_assert(unlink(SERVER_SOCKET_PATH) == 0);

    s1 = socket(AF_UNIX, SOCK_STREAM, 0);
    test_assert(s1 >= 0);
    test_assert(bind(s1, (struct sockaddr *) &addr, addr_len) == 0);
    test_assert(listen(s1, 1) == 0);

    /* Try to connect a datagram socket to a stream socket. */
    s2 = socket(AF_UNIX, SOCK_DGRAM, 0);
    test_assert(s2 >= 0);
    test_assert(connect(s2, (struct sockaddr *) &addr, addr_len) == -1);
    test_assert(errno == EPROTOTYPE);
    test_assert(close(s2) == 0);

    /* Close listening socket while client sockets are connecting. */
    test_assert(pthread_create(&pt, NULL, uds_stream_dummy_server, (void *)(long) s1) == 0);
    for (int i = 0; i < CLIENT_COUNT; i++) {
        s3[i] = socket(AF_UNIX, SOCK_STREAM, 0);
        test_assert(s3[i] >= 0);
        if (connect(s3[i], (struct sockaddr *) &addr, addr_len) < 0)
            test_assert(errno == ECONNREFUSED);
    }
    for (int i = 0; i < CLIENT_COUNT; i++)
        test_assert(close(s3[i]) == 0);
    test_assert(pthread_join(pt, NULL) == 0);
    test_assert(unlink(SERVER_SOCKET_PATH) == 0);

    /* Close peer socket (in the server thread) during blocking read. */
    s1 = socket(AF_UNIX, SOCK_STREAM, 0);
    test_assert(s1 >= 0);
    test_assert(bind(s1, (struct sockaddr *)&addr, addr_len) == 0);
    test_assert(listen(s1, 1) == 0);
    s2 = socket(AF_UNIX, SOCK_STREAM, 0);
    test_assert(s2 >= 0);
    test_assert(pthread_create(&pt, NULL, uds_stream_closing_server, (void *)(long)s1) == 0);
    test_assert(connect(s2, (struct sockaddr *)&addr, addr_len) == 0);
    test_assert(read(s2, writeBuf, 1) == 0);
    test_assert(pthread_join(pt, NULL) == 0);
    close(s2);
    test_assert(unlink(SERVER_SOCKET_PATH) == 0);
}

static void *uds_dgram_server(void *arg)
{
    int fd = (long) arg;
    struct sockaddr_un addr;
    socklen_t addr_len = sizeof(addr);
    uint8_t readBuf[SMALLBUF_SIZE];

    test_assert(recv(fd, readBuf, SMALLBUF_SIZE, 0) == 1);

    test_assert(recvfrom(fd, readBuf, SMALLBUF_SIZE / 2, 0, (struct sockaddr *)&addr, &addr_len) ==
            SMALLBUF_SIZE / 2);
    test_assert(addr_len > sizeof(addr.sun_family));
    test_assert(addr_len <= sizeof(addr));
    test_assert(addr.sun_family == AF_UNIX);
    test_assert(!strcmp(addr.sun_path, CLIENT_SOCKET_PATH));

    for (int i = 0; i < SMALLBUF_SIZE / 2; i++) {
        test_assert(readBuf[i] == i);
    }
    test_assert(recv(fd, readBuf, SMALLBUF_SIZE, 0) == 1);
    test_assert(readBuf[0] == 0);

    /* zero-length datagram */
    test_assert(recv(fd, readBuf, SMALLBUF_SIZE, 0) == 0);

    for (int i = 0; i < 2; i++) {
        usleep(100 * 1000); /* to make the sender block */
        for (int j = 0; j < DGRAM_COUNT; j++)
            test_assert(recv(fd, readBuf, SMALLBUF_SIZE, 0) == SMALLBUF_SIZE);
    }

    return NULL;
}

static void uds_dgram_test(void)
{
    int s1, s2;
    struct sockaddr_un client_addr, server_addr;
    socklen_t addr_len = sizeof(struct sockaddr_un);
    pthread_t pt;
    uint8_t writeBuf[SMALLBUF_SIZE];
    int i;
    struct pollfd fds;

    s1 = socket(AF_UNIX, SOCK_DGRAM, 0);
    test_assert(s1 >= 0);
    test_getsockopt(s1, SOCK_DGRAM);
    client_addr.sun_family = server_addr.sun_family = AF_UNIX;
    strcpy(client_addr.sun_path, CLIENT_SOCKET_PATH);
    strcpy(server_addr.sun_path, SERVER_SOCKET_PATH);
    test_assert(bind(s1, (struct sockaddr *) &server_addr, addr_len) == 0);
    test_assert(listen(s1, 1) == -1 && errno == EOPNOTSUPP);
    test_assert(accept(s1, (struct sockaddr *) &server_addr, &addr_len) == -1);
    test_assert(errno == EOPNOTSUPP);

    /* Try to connect a STREAM socket to a DGRAM socket. */
    s2 = socket(AF_UNIX, SOCK_STREAM, 0);
    test_assert(s2 >= 0);
    test_assert(connect(s2, (struct sockaddr *) &server_addr, addr_len) == -1);
    test_assert(errno == EPROTOTYPE);
    test_assert(close(s2) == 0);

    s2 = socket(AF_UNIX, SOCK_DGRAM, 0);
    test_assert(s2 >= 0);
    test_assert(bind(s2, (struct sockaddr *) &client_addr, addr_len) == 0);

    test_assert(pthread_create(&pt, NULL, uds_dgram_server, (void *)(long) s1)
            == 0);
    fds.fd = s2;
    fds.events = POLLIN | POLLOUT | POLLHUP;
    test_assert((poll(&fds, 1, -1) == 1) && (fds.revents == POLLOUT));
    test_assert((send(s2, writeBuf, sizeof(writeBuf), 0) == -1) && (errno == ENOTCONN));
    test_assert(sendto(s2, writeBuf, 1, 0, (struct sockaddr *)&server_addr, addr_len) == 1);
    test_assert(connect(s2, (struct sockaddr *) &server_addr, addr_len) == 0);
    for (int i = 0; i < SMALLBUF_SIZE; i++) {
        writeBuf[i] = i;
    }
    test_assert(send(s2, writeBuf, SMALLBUF_SIZE, 0) == SMALLBUF_SIZE);
    test_assert(send(s2, writeBuf, 1, 0) == 1);

    /* zero-length datagram */
    test_assert(send(s2, writeBuf, 0, 0) == 0);

    /* wakeup after blocking send */
    for (i = 0; i < DGRAM_COUNT; i++)
        test_assert(send(s2, writeBuf, SMALLBUF_SIZE, 0) == SMALLBUF_SIZE);

    /* poll after non-blocking send */
    test_assert(fcntl(s2, F_SETFL, fcntl(s2, F_GETFL) | O_NONBLOCK) == 0);
    for (i = 0; i < DGRAM_COUNT; i++) {
        if (send(s2, writeBuf, SMALLBUF_SIZE, 0) != SMALLBUF_SIZE) {
            test_assert(errno == EAGAIN);
            test_assert((poll(&fds, 1, -1) == 1) && (fds.revents == POLLOUT));
            test_assert(send(s2, writeBuf, SMALLBUF_SIZE, 0) == SMALLBUF_SIZE);
        }
    }

    /* Connect to the same address as already connected (should be a no-op). */
    test_assert(connect(s2, (struct sockaddr *)&server_addr, addr_len) == 0);

    test_assert(pthread_join(pt, NULL) == 0);
    test_assert(close(s1) == 0);
    test_assert((poll(&fds, 1, -1) == 1) && (fds.revents == POLLOUT));
    test_assert((send(s2, writeBuf, 1, 0) == -1) && (errno == ECONNREFUSED));
    test_assert(close(s2) == 0);
    test_assert(unlink(SERVER_SOCKET_PATH) == 0);
    test_assert(unlink(CLIENT_SOCKET_PATH) == 0);
}

static void *uds_seqpacket_server(void *arg)
{
    int fd = (long) arg;
    struct sockaddr_un addr;
    socklen_t addr_len = sizeof(addr);
    int client_fd;
    uint8_t readBuf[SMALLBUF_SIZE];

    client_fd = accept(fd, (struct sockaddr *) &addr, &addr_len);
    test_assert(client_fd >= 0);
    test_assert(addr_len == sizeof(addr.sun_family));
    test_assert(addr.sun_family == AF_UNIX);

    test_assert(recv(client_fd, readBuf, SMALLBUF_SIZE / 2, 0) == SMALLBUF_SIZE / 2);
    for (int i = 0; i < SMALLBUF_SIZE / 2; i++) {
        test_assert(readBuf[i] == i);
    }
    test_assert(recv(client_fd, readBuf, SMALLBUF_SIZE, 0) == 1);
    test_assert(readBuf[0] == 0);

    /* zero-length packet */
    test_assert(recv(client_fd, readBuf, SMALLBUF_SIZE, 0) == 0);

    usleep(100 * 1000); /* to make the sender block */
    for (int j = 0; j < DGRAM_COUNT; j++)
        test_assert(recv(client_fd, readBuf, SMALLBUF_SIZE, 0) == SMALLBUF_SIZE);

    usleep(100 * 1000); /* to make the sender block */
    test_assert(close(client_fd) == 0);
    return NULL;
}

static void uds_seqpacket_test(void)
{
    int s1, s2;
    struct sockaddr_un addr;
    socklen_t addr_len = sizeof(addr);
    struct sockaddr_un ret_addr;
    struct stat s;
    pthread_t pt;
    uint8_t writeBuf[SMALLBUF_SIZE];
    int i;
    ssize_t nbytes;
    struct pollfd fds;

    s1 = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    test_assert(s1 >= 0);
    addr.sun_family = AF_UNIX;

    test_assert((bind(s1, NULL, addr_len) == -1) && (errno == EFAULT));
    test_assert((bind(s1, (struct sockaddr *) &addr, 0) == -1) && (errno == EINVAL));

    strcpy(addr.sun_path, "/nonexistent/socket");
    test_assert((bind(s1, (struct sockaddr *) &addr, addr_len) == -1) && (errno == ENOENT));
    test_assert((connect(s1, (struct sockaddr *) &addr, addr_len) == -1) && (errno == ENOENT));

    strcpy(addr.sun_path, "unixsocket");
    test_assert((bind(s1, (struct sockaddr *) &addr, addr_len) == -1) && (errno == EADDRINUSE));
    test_assert(connect(s1, (struct sockaddr *) &addr, addr_len) == -1);
    test_assert(errno == ECONNREFUSED);

    strcpy(addr.sun_path, SERVER_SOCKET_PATH);
    test_assert(bind(s1, (struct sockaddr *) &addr, addr_len) == 0);
    test_assert(stat(SERVER_SOCKET_PATH, &s) == 0);
    test_assert((s.st_mode & S_IFMT) == S_IFSOCK);
    test_assert(getsockname(s1, (struct sockaddr *) &ret_addr, &addr_len) == 0);
    test_assert(addr_len == offsetof(struct sockaddr_un, sun_path) + sizeof(SERVER_SOCKET_PATH));
    test_assert(!strcmp(addr.sun_path, ret_addr.sun_path));
    test_assert((bind(s1, (struct sockaddr *) &addr, addr_len) == -1) && (errno == EADDRINUSE));

    /* Try to connect a STREAM socket to a SEQPACKET socket. */
    s2 = socket(AF_UNIX, SOCK_STREAM, 0);
    test_assert(s2 >= 0);
    test_assert((connect(s2, (struct sockaddr *) &addr, addr_len) == -1) && (errno == EPROTOTYPE));
    test_assert(close(s2) == 0);

    s2 = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    test_assert(s2 >= 0);
    test_assert((bind(s2, (struct sockaddr *) &addr, addr_len) == -1) && (errno == EADDRINUSE));
    test_assert(connect(s2, (struct sockaddr *) &addr, addr_len) == -1);
    test_assert(errno == ECONNREFUSED);

    test_assert((accept(s1, (struct sockaddr *) &addr, &addr_len) == -1) && (errno == EINVAL));

    fds.fd = s2;
    fds.events = POLLIN | POLLOUT | POLLHUP;
    test_assert((poll(&fds, 1, -1) == 1) && (fds.revents & POLLHUP));

    test_assert(listen(s1, 1) == 0);
    test_assert(pthread_create(&pt, NULL, uds_seqpacket_server, (void *)(long) s1) == 0);

    test_assert(sendto(s2, writeBuf, sizeof(writeBuf), 0, (struct sockaddr *)&addr,
        addr_len) == -1);
    test_assert(errno == ENOTCONN);
    test_assert((send(s2, writeBuf, sizeof(writeBuf), 0) == -1) && (errno == ENOTCONN));

    test_assert(connect(s2, (struct sockaddr *) &addr, addr_len) == 0);
    test_assert((connect(s2, (struct sockaddr *) &addr, addr_len) == -1) && (errno == EISCONN));

    test_assert((poll(&fds, 1, -1) == 1) && (fds.revents == POLLOUT));

    for (int i = 0; i < SMALLBUF_SIZE; i++) {
        writeBuf[i] = i;
    }
    test_assert(send(s2, writeBuf, SMALLBUF_SIZE, 0) == SMALLBUF_SIZE);
    test_assert(send(s2, writeBuf, 1, 0) == 1);

    /* zero-length packet */
    test_assert(send(s2, writeBuf, 0, 0) == 0);

    /* wakeup after blocking send */
    for (i = 0; i < DGRAM_COUNT; i++)
        test_assert(send(s2, writeBuf, SMALLBUF_SIZE, 0) == SMALLBUF_SIZE);

    /* close receiving socket (in the server thread) during blocking send */
    while (1) {
        nbytes = send(s2, writeBuf, 1, 0);
        if (nbytes != 1) {
            test_assert(nbytes == -1);
            break;
        }
    }

    test_assert(pthread_join(pt, NULL) == 0);

    test_assert((poll(&fds, 1, -1) == 1) && (fds.revents & POLLHUP));
    test_assert(recv(s2, writeBuf, 1, 0) == 0);
    test_assert((send(s2, writeBuf, 1, 0) == -1) && (errno == EPIPE));

    test_assert(close(s1) == 0);
    test_assert(connect(s2, (struct sockaddr *) &addr, addr_len) == -1);
    test_assert(errno == ECONNREFUSED);

    test_assert(close(s2) == 0);
    test_assert(unlink(SERVER_SOCKET_PATH) == 0);
}

static sem_t sem;

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
    sem_wait(&sem);
    test_assert(close(client_fd) == 0);
    return NULL;
}

static void uds_nonblocking_test(void)
{
    int s1, s2;
    int s3[CLIENT_COUNT];
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
    fds.fd = s2;
    fds.events = POLLIN | POLLOUT | POLLHUP;
    test_assert((poll(&fds, 1, -1) == 1) && (fds.revents == (POLLOUT | POLLHUP)));
    int rv = connect(s2, (struct sockaddr *) &addr, addr_len);
    test_assert(rv == 0);
    test_assert(connect(s2, (struct sockaddr *) &addr, addr_len) == -1);
    test_assert(errno == EISCONN);

    test_assert(pthread_create(&pt, NULL, uds_nonblocking_server,
            (void *)(long) s1) == 0);
    test_assert((poll(&fds, 1, -1) == 1) && (fds.revents == POLLOUT));
    sem_post(&sem);
    test_assert(pthread_join(pt, NULL) == 0);
    test_assert((poll(&fds, 1, -1) == 1) && (fds.revents == (POLLIN | POLLOUT | POLLHUP)));
    test_assert(close(s2) == 0);

    s2 = socket(AF_UNIX, SOCK_STREAM, 0);
    test_assert(s2 >= 0);
    test_assert(pthread_create(&pt, NULL, uds_nonblocking_server,
            (void *)(long) s1) == 0);
    usleep(100 * 1000);
    test_assert(connect(s2, (struct sockaddr *) &addr, addr_len) == 0);
    sem_post(&sem);
    test_assert(pthread_join(pt, NULL) == 0);

    /* Try to connect more sockets than the server backlog allows. */
    for (int i = 0; i < CLIENT_COUNT; i++) {
        s3[i] = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
        test_assert(s3[i] >= 0);
        if (connect(s3[i], (struct sockaddr *) &addr, addr_len) < 0)
            test_assert(errno == EAGAIN);
    }
    for (int i = 0; i < CLIENT_COUNT; i++)
        test_assert(close(s3[i]) == 0);

    test_assert(close(s1) == 0);
    fds.fd = s2;
    test_assert((poll(&fds, 1, -1) == 1) && (fds.revents & POLLHUP));
    test_assert(close(s2) == 0);
    test_assert(unlink(SERVER_SOCKET_PATH) == 0);
}

static void *uds_fault_test_thread(void *arg)
{
    int fd;
    struct sockaddr_un addr;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    test_assert(fd >= 0);
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, SERVER_SOCKET_PATH);
    connect(fd, (struct sockaddr *) &addr, sizeof(addr));
    close(fd);
    return NULL;
}

static void uds_fault_test(void)
{
    int s1, s2;
    struct sockaddr_un addr;
    socklen_t len = sizeof(addr);
    uint8_t buf[64];
    void *fault_addr = FAULT_ADDR;
    struct msghdr msg;
    pthread_t pt;

    s1 = socket(AF_UNIX, SOCK_DGRAM, 0);
    test_assert(s1 >= 0);

    test_assert((bind(s1, fault_addr, len) == -1) && (errno == EFAULT));

    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, SERVER_SOCKET_PATH);
    test_assert(bind(s1, (struct sockaddr *) &addr, len) == 0);
    s2 = socket(AF_UNIX, SOCK_DGRAM, 0);
    test_assert(s2 >= 0);

    test_assert((sendto(s2, buf, sizeof(buf), 0, fault_addr, len) == -1) && (errno == EFAULT));

    test_assert((connect(s2, fault_addr, len) == -1) && (errno == EFAULT));
    test_assert(connect(s2, (struct sockaddr *)&addr, len) == 0);

    test_assert((write(s2, fault_addr, 1) == -1) && (errno == EFAULT));

    test_assert(write(s2, buf, sizeof(buf)) == sizeof(buf));
    test_assert((read(s1, fault_addr, 1) == -1) && (errno == EFAULT));

    test_assert(write(s2, buf, sizeof(buf)) == sizeof(buf));
    test_assert((recvmsg(s1, fault_addr, 0) == -1) && (errno == EFAULT));

    msg.msg_iov = fault_addr;
    msg.msg_iovlen = 1;
    msg.msg_namelen = 0;
    msg.msg_controllen = 0;
    test_assert(write(s2, buf, sizeof(buf)) == sizeof(buf));
    test_assert((recvmsg(s1, &msg, 0) == -1) && (errno == EFAULT));

    test_assert(write(s2, buf, sizeof(buf)) == sizeof(buf));
    test_assert(recvfrom(s1, buf, sizeof(buf), 0, (struct sockaddr *)&addr, fault_addr) == -1);
    test_assert(errno == EFAULT);

    test_assert((getsockopt(s1, SOL_SOCKET, SO_TYPE, fault_addr, &len) == -1) && (errno == EFAULT));

    close(s1);
    close(s2);
    unlink(SERVER_SOCKET_PATH);

    s1 = socket(AF_UNIX, SOCK_STREAM, 0);
    test_assert(s1 >= 0);
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, SERVER_SOCKET_PATH);
    test_assert((bind(s1, (struct sockaddr *) &addr, len) == 0) && (listen(s1, 1) == 0));
    test_assert(pthread_create(&pt, NULL, uds_fault_test_thread, NULL) == 0);
    test_assert((accept(s1, fault_addr, &len) == -1) && (errno == EFAULT));
    test_assert(pthread_join(pt, NULL) == 0);

    close(s1);
    unlink(SERVER_SOCKET_PATH);
}

int main(int argc, char **argv)
{
    uds_stream_test();
    uds_dgram_test();
    uds_seqpacket_test();
    uds_nonblocking_test();
    uds_fault_test();
    printf("Unix domain socket tests OK\n");
    return EXIT_SUCCESS;
}
