#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <runtime.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define BUF_SIZE    8192

static u8 readBuf[BUF_SIZE], writeBuf[BUF_SIZE];
static volatile int thread_done;

static void basic_test(void)
{
    ssize_t nbytes, total;
    int fd[2];
    void *fault_addr = (void *)0xbadf0000;
    int ret = socketpair(AF_UNIX, SOCK_STREAM, 0, fd);

    if (ret < 0) {
        printf("socketpair basic test: socketpair error %d\n", errno);
        exit(EXIT_FAILURE);
    }
    memset(writeBuf, 0xA5, sizeof(writeBuf));
    total = 0;
    do {
        nbytes = write(fd[0], writeBuf + total, BUF_SIZE - total);
        if (nbytes <= 0) {
            printf("socketpair basic test: write error\n");
            exit(EXIT_FAILURE);
        }
        total += nbytes;
    } while (total < BUF_SIZE);
    total = 0;
    do {
        nbytes = read(fd[1], readBuf + total, BUF_SIZE / 2 - total);
        if (nbytes <= 0) {
            printf("socketpair basic test: read error\n");
            exit(EXIT_FAILURE);
        }
        total += nbytes;
    } while (total < BUF_SIZE / 2);
    if (total != BUF_SIZE / 2) {
        printf("socketpair basic test: read more data than requested\n");
        exit(EXIT_FAILURE);
    }
    do {
        nbytes = read(fd[1], readBuf + total, BUF_SIZE - total);
        if (nbytes <= 0) {
            printf("socketpair basic test: read error\n");
            exit(EXIT_FAILURE);
        }
        total += nbytes;
    } while (total < BUF_SIZE);
    if (memcmp(readBuf, writeBuf, BUF_SIZE)) {
        printf("socketpair basic test: data mismatch\n");
        exit(EXIT_FAILURE);
    }
    close(fd[0]);
    close(fd[1]);

    ret = socketpair(AF_UNIX, SOCK_STREAM, 0, fault_addr);
    if ((ret != -1) || (errno != EFAULT)) {
        printf("socketpair fault test failed (%d, %d)\n", ret, errno);
        exit(EXIT_FAILURE);
    }
}

static void hangup_test(void)
{
    int fd[2];
    struct pollfd fds;
    int ret = socketpair(AF_UNIX, SOCK_STREAM, 0, fd);

    if (ret < 0) {
        printf("socketpair hangup test: socketpair error %d\n", errno);
        exit(EXIT_FAILURE);
    }
    close(fd[0]);
    fds.fd = fd[1];
    fds.events = 0;
    ret = poll(&fds, 1, 0);
    if (ret <= 0) {
        printf("socketpair hangup test: poll returned %d\n", ret);
        exit(EXIT_FAILURE);
    }
    if (!(fds.revents & POLLHUP)) {
        printf("socketpair hangup test: unexpected events %x\n", fds.revents);
        exit(EXIT_FAILURE);
    }
    ret = read(fd[1], readBuf, BUF_SIZE);
    if (ret != 0) {
        printf("socketpair hangup test: read returned %d\n", ret);
        exit(EXIT_FAILURE);
    }
    close(fd[1]);
}

static void *blocking_read_test_child(void *arg)
{
    int fd = (long)arg;
    ssize_t nbytes;

    nbytes = read(fd, readBuf, BUF_SIZE);
    thread_done = true;
    if (nbytes <= 0) {
        printf("socketpair blocking read test child: read returned %ld\n",
                nbytes);
        return (void *)EXIT_FAILURE;
    }
    return (void *)EXIT_SUCCESS;
}

static void blocking_read_test(void)
{
    pthread_t pt;
    ssize_t nbytes;
    void *retval;
    int fd[2];
    int ret = socketpair(AF_UNIX, SOCK_STREAM, 0, fd);

    if (ret < 0) {
        printf("socketpair blocking read test: socketpair error %d\n", errno);
        exit(EXIT_FAILURE);
    }
    thread_done = false;
    if (pthread_create(&pt, NULL, blocking_read_test_child,
            (void *)(long)fd[0])) {
        printf("socketpair blocking read test: cannot create thread\n");
        exit(EXIT_FAILURE);
    }
    usleep(100 * 1000);
    if (thread_done) {
        printf("socketpair blocking read test: thread didn't block\n");
        exit(EXIT_FAILURE);
    }
    nbytes = write(fd[1], writeBuf, BUF_SIZE);
    if (nbytes <= 0) {
        printf("socketpair blocking read test: write returned %ld\n", nbytes);
        exit(EXIT_FAILURE);
    }
    if (pthread_join(pt, &retval)) {
        printf("socketpair blocking read test: cannot join thread\n");
        exit(EXIT_FAILURE);
    }
    if ((long)retval != EXIT_SUCCESS) {
        printf("socketpair blocking read test: thread errored out\n");
        exit(EXIT_FAILURE);
    }
    close(fd[0]);
    close(fd[1]);
}

static void nonblocking_test(void)
{
    int fd[2];
    int ret = socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fd);

    if (ret < 0) {
        printf("socketpair non-blocking test: socketpair error %d\n", errno);
        exit(EXIT_FAILURE);
    }
    ret = read(fd[0], readBuf, BUF_SIZE);
    if ((ret != -1) || (errno != EAGAIN)) {
        printf("socketpair non-blocking test: read didn't error out (%d, %d)\n",
                ret, errno);
        exit(EXIT_FAILURE);
    }
    close(fd[0]);
    close(fd[1]);
}

int main(int argc, char **argv)
{
    basic_test();
    hangup_test();
    blocking_read_test();
    nonblocking_test();
    printf("socketpair tests OK\n");
    return EXIT_SUCCESS;
}
