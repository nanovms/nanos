#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <runtime.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../test_utils.h"

#define BUF_SIZE    8192

static u8 readBuf[BUF_SIZE], writeBuf[BUF_SIZE];
static volatile int thread_done;

static void basic_test(void)
{
    ssize_t nbytes, total;
    int fd[2];
    void *fault_addr = FAULT_ADDR;
    int ret = socketpair(AF_UNIX, SOCK_STREAM, 0, fd);

    if (ret < 0) {
        test_perror("socketpair basic test: socketpair");
    }
    memset(writeBuf, 0xA5, sizeof(writeBuf));
    total = 0;
    do {
        nbytes = write(fd[0], writeBuf + total, BUF_SIZE - total);
        if (nbytes <= 0) {
            test_error("socketpair basic test: write");
        }
        total += nbytes;
    } while (total < BUF_SIZE);
    total = 0;
    do {
        nbytes = read(fd[1], readBuf + total, BUF_SIZE / 2 - total);
        if (nbytes <= 0) {
            test_error("socketpair basic test: read");
        }
        total += nbytes;
    } while (total < BUF_SIZE / 2);
    if (total != BUF_SIZE / 2) {
        test_error("socketpair basic test: read more data than requested");
    }
    do {
        nbytes = read(fd[1], readBuf + total, BUF_SIZE - total);
        if (nbytes <= 0) {
            test_error("socketpair basic test: read");
        }
        total += nbytes;
    } while (total < BUF_SIZE);
    if (memcmp(readBuf, writeBuf, BUF_SIZE)) {
        test_error("socketpair basic test: data mismatch");
    }
    close(fd[0]);
    close(fd[1]);

    ret = socketpair(AF_UNIX, SOCK_STREAM, 0, fault_addr);
    if ((ret != -1) || (errno != EFAULT)) {
        test_error("socketpair fault test (%d, %d)", ret, errno);
    }
}

static void hangup_test(void)
{
    int fd[2];
    struct pollfd fds;
    int ret = socketpair(AF_UNIX, SOCK_STREAM, 0, fd);

    if (ret < 0) {
        test_perror("socketpair hangup test: socketpair");
    }
    close(fd[0]);
    fds.fd = fd[1];
    fds.events = 0;
    ret = poll(&fds, 1, 0);
    if (ret <= 0) {
        test_error("socketpair hangup test: poll returned %d", ret);
    }
    if (!(fds.revents & POLLHUP)) {
        test_error("socketpair hangup test: unexpected events %x", fds.revents);
    }
    ret = read(fd[1], readBuf, BUF_SIZE);
    if (ret != 0) {
        test_error("socketpair hangup test: read returned %d", ret);
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
        test_perror("socketpair blocking read test: socketpair");
    }
    thread_done = false;
    if (pthread_create(&pt, NULL, blocking_read_test_child,
            (void *)(long)fd[0])) {
        test_error("socketpair blocking read test: cannot create thread");
    }
    usleep(100 * 1000);
    if (thread_done) {
        test_error("socketpair blocking read test: thread didn't block");
    }
    nbytes = write(fd[1], writeBuf, BUF_SIZE);
    if (nbytes <= 0) {
        test_error("socketpair blocking read test: write returned %ld", nbytes);
    }
    if (pthread_join(pt, &retval)) {
        test_error("socketpair blocking read test: cannot join thread");
    }
    if ((long)retval != EXIT_SUCCESS) {
        test_error("socketpair blocking read test: thread errored out");
    }
    close(fd[0]);
    close(fd[1]);
}

static void nonblocking_test(void)
{
    int fd[2];
    int ret = socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fd);

    if (ret < 0) {
        test_perror("socketpair non-blocking test: socketpair");
    }
    ret = read(fd[0], readBuf, BUF_SIZE);
    if ((ret != -1) || (errno != EAGAIN)) {
        test_error("socketpair non-blocking test: read didn't error out (%d, %d)",
                ret, errno);
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
