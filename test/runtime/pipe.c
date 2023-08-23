#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <poll.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>

#include <runtime.h>

#define handle_error(msg) \
       do { perror(msg); exit(EXIT_FAILURE); } while (0)

int __pipe(int fildes[2])
{
    return syscall(SYS_pipe2, fildes, 0);
}

void basic_test(heap h, int * fds)
{
    int capacity;
    int test_val = 0x12345678;
    const int BSIZE = 1000;
    ssize_t nbytes;
    struct pollfd pfd[2];
    int ret;

    if (write(fds[1], &test_val, sizeof(test_val)) < 0)
        handle_error("pipe write");
    capacity = fcntl(fds[0], F_GETPIPE_SZ);
    if (capacity < 0)
        handle_error("F_GETPIPE_SZ");
    nbytes = fcntl(fds[0], F_SETPIPE_SZ, 3 * capacity);
    if (nbytes < 0)
        handle_error("F_SETPIPE_SZ");
    if (nbytes < 3 * capacity) {
        printf("pipe capacity set error (%ld)\n", nbytes);
        exit(EXIT_FAILURE);
    }
    capacity = nbytes;
    nbytes = fcntl(fds[0], F_GETPIPE_SZ);
    if (nbytes != capacity) {
        printf("pipe capacity get error (fd 0, %ld)\n", nbytes);
        exit(EXIT_FAILURE);
    }
    nbytes = fcntl(fds[1], F_GETPIPE_SZ);
    if (nbytes != capacity) {
        printf("pipe capacity get error (fd 1, %ld)\n", nbytes);
        exit(EXIT_FAILURE);
    }
    nbytes = read(fds[0], &test_val, sizeof(test_val));
    if ((nbytes != sizeof(test_val)) || (test_val != 0x12345678)) {
        printf("pipe read error after set capacity (%ld, 0x%x)\n", nbytes,
               test_val);
        exit(EXIT_FAILURE);
    }

    char *test_string = "This is a pipe test string!";
    int test_len = strlen(test_string);
    buffer in = allocate_buffer(h, BSIZE);

    nbytes = write(fds[1], test_string, test_len);
    if (nbytes < 0)
        handle_error("basic test write");

    if (nbytes < test_len) {
        printf("pipe basic test: short write (%ld)\n", nbytes);
        exit(EXIT_FAILURE);
    }

    pfd[0].fd = fds[0];
    pfd[1].fd = fds[1];
    pfd[0].events = pfd[1].events = POLLIN | POLLOUT;
    ret = poll(pfd, 2, -1);
    if ((ret != 2) || (pfd[0].revents != POLLIN) || (pfd[1].revents != POLLOUT)) {
        printf("pipe before read: poll returned %d, pfd[0].revents 0x%x, pfd[1].revents 0x%x\n",
               ret, pfd[0].revents, pfd[1].revents);
        exit(EXIT_FAILURE);
    }

    int nread = 0;
    char * ibuf = buffer_ref(in, 0);
    do {
        nbytes = read(fds[0], ibuf + nread, 5);
        if (nbytes < 0)
            handle_error("basic test read");
        nread += nbytes;
    } while (nread < test_len);

    ret = poll(pfd, 2, -1);
    if ((ret != 1) || (pfd[0].revents != 0) || (pfd[1].revents != POLLOUT)) {
        printf("pipe after read: poll returned %d, pfd[0].revents 0x%x, pfd[1].revents 0x%x\n",
               ret, pfd[0].revents, pfd[1].revents);
        exit(EXIT_FAILURE);
    }

    buffer_produce(in, test_len);
    buffer_write_byte(in, (u8)'\0');
    buffer_clear(in);

    if (strcmp(test_string, (const char *)buffer_ref(in, 0))) {
        printf("PIPE-RD/WR - ERROR - test message corrupted, expected %s and got %s\n",
               test_string, (char *)buffer_ref(in, 0));
        exit(EXIT_FAILURE);
    } else {
        printf("PIPE-RD/WR - SUCCESS - test message received\n");
    }
}

#define BLOCKING_TEST_LEN (256 * KB)

static char blocking_srcbuf[BLOCKING_TEST_LEN];

void * blocking_test_child(void * arg)
{
    const int dstbufsiz = 256;
    int * fds = (int *)arg;
    char dstbuf[dstbufsiz];
    int nread = 0;

    do {
        int nbytes = read(fds[0], dstbuf, dstbufsiz);
        if (nbytes < 0)
            handle_error("blocking test read");
        for (int i = 0; i < nbytes; i++) {
            if (dstbuf[i] != blocking_srcbuf[nread + i]) {
                printf("blocking test: mismatch at offset %d\n", nread + i);
                return (void *)EXIT_FAILURE;
            }
        }
        nread += nbytes;
    } while (nread < BLOCKING_TEST_LEN);

    printf("blocking test: read data successfully; child exiting\n");
    return (void *)EXIT_SUCCESS;
}

void blocking_test(heap h, int * fds)
{
    for (int i=0; i < BLOCKING_TEST_LEN; i++)
        blocking_srcbuf[i] = (char)random_u64();

    pthread_t pt;
    if (pthread_create(&pt, NULL, blocking_test_child, fds))
        handle_error("blocking test pthread_create");

    int nwritten = 0;
    do {
        int nbytes = write(fds[1], blocking_srcbuf + nwritten,
                           BLOCKING_TEST_LEN - nwritten);
        if (nbytes < 0)
            handle_error("blocking test write");
        nwritten += nbytes;
    } while(nwritten < BLOCKING_TEST_LEN);

    printf("blocking test: finished writing data; waiting for read thread\n");

    void * retval = 0;
    if (pthread_join(pt, &retval))
        handle_error("blocking test pthread_join");
    if (retval != (void *)EXIT_SUCCESS) {
        printf("blocking test failed: read thread failed with retval %lld\n",
               (long long)retval);
        exit(EXIT_FAILURE);
    }
    printf("blocking test passed\n");
}

static void fault_test(void)
{
    int fds[2];
    int status;
    u8 buf[64];
    void *fault_addr = (void *)0xbadf0000;

    if ((__pipe(fault_addr) != -1) || (errno != EFAULT)) {
        printf("pipe with faulting buffer error\n");
        exit(EXIT_FAILURE);
    }
    status = __pipe(fds);
    if (status == -1)
        handle_error("pipe");
    if ((write(fds[1], fault_addr, 1) != -1) || (errno != EFAULT)) {
        printf("write with faulting buffer error\n");
        exit(EXIT_FAILURE);
    }

    if (write(fds[1], buf, sizeof(buf)) < 0)
        handle_error("write");
    if ((read(fds[0], fault_addr, 1) != -1) || (errno != EFAULT)) {
        printf("read with faulting buffer error\n");
        exit(EXIT_FAILURE);
    }

    close(fds[0]);
    close(fds[1]);
}

int main(int argc, char **argv)
{
    int fds[2] = {0,0};
    int status;
    struct pollfd pfd;

    heap h = init_process_runtime();

    status = __pipe(fds);
    if (status == -1)
        handle_error("pipe");

    printf("PIPE-CREATE - SUCCESS, fds %d %d\n", fds[0], fds[1]);

    basic_test(h, fds);

    blocking_test(h, fds);

    close(fds[1]);
    pfd.fd = fds[0];
    pfd.events = POLLIN | POLLOUT;
    status = poll(&pfd, 1, -1);
    if ((status != 1) || (pfd.revents != POLLHUP)) {
        printf("after closing writer fd: poll on reader fd returned %d, pfd.revents 0x%x\n",
               status, pfd.revents);
        exit(EXIT_FAILURE);
    }

    close(fds[0]);
    fault_test();
    return(EXIT_SUCCESS);
}
