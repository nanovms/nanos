#include <errno.h>
#define _GNU_SOURCE
#define __USE_GNU
#include <fcntl.h>
#include <linux/aio_abi.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include <unistd.h>

#define BUF_SIZE        8192
#define SMALLBUF_SIZE   256

#define test_assert(expr) do { \
    if (!(expr)) { \
        printf("Error: %s -- failed at %s:%d\n", #expr, __FILE__, __LINE__); \
        exit(EXIT_FAILURE); \
    } \
} while (0)

static void iocb_setup_pread(struct iocb *iocb, int fd, void *buf,
        size_t count, long long offset)
{
    memset(iocb, 0, sizeof(*iocb));
    iocb->aio_fildes = fd;
    iocb->aio_lio_opcode = IOCB_CMD_PREAD;
    iocb->aio_buf = (__u64) buf;
    iocb->aio_nbytes = count;
    iocb->aio_offset = offset;
}

static void iocb_setup_pwrite(struct iocb *iocb, int fd, void *buf,
        size_t count, long long offset)
{
    memset(iocb, 0, sizeof(*iocb));
    iocb->aio_fildes = fd;
    iocb->aio_lio_opcode = IOCB_CMD_PWRITE;
    iocb->aio_buf = (__u64) buf;
    iocb->aio_nbytes = count;
    iocb->aio_offset = offset;
}

static void aio_test_readwrite(void)
{
    int fd;
    aio_context_t ioc = 0;
    uint8_t read_buf[BUF_SIZE], write_buf[BUF_SIZE];
    struct iocb iocb;
    struct iocb *iocbp = &iocb;
    struct io_event evt;

    fd = open("file_rw", O_RDWR | O_CREAT, S_IRWXU);
    test_assert(fd > 0);
    test_assert(syscall(SYS_io_setup, 1, &ioc) == 0);

    test_assert(syscall(SYS_io_submit, ioc, 0, &iocbp) == 0);

    iocb_setup_pwrite(&iocb, fd, NULL, BUF_SIZE, 0);
    test_assert(syscall(SYS_io_submit, ioc, 1, &iocbp) == -1);
    test_assert(errno == EINVAL);

    iocb_setup_pwrite(&iocb, fd, write_buf, BUF_SIZE, 0);
    iocb.aio_lio_opcode = -1;
    test_assert(syscall(SYS_io_submit, ioc, 1, &iocbp) == -1);
    test_assert(errno == EINVAL);

    iocb_setup_pwrite(&iocb, -fd, write_buf, BUF_SIZE, 0);
    test_assert(syscall(SYS_io_submit, ioc, 1, &iocbp) == -1);
    test_assert(errno == EBADF);

    for (int i = 0; i < BUF_SIZE; i++) {
        write_buf[i] = i & 0xFF;
    }
    iocb_setup_pwrite(&iocb, fd, write_buf, BUF_SIZE, 0);
    iocb.aio_data = (__u64) read_buf;
    test_assert(syscall(SYS_io_submit, ioc, 1, &iocbp) == 1);
    test_assert(syscall(SYS_io_getevents, ioc, 1, 1, &evt, NULL) == 1);
    test_assert((evt.data == (__u64) read_buf) && (evt.obj == (__u64) iocbp));
    test_assert(evt.res == BUF_SIZE);

    iocb_setup_pread(&iocb, fd, read_buf, BUF_SIZE, 0);
    iocb.aio_data = (__u64) write_buf;
    test_assert(syscall(SYS_io_submit, ioc, 1, &iocbp) == 1);
    test_assert(syscall(SYS_io_getevents, ioc, 1, 1, &evt, NULL) == 1);
    test_assert((evt.data == (__u64) write_buf) && (evt.obj == (__u64) iocbp));
    test_assert(evt.res == BUF_SIZE);
    for (int i = 0; i < BUF_SIZE; i++) {
        test_assert(read_buf[i] == (i & 0xFF));
    }

    test_assert(syscall(SYS_io_destroy, ioc) == 0);

    /* Call io_destroy without waiting for I/O completion. */
    ioc = 0;
    test_assert(syscall(SYS_io_setup, 1, &ioc) == 0);
    iocb_setup_pread(&iocb, fd, read_buf, BUF_SIZE, 0);
    test_assert(syscall(SYS_io_submit, ioc, 1, &iocbp) == 1);
    test_assert(syscall(SYS_io_destroy, ioc) == 0);

    test_assert(close(fd) == 0);
}

static void aio_test_eventfd(void)
{
    int fd;
    aio_context_t ioc = 0;
    struct iocb iocb;
    struct iocb *iocbp = &iocb;
    int efd;
    uint64_t efd_val;
    struct timespec ts;
    struct io_event evt;

    fd = open("file_efd", O_RDWR | O_CREAT, S_IRWXU);
    test_assert(fd > 0);
    test_assert(syscall(SYS_io_setup, 1, &ioc) == 0);

    iocb_setup_pwrite(&iocb, fd, "test", strlen("test"), 0);
    efd = eventfd(0, 0);
    test_assert(efd > 0);
    iocb.aio_resfd = efd;
    iocb.aio_flags = IOCB_FLAG_RESFD;

    test_assert(syscall(SYS_io_submit, ioc, 1, &iocbp) == 1);
    test_assert(read(efd, &efd_val, sizeof(efd_val)) == sizeof(efd_val));
    test_assert(efd_val == 1);

    /* The I/O event should now be available without blocking. */
    ts.tv_sec = ts.tv_nsec = 0;
    test_assert(syscall(SYS_io_getevents, ioc, 1, 1, &evt, &ts) == 1);
    test_assert((evt.obj == (__u64) iocbp) && (evt.res == strlen("test")));

    ts.tv_nsec = 1000000;
    test_assert(syscall(SYS_io_getevents, ioc, 1, 1, &evt, &ts) == 0);

    test_assert(close(efd) == 0);
    test_assert(syscall(SYS_io_destroy, ioc) == 0);
    test_assert(close(fd) == 0);
}

static void aio_test_multiple()
{
    int fd;
    aio_context_t ioc = 0;
    struct iocb iocbs[8];
    struct iocb *iocb_ptrs[8];
    uint8_t read_buf[SMALLBUF_SIZE], write_buf[SMALLBUF_SIZE];
    struct io_event evts[8];

    fd = open("file_mult", O_RDWR | O_CREAT, S_IRWXU);
    test_assert(fd > 0);

    test_assert(syscall(SYS_io_setup, 8, &ioc) == 0);

    for (int i = 0; i < SMALLBUF_SIZE; i++) {
        write_buf[i] = i;
    }
    for (int i = 0; i < 8; i++) {
        iocb_ptrs[i] = &iocbs[i];
        iocb_setup_pwrite(&iocbs[i], fd, write_buf + i * 8, 8, i * 8);
        iocbs[i].aio_data = (__u64) write_buf;
    }
    test_assert(syscall(SYS_io_submit, ioc, 8, iocb_ptrs) == 8);
    test_assert(syscall(SYS_io_getevents, ioc, 8, 8, evts, NULL) == 8);
    for (int i = 0; i < 8; i++) {
        test_assert(evts[i].data == (__u64) write_buf);
        test_assert(evts[i].res == 8);
        iocb_setup_pread(&iocbs[i], fd, read_buf + i * 8, 8, i * 8);
        iocbs[i].aio_data = (__u64) read_buf;
    }
    test_assert(syscall(SYS_io_submit, ioc, 18, iocb_ptrs) == 8);
    test_assert(syscall(SYS_io_getevents, ioc, 8, 8, evts, NULL) == 8);
    for (int i = 0; i < 8; i++) {
        test_assert(evts[i].data == (__u64) read_buf);
        test_assert(evts[i].res == 8);
    }
    for (int i = 0; i < SMALLBUF_SIZE; i++) {
        test_assert(read_buf[i] == i);
    }

    iocb_setup_pread(&iocbs[0], fd, read_buf, 0, 0);
    iocb_setup_pread(&iocbs[1], -fd, read_buf, 0, 0);
    test_assert(syscall(SYS_io_submit, ioc, 2, iocb_ptrs) == 1);
    test_assert(syscall(SYS_io_getevents, ioc, 1, 8, evts, NULL) == 1);

    test_assert(syscall(SYS_io_destroy, ioc) == 0);
    test_assert(close(fd) == 0);
}

int main(int argc, char **argv)
{
    aio_context_t ioc = 0;

    setbuf(stdout, NULL);

    test_assert((syscall(SYS_io_setup, 1, NULL) == -1) && (errno == EFAULT));
    test_assert((syscall(SYS_io_setup, 0, &ioc) == -1) && (errno == EINVAL));
    aio_test_readwrite();
    aio_test_eventfd();
    aio_test_multiple();
    printf("AIO test OK\n");
    return EXIT_SUCCESS;
}
