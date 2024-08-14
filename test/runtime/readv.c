#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

#include "../test_utils.h"

#define EXPECT_STRN_EQUAL(expected, actual_str, actual_len) \
    if (strncmp(expected, actual_str, actual_len) != 0) { \
        char actual_buf[actual_len + 1]; \
        memcpy(actual_buf, actual_str, actual_len); \
        actual_buf[actual_len] = '\0'; \
        test_error("\"%s\" != \"%s\"", expected, actual_buf);   \
    }

#define EXPECT_LONG_EQUAL(expected, actual) \
    if (expected != actual) { \
        test_error("\"%ld\" != \"%ld\"", (long)expected, (long)actual); \
    }

static void readv_test_direct(void)
{
    const int alignment = 512;
    int fd = open("hello", O_RDONLY | O_DIRECT);
    test_assert(fd >= 0);
    unsigned char buf[3 * alignment];
    struct iovec iovs[2];
    unsigned char *ptr;
    int file_len;

    /* unaligned base pointers: readv() may or may not fail with EINVAL (it fails on Nanos and
     * succeeds on Linux with ext4 filesystem) */
    if ((intptr_t)buf & (alignment - 1))
        ptr = buf;
    else
        ptr = buf + 1;
    iovs[0].iov_base = ptr;
    iovs[1].iov_base = ptr + alignment;
    iovs[0].iov_len = iovs[1].iov_len = alignment;
    if (readv(fd, iovs, 2) > 0)
        test_assert(lseek(fd, 0, SEEK_SET) == 0);
    else
        test_assert(errno == EINVAL);

    /* unaligned buffer length */
    ptr = (unsigned char *)((intptr_t)(buf - 1) & ~(alignment - 1)) + alignment;
    iovs[0].iov_base = ptr;
    iovs[1].iov_base = ptr + alignment;
    iovs[0].iov_len = 1;
    test_assert((readv(fd, iovs, 2) == -1) && (errno == EINVAL));

    /* aligned buffer address and length */
    iovs[0].iov_len = alignment;
    file_len = readv(fd, iovs, 2);
    test_assert((file_len > 0) && (file_len < 2 * alignment));

    close(fd);
}

int main()
{
    struct iovec iovs[3];
    char onev[4], twov[4], threev[4];
    iovs[0].iov_base = onev;
    iovs[1].iov_base = twov;
    iovs[2].iov_base = threev;
    iovs[0].iov_len = iovs[1].iov_len = iovs[2].iov_len = 4;

    int fd = open("hello", O_RDWR);
    if (fd < 0) {
        test_perror("open");
    }

    int startpos = 4;
    int rv = lseek(fd, startpos, SEEK_SET);
    if (rv < 0) {
        test_perror("lseek");
    }

    rv = readv(fd, iovs, 3);
    if (rv < 0) {
        test_perror("readv");
    }
    int bytes_read = rv;

    EXPECT_STRN_EQUAL("one ", iovs[0].iov_base, 4);
    EXPECT_STRN_EQUAL("six ", iovs[1].iov_base, 4);
    EXPECT_STRN_EQUAL("four", iovs[2].iov_base, 4);

    rv = lseek(fd, 0, SEEK_CUR);
    if (rv < 0) {
        test_perror("lseek");
    }
    int curpos = rv;
    EXPECT_LONG_EQUAL(startpos + bytes_read, curpos);

    rv = preadv(fd, iovs, 3, -1);   /* invalid offset */
    EXPECT_LONG_EQUAL(rv, -1);
    EXPECT_LONG_EQUAL(errno, EINVAL);

    bytes_read = preadv(fd, iovs, 3, 0);
    EXPECT_LONG_EQUAL(bytes_read, 12);
    EXPECT_STRN_EQUAL("pad ", iovs[0].iov_base, 4);
    EXPECT_STRN_EQUAL("one ", iovs[1].iov_base, 4);
    EXPECT_STRN_EQUAL("six ", iovs[2].iov_base, 4);
    rv = lseek(fd, 0, SEEK_CUR);
    EXPECT_LONG_EQUAL(rv, curpos);

    if (lseek(fd, 0, SEEK_END) < 0) {
        test_perror("lseek(end)");
    }
    rv = readv(fd, iovs, 3);
    if (rv != 0) {
        test_error("readv at end of file returned %d", rv);
    }

    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN | POLLOUT;
    rv = poll(&pfd, 1, 0);
    if (rv != 1) {
        test_error("unexpected poll return value %d", rv);
    }
    if (pfd.revents != (POLLIN | POLLOUT)) {
        test_error("unexpected poll events 0x%x", pfd.revents);
    }

    if (close(fd) < 0) {
        test_perror("close");
    }

    fd = open("hello", O_WRONLY);
    if (fd < 0) {
        test_perror("open write-only");
    }
    if (readv(fd, iovs, 3) != -1) {
        test_error("could readv from write-only file");
    } else if (errno != EBADF) {
        test_perror("readv from write-only file: unexpected error");
    }
    if (close(fd) < 0) {
        test_perror("close write-only");
    }

    void *fault_addr = FAULT_ADDR;
    fd = open(fault_addr, O_RDWR);
    if ((fd != -1) || (errno != EFAULT)) {
        test_error("open with faulting buffer test (%d, %d)", fd, errno);
    }
    fd = open("hello", O_RDWR);
    if (fd < 0) {
        test_perror("open");
    }
    rv = read(fd, fault_addr, 1);
    if ((rv != -1) || (errno != EFAULT)) {
        test_error("read with faulting buffer test (%d, %d)", rv, errno);
    }
    rv = readv(fd, fault_addr, 1);
    if ((rv != -1) || (errno != EFAULT)) {
        test_error("readv with faulting iov test (%d, %d)", rv, errno);
    }
    iovs[0].iov_base = fault_addr;
    rv = readv(fd, iovs, 3);
    if ((rv != -1) || (errno != EFAULT)) {
        test_error("readv with faulting iov_base test (%d, %d)", rv, errno);
    }
    close(fd);

    readv_test_direct();

    printf("readv test PASSED\n");

    return EXIT_SUCCESS;
}
