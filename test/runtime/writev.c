#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>
#include <assert.h>

#include "../test_utils.h"

#define BUFLEN 256

#define _READ(b, l)             \
    rv = read(fd, b, l);                    \
    if (rv < 0) {                           \
        close(fd);          \
        test_perror("read");                \
    }

#define _LSEEK(o, w)                \
    rv = lseek(fd, o, w);                   \
    if (rv < 0) {                           \
        close(fd);          \
        test_perror("lseek");               \
    }

static void writev_test_direct(void)
{
    const char *file_name = "test_direct";
    const int alignment = 512;
    int fd = open(file_name, O_CREAT | O_RDWR | O_DIRECT, S_IRUSR | S_IWUSR);
    test_assert(fd >= 0);
    unsigned char wbuf[3 * alignment];
    unsigned char rbuf[3 * alignment];
    struct iovec iovs[2];
    unsigned char *ptr;

    /* unaligned base pointers: writev() may or may not fail with EINVAL (it fails on Nanos and
     * succeeds on Linux with ext4 filesystem) */
    if ((intptr_t)wbuf & (alignment - 1))
        ptr = wbuf;
    else
        ptr = wbuf + 1;
    iovs[0].iov_base = ptr;
    iovs[1].iov_base = ptr + alignment;
    iovs[0].iov_len = iovs[1].iov_len = alignment;
    if (writev(fd, iovs, 2) > 0)
        test_assert(lseek(fd, 0, SEEK_SET) == 0);
    else
        test_assert(errno == EINVAL);

    /* unaligned buffer length */
    ptr = (unsigned char *)((intptr_t)(wbuf - 1) & ~(alignment - 1)) + alignment;
    iovs[0].iov_base = ptr;
    iovs[1].iov_base = ptr + alignment;
    iovs[0].iov_len = 1;
    test_assert((writev(fd, iovs, 2) == -1) && (errno == EINVAL));

    /* aligned buffer address and length */
    for (int i = 0; i < 2 * alignment; i += sizeof(uint64_t))
        *(uint64_t *)(ptr + i) = i;
    iovs[0].iov_len = alignment;
    test_assert(writev(fd, iovs, 2) == 2 * alignment);

    /* aligned buffer address and length */
    test_assert(lseek(fd, 0, SEEK_SET) == 0);
    ptr = (unsigned char *)((intptr_t)(rbuf - 1) & ~(alignment - 1)) + alignment;
    test_assert(read(fd, ptr, 2 * alignment) == 2 * alignment);

    test_assert(!memcmp(ptr, iovs[0].iov_base, alignment));
    test_assert(!memcmp(ptr + alignment, iovs[1].iov_base, alignment));
    close(fd);
    unlink(file_name);
}

int main()
{
    struct iovec iovs[3];
    ssize_t rv;
    char buf[BUFLEN];
    char arr1[] = "This seems ", arr2[] = "to have ", arr3[] = "worked";
    char *str = "This seems to have worked";

    iovs[0].iov_base = arr1;
    iovs[0].iov_len = strlen(arr1);

    iovs[1].iov_base = arr2;
    iovs[1].iov_len = strlen(arr2);

    iovs[2].iov_base = arr3;
    iovs[2].iov_len = strlen(arr3);

    int total_write_len = iovs[0].iov_len + iovs[1].iov_len + iovs[2].iov_len;
    assert(total_write_len == strlen(str));

    int fd = open("hello", O_RDWR);
    if (fd < 0) {
        test_perror("open");
    }

    _READ(buf, BUFLEN);

    if (rv == 0) {
        printf("Source file empty\n");
    } else {
        buf[rv] = '\0';
        printf("Source file content: \"%s\"\n", buf);
    }

    int startpos = 10;

    _LSEEK(startpos, SEEK_SET);
    printf("Writev start position: %d, length: %d\n", startpos, total_write_len);

    rv = writev(fd, iovs, 3);
    if (rv < 0) {
        test_perror("writev");
    }

    if (rv != total_write_len) {
        test_error("written bytes number %ld is not equal to expected %d", rv, total_write_len);
    }

    int endpos = lseek(fd, 0, SEEK_CUR);
    if (startpos + total_write_len != endpos)
    {
        test_error("file offset at the end of writev is not correct: expected %d != actual %d",
            startpos + total_write_len, endpos);
    }

    _LSEEK(startpos, SEEK_SET);

    memset(buf, 0, BUFLEN);
    _READ(buf, total_write_len);

    if (rv != total_write_len) {
        test_error("read: expecting %d bytes, rv: %ld", total_write_len, rv);
    }

    if (strncmp(str, buf, strlen(str))) {
        buf[rv] = '\0';
        test_error("write: string mismatch, expected \"%s\", actual \"%s\"", str, buf);
    }

    rv = pwritev(fd, iovs, 3, -1);
    if ((rv != -1) || (errno != EINVAL)) {
        test_error("pwritev with invalid offset returned %ld (errno %d)", rv, errno);
    }

    startpos += 10;
    rv = pwritev(fd, iovs, 3, startpos);
    if (rv != total_write_len) {
        test_error("bytes written with pwritev: %ld (expected %d)", rv, total_write_len);
    }
    rv = lseek(fd, 0, SEEK_CUR);
    if (rv != endpos) {
        test_error("file offset at the end of pwritev: %ld (expected %d)", rv, endpos);
    }
    _LSEEK(startpos, SEEK_SET);
    _READ(buf, total_write_len);
    if (rv != total_write_len) {
        test_error("read after pwritev: expecting %d bytes, rv: %ld", total_write_len, rv);
    }
    if (strncmp(str, buf, strlen(str))) {
        buf[rv] = '\0';
        test_error("pwritev: string mismatch, expected \"%s\", actual \"%s\"", str, buf);
    }

    close(fd);

    fd = open("hello", O_RDONLY);
    if (fd < 0) {
        test_perror("open read-only");
    }
    if (writev(fd, iovs, 3) != -1) {
        test_error("could writev to read-only file");
    } else if (errno != EBADF) {
        test_perror("writev to read-only file: unexpected error");
    }
    if (close(fd) < 0) {
        test_perror("close read-only");
    }

    writev_test_direct();

    printf("write test passed\n");

    return 0;
}
