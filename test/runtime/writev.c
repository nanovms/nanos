#include <errno.h>
#include <fcntl.h>
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

    printf("write test passed\n");

    return 0;
}
