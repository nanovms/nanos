#include <errno.h>
#define _GNU_SOURCE
#define __USE_GNU
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define test_assert(expr) do { \
    if (!(expr)) { \
        printf("Error: %s -- failed at %s:%d\n", #expr, __FILE__, __LINE__); \
        exit(EXIT_FAILURE); \
    } \
} while (0)

int main(int argc, char **argv)
{
    int fd;
    uint8_t buf[8192];
    unsigned long alloc_size, file_size;
    int ret;

    setbuf(stdout, NULL);

    test_assert((fallocate(0, 0, 0, 1) == -1) && (errno == ESPIPE));

    fd = open("my_file", O_RDONLY | O_CREAT, S_IRWXU);
    test_assert(fd > 0);
    test_assert(fallocate(fd, FALLOC_FL_KEEP_SIZE, 0, 1) == -1);
    test_assert(errno == EBADF);    /* the file is open in read-only mode */
    test_assert(close(fd) == 0);

    fd = open("my_file", O_RDWR | O_CREAT, S_IRWXU);
    test_assert(fd > 0);
    test_assert(fallocate(fd, FALLOC_FL_KEEP_SIZE, 0, 1) == 0);
    test_assert(read(fd, buf, sizeof(buf)) == 0);

    test_assert(fallocate(fd, 0, 0, 1) == 0);
    buf[0] = 0xff;
    test_assert((read(fd, buf, sizeof(buf)) == 1) && (buf[0] == 0));

    test_assert(fallocate(fd, 0, 0, sizeof(buf)) == 0);
    memset(buf, 0xff, sizeof(buf));
    test_assert(lseek(fd, 4095, SEEK_SET) == 4095);
    test_assert(write(fd, &buf[4095], 2) == 2);
    test_assert(lseek(fd, 0, SEEK_SET) == 0);
    test_assert(read(fd, buf, sizeof(buf)) == sizeof(buf));
    for (int i = 0; i < 4095; i++) {
        test_assert(buf[i] == 0);
    }
    test_assert((buf[4095] == 0xff) && (buf[4096] == 0xff));
    for (int i = 4097; i < 8192; i++) {
        test_assert(buf[i] == 0);
    }

    alloc_size = 1;
    do {
        alloc_size *= 3;
        ret = fallocate(fd, 0, alloc_size, alloc_size);
        test_assert((ret == 0) || ((ret == -1) && (errno == ENOSPC)));
    } while (ret == 0);
    file_size = lseek(fd, 0, SEEK_END);
    test_assert(file_size == 2 * alloc_size / 3);

    memset(buf, 0xff, sizeof(buf));
    test_assert(lseek(fd, 0, SEEK_SET) == 0);
    test_assert(write(fd, buf, sizeof(buf)) == sizeof(buf));
    for (int hole = 1; hole <= sizeof(buf) - 2; hole *= 3) {
        ret = fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, hole,
                hole);
        test_assert(ret == 0);
        test_assert(lseek(fd, hole - 1, SEEK_SET) == hole - 1);
        test_assert(read(fd, buf, hole + 2) == hole + 2);
        test_assert(buf[0] == 0xff);
        for (int i = 1; i <= hole; i++) {
            test_assert(buf[i] == 0);
        }
        test_assert(buf[hole + 1] == ((hole < sizeof(buf) / 2) ? 0xff : 0x00));
    }

    ret = fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 0,
            file_size);
    test_assert(ret == 0);
    test_assert(read(fd, buf, sizeof(buf)) == sizeof(buf));
    for (int i = 0; i < sizeof(buf); i++) {
        test_assert(buf[i] == 0);
    }

    test_assert(lseek(fd, 0, SEEK_END) == file_size);

    test_assert(close(fd) == 0);

    printf("fallocate test OK\n");
    return EXIT_SUCCESS;
}
