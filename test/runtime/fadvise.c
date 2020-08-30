#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

/* fadvise stub test for parameters only */

void test_fadvise(int fd, int64_t off, uint64_t len, int adv, int exp, char *name)
{
    int r = posix_fadvise(fd, off, len, adv);
    if (r != exp) {
        char b[256];
        snprintf(b, sizeof b, "fadvise test '%s' did not get expected result: %d != %d",
            name, r, exp);
        perror(b);
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char **argv)
{
    int fd = open("test_fadvise", O_CREAT|O_RDWR, 0644);
    if (fd < 0) {
        perror("open");
        exit(EXIT_FAILURE);
    }
    test_fadvise(fd, 0, 128, POSIX_FADV_SEQUENTIAL, 0, "set sequential");
    test_fadvise(fd, 0, 128, POSIX_FADV_RANDOM, 0, "set random");
    test_fadvise(fd, 0, 128, POSIX_FADV_NOREUSE, 0, "set noreuse");
    test_fadvise(fd, 0, 128, POSIX_FADV_WILLNEED, 0, "set willneed");
    test_fadvise(fd, 0, 128, POSIX_FADV_DONTNEED, 0, "set dontneed");
    test_fadvise(fd, 0, 128, POSIX_FADV_NORMAL, 0, "set normal");
    test_fadvise(fd, 0, 128, 9999, EINVAL, "use bad advice");
    close(fd);
    test_fadvise(fd, 0, 128, 9999, EBADF, "use bad fd");
    printf("fadvise test passed\n");
    exit(EXIT_SUCCESS);
}
