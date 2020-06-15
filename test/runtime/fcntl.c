#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>

#define test_assert(expr) do { \
    if (!(expr)) { \
        printf("Error: %s -- failed at %s:%d\n", #expr, __FILE__, __LINE__); \
        exit(EXIT_FAILURE); \
    } \
} while (0)

/* covers F_GETLK, F_SETLK, F_SETLKW; expect = 0 for success, errno otherwise */
void test_lk(int fd, int cmd, struct flock *lock, int expect)
{
    printf("fcntl(%d, %d, %p) => ", fd, cmd, lock);
    int r = fcntl(fd, cmd, lock);
    if (r < 0) {
        printf("%s\n", strerror(errno));
        if (errno != expect)
            goto fail;
    } else {
        printf("%d\n", r);
        if (expect)
            goto fail;

        if ((cmd == F_GETLK) && (lock->l_type != F_UNLCK)) {
            printf("F_GETLK expected F_UNLCK, instead got: %d\n", lock->l_type);
            goto fail;
        }
    }
    return;
  fail:
    printf("test failed\n");
    exit(EXIT_FAILURE);
}

void test_dupfd(int fd)
{
    int new_fd1, new_fd2;

    new_fd1 = fcntl(fd, F_DUPFD, 0);
    test_assert(new_fd1 > fd);
    test_assert(close(new_fd1) == 0);

    new_fd1 = fcntl(fd, F_DUPFD, 10);
    test_assert(new_fd1 == 10);

    new_fd2 = fcntl(new_fd1, F_DUPFD, 0);
    test_assert(new_fd2 < new_fd1);

    test_assert(close(new_fd1) == 0);
    test_assert(close(new_fd2) == 0);
}

int main(int argc, char **argv)
{
    struct flock lock;
    int fd = open("test", O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);

    lock.l_type   = F_WRLCK;
    lock.l_start  = 0;
    lock.l_whence = SEEK_SET;
    lock.l_len    = 0;

    test_lk(fd, F_GETLK,  &lock, 0);
    test_lk(fd, F_SETLK,  &lock, 0);
    test_lk(fd, F_SETLKW, &lock, 0);

    test_dupfd(fd);

    printf("test passed\n");
    return EXIT_SUCCESS;
}
