#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>

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

    printf("test passed\n");
    return EXIT_SUCCESS;
}
