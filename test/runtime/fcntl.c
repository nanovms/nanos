#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>

/* expect = 0 for success, errno otherwise */
void getlk(int fd, struct flock *lock, int expect)
{
    printf("fcntl(%d, %d, %p) => ", fd, F_GETLK, lock);
    int r = fcntl(fd, F_GETLK, lock);
    if (r < 0) {
        printf("%s\n", strerror(errno));
        if (errno != expect)
            goto fail;
    } else {
        printf("%d\n", r);
        if (expect)
            goto fail;

        if (lock->l_type != F_UNLCK) {
            printf("getlk expected F_UNLCK, instead got: %d\n", lock->l_type);
            goto fail;
        }
    }
    return;
  fail:
    printf("test failed\n");
    exit(EXIT_FAILURE);
}

/* expect = 0 for success, errno otherwise */
void setlk(int fd, struct flock *lock, int expect)
{
    printf("fcntl(%d, %d, %p) => ", fd, F_SETLK, lock);
    int r = fcntl(fd, F_SETLK, lock);
    if (r < 0) {
        printf("%s\n", strerror(errno));
        if (errno != expect)
            goto fail;
    } else {
        printf("%d\n", r);
        if (expect)
            goto fail;
    }
    return;
  fail:
    printf("test failed\n");
    exit(EXIT_FAILURE);
}

/* expect = 0 for success, errno otherwise */
void setlkw(int fd, struct flock *lock, int expect)
{
    printf("fcntl(%d, %d, %p) => ", fd, F_SETLKW, lock);
    int r = fcntl(fd, F_SETLKW, lock);
    if (r < 0) {
        printf("%s\n", strerror(errno));
        if (errno != expect)
            goto fail;
    } else {
        printf("%d\n", r);
        if (expect)
            goto fail;
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

    getlk(fd, &lock, 0);
    setlk(fd, &lock, 0);
    setlkw(fd, &lock, 0);

    printf("test passed\n");
    return EXIT_SUCCESS;
}
