#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>

#if !defined(F_SEAL_FUTURE_WRITE)   /* for older glibc versions */
#define F_SEAL_FUTURE_WRITE 0x0010
#endif

#include "../test_utils.h"

static void test_access_mode(int fd)
{
    int old_flags, access_mode, new_flags;

    old_flags = fcntl(fd, F_GETFL);
    test_assert(old_flags >= 0);
    access_mode = old_flags & O_ACCMODE;

    /* Try to change file access mode and verify that it does not change. */
    access_mode = (access_mode == O_RDWR) ? O_RDONLY : O_RDWR;
    new_flags = (old_flags & ~O_ACCMODE) | access_mode;
    test_assert(fcntl(fd, F_SETFL, new_flags) == 0);
    new_flags = fcntl(fd, F_GETFL);
    test_assert((new_flags & O_ACCMODE) == (old_flags & O_ACCMODE));
}

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

static void test_seals(int non_tmpfs_fd)
{
    int tmpfs_fd;
    int seals;
    char buf[8];
    void *addr0, *addr1;

    /* seal operations on non-regular files or files whose filesystem doesn't support sealing */
    test_assert((fcntl(0, F_GET_SEALS) == -1) && (errno == EINVAL));
    test_assert((fcntl(0, F_ADD_SEALS) == -1) && (errno == EINVAL));
    test_assert((fcntl(non_tmpfs_fd, F_GET_SEALS) == -1) && (errno == EINVAL));
    test_assert((fcntl(non_tmpfs_fd, F_ADD_SEALS) == -1) && (errno == EINVAL));

    /* memfd descriptor that doesn't allow sealing */
    tmpfs_fd = memfd_create("", 0);
    test_assert(tmpfs_fd >= 0);
    test_assert(fcntl(tmpfs_fd, F_GET_SEALS) == F_SEAL_SEAL);
    test_assert((fcntl(tmpfs_fd, F_ADD_SEALS, 0) == -1) && (errno == EPERM));
    close(tmpfs_fd);

    tmpfs_fd = memfd_create("", MFD_ALLOW_SEALING);
    test_assert(tmpfs_fd >= 0);
    test_assert((fcntl(tmpfs_fd, F_ADD_SEALS, -1u) == -1) && (errno == EINVAL));
    test_assert(fcntl(tmpfs_fd, F_GET_SEALS) == 0);
    test_assert(ftruncate(tmpfs_fd, 4) == 0);

    test_assert(fcntl(tmpfs_fd, F_ADD_SEALS, F_SEAL_SHRINK) == 0);
    test_assert(fcntl(tmpfs_fd, F_GET_SEALS) == F_SEAL_SHRINK);
    test_assert((ftruncate(tmpfs_fd, 3) == -1) && (errno == EPERM));
    test_assert(ftruncate(tmpfs_fd, 5) == 0);

    test_assert(fcntl(tmpfs_fd, F_ADD_SEALS, F_SEAL_GROW) == 0);
    test_assert(fcntl(tmpfs_fd, F_GET_SEALS) == (F_SEAL_SHRINK | F_SEAL_GROW));
    test_assert(lseek(tmpfs_fd, -1, SEEK_END) == 4);
    test_assert((write(tmpfs_fd, buf, 2) == -1) && (errno == EPERM));
    test_assert(write(tmpfs_fd, buf, 1) == 1);
    test_assert(write(tmpfs_fd, buf, 0) == 0);
    test_assert((write(tmpfs_fd, buf, 1) == -1) && (errno == EPERM));
    test_assert((ftruncate(tmpfs_fd, 6) == -1) && (errno == EPERM));
    test_assert(ftruncate(tmpfs_fd, 5) == 0);

    addr0 = mmap(NULL, 4096, PROT_WRITE, MAP_SHARED, tmpfs_fd, 0);
    test_assert(addr0 != MAP_FAILED);
    test_assert(fcntl(tmpfs_fd, F_ADD_SEALS, F_SEAL_FUTURE_WRITE) == 0);
    seals = fcntl(tmpfs_fd, F_GET_SEALS);
    test_assert(seals == (F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_FUTURE_WRITE));
    test_assert(lseek(tmpfs_fd, 0, SEEK_SET) == 0);
    test_assert(write(tmpfs_fd, buf, 0) == 0);
    test_assert((write(tmpfs_fd, buf, 1) == -1) && (errno == EPERM));

    /* shared file mapping after F_SEAL_FUTURE_WRITE */
    addr1 = mmap(NULL, 4096, PROT_READ, MAP_SHARED, tmpfs_fd, 0);
    test_assert(addr1 != MAP_FAILED);
    test_assert((mprotect(addr1, 4096, PROT_READ | PROT_WRITE) == -1) && (errno == EACCES));
    munmap(addr1, 4096);
    test_assert(mmap(NULL, 4096, PROT_WRITE, MAP_SHARED, tmpfs_fd, 0) == MAP_FAILED);
    test_assert(errno == EPERM);

    /* F_SEAL_WRITE cannot be added with an existing writable mapping (regardless of its currrent
     * access protection flags). */
    test_assert((fcntl(tmpfs_fd, F_ADD_SEALS, F_SEAL_WRITE) == -1) && (errno == EBUSY));
    test_assert(mprotect(addr0, 4096, PROT_READ) == 0);
    test_assert((fcntl(tmpfs_fd, F_ADD_SEALS, F_SEAL_WRITE) == -1) && (errno == EBUSY));

    munmap(addr0, 4096);
    test_assert(fcntl(tmpfs_fd, F_ADD_SEALS, F_SEAL_WRITE) == 0);
    seals = fcntl(tmpfs_fd, F_GET_SEALS);
    test_assert(seals == (F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_FUTURE_WRITE));

    test_assert(fcntl(tmpfs_fd, F_ADD_SEALS, F_SEAL_SEAL) == 0);
    seals = fcntl(tmpfs_fd, F_GET_SEALS);
    test_assert(seals ==
                (F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_FUTURE_WRITE | F_SEAL_SEAL));

    test_assert(write(tmpfs_fd, buf, 0) == 0);  /* dummy write */

    /* private file mapping of sealed file */
    addr0 = mmap(NULL, 4096, PROT_WRITE, MAP_PRIVATE, tmpfs_fd, 0);
    test_assert(addr0 != MAP_FAILED);
    munmap(addr0, 4096);

    close(tmpfs_fd);
}

int main(int argc, char **argv)
{
    struct flock lock;
    int fd = open("test", O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);

    test_access_mode(fd);

    test_lk(fd, F_GETLK, FAULT_ADDR, EFAULT);

    lock.l_type   = F_WRLCK;
    lock.l_start  = 0;
    lock.l_whence = SEEK_SET;
    lock.l_len    = 0;

    test_lk(fd, F_GETLK,  &lock, 0);
    test_lk(fd, F_SETLK,  &lock, 0);
    test_lk(fd, F_SETLKW, &lock, 0);

    test_dupfd(fd);
    test_seals(fd);

    printf("test passed\n");
    return EXIT_SUCCESS;
}
