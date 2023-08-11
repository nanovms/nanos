#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <sys/vfs.h>

#define FAULT_ADDR  ((void *)0xBADF0000)

static void test_unlink(const char *path)
{
    struct stat s;

    int fd = open(path, O_CREAT, S_IRWXU);
    if (fd < 0) {
        perror("open");
        exit(EXIT_FAILURE);
    }
    close(fd);
    if (unlink(path) < 0) {
        perror("unlink");
        exit(EXIT_FAILURE);
    }
    if ((stat(path, &s) == 0) || (errno != ENOENT)) {
        printf("file not deleted\n");
        exit(EXIT_FAILURE);
    }
}

static void test_unlinkat(int dirfd)
{
    struct stat s;

    if ((unlinkat(dirfd, FAULT_ADDR, 0) != -1) || (errno != EFAULT)) {
        printf("unlinkat test with faulting path failed\n");
        exit(EXIT_FAILURE);
    }

    int fd = openat(dirfd, "file", O_CREAT, S_IRWXU);
    if (fd < 0) {
        perror("openat");
        exit(EXIT_FAILURE);
    }
    close(fd);
    if ((unlinkat(STDOUT_FILENO, "file", 0) != -1) || (errno != ENOTDIR)) {
        printf("unlinkat test with invalid dir fd failed\n");
        exit(EXIT_FAILURE);
    }
    if (unlinkat(dirfd, "file", 0) < 0) {
        perror("unlinkat");
        exit(EXIT_FAILURE);
    }
    if ((fstatat(dirfd, "file", &s, 0) == 0) || (errno != ENOENT)) {
        printf("file not deleted\n");
        exit(EXIT_FAILURE);
    }
}

static void test_tmpfile()
{
    int fd;
    struct statfs statbuf;
    char buf[8192];
    char vbuf[8192];

    if (mkdir("/tmp", 0777) != 0 && errno != EEXIST) {
        perror("mkdir /tmp");
        exit(EXIT_FAILURE);
    }
    statfs("/", &statbuf);
    unsigned long fsfree = statbuf.f_bfree;
    fd = open("/tmp", O_RDONLY|O_TMPFILE, 0666);
    if (fd != -1) {
        perror("tmpfile rdonly open");
        exit(EXIT_FAILURE);
    }
    fd = open("/tmp", O_RDWR|O_TMPFILE, 0666);
    if (fd < 0) {
        perror("tmpfile open");
        exit(EXIT_FAILURE);
    }
    for (int i = 0; i < sizeof(buf); i++)
        buf[i] = i;
    if (pwrite(fd, buf, sizeof(buf), 0) != sizeof(buf)) {
        perror("tmpfile write");
        exit(EXIT_FAILURE);
    }
    statfs("/", &statbuf);
    if (statbuf.f_bfree >= fsfree) {
        perror("bfree check shrink");
        exit(EXIT_FAILURE);
    }
    fsfree = statbuf.f_bfree;
    if (pread(fd, vbuf, sizeof(vbuf), 0) != sizeof(vbuf) || memcmp(buf, vbuf, sizeof(buf)) != 0) {
        perror("tmpfile read/verify");
        exit(EXIT_FAILURE);
    }
    close(fd);
    usleep(8);  /* Give some time to the kernel to deallocate storage space asynchronously. */
    statfs("/", &statbuf);
    if (statbuf.f_bfree <= fsfree) {
        printf("bfree check grow\n");
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char **argv)
{
    int fd;
    char name_too_long[NAME_MAX + 2];
    struct stat s;

    if ((unlink(FAULT_ADDR) != -1) || (errno != EFAULT)) {
        printf("unlink test with faulting path failed\n");
        exit(EXIT_FAILURE);
    }
    if ((unlink("") != -1) || (errno != ENOENT)) {
        printf("empty path unlink test failed\n");
        exit(EXIT_FAILURE);
    }

    memset(name_too_long, '-', sizeof(name_too_long) - 1);
    name_too_long[sizeof(name_too_long) - 1] = '\0';
    if ((unlink(name_too_long) != -1) || (errno != ENAMETOOLONG)) {
        printf("name too long unlink test failed\n");
        return EXIT_FAILURE;
    }
    if ((rmdir(name_too_long) != -1) || (errno != ENAMETOOLONG)) {
        printf("name too long rmdir test failed\n");
        return EXIT_FAILURE;
    }

    test_unlink("/file");

    if (mkdir("/dir", 0) < 0) {
        perror("mkdir");
        return EXIT_FAILURE;
    }
    fd = open("/dir", 0);
    if (fd < 0) {
        perror("open");
        return EXIT_FAILURE;
    }
    test_unlinkat(fd);
    close(fd);

    fd = open("/dir/file", O_CREAT, S_IRWXU);
    if (fd < 0) {
        perror("open");
        return EXIT_FAILURE;
    }
    if ((unlinkat(fd, "dummy", 0) == 0) || (errno != ENOTDIR)) {
        printf("non-directory file descriptor unlinkat test failed\n");
        exit(EXIT_FAILURE);
    }
    close(fd);

    if ((rmdir("/dir") == 0) || (errno != ENOTEMPTY)) {
        printf("non-empty directory rmdir test failed\n");
        return EXIT_FAILURE;
    }
    test_unlink("/dir/file");
    if ((unlink("/dir") == 0) || (errno != EISDIR)) {
        printf("directory unlink test failed\n");
        exit(EXIT_FAILURE);
    }

    if (rmdir("/dir") < 0) {
        perror("rmdir");
        return EXIT_FAILURE;
    }
    if ((stat("/dir", &s) == 0) || (errno != ENOENT)) {
        printf("directory not deleted\n");
        exit(EXIT_FAILURE);
    }

    if ((unlink("/nonexisting") == 0) || (errno != ENOENT)) {
        printf("non-existing file unlink test failed\n");
        return EXIT_FAILURE;
    }
    if ((rmdir("/nonexisting") == 0) || (errno != ENOENT)) {
        printf("non-existing directory rmdir test failed\n");
        return EXIT_FAILURE;
    }
    if ((rmdir("/unlink") == 0) || (errno != ENOTDIR)) {
        printf("file rmdir test failed\n");
        return EXIT_FAILURE;
    }
    test_unlinkat(AT_FDCWD);
    if ((unlinkat(1234, "file", 0) == 0) || (errno != EBADF)) {
        printf("bad file descriptor unlinkat test failed\n");
        return EXIT_FAILURE;
    }

    if (mkdir("/dir", 0) < 0) {
        perror("mkdir");
        return EXIT_FAILURE;
    }
    if (unlinkat(1234, "/dir", AT_REMOVEDIR) < 0) {
        perror("unlinkat");
        return EXIT_FAILURE;
    }
    if ((stat("/dir", &s) == 0) || (errno != ENOENT)) {
        printf("directory not deleted\n");
        exit(EXIT_FAILURE);
    }

    test_tmpfile();

    printf("test passed\n");
    return EXIT_SUCCESS;
}
