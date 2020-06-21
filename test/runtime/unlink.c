#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

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

    int fd = openat(dirfd, "file", O_CREAT, S_IRWXU);
    if (fd < 0) {
        perror("openat");
        exit(EXIT_FAILURE);
    }
    close(fd);
    if (unlinkat(dirfd, "file", 0) < 0) {
        perror("unlinkat");
        exit(EXIT_FAILURE);
    }
    if ((fstatat(dirfd, "file", &s, 0) == 0) || (errno != ENOENT)) {
        printf("file not deleted\n");
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char **argv)
{
    int fd;
    struct stat s;

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

    printf("test passed\n");
    return EXIT_SUCCESS;
}
