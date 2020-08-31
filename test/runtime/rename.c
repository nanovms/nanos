#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "runtime.h"

#define test_assert(expr) do { \
    if (!(expr)) { \
        printf("Error: %s -- failed at %s:%d\n", #expr, __FILE__, __LINE__); \
        exit(EXIT_FAILURE); \
    } \
} while (0)

static void test_rename(const char *oldpath, const char *newpath)
{
    struct stat s;

    int fd = open(oldpath, O_CREAT, S_IRWXU);
    test_assert(fd >= 0);
    close(fd);
    test_assert(rename(oldpath, newpath) == 0);
    test_assert((stat(oldpath, &s) < 0) && (errno == ENOENT));
    test_assert(stat(newpath, &s) == 0);

    /* Replacement of an existing path. */
    fd = open(oldpath, O_CREAT, S_IRWXU);
    test_assert(fd >= 0);
    close(fd);
    test_assert(rename(newpath, oldpath) == 0);
    test_assert((stat(newpath, &s) < 0) && (errno == ENOENT));
    test_assert(stat(oldpath, &s) == 0);

    /* Dummy rename. */
    test_assert(rename(oldpath, oldpath) == 0);
    test_assert(stat(oldpath, &s) == 0);

    /* Directory rename. */
    test_assert(unlink(oldpath) == 0);
    test_assert(mkdir(oldpath, 0) == 0);
    test_assert(rename(oldpath, newpath) == 0);
    test_assert((stat(oldpath, &s) < 0) && (errno == ENOENT));
    test_assert(stat(newpath, &s) == 0);

    /* Replacement of an existing empty directory. */
    test_assert(mkdir(oldpath, 0) == 0);
    test_assert(rename(newpath, oldpath) == 0);
    test_assert((stat(newpath, &s) < 0) && (errno == ENOENT));
    test_assert(stat(oldpath, &s) == 0);
}

static void test_renameat(int olddirfd, int newdirfd)
{
    struct stat s;

    int fd = openat(olddirfd, "file1", O_CREAT, S_IRWXU);
    test_assert(fd >= 0);
    close(fd);
    test_assert(renameat(olddirfd, "file1", newdirfd, "file2") == 0);
    test_assert((fstatat(olddirfd, "file1", &s, 0) < 0) && (errno == ENOENT));
    test_assert(fstatat(newdirfd, "file2", &s, 0) == 0);
}

static void test_renameat2(int olddirfd, int newdirfd)
{
    struct stat s;

    int fd = openat(olddirfd, "file", O_CREAT, S_IRWXU);
    test_assert(fd >= 0);
    close(fd);
    test_assert((syscall(SYS_renameat2, olddirfd, "file", newdirfd, "dir",
            RENAME_EXCHANGE) < 0) && (errno == ENOENT));
    test_assert(mkdirat(newdirfd, "dir", 0) == 0);
    test_assert((syscall(SYS_renameat2, olddirfd, "file", newdirfd, "dir",
            RENAME_NOREPLACE) < 0) && (errno == EEXIST));
    test_assert((syscall(SYS_renameat2, olddirfd, "file", newdirfd, "dir",
            RENAME_NOREPLACE | RENAME_EXCHANGE) < 0) && (errno == EINVAL));
    test_assert((syscall(SYS_renameat2, olddirfd, "file", newdirfd, "dir",
            (unsigned int)-1) < 0) && (errno == EINVAL));
    test_assert(syscall(SYS_renameat2, olddirfd, "file", newdirfd, "dir",
            RENAME_EXCHANGE) == 0);
    test_assert((fstatat(olddirfd, "file", &s, 0) == 0) &&
            (s.st_mode & S_IFDIR));
    test_assert((fstatat(newdirfd, "dir", &s, 0) == 0) &&
            (s.st_mode & S_IFREG));
}

int main(int argc, char **argv)
{
    int fd1, fd2;

    test_rename("/file1", "/file2");

    test_assert(mkdir("/dir1", 0) == 0);
    fd1 = open("/dir1", 0);
    test_assert(fd1 >= 0);
    test_assert(mkdir("/dir2", 0) == 0);
    fd2 = open("/dir2", 0);
    test_assert(fd2 >= 0);
    test_renameat(fd1, fd2);
    test_renameat2(fd1, fd2);
    close(fd1);
    test_assert((syscall(SYS_renameat2, fd1, "file", fd2, "file", 0) < 0) &&
            (errno == EBADF));
    close(fd2);

    fd2 = open("/dir2/my_file", O_CREAT, S_IRWXU);
    test_assert(fd2 >= 0);
    close(fd2);
    test_assert((rename("/dir1", "/dir2") < 0) &&
            ((errno == ENOTEMPTY) || (errno == EEXIST)));

    test_assert((rename("/dir1", "/dir1/dir2") < 0) && (errno == EINVAL));

    test_assert(mkdir("dir1/dir2", 0) == 0);
    test_assert(chdir("dir1/dir2") == 0);
    test_assert(rename("..", "dir3") < 0);

    fd1 = open("/my_file", O_CREAT, S_IRWXU);
    test_assert(fd1 >= 0);
    close(fd1);
    test_assert(mkdir("/my_dir", 0) == 0);
    test_assert((rename("/my_file", "/my_dir") < 0) && (errno == EISDIR));
    test_assert((rename("/my_dir", "/my_file") < 0) && (errno == ENOTDIR));

    test_assert((rename("/nonexisting", "/my_dir") < 0) && (errno == ENOENT));
    test_assert((rename("/my_file", "/nonexisting/my_file") < 0) &&
            (errno == ENOENT));
    test_assert((rename("/my_file", "") < 0) && (errno == ENOENT));
    test_assert((rename("", "/my_file") < 0) && (errno == ENOENT));

    printf("Test passed\n");
    return EXIT_SUCCESS;
}
