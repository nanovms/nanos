#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <sys/vfs.h>

#include "../test_utils.h"

static void test_unlink(const char *path)
{
    struct stat s;

    int fd = open(path, O_CREAT, S_IRWXU);
    if (fd < 0) {
        test_perror("open");
    }
    close(fd);
    if (unlink(path) < 0) {
        test_perror("unlink");
    }
    if ((stat(path, &s) == 0) || (errno != ENOENT)) {
        test_error("file not deleted");
    }
}

static void test_unlinkat(int dirfd)
{
    struct stat s;

    if ((unlinkat(dirfd, FAULT_ADDR, 0) != -1) || (errno != EFAULT)) {
        test_error("unlinkat test with faulting path");
    }

    int fd = openat(dirfd, "file", O_CREAT, S_IRWXU);
    if (fd < 0) {
        test_perror("openat");
    }
    close(fd);
    if ((unlinkat(STDOUT_FILENO, "file", 0) != -1) || (errno != ENOTDIR)) {
        test_error("unlinkat test with invalid dir fd");
    }
    if (unlinkat(dirfd, "file", 0) < 0) {
        test_perror("unlinkat");
    }
    if ((fstatat(dirfd, "file", &s, 0) == 0) || (errno != ENOENT)) {
        test_error("file not deleted");
    }
}

static void test_tmpfile()
{
    int fd;
    struct statfs statbuf;
    char buf[8192];
    char vbuf[8192];

    if (mkdir("/tmp", 0777) != 0 && errno != EEXIST) {
        test_perror("mkdir /tmp");
    }
    statfs("/", &statbuf);
    unsigned long fsfree = statbuf.f_bfree;
    fd = open("/tmp", O_RDONLY|O_TMPFILE, 0666);
    if (fd != -1) {
        test_error("tmpfile rdonly open");
    }
    fd = open("/tmp", O_RDWR|O_TMPFILE, 0666);
    if (fd < 0) {
        test_perror("tmpfile open");
    }
    for (int i = 0; i < sizeof(buf); i++)
        buf[i] = i;
    if (pwrite(fd, buf, sizeof(buf), 0) != sizeof(buf)) {
        test_perror("tmpfile write");
    }
    statfs("/", &statbuf);
    if (statbuf.f_bfree >= fsfree) {
        test_error("bfree check shrink");
    }
    fsfree = statbuf.f_bfree;
    if (pread(fd, vbuf, sizeof(vbuf), 0) != sizeof(vbuf) || memcmp(buf, vbuf, sizeof(buf)) != 0) {
        test_perror("tmpfile read/verify");
    }
    close(fd);
    usleep(8);  /* Give some time to the kernel to deallocate storage space asynchronously. */
    statfs("/", &statbuf);
    if (statbuf.f_bfree <= fsfree) {
        test_error("bfree check grow");
    }
}

int main(int argc, char **argv)
{
    int fd;
    char name_too_long[NAME_MAX + 2];
    struct stat s;

    if ((unlink(FAULT_ADDR) != -1) || (errno != EFAULT)) {
        test_error("unlink test with faulting path");
    }
    if ((unlink("") != -1) || (errno != ENOENT)) {
        test_error("empty path unlink test");
    }

    memset(name_too_long, '-', sizeof(name_too_long) - 1);
    name_too_long[sizeof(name_too_long) - 1] = '\0';
    if ((unlink(name_too_long) != -1) || (errno != ENAMETOOLONG)) {
        test_error("name too long unlink test");
    }
    if ((rmdir(name_too_long) != -1) || (errno != ENAMETOOLONG)) {
        test_error("name too long rmdir test");
    }

    test_unlink("/file");

    if (mkdir("/dir", 0) < 0) {
        test_perror("mkdir");
    }
    fd = open("/dir", 0);
    if (fd < 0) {
        test_perror("open");
    }
    test_unlinkat(fd);
    close(fd);

    fd = open("/dir/file", O_CREAT, S_IRWXU);
    if (fd < 0) {
        test_perror("open");
    }
    if ((unlinkat(fd, "dummy", 0) == 0) || (errno != ENOTDIR)) {
        test_error("non-directory file descriptor unlinkat test");
    }
    close(fd);

    if ((rmdir("/dir") == 0) || (errno != ENOTEMPTY)) {
        test_error("non-empty directory rmdir test");
    }
    test_unlink("/dir/file");
    if ((unlink("/dir") == 0) || (errno != EISDIR)) {
        test_error("directory unlink test");
    }

    if (rmdir("/dir") < 0) {
        test_perror("rmdir");
    }
    if ((stat("/dir", &s) == 0) || (errno != ENOENT)) {
        test_error("directory not deleted");
    }

    if ((unlink("/nonexisting") == 0) || (errno != ENOENT)) {
        test_error("non-existing file unlink test");
    }
    if ((rmdir("/nonexisting") == 0) || (errno != ENOENT)) {
        test_error("non-existing directory rmdir test");
    }
    if ((rmdir("/unlink") == 0) || (errno != ENOTDIR)) {
        test_error("file rmdir test");
    }
    test_unlinkat(AT_FDCWD);
    if ((unlinkat(1234, "file", 0) == 0) || (errno != EBADF)) {
        test_error("bad file descriptor unlinkat test");
    }

    if (mkdir("/dir", 0) < 0) {
        test_perror("mkdir");
    }
    if (unlinkat(1234, "/dir", AT_REMOVEDIR) < 0) {
        test_perror("unlinkat");
    }
    if ((stat("/dir", &s) == 0) || (errno != ENOENT)) {
        test_error("directory not deleted");
    }

    test_tmpfile();

    printf("test passed\n");
    return EXIT_SUCCESS;
}
