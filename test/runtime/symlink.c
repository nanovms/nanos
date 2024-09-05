#include <errno.h>
#define _GNU_SOURCE
#define __USE_GNU
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../test_utils.h"

int main(int argc, char **argv)
{
    int fd;
    char buf[8];
    char name_too_long[NAME_MAX + 2];
    char path_too_long[PATH_MAX + 1];
    struct pollfd pfd;
    struct stat s;
    char *cwd;

    test_assert(readlink("/proc/self/exe", buf, sizeof(buf)) > 0);

    test_assert(readlink("link", buf, sizeof(buf)) == -1);
    test_assert(errno == ENOENT);

    test_assert((symlink(FAULT_ADDR, "link") == -1) && (errno == EFAULT));
    test_assert((symlink("target", FAULT_ADDR) == -1) && (errno == EFAULT));
    test_assert((symlinkat(FAULT_ADDR, AT_FDCWD, "link") == -1) && (errno == EFAULT));
    test_assert((symlinkat("target", AT_FDCWD, FAULT_ADDR) == -1) && (errno == EFAULT));

    memset(name_too_long, '-', sizeof(name_too_long) - 1);
    name_too_long[sizeof(name_too_long) - 1] = '\0';
    test_assert((symlink("target", name_too_long) == -1) && (errno == ENAMETOOLONG));
    test_assert((readlink(name_too_long, buf, sizeof(buf)) == -1) && (errno == ENAMETOOLONG));

    memset(path_too_long, '-', sizeof(path_too_long) - 1);
    path_too_long[sizeof(path_too_long) - 1] = '\0';
    test_assert((symlink(path_too_long, "link") == -1) && (errno == ENAMETOOLONG));

    path_too_long[sizeof(path_too_long) - 2] = '\0';
    test_assert(symlink(path_too_long, "link") == 0);
    fd = open("link", O_RDONLY);
    test_assert((fd == -1) && (errno == ENAMETOOLONG));
    test_assert(unlink("link") == 0);

    for (int i = NAME_MAX; i < PATH_MAX - 1; i += NAME_MAX)
        path_too_long[i] = '/';
    test_assert(symlink(path_too_long, "link") == 0);
    fd = open("link", O_RDONLY);
    test_assert((fd == -1) && (errno == ENOENT));
    test_assert(unlink("link") == 0);

    test_assert(symlink("target", "link") == 0);
    test_assert((symlink("target", "link") == -1) && (errno == EEXIST));
    test_assert((readlink("link", FAULT_ADDR, 1) == -1) && (errno == EFAULT));
    test_assert((readlinkat(AT_FDCWD, "link", FAULT_ADDR, 1) == -1) && (errno == EFAULT));
    test_assert((readlinkat(STDOUT_FILENO, "link", buf, sizeof(buf)) == -1) && (errno == ENOTDIR));
    memset(buf, 0, sizeof(buf));
    test_assert((readlink("link", buf, 1) == 1) && (buf[0] == 't'));
    test_assert((readlinkat(AT_FDCWD, "link", buf, 1) == 1) && (buf[0] == 't'));
    test_assert(readlink("link", buf, sizeof(buf)) == strlen("target"));
    test_assert(!strcmp(buf, "target"));

    test_assert((access("link", F_OK) == -1) && (errno == ENOENT));
    test_assert((open("link", O_RDONLY) == -1) && (errno == ENOENT));

    test_assert((open("link", O_RDONLY | O_NOFOLLOW) == -1) &&
            (errno == ELOOP));

    fd = open("link", O_RDONLY | O_NOFOLLOW | O_PATH);
    test_assert(fd >= 0);
    test_assert((fsync(fd) == -1) && (errno == EBADF));
    test_assert((fdatasync(fd) == -1) && (errno == EBADF));
    test_assert((read(fd, buf, sizeof(buf)) == -1) && (errno == EBADF));
    pfd.fd = fd;
    pfd.events = POLLIN | POLLOUT;
    test_assert((poll(&pfd, 1, 0) == 1) && (pfd.revents == POLLNVAL));
    close(fd);

    fd = open("link", O_RDWR | O_NOFOLLOW | O_PATH);
    test_assert(fd >= 0);
    test_assert((write(fd, buf, sizeof(buf)) == -1) && (errno == EBADF));
    close(fd);

    test_assert((faccessat(AT_FDCWD, "link", F_OK, AT_SYMLINK_NOFOLLOW) == 0));
    test_assert((faccessat(AT_FDCWD, "link", R_OK|W_OK, AT_SYMLINK_NOFOLLOW) == 0));
    test_assert((faccessat(AT_FDCWD, "link", X_OK, AT_SYMLINK_NOFOLLOW) == -1 && (errno == EACCES)));
    test_assert((faccessat(AT_FDCWD, "link", F_OK, 0) == -1) && (errno == ENOENT));

    fd = open("target", O_RDWR | O_CREAT, S_IRWXU);
    test_assert(fd >= 0);
    close(fd);

    test_assert((faccessat(AT_FDCWD, "link", F_OK, 0) == 0));
    test_assert((faccessat(AT_FDCWD, "link", X_OK, AT_SYMLINK_NOFOLLOW) == -1 && (errno == EACCES)));
    test_assert((faccessat(AT_FDCWD, "link", X_OK|R_OK|W_OK, 0) == 0));
    test_assert((access("link", F_OK) == 0));
    test_assert((access("link", X_OK|R_OK|W_OK) == 0));

    test_assert(readlink("target", buf, sizeof(buf)) == -1);
    test_assert(errno == EINVAL);
    test_assert((lstat("link", &s) == 0) && ((s.st_mode & S_IFMT) == S_IFLNK));
    test_assert(s.st_size == sizeof("target") - 1);
    test_assert((stat("link", &s) == 0) && ((s.st_mode & S_IFMT) == S_IFREG));
    test_assert(fstatat(AT_FDCWD, "link", &s, AT_SYMLINK_NOFOLLOW) == 0);
    test_assert((s.st_mode & S_IFMT) == S_IFLNK);
    test_assert(fstatat(AT_FDCWD, "link", &s, 0) == 0);
    test_assert((s.st_mode & S_IFMT) == S_IFREG);
    fd = open("link", O_RDONLY);
    test_assert(fd >= 0);
    close(fd);

    test_assert(truncate("link", 1) == 0);
    fd = open("target", O_RDONLY);
    test_assert(fd >= 0);
    test_assert(read(fd, buf, sizeof(buf)) == 1);
    close(fd);

    test_assert(symlink("link", "link1") == 0);
    fd = open("link1", O_RDONLY);
    test_assert(fd >= 0);
    close(fd);

    test_assert(symlinkat("link", AT_FDCWD, "link2") == 0);
    fd = open("link2", O_RDONLY);
    test_assert(fd >= 0);
    close(fd);

    test_assert(symlinkat("link", -1, "/link3") == 0);
    fd = open("link3", O_RDONLY);
    test_assert(fd >= 0);
    close(fd);

    test_assert(mkdir("dir", S_IRWXU) == 0);
    test_assert(symlink("../link", "/dir/link") == 0);
    fd = open("/dir/link", O_RDONLY);
    test_assert(fd >= 0);
    close(fd);

    test_assert((symlink("target", "nonexistent/link") == -1) &&
            (errno == ENOENT));
    test_assert((symlink("target", "target/link") == -1) && (errno == ENOTDIR));

    test_assert(unlink("target") == 0);
    test_assert((open("link", O_RDONLY) == -1) && (errno == ENOENT));
    test_assert((open("link1", O_RDONLY) == -1) && (errno == ENOENT));
    test_assert((open("link2", O_RDONLY) == -1) && (errno == ENOENT));
    test_assert((open("link3", O_RDONLY) == -1) && (errno == ENOENT));
    test_assert((open("/dir/link", O_RDONLY) == -1) && (errno == ENOENT));

    test_assert(symlink("link_to_self", "link_to_self") == 0);
    test_assert((open("link_to_self", O_RDONLY) == -1) && (errno == ELOOP));

    test_assert(symlink("/link_loop0", "link_loop1") == 0);
    test_assert(symlink("/link_loop1", "link_loop0") == 0);
    test_assert((open("link_loop0", O_RDONLY) == -1) && (errno == ELOOP));

    test_assert(symlink("/dir/link_loop3", "link_loop2") == 0);
    test_assert(symlink("../link_loop2", "/dir/link_loop3") == 0);
    test_assert((open("link_loop2", O_RDONLY) == -1) && (errno == ELOOP));

    test_assert(symlink("dir", "dir_link") == 0);
    test_assert((rename("dir", "/dir_link/dir") < 0) && (errno == EINVAL));

    test_assert(symlink("nonexistent", "broken_link") == 0);
    test_assert((rename("dir", "/broken_link/dir") < 0) && (errno == ENOENT));

    test_assert(chdir("/dir_link") == 0);
    cwd = getcwd(buf, sizeof(buf));
    test_assert(cwd && !strcmp(cwd, "/dir"));

    printf("Test passed\n");
    return EXIT_SUCCESS;
}
