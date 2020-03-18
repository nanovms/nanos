#include <errno.h>
#define _GNU_SOURCE
#define __USE_GNU
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define test_assert(expr) do { \
    if (!(expr)) { \
        printf("Error: %s -- failed at %s:%d\n", #expr, __FILE__, __LINE__); \
        exit(EXIT_FAILURE); \
    } \
} while (0)

int main(int argc, char **argv)
{
    int fd;
    char buf[8];
    struct stat s;
    char *cwd;

    setbuf(stdout, NULL);

    test_assert(readlink("link", buf, sizeof(buf)) == -1);
    test_assert(errno == ENOENT);

    test_assert(symlink("target", "link") == 0);
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
    close(fd);

    fd = open("target", O_RDWR | O_CREAT, S_IRWXU);
    test_assert(fd >= 0);
    close(fd);
    test_assert(readlink("target", buf, sizeof(buf)) == -1);
    test_assert(errno == EINVAL);
    test_assert((lstat("link", &s) == 0) && ((s.st_mode & S_IFMT) == S_IFLNK));
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
