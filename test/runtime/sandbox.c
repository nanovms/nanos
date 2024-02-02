#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "../test_utils.h"

static int pledge(const char *promises, const char *execpromises)
{
    return syscall(335, promises, execpromises);
}

static int unveil(const char *path, const char *permissions)
{
    return syscall(336, path, permissions);
}

static void test_unveil_symlink(void)
{
    const char *link_name = "link";
    const char *target_name = "sandbox";
    char buf[8];
    int fd;

    /* link_name is veiled */
    test_assert((symlink(target_name, link_name) == -1) && (errno == ENOENT));

    test_assert(unveil(link_name, "c") == 0);
    test_assert(symlink(target_name, link_name) == 0);

    /* link_name does not have read permissions */
    test_assert((readlink(link_name, buf, sizeof(buf)) == -1) && (errno == EACCES));

    /* target_name is veiled */
    fd = open(link_name, O_RDONLY);
    test_assert((fd == -1) && (errno == ENOENT));

    test_assert(unveil(target_name, "r") == 0);
    fd = open(link_name, O_RDONLY);
    test_assert(fd > 0);
    close(fd);

    test_assert(unlink(link_name) == 0);
}

static void test_unveil_unixsock(void)
{
    const char *sock_name = "sock";
    int fd;
    struct sockaddr_un addr;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    test_assert(fd > 0);

    /* sock_name is veiled */
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, sock_name);
    test_assert((bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) && (errno == ENOENT));

    test_assert(unveil(sock_name, "c") == 0);
    test_assert(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    test_assert(access(sock_name, F_OK) == 0);
    test_assert((access(sock_name, R_OK) == -1) && (errno == EACCES));
    test_assert((access(sock_name, W_OK) == -1) && (errno == EACCES));
    test_assert(unlink(sock_name) == 0);

    /* remove create permissions */
    test_assert(unveil(sock_name, "") == 0);
    test_assert((bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) && (errno == EACCES));

    close(fd);
}

static void test_unveil_truncate(void)
{
    const char *file_name = "trunc";
    int fd;

    test_assert(unveil(file_name, "wc") == 0);
    fd = creat(file_name, 0644);
    test_assert(fd > 0);
    close(fd);
    test_assert(truncate(file_name, 0) == 0);

    /* remove write permissions */
    test_assert(unveil(file_name, "c") == 0);
    test_assert((truncate(file_name, 0) == -1) && (errno == EACCES));

    test_assert(unlink(file_name) == 0);
}

static void test_unveil_rename(void)
{
    const char *file1_name = "file1";
    const char *file2_name = "file2";
    int fd;

    test_assert((creat(file1_name, 0644) == -1) && (errno == ENOENT));  /* file1_name is veiled */

    test_assert(unveil(file1_name, "wc") == 0);
    fd = creat(file1_name, 0644);
    test_assert(fd > 0);
    close(fd);

    /* file2_name is veiled */
    test_assert((rename(file1_name, file2_name) == -1) && (errno == ENOENT));

    test_assert(unveil(file2_name, "c") == 0);
    test_assert(rename(file1_name, file2_name) == 0);
    test_assert(unlink(file2_name) == 0);
}

static void test_unveil(void)
{
    int fd;

    test_assert(unveil("nonexistent", "wc") == 0);
    fd = creat("nonexistent", 0644);
    test_assert(fd > 0);
    close(fd);
    test_assert((open("nonexistent", O_RDONLY) == -1) && (errno == EACCES));
    test_assert(unlink("nonexistent") == 0);

    /* remove create permissions */
    test_assert(unveil("nonexistent", "w") == 0);
    test_assert((creat("nonexistent", 0644) == -1) && (errno == EACCES));

    test_assert((unlink((const char *)1) == -1) && (errno == EFAULT));
    test_assert((unlink("sandbox") == -1) && (errno == ENOENT));    /* path is veiled */

    test_assert((unveil("nonexistent-dir/", "c") == -1) && (errno == ENOENT));

    /* create a directory by using an unveil entry in the parent directory */
    test_assert(unveil("/dir", "c") == 0);
    test_assert((mkdir("/dir", 0755) == 0) && (rmdir("dir") == 0));

    /* try to unveil a file in a nonexistent directory */
    test_assert((unveil("dir/f", "wc") == -1) && (errno == ENOENT));

    /* create a file by using an unveil entry in the parent directory */
    test_assert(mkdir("dir", 0755) == 0);
    test_assert(unveil("dir/f", "wc") == 0);
    fd = creat("dir/f", 0644);
    test_assert((fd > 0) && (unlink("dir/f") == 0));
    close(fd);
    test_assert(rmdir("dir") == 0);

    test_assert(unveil("d1", "c") == 0);
    test_assert(mkdir("d1", 0755) == 0);
    test_assert(mkdir("d1/d2", 0755) == 0);
    test_assert(mkdir("d1/d2/d3", 0755) == 0);
    test_assert(mkdir("d1/d2/d3/d4", 0755) == 0);
    test_assert(mkdir("d1/d2/d3/d4/d5", 0755) == 0);
    test_assert(rmdir("d1/d2/d3/d4/d5") == 0);
    test_assert(rmdir("d1/d2/d3/d4") == 0);
    test_assert(rmdir("d1/d2/d3") == 0);
    test_assert(rmdir("d1/d2") == 0);
    test_assert(rmdir("d1") == 0);

    test_unveil_symlink();
    test_unveil_unixsock();
    test_unveil_truncate();
    test_unveil_rename();
    test_assert(unveil("/", "rwxc") == 0);

    /* try to change unveil permissions after disabling unveil calls */
    test_assert(unveil(NULL, NULL) == 0);
    test_assert((unveil("/", "r") == -1) && (errno == EPERM));
}

static void test_pledge(void)
{
    void *mem;
    int fd;

    test_assert(pledge(NULL, NULL) == 0);   /* no-op */
    test_assert((pledge("invalid", NULL) == -1) && (errno == EINVAL));

    test_assert(pledge("stdio rpath cpath tmppath unix error", NULL) == 0);
    fd = open("sandbox", O_RDONLY);
    test_assert(fd > 0);
    close(fd);
    test_assert((mkdir("dir", 0755) == 0) && (rmdir("dir") == 0));

    /* remove rpath and cpath, keeping tmppath */
    test_assert(pledge("stdio tmppath unix error", NULL) == 0);
    test_assert((open("sandbox", O_RDONLY) == -1) && (errno == ENOSYS));
    test_assert((mkdir("dir", 0755) == -1) && (errno == ENOSYS));
    test_assert((open("/tmp/foo", O_RDONLY) == -1) && (errno == ENOENT));

    /* remove tmppath */
    test_assert(pledge("stdio unix error", NULL) == 0);
    test_assert((open("/tmp/foo", O_RDONLY) == -1) && (errno == ENOSYS));

    /* missing prot_exec promise */
    test_assert(mmap(0, 4096, PROT_EXEC, MAP_ANONYMOUS | MAP_SHARED, -1, 0) == MAP_FAILED);
    test_assert(errno == ENOSYS);
    mem = mmap(0, 4096, PROT_READ, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    test_assert(mem != MAP_FAILED);
    test_assert(munmap(mem, 4096) == 0);

    /* try to add a new promise */
    test_assert((pledge("inet", NULL) == -1) && (errno == EPERM));

    /* unix promise */
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    test_assert(fd > 0);
    close(fd);

    /* missing inet promise */
    test_assert((socket(AF_INET, SOCK_STREAM, 0) == -1) && (errno == ENOSYS));
}

int main(int argc, char *argv[])
{
    test_unveil();
    test_pledge();
    printf("Sandbox tests OK\n");
    return 0;
}
