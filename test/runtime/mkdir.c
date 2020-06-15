#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/stat.h>
#define _GNU_SOURCE
#define __USE_GNU
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>     /* Defines DT_* constants */
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <libgen.h>


#define EXIT_FAILURE 1

#define handle_error(msg) \
       do { perror(msg); exit(EXIT_FAILURE); } while (0)

struct linux_dirent {
   long           d_ino;
   off_t          d_off;
   unsigned short d_reclen;
   char           d_name[];
};

#define BUF_SIZE 64

int
listdir(const char *label, const char *dir)
{
    int fd, nread;
    char buf[BUF_SIZE];
    struct linux_dirent *d;
    int bpos;
    char d_type;
 
    fd = open(dir, O_RDONLY | O_DIRECTORY);
    if (fd == -1)
        handle_error("open");
 
    for ( ; ; ) {
        nread = syscall(SYS_getdents, fd, buf, BUF_SIZE);
        if (nread == -1)
            handle_error("getdents");
 
        if (nread == 0)
            break;
 
        for (bpos = 0; bpos < nread;) {
            d = (struct linux_dirent *) (buf + bpos);
            d_type = *(buf + bpos + d->d_reclen - 1);
            printf("(%s) - (%s) %-10s ", label, dir, (d_type == DT_REG) ?  "regular" :
                             (d_type == DT_DIR) ?  "directory" :
                             (d_type == DT_FIFO) ? "FIFO" :
                             (d_type == DT_SOCK) ? "socket" :
                             (d_type == DT_LNK) ?  "symlink" :
                             (d_type == DT_BLK) ?  "block dev" :
                             (d_type == DT_CHR) ?  "char dev" : "???");
            printf("%s\n", d->d_name);
            bpos += d->d_reclen;
        }
    }

    close(fd);
    return 0;
}

void _mkdir(const char *path, int m)
{
    errno = 0;
    printf("mkdir(%s, 0x%x) => ", path, m);
    int r = mkdir(path, (mode_t) m);
    if (r) printf("r = %d, errno = %d\n", r, errno);
    int dfd = open(path, O_RDONLY | O_DIRECTORY);
    if (dfd == -1) {
        printf("dfd = %d, for %s, errno = %d\n", dfd, path, errno);
        if (!r) /* couldn't open the directory after having created it */
            exit(EXIT_FAILURE);
    } else {
        close(dfd);
        printf("ok\n");
    }
}

void _mkdirat(int fd, const char *path, int m)
{
    errno = 0;
    printf("mkdirat(%d, %s, 0x%x) => ", fd, path, m);
    int r = mkdirat(fd, path, (mode_t) m);
    printf("r = %d, errno = %d\n", r, errno);
}

void _chdir(const char *path)
{
    errno = 0;
    printf("chdir(%s) => ", path);
    int r = chdir(path);
    printf("r = %d, errno = %d\n", r, errno);

    int path_len = strlen(path);
    char *cwd = malloc(path_len + 1);
    if (!cwd) {
        printf("ERROR - malloc() failed\n");
        exit(EXIT_FAILURE);
    }
    char *ret = getcwd(cwd, path_len);
    if (ret || (errno != ERANGE)) {
        printf("ERROR - getcwd() didn't return ERANGE error\n");
        exit(EXIT_FAILURE);
    }
    ret = getcwd(cwd, path_len + 1);
    if (!ret || strcmp(cwd, path)) {
        printf("ERROR - getcwd() didn't return expected directory\n");
        exit(EXIT_FAILURE);
    }
    free(cwd);
}

void _fchdir(int fd)
{
    errno = 0;
    printf("fchdir(%d) => ", fd);
    int r = fchdir(fd);
    printf("r = %d, errno = %d\n", r, errno);
}

void check(const char *path)
{
    struct stat st;
    int rc;

    rc = stat(path, &st);
    if (rc) {
        printf("      => \"%s\" does not exist.\n", path);
        return;
    }

    if (!S_ISDIR(st.st_mode)) {
        printf("     => \"%s\" is not a directory.\n", path);
        return;
    }
}

static inline int _open(char *path, int flags, mode_t mode, const char *func, int line)
{
    int fd = open(path, flags, mode);
    if (fd == -1) {
        printf("%s(%d): ERROR opening %s, errno = %d\n", func, line, path, errno);
        handle_error("open");
    }
    return fd;
}

static inline int _openat(int dfd, char *path, int flags, mode_t mode, const char *func, int line)
{
    int fd = openat(dfd, path, flags, mode);
    if (fd == -1) {
        printf("%s(%d): ERROR opening %s, errno = %d\n", func, line, path, errno);
    }
    return fd;
}

#define OPEN(PATH, FLAGS, MODE)   _open(PATH, FLAGS, MODE, __func__, __LINE__)
#define OPENAT(DFD,PATH, FLAGS, MODE)   _openat(DFD,PATH, FLAGS, MODE, __func__, __LINE__)

void check2(int dfd, char *fullpath, char *relpath, int flags)
{
    struct stat st;
    int stat_ino = -1;
    int fstat_ino = -1;
    int fstatat_ino = -1;

    int full_fd = OPEN(fullpath, O_RDONLY, 0);
    char *full_dname = dirname(strdup(fullpath));
    int full_dfd = OPEN(full_dname, O_RDONLY | O_DIRECTORY, 0);

    char *rel_dname = dirname(strdup(relpath));
    int rel_dfd = OPENAT(dfd, rel_dname, O_RDONLY | O_DIRECTORY, 0);
    int rel_fd = OPENAT(AT_FDCWD, relpath, O_RDONLY, 0);

    if (!stat(fullpath, &st))
        stat_ino = (int)st.st_ino;
    else {
        printf("ERROR - can't stat %s\n", fullpath);
        exit(EXIT_FAILURE);
    }

    if (!fstat(full_fd, &st))
        fstat_ino = (int)st.st_ino;

    if (stat_ino != fstat_ino)
        printf("ERROR: stat/fstat miscompare(%d,%d)\n", stat_ino, fstat_ino);

    if (!fstatat(200, fullpath, &st, 0))
        fstatat_ino = (int)st.st_ino;

    if (stat_ino != fstatat_ino) {
        printf("ERROR: stat/fstatat (%s)  miscompare(%d,%d)\n", 
            "absolution path",
            stat_ino, fstatat_ino);
    }

    if (!fstatat(AT_FDCWD, fullpath, &st, 0))
        fstatat_ino = (int)st.st_ino;

    if (stat_ino != fstatat_ino) {
        printf("ERROR: stat/fstatat (%s)  miscompare(%d,%d)\n", 
            "absolution path with AT_FDCWD",
            stat_ino, fstatat_ino);
    }

    if (!fstatat(AT_FDCWD, relpath, &st, 0))
        fstatat_ino = (int)st.st_ino;

    if (stat_ino != fstatat_ino) {
        printf("ERROR: stat/fstatat (%s)  miscompare(%d,%d)\n", 
            "relative path with AT_FDCWD",
            stat_ino, fstatat_ino);
    }
    if (!fstatat(dfd, relpath, &st, 0))
        fstatat_ino = (int)st.st_ino;

    if (stat_ino != fstatat_ino) {
        printf("ERROR: stat/fstatat (%s)  miscompare(%d,%d)\n", 
            "relative path with dfd",
            stat_ino, fstatat_ino);
    }
    if (!fstatat(rel_fd, "", &st, AT_EMPTY_PATH))
        fstatat_ino = (int)st.st_ino;

    if (stat_ino != fstatat_ino) {
        printf("ERROR: stat/fstatat (%s)  miscompare(%d,%d)\n", 
            "AT_EMPTY_PATH path with reldfd",
            stat_ino, fstatat_ino);
    }
    close(rel_fd);
    close(rel_dfd);
    close(full_dfd);
    close(full_fd);
}

/* expect = 0 for success, errno otherwise */
void _creat(const char *path, int m, int expect)
{
    printf("creat(%s, 0x%x) => ", path, m);
    int r = creat(path, (mode_t) m);
    if (r < 0) {
        printf("%s\n", strerror(errno));
        if (errno != expect)
            goto fail;
    } else {
        printf("fd %d\n", r);
        close(r);
        if (expect)
            goto fail;
    }
    return;

fail:
    printf("test failed\n");
    //exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
    setbuf(stdout, NULL);

    char c;
    char *cwd = getcwd(&c, 1);
    if (cwd || (errno != ERANGE)) {
        printf("ERROR - getcwd() didn't return ERANGE error\n");
        exit(EXIT_FAILURE);
    }

    _mkdir("/test", 0); check("/test");
    _mkdir("/test_slash/", 0);
    _mkdir("/blurb/test/deep", 0);
    _mkdir("/test/subdir", 0); check("/test/subdir");
    _mkdir("/test/subdira", 0); check("/test/subdira");

    int fd = OPEN("/test", O_DIRECTORY, 0);
    listdir("/","/");
    listdir("/test", "/test");
    _mkdirat(fd, "subdir2", 0); check("/test/subdir2");
    listdir("/","/");
    listdir("/test", "/test");
    _mkdirat(fd, "subdir2/subdir2a", 0); check("/test/subdir2/subdir2a");
    listdir("/","/");
    listdir("/test", "/test");
    listdir("/test/subdir2","/test/subdir2");
    _mkdirat(fd, "/test1", 0); check("/test/test1");
    listdir("/","/");
    listdir("/test", "/test");

    // Validate AT_FDCWD usage
    _mkdirat(AT_FDCWD, "test2", 0); check("/test2");
    listdir("/","/");
    listdir("/test", "/test");

    // Validate it fails on non-directories
    int r = open("/zip", O_WRONLY | O_CREAT, 0644);
    _mkdirat(r, "zipa", 0);
    close(r);
    listdir("/","/");
    listdir("/test", "/test");

    _chdir("/");
    _creat("root_newfile", 0, 0);
    listdir("/",".");
    check2(AT_FDCWD, "/root_newfile", "root_newfile", 0);
    //check2(fd, "/test/subdir/test_newfile", "subdir/test_new_file", 0);

    close(fd);

    fd = OPEN("/test/subdir", O_DIRECTORY, 0);
    _chdir("/test/subdir");
    _mkdir("testdir_from_chdir", 0); check("testdir_from_chdir");
    _creat("test_newfile", 0, 0);
    int tmpfd = OPENAT(AT_FDCWD, "test_newfile2", O_CREAT, 0660);
    close(tmpfd);
    tmpfd = OPENAT(fd, "test_newfile3", O_CREAT, 0660);
    close(tmpfd);
    tmpfd = OPENAT(fd, "test_newfile3", O_RDONLY, 0660);
    close(tmpfd);
    close(fd);

    _chdir("/test/subdir");
    listdir("/test/subdir", ".");
    check2(AT_FDCWD, "/test/subdir/test_newfile", "test_newfile", 0);
    _chdir("/test");
    close(fd);
    fd = OPEN("/test", O_DIRECTORY, 0);
    check2(fd, "/test/subdir/test_newfile", "subdir/test_newfile", 0);
    _fchdir(fd);
    close(fd);
    listdir("test", ".");
    exit(EXIT_SUCCESS);
}
