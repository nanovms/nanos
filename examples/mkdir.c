#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <errno.h>
#define _GNU_SOURCE
#include <dirent.h>     /* Defines DT_* constants */
#include <unistd.h>
#include <stdlib.h>
#include <sys/syscall.h>

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
listdir(char *dir)
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
           printf("%-10s ", (d_type == DT_REG) ?  "regular" :
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
    return 0;
}

void _mkdir(const char *path, int m)
{
    errno = 0;
    printf("mkdir(%s, 0x%x) => ", path, m);
    int r = mkdir(path, (mode_t) m);
    printf("r = %d, errno = %d\n", r, errno);
}

void _mkdirat(int fd, const char *path, int m)
{
    errno = 0;
    printf("mkdirt(%s, 0x%x) => ", path, m);
    int r = mkdirat(fd, path, (mode_t) m);
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

int main(int argc, char **argv)
{
    _mkdir("/test", 0); check("/test");
    _mkdir("/blurb/test/deep", 0);
    _mkdir("/test/subdir", 0); check("/test/subdir");
    _mkdir("/test/subdira", 0); check("/test/subdira");

    int fd = open("/test", O_DIRECTORY);
    if (fd == -1) {
        handle_error("open");
    }
    listdir("/");
    listdir("/test");
    _mkdirat(fd, "subdir2", 0); check("/test/subdir2");
    listdir("/");
    listdir("/test");
    _mkdirat(fd, "subdir2/subdir2a", 0); check("/test/subdir2/subdir2a");
    listdir("/");
    listdir("/test");
    listdir("/test/subdir2");
    _mkdirat(fd, "/test1", 0); check("/test1");
    listdir("/");
    listdir("/test");
}
