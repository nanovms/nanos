#define _GNU_SOURCE
#include <dirent.h>     /* Defines DT_* constants */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#include "../test_utils.h"

struct linux_dirent {
   long           d_ino;
   off_t          d_off;
   unsigned short d_reclen;
   char           d_name[];
};

struct linux_dirent64 {
    unsigned long long            d_ino;    /* 64-bit inode number */
    unsigned long long            d_off;    /* 64-bit offset to next structure */
    unsigned short d_reclen; /* Size of this dirent */
    unsigned char  d_type;   /* File type */
    char           d_name[]; /* Filename (null-terminated) */
};


#define BUF_SIZE 64

#define DO_GETDENTS(SYSCALL, STRUCT, DTYPE) do { \
   struct STRUCT *d; \
   int nread; \
   char buf[BUF_SIZE]; \
   int bpos; \
   char d_type; \
   for ( ; ; ) { \
       nread = syscall(SYSCALL, fd, buf, BUF_SIZE); \
       if (nread == -1) \
           test_perror("getdents"); \
       if (nread == 0) \
           break; \
       printf("--------------- nread=%d ---------------\n", nread); \
       printf("inode#    file type  d_reclen  d_off   d_name\n"); \
       for (bpos = 0; bpos < nread;) { \
           d = (struct STRUCT *) (buf + bpos); \
	        struct stat st; \
           printf("%8lld  ", (long long) d->d_ino); \
           d_type = (DTYPE); \
           printf("%-10s ", (d_type == DT_REG) ?  "regular" : \
                            (d_type == DT_DIR) ?  "directory" : \
                            (d_type == DT_FIFO) ? "FIFO" : \
                            (d_type == DT_SOCK) ? "socket" : \
                            (d_type == DT_LNK) ?  "symlink" : \
                            (d_type == DT_BLK) ?  "block dev" : \
                            (d_type == DT_CHR) ?  "char dev" : "???"); \
           printf("%4d %10lld  %s\n", d->d_reclen, \
                   (long long) d->d_off, d->d_name); \
           bpos += d->d_reclen; \
           if ((lstat(d->d_name, &st) != -1) && (d->d_ino != st.st_ino)) { \
                printf("ERROR - getdent entry ino (%8lld) doesn't match stat's ino (%8ld)\n", (long long) d->d_ino, st.st_ino); \
           } \
       } \
   } \
} while (0)

#define OPEN_DIR(NAME) do { \
   fd = open(NAME, O_RDONLY | O_DIRECTORY); \
   if (fd == -1) \
       test_perror("open"); \
} while(0)

int
main(int argc, char *argv[])
{
    int fd;
    char *dirname = (argc > 1 ? argv[1] : ".");
    struct pollfd pfd;
    long rv;
    DIR *dir;

#ifdef __x86_64__
    OPEN_DIR(dirname);
    DO_GETDENTS(SYS_getdents, linux_dirent, (*(buf + bpos + d->d_reclen - 1)));
    close(fd);
#endif
    OPEN_DIR(dirname);
    pfd.fd = fd;
    pfd.events = POLLIN | POLLOUT;
    rv = poll(&pfd, 1, 0);
    if (rv != 1) {
        printf("unexpected poll return value %ld on dir fd\n", rv);
        exit(EXIT_FAILURE);
    }
    if (pfd.revents != (POLLIN | POLLOUT)) {
        printf("unexpected poll events 0x%x on dir fd\n", pfd.revents);
        exit(EXIT_FAILURE);
    }
    DO_GETDENTS(SYS_getdents64, linux_dirent64, d->d_type);
    close(fd);

    dir = opendir(dirname);
    if (!dir)
        test_perror("opendir");
    fd = dirfd(dir);
    if (fd < 0)
        test_perror("dirfd");
    rv = lseek(fd, 1, SEEK_END);
    if ((rv != -1) || (errno != EINVAL)) {
        printf("unexpected lseek results (%ld, %d)\n", rv, errno);
        exit(EXIT_FAILURE);
    }
    if (lseek(fd, 0, SEEK_END) < 0)
        test_perror("lseek");
    if (readdir(dir) != NULL) {
        printf("unexpected dir entry after lseek\n");
        exit(EXIT_FAILURE);
    }
    closedir(dir);

    exit(EXIT_SUCCESS);
}
