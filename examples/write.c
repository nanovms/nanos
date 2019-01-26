#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

#define BUFLEN 512

static char *str1 = "00ABCDEFGHIJKLMNOPQRSTUVWXYZ00";
static char *str2 = "11abcdefghijklmnopqrstuvwxyz11";
static char buf[BUFLEN * 4];

static inline ssize_t  READ(int fd, char *buf, ssize_t size)
{   
    memset(buf, 0xff, size); 
    ssize_t _rv = read(fd, buf, size);
    if (_rv < 0) {
        perror("read #1");
        close(fd);
        exit( EXIT_FAILURE);
    }
    return _rv;
}

#define  CHECK(FD, EXPECTED) do { \
    struct stat st; \
    int rc; \
    rc = fstat((FD), &st); \
    if (st.st_size != (EXPECTED)) { \
        printf("%d: file size mismatch! Got %d, expected %d\n", __LINE__, (int)st.st_size, (int)(EXPECTED)); \
        exit(EXIT_FAILURE); \
    } \
} while(0)


#define SEEK(FD,WHERE,HOW) do { \
    if (lseek(FD, WHERE, HOW) < 0) { \
        perror("lseek #1"); \
        goto out_fail; \
    } \
} while (0)

#define WRITE(FD,BUF,LEN) do { \
    if (write(FD, BUF, LEN) < LEN) { \
        perror("write"); \
        goto out_fail; \
    } \
} while (0)


int main(int argc, char **argv)
{
    ssize_t rv;
    ssize_t initial_size;
    int len = strlen(str1);
    int len2 = strlen(str2);

    int fd = open("/hello-new", O_CREAT, O_RDWR);
    if (fd < 0) {
        perror("open");
        return EXIT_FAILURE;
    }

    WRITE(fd, str1, len);
    SEEK(fd,0,SEEK_SET);
    initial_size = rv = READ(fd, buf, 256);

    if (rv == 0)
        printf("empty source file\n");

    CHECK(fd, len);

   if (rv >= BUFLEN)
        rv = BUFLEN - 1;

    buf[rv] = '\0';
    printf("original: \"%s\" rv %d initial_size %d\n", buf, (int)rv, (int)initial_size);

    SEEK(fd,0,SEEK_SET);
    rv = READ(fd, buf, 256 * 3);
    buf[rv] = '\0';
    printf("next: \"%s\" size %d\n", buf, (int)rv);
    SEEK(fd,0,SEEK_SET);

    /* Not to worry about signals, etc... */
    WRITE(fd, str1, len);
    WRITE(fd, str2, len2);
    SEEK(fd,0,SEEK_SET);
    rv = READ(fd, buf, 256 * 3);
    buf[rv] = '\0';
    printf("next: \"%s\" size %d\n", buf+30, (int)rv);
    CHECK(fd, len + len2);
    WRITE(fd, buf, 513);
    CHECK(fd, len + len2 + 513);
    SEEK(fd,0,SEEK_SET);
    WRITE(fd, buf, 515 * 3);
    CHECK(fd, 515 * 3);
    // now, we move to offset 10 and write same amout, the file should just be extended 10 bytes
    SEEK(fd,10,SEEK_SET);
    WRITE(fd, buf, 515 * 3);
    CHECK(fd, (515 * 3) + 10);
    SEEK(fd,1000,SEEK_SET);
    WRITE(fd, buf, 515 * 3);
    CHECK(fd, (515 * 3) + 1000); // 2545

    SEEK(fd,500,SEEK_SET);
    WRITE(fd, buf, 30);
    WRITE(fd, buf, 512);
    CHECK(fd, (515 * 3) + 1000);
    SEEK(fd,0,SEEK_SET);
    WRITE(fd, buf, 1024);
    CHECK(fd, (515 * 3) + 1000); //2545
    SEEK(fd,0,SEEK_END); // this puts us at end, so next write extends file
    WRITE(fd, buf, 1024 + len2);
    CHECK(fd, (515 * 3) + 1000 + 1024 + len2);
    // create hole
    SEEK(fd,5000,SEEK_SET);
    WRITE(fd, buf, 1024);
    CHECK(fd, 5000 + 1024);
    SEEK(fd,480,SEEK_SET);
    WRITE(fd, buf, 1024);
    CHECK(fd, 5000 + 1024);
    close(fd);
    len = 0;
    len2 = 0;
    return EXIT_SUCCESS;
  out_fail:
    close(fd);
    return EXIT_FAILURE;
}
