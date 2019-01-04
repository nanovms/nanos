#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#define BUFLEN 256

static char *str = "This seems to have worked.";
static char buf[BUFLEN];

int main(int argc, char **argv)
{
    ssize_t rv;
    int fd = open("/hello", O_CREAT, O_RDWR);
    if (fd < 0) {
        perror("open");
        return EXIT_FAILURE;
    }
    printf("open succeeded, fd %d\n", fd);

    rv = read(fd, buf, 256);
    if (rv < 0) {
        perror("read #1");
        goto out_fail;
    }

    if (rv == 0)
        printf("empty source file\n");

    if (rv >= BUFLEN)
        rv = BUFLEN - 1;
    buf[rv] = '\0';
    printf("original: \"%s\"\n", buf);
    if (lseek(fd, 0, SEEK_SET) < 0) {
        perror("lseek #1");
        goto out_fail;
    }

    /* Not to worry about signals, etc... */
    int len = strlen(str);
    if (write(fd, str, len) < len) {
        perror("write");
        goto out_fail;
    }

    if (lseek(fd, 0, SEEK_SET) < 0) {
        perror("lseek #2");
        goto out_fail;
    }

    memset(buf, 0, 256);

    rv = read(fd, buf, 256);
    if (rv < 0) {
        perror("read #2");
        goto out_fail;
    }

    if (rv != len) {
        printf("read #2 fail: expecting %d bytes, rv: %d\n", len, rv);
        goto out_fail;
    }

    printf("new: \"%s\"\n", buf);
    close(fd);
    return EXIT_SUCCESS;
  out_fail:
    close(fd);
    return EXIT_FAILURE;
}
