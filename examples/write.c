#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <limits.h>

#define BUFLEN 256

static char *str = "This seems to have worked.";

#define _READ(b, l)                             \
    rv = read(fd, b, l);                        \
    if (rv < 0) {                               \
        perror("read");                         \
        goto out_fail;                          \
    }

#define _LSEEK(o, w)                            \
    rv = lseek(fd, o, w);                       \
    if (rv < 0) {                               \
        perror("lseek");                        \
        goto out_fail;                          \
    }

#define _WRITE(b, l)                            \
    rv = write(fd, b, l);                       \
    if (rv < l) {                               \
        perror("write");                        \
        goto out_fail;                          \
    }

void basic_write_test()
{
    char buf[BUFLEN];
    ssize_t rv;
    int fd = open("hello", O_RDWR);
    if (fd < 0) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    _READ(buf, BUFLEN);

    if (rv == 0)
        printf("empty source file\n");

    if (rv >= BUFLEN)
        rv = BUFLEN - 1;
    buf[rv] = '\0';
    printf("original: \"%s\"\n", buf);

    _LSEEK(0, SEEK_SET);

    /* Not to worry about signals, etc... */
    ssize_t len = strlen(str);
    _WRITE(str, len);

    _LSEEK(0, SEEK_SET);

    memset(buf, 0, BUFLEN);

    _READ(buf, BUFLEN);

    if (rv != len) {
        printf("read #2 fail: expecting %ld bytes, rv: %ld\n", len, rv);
        goto out_fail;
    }

    printf("new: \"%s\"\n", buf);

    if (strncmp(str, buf, strlen(str))) {
        printf("basic write fail: string mismatch\n");
        exit(EXIT_FAILURE);
    }
    close(fd);
    printf("basic write test passed\n");
    return;
  out_fail:
    close(fd);
    exit(EXIT_FAILURE);
}

#define min(x, y) ((x) < (y) ? (x) : (y))
#define SCATTER_BUFLEN  2048
#define SCATTER_ITERATIONS 4
#define _random(x) (labs(random()))
void scatter_write_test()
{
    ssize_t rv;
    char tmp[BUFLEN];
    char * buf = malloc(SCATTER_BUFLEN);
    if (!buf) {
        printf("malloc of size %d failed\n", SCATTER_BUFLEN);
        exit(EXIT_FAILURE);
    }
    bzero(buf, SCATTER_BUFLEN);

    int fd = open("scatter", O_CREAT | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    /* This will simultaneously test file creation, extension, holes and writes. */
    for (int iter = 0; iter < SCATTER_ITERATIONS; iter++) {
        int position = _random() % SCATTER_BUFLEN;
        int x = _random() % (SCATTER_BUFLEN / 8);
        int length = min(x, SCATTER_BUFLEN - position);

        if (length == 0)
            length = 1;

        for (int i = position; i < position + length; i++)
            buf[i] = _random() % UCHAR_MAX;

        /* write fragment */
        _LSEEK(position, SEEK_SET);
        _WRITE(buf + position, length);

        /* verify content
           could just as well randomize the read offset... */
        _LSEEK(0, SEEK_SET);
        int n = 0;
        do {
            _READ(tmp, min(length - n, BUFLEN));
            for (int i = 0; i < rv; i++) {
                if (tmp[i] != buf[n + i]) {
                    printf("scatter test fail: read content mismatch at offset %d\n", n + i);
                    exit(EXIT_FAILURE);
                }
            }
            n += rv;
        } while (n < length);
        printf("iter %d complete\n", iter);
    }
    printf("scatter write test passed\n");
    close(fd);
    return;
  out_fail:
    close(fd);
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    basic_write_test();
    scatter_write_test();
}
