#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>
#include <errno.h>
#include <sys/eventfd.h>
#include <sys/stat.h>

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
#define _random() (labs(random()))

void scatter_write_test(ssize_t buflen, int iterations, int max_writesize)
{
    ssize_t rv;
    unsigned char tmp[BUFLEN];
    unsigned char * buf = malloc(buflen);
    if (!buf) {
        printf("malloc of size %ld failed\n", buflen);
        exit(EXIT_FAILURE);
    }
    bzero(buf, buflen);

    int fd = open("scatter", O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        perror("open");
        exit(EXIT_FAILURE);
    }
    _READ(buf, buflen);

    int rmost = 0;

    /* This will simultaneously test file creation, extension, holes and writes. */
    for (int iter = 0; iter < iterations; iter++) {
        int position = _random() % buflen;
        int x = _random() % max_writesize;
        ssize_t length = min(x, buflen - position);

        if (length == 0)
            length = 1;

        for (int i = position; i < position + length; i++)
            buf[i] = _random() % UCHAR_MAX;

        /* write fragment */
        _LSEEK(position, SEEK_SET);
        _WRITE(buf + position, length);
        if (position + length > rmost)
            rmost = position + length;

        /* verify content
           could just as well randomize the read offset... */
        _LSEEK(0, SEEK_SET);
        int n = 0;
        do {
            bzero(tmp, BUFLEN);
            _READ(tmp, min(rmost - n, BUFLEN));
            for (int i = 0; i < rv; i++) {
                if (tmp[i] != buf[n + i]) {
                    printf("scatter test fail: read content mismatch at offset %d\n", n + i);
#if 0
                    for (int z = 0; z < BUFLEN; z++) {
                        printf("%d - buf: %d, read: %d\n", z, buf[n + z], tmp[z]);
                    }
#endif
                    exit(EXIT_FAILURE);
                }
            }
            n += rv;
        } while (n < rmost);
    }
    printf("scatter write test passed\n");
    close(fd);
    return;
  out_fail:
    close(fd);
    exit(EXIT_FAILURE);
}

void append_write_test()
{
    ssize_t rv;
    unsigned char tmp[BUFLEN];
    int fd = open("append", O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    /* XXX kinda stupid, this should use some known pattern and check it */
    printf("existing content: \"");
    do {
        _READ(tmp, BUFLEN);
        for (int i = 0; i < rv; i++) {
            if (isalpha(tmp[i]))
                putchar(tmp[i]);
            else
                putchar('_');
        }
    } while (rv > 0);
    printf("\"\nappending \"");

    ssize_t len = _random() % (BUFLEN / 4);
    for (int i = 0; i < len; i++) {
        tmp[i] = 'a' + (_random() % 26);
        putchar(tmp[i]);
    }

    printf("\"\n");
    _WRITE(tmp, len);
    close(fd);
    return;
  out_fail:
    close(fd);
    exit(EXIT_FAILURE);
}

void truncate_test()
{
    unsigned char tmp[BUFLEN];
    ssize_t rv;
    struct stat s;

    int fd = open("new_file", O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        perror("open");
        exit(EXIT_FAILURE);
    }
    if (ftruncate(fd, BUFLEN / 2) < 0) {
        perror("ftruncate to BUFLEN / 2");
        exit(EXIT_FAILURE);
    }
    rv = lseek(fd, 0, SEEK_END);
    if (rv < 0) {
        perror("lseek");
        exit(EXIT_FAILURE);
    }
    if (rv != BUFLEN / 2) {
        printf("unexpected file size %ld\n", rv);
        exit(EXIT_FAILURE);
    }
    close(fd);

    rv = stat("new_file", &s);
    if (rv < 0) {
        perror("stat");
        exit(EXIT_FAILURE);
    }
    if (s.st_size != BUFLEN / 2) {
        printf("unexpected file size %ld\n", s.st_size);
        exit(EXIT_FAILURE);
    }
    fd = open("new_file", O_RDWR);
    if (fd < 0) {
        perror("open");
        exit(EXIT_FAILURE);
    }
    _READ(tmp, BUFLEN);
    if (rv != BUFLEN / 2) {
        printf("read %ld bytes, expected %d\n", rv, BUFLEN / 2);
        exit(EXIT_FAILURE);
    }
    for (int i = 0; i < BUFLEN / 2; i++) {
        if (tmp[i] != 0) {
            printf("unexpected data 0x%02x at offset %d\n", tmp[i], i);
            exit(EXIT_FAILURE);
        }
    }
    if (ftruncate(fd, BUFLEN / 2) < 0) {
        perror("ftruncate to same length as current length");
        exit(EXIT_FAILURE);
    }
    if ((ftruncate(fd, -1) == 0) || (errno != EINVAL)) {
        printf("negative length truncate test failed\n");
        exit(EXIT_FAILURE);
    }
    _LSEEK(0, SEEK_SET);
    for (int i = 0; i < BUFLEN / 2; i++) {
        tmp[i] = i;
    }
    _WRITE(tmp, BUFLEN / 2);
    if (ftruncate(fd, BUFLEN / 4) < 0) {
        perror("ftruncate to BUFLEN / 4");
        exit(EXIT_FAILURE);
    }
    close(fd);

    fd = open("new_file", O_RDWR);
    if (fd < 0) {
        perror("open");
        exit(EXIT_FAILURE);
    }
    _READ(tmp, BUFLEN);
    if (rv != BUFLEN / 4) {
        printf("read %ld bytes, expected %d\n", rv, BUFLEN / 4);
        exit(EXIT_FAILURE);
    }
    for (int i = 0; i < BUFLEN / 4; i++) {
        if (tmp[i] != i) {
            printf("unexpected data 0x%02x at offset %d\n", tmp[i], i);
            exit(EXIT_FAILURE);
        }
    }
    close(fd);

    fd = open("new_file", O_RDONLY);
    if (fd < 0) {
        perror("open");
        exit(EXIT_FAILURE);
    }
    if ((ftruncate(fd, 0) == 0) || ((errno != EBADF) && (errno != EINVAL))) {
        printf("read-only file truncate test failed\n");
        exit(EXIT_FAILURE);
    }
    close(fd);

    if ((ftruncate(fd, 0) == 0) || ((errno != EBADF) && (errno != EINVAL))) {
        printf("bad file descriptor truncate test failed\n");
        exit(EXIT_FAILURE);
    }

    if (mkdir("my_dir", S_IRUSR | S_IWUSR) < 0) {
        perror("mkdir");
        exit(EXIT_FAILURE);
    }
    if ((truncate("my_dir", 0) == 0) || (errno != EISDIR)) {
        printf("directory truncate test failed\n");
        exit(EXIT_FAILURE);
    }

    if ((truncate("nonexisting", 0) == 0) || (errno != ENOENT)) {
        printf("non-existing file truncate test failed\n");
        exit(EXIT_FAILURE);
    }

    fd = eventfd(0, 0);
    if (fd < 0) {
        perror("eventfd");
        exit(EXIT_FAILURE);
    }
    if ((ftruncate(fd, 0) == 0) || (errno != EINVAL)) {
        printf("non-regular file truncate test failed\n");
        exit(EXIT_FAILURE);
    }
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
    scatter_write_test(1 << 18, 64, 1 << 12);
    append_write_test();
    truncate_test();
    printf("write test passed\n");
    return EXIT_SUCCESS;
}
