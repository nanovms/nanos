#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#define _GNU_SOURCE
#define __USE_GNU
#include <fcntl.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <sys/eventfd.h>
#include <sys/stat.h>

//#define WRITETEST_DEBUG
#ifdef WRITETEST_DEBUG
#define writetest_debug(x, ...) do {printf("%s: " x, __func__, ##__VA_ARGS__);} while(0)
#else
#define writetest_debug(x, ...)
#endif

#define BUFLEN 256
#define DEFAULT_BULK_SIZE (20 << 20) /* 20M */

static char *str = "I'm staying. Finishing my coffee. Enjoying my coffee.";

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
        writetest_debug("empty source file\n");

    if (rv >= BUFLEN)
        rv = BUFLEN - 1;
    buf[rv] = '\0';
    writetest_debug("original: \"%s\"\n", buf);

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

    writetest_debug("new: \"%s\"\n", buf);

    if (strncmp(str, buf, strlen(str))) {
        printf("basic write fail: string mismatch\n");
        exit(EXIT_FAILURE);
    }
    close(fd);
    writetest_debug("basic write test passed\n");
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
    writetest_debug("scatter write test passed\n");
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
    writetest_debug("existing content: \"");
    do {
        _READ(tmp, BUFLEN);
#ifdef WRITETEST_DEBUG
        for (int i = 0; i < rv; i++) {
            if (isalpha(tmp[i]))
                putchar(tmp[i]);
            else
                putchar('_');
        }
        printf("\"\n");
#endif
    } while (rv > 0);
    writetest_debug("appending \"");

    ssize_t len = _random() % (BUFLEN / 4);
    for (int i = 0; i < len; i++) {
        tmp[i] = 'a' + (_random() % 26);
#ifdef WRITETEST_DEBUG
        putchar(tmp[i]);
#endif
    }

#ifdef WRITETEST_DEBUG
    printf("\"\n");
#endif
    _WRITE(tmp, len);
    close(fd);
    return;
  out_fail:
    close(fd);
    exit(EXIT_FAILURE);
}

void truncate_test(const char *prog)
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

    if (truncate(prog, 0) == 0) {
        printf("Could truncate program executable file\n");
        exit(EXIT_FAILURE);
    }

    return;
  out_fail:
    close(fd);
    exit(EXIT_FAILURE);
}

static void write_exec_test(const char *prog)
{
    int fd;

    if (access(prog, W_OK) == 0) {
        printf("Could access program executable file in write mode\n");
        exit(EXIT_FAILURE);
    } else if (errno != EACCES) {
        perror("Unexpected error from access(prog, W_OK)");
        exit(EXIT_FAILURE);
    }
    fd = open(prog, O_RDWR);
    if (fd >= 0) {
        printf("Could open program executable file for writing\n");
        exit(EXIT_FAILURE);
    }
    fd = open(prog, O_WRONLY);
    if (fd >= 0) {
        printf("Could open program executable file in write-only mode\n");
        exit(EXIT_FAILURE);
    }
}

/* isn't this in a std include somewhere? */
static inline void timerspec_sub(struct timespec *a, struct timespec *b, struct timespec *r)
{
    r->tv_sec = a->tv_sec - b->tv_sec;
    r->tv_nsec = a->tv_nsec - b->tv_nsec;
    if (a->tv_nsec < b->tv_nsec) {
        r->tv_sec--;
        r->tv_nsec += 1000000000ull;
    }
}

#define BULK_WRITE_BUFLEN (64 << 10)

static void print_op_stats(const char *op, struct timespec *start, struct timespec *end,
                           unsigned long long bytes)
{
    struct timespec delta;
    timerspec_sub(end, start, &delta);
    printf("   %5s   %ld.%.9lds", op, delta.tv_sec, delta.tv_nsec);
    if (bytes > 0) {
        unsigned long long ns = delta.tv_sec * 1000000000ull + delta.tv_nsec;
        unsigned long long kbps = (1000000000ull / 1024) * bytes / ns;
        printf(" (%lld KB/s)\n", kbps);
    } else {
        printf("\n");
    }
}

void bulk_write_test(unsigned long long size)
{
    if (size == 0)
        return;

    int rv, fd;
    fd = open("new_file_2", O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        perror("bulk_write_test: open");
        exit(EXIT_FAILURE);
    }

    writetest_debug("starting bulk write test...\n");
    struct timespec start;
    if (clock_gettime(CLOCK_MONOTONIC, &start) < 0) {
        perror("bulk_write_test: clock_gettime");
        goto out_fail;
    }

    unsigned char buf[BULK_WRITE_BUFLEN];
    for (int i = 0; i < BULK_WRITE_BUFLEN; i++) {
        buf[i] = i & 0xff;
    }
    unsigned long long remain = size;
    do {
        int bufremain = remain < BULK_WRITE_BUFLEN ? remain : BULK_WRITE_BUFLEN;
        unsigned char *p = buf;
        do {
            int rv = write(fd, p, bufremain);
            if (rv < 0) {
                perror("bulk_write_test: write");
                goto out_fail;
            }
            bufremain -= rv;
            remain -= rv;
            p += rv;
        } while (bufremain > 0);
    } while (remain > 0);

    struct timespec postwrite;
    if (clock_gettime(CLOCK_MONOTONIC, &postwrite) < 0) {
        perror("bulk_write_test: clock_gettime");
        goto out_fail;
    }
    printf("bulk write test, size %llu KB:\n", size >> 10);
    print_op_stats("write", &start, &postwrite, 0);

    /* fsync */
    if (fsync(fd) < 0) {
        perror("bulk_write_test: fsync");
        goto out_fail;
    }

    struct timespec postsync;
    if (clock_gettime(CLOCK_MONOTONIC, &postsync) < 0) {
        perror("bulk_write_test: clock_gettime");
        goto out_fail;
    }
    print_op_stats("fsync", &postwrite, &postsync, 0);

    /* read / verify - we're not dropping cached data, so this isn't any kind of I/O test */
    _LSEEK(0, SEEK_SET);
    remain = size;
    unsigned char readbuf[BULK_WRITE_BUFLEN];
    do {
        int readlen = remain < BULK_WRITE_BUFLEN ? remain : BULK_WRITE_BUFLEN;
        int bufremain = readlen;
        unsigned char *p = readbuf;
        do {
            int rv = read(fd, p, bufremain);
            if (rv < 0) {
                perror("bulk_write_test: read");
                goto out_fail;
            }
            if (rv == 0) {
                printf("premature EOF during read at offset %lld\n", size - remain + (readlen - bufremain));
                goto out_fail;
            }
            bufremain -= rv;
            p += rv;
        } while (bufremain > 0);

        for (int i = 0; i < readlen; i++) {
            if (readbuf[i] != buf[i]) {
                printf("read validate mismatch at offset %lld\n", size - remain + i);
                goto out_fail;
            }
        }
        remain -= readlen;
    } while (remain > 0);

    struct timespec postread;
    if (clock_gettime(CLOCK_MONOTONIC, &postread) < 0) {
        perror("bulk_write_test: clock_gettime");
        goto out_fail;
    }
    print_op_stats("read", &postsync, &postread, 0);
    print_op_stats("total", &start, &postread, size);
    close(fd);
    return;
  out_fail:
    close(fd);
    exit(EXIT_FAILURE);
}

#define PERSIST_ALLOC_BYTES   8192
#define PERSIST_PATTERN_START 701
#define PERSIST_PATTERN_LEN   2048

/* tests basic persistence, fallocate and filling of uninited extents */
void persistence_write_test(void)
{
    const char *name = "persistence_test_file";
    char *err;
    struct stat s;
    printf("persistence test: ");
    int fd = -1;
    int rv = stat(name, &s);
    if (rv < 0) {
        if (errno != ENOENT) {
            err = "stat";
            goto fail_perror;
        }
        printf("creating file\n");
        fd = open(name, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
        if (fd < 0) {
            err = "open";
            goto fail_perror;
        }
        rv = fallocate(fd, 0, 0, PERSIST_ALLOC_BYTES);
        if (rv < 0) {
            err = "fallocate";
            goto fail_perror;
        }
        rv = lseek(fd, PERSIST_PATTERN_START, SEEK_SET);
        if (rv < 0) {
            err = "lseek";
            goto fail_perror;
        }
        char buf[PERSIST_PATTERN_LEN];
        for (int i = 0; i < PERSIST_PATTERN_LEN; i++) {
            buf[i] = 0xff;
        }
        rv = write(fd, buf, PERSIST_PATTERN_LEN);
        if (rv < 0) {
            err = "write";
            goto fail_perror;
        }
        if (rv < PERSIST_PATTERN_LEN) {
            printf("short write, length %d\n", rv);
            goto fail;
        }
        close(fd);
        return;
    }
    printf("file found; second pass\n");
    if (s.st_size != PERSIST_ALLOC_BYTES) {
        printf("invalid size %ld\n", s.st_size);
        goto fail;
    }
    unsigned char buf[PERSIST_ALLOC_BYTES];
    fd = open(name, O_RDONLY, 0);
    if (fd < 0) {
        err = "open";
        goto fail_perror;
    }
    rv = read(fd, buf, PERSIST_ALLOC_BYTES);
    if (rv < 0) {
        err = "read";
        goto fail_perror;
    }
    if (rv != PERSIST_ALLOC_BYTES) {
        printf("short read, length %d\n", rv);
        goto fail;
    }
    close(fd);
    for (int i = 0; i < PERSIST_ALLOC_BYTES; i++) {
        int z = i < PERSIST_PATTERN_START || i >= (PERSIST_PATTERN_START + PERSIST_PATTERN_LEN);
        if ((z && buf[i] != 0) || (!z && buf[i] != 0xff)) {
            printf("mismatch at index %d, expect 0x%.2x, read 0x%.2x\n",
                   i, z ? 0 : 0xff, (unsigned char)buf[i]);
            goto fail;
        }
    }
    return;
  fail_perror:
    perror(err);
  fail:
    if (fd >= 0)
        close(fd);
    exit(EXIT_FAILURE);
}

enum {
    WRITE_OP_ALL,
    WRITE_OP_BASIC_ONLY,
    WRITE_OP_BULK_ONLY,
    WRITE_OP_PERSISTENCE_ONLY
};

static void usage(const char *program_name)
{
    const char *p = strrchr(program_name, '/');
    p = p != NULL ? p + 1 : program_name;
    printf("Usage: %s [-b file-size]\n"
           "\n"
           "-b - run basic tests only (no bulk / performance tests)\n"
           "-p - run persistence test only\n"
           "-w - run bulk data write test only\n"
           "-s - set bulk data size; size may be expressed by suffix\n"
           "     (k or K for KB, m or M for MB, g or G for GB)\n",
           p);
}

int main(int argc, char **argv)
{
    int c, op = WRITE_OP_ALL;
    long long size = DEFAULT_BULK_SIZE;
    char *endptr;
    setvbuf(stdout, NULL, _IOLBF, 0);

    while ((c = getopt(argc, argv, "hbws:p")) != EOF) {
        switch (c) {
        case 'h':
            usage(argv[0]);
            break;
        case 'b':
            op = WRITE_OP_BASIC_ONLY;
            break;
        case 'w':
            op = WRITE_OP_BULK_ONLY;
            break;
        case 'p':
            op = WRITE_OP_PERSISTENCE_ONLY;
            break;
        case 's':
            size = strtoll(optarg, &endptr, 0);
            if (size <= 0) {
                printf("invalid write file size %lld\n", size);
                usage(argv[0]);
                exit(1);
            }
            switch (*endptr) {
            case 'k':
            case 'K':
                size <<= 10;
                break;
            case 'm':
            case 'M':
                size <<= 20;
                break;
            case 'g':
            case 'G':
                size <<= 30;
                break;
            case '\0':
                break;
            default:
                printf("invalid write file size suffix '%s'\n", endptr);
                usage(argv[0]);
                exit(1);
            }
            break;
        default:
            usage(argv[0]);
            break;
        }
    }

    if (op == WRITE_OP_ALL || op == WRITE_OP_BASIC_ONLY) {
        basic_write_test();
        scatter_write_test(1 << 18, 64, 1 << 12);
        append_write_test();
        truncate_test(argv[0]);
        write_exec_test(argv[0]);
    }

    if (op == WRITE_OP_ALL || op == WRITE_OP_BULK_ONLY) {
        bulk_write_test(size);
    }

    if (op == WRITE_OP_PERSISTENCE_ONLY) {
        persistence_write_test();
    }

    printf("write test passed\n");
    return EXIT_SUCCESS;
}
