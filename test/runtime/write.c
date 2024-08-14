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
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../test_utils.h"

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
    int fd = open("/", O_RDWR);
    if (fd != -1 || errno != EISDIR) {
        test_perror("open directory rdwr");
    }
    fd = open("/", O_WRONLY);
    if (fd != -1 || errno != EISDIR) {
        test_perror("open directory wr");
    }
    fd = open("/", O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
        test_perror("open directory");
    }
    close(fd);
    fd = open("/", O_RDONLY);
    if (fd < 0) {
        test_perror("open directory rd");
    }
    if (read(fd, buf, BUFLEN) != -1 || errno != EISDIR) {
        test_perror("read directory");
    }
    if (write(fd, buf, BUFLEN) != -1 || errno != EBADF) {
        test_perror("write directory");
    }
    close(fd);

    fd = open("hello", O_RDWR | O_DIRECTORY);
    if (fd != -1 || errno != ENOTDIR) {
        test_perror("open file as directory");
    }
    fd = open("hello", O_RDWR);
    if (fd < 0) {
        test_perror("open");
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
        test_error("basic write: string mismatch");
    }

    struct stat s;
    rv = fstat(fd, &s);
    if (rv < 0) {
        perror("stat");
        goto out_fail;
    }
    if (s.st_blocks < 1) {
        printf("invalid number of allocated blocks: %ld\n", s.st_blocks);
        goto out_fail;
    }

    rv = write(fd, FAULT_ADDR, 4096);
    if ((rv != -1) || (errno != EFAULT)) {
        test_error("write with faulting buffer: rv %ld, errno %d", rv, errno);
    }

    rv = syncfs(fd);
    if (rv < 0) {
        perror("syncfs");
        goto out_fail;
    }
    close(fd);
    rv = syncfs(fd);
    if ((rv != -1) || (errno != EBADF)) {
        printf("syncfs(): expected rv -1 (errno %d), found rv %ld (errno %d)\n", EBADF, rv, errno);
        goto out_fail;
    }

    writetest_debug("basic write test passed\n");
    return;
  out_fail:
    close(fd);
    exit(EXIT_FAILURE);
}

#define min(x, y) ((x) < (y) ? (x) : (y))
#define _random() (labs(random()))

static void scatter_write_test_fd(int fd, ssize_t buflen, int iterations, int max_writesize)
{
    ssize_t rv;
    unsigned char tmp[BUFLEN];
    unsigned char * buf = malloc(buflen);
    if (!buf) {
        test_error("malloc of size %ld", buflen);
    }
    bzero(buf, buflen);

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
#if 0
                    for (int z = 0; z < BUFLEN; z++) {
                        printf("%d - buf: %d, read: %d\n", z, buf[n + z], tmp[z]);
                    }
#endif
                    test_error("scatter test: read content mismatch at offset %d", n + i);
                }
            }
            n += rv;
        } while (n < rmost);
    }
    free(buf);
    return;
  out_fail:
    exit(EXIT_FAILURE);
}

void scatter_write_test(ssize_t buflen, int iterations, int max_writesize)
{
    int fd = open("scatter", O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        test_perror("open");
    }
    scatter_write_test_fd(fd, buflen, iterations, max_writesize);
    close(fd);

    fd = open(".", O_TMPFILE | O_RDWR, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        test_perror("open tmpfile");
    }
    scatter_write_test_fd(fd, buflen, iterations, max_writesize);
    close(fd);

    writetest_debug("scatter write test passed\n");
}

void append_write_test()
{
    ssize_t rv;
    unsigned char tmp[BUFLEN];
    int fd = open("append", O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        test_perror("open");
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

void sync_write_test(void)
{
    int fd = open("sync_write", O_CREAT | O_RDWR | O_SYNC, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        test_perror("sync_write open");
    }
    scatter_write_test_fd(fd, 1 << 12, 1, 512);
    close(fd);
    unlink("sync_write");
    writetest_debug("sync write test passed\n");
}

void truncate_test(const char *prog)
{
    char name_too_long[NAME_MAX + 2];
    unsigned char tmp[BUFLEN];
    ssize_t rv;
    struct stat s;

    rv = truncate(FAULT_ADDR, 0);
    if ((rv != -1) || (errno != EFAULT)) {
        test_error("truncate() with faulting path (%ld, %d)", rv, errno);
    }

    memset(name_too_long, '-', sizeof(name_too_long) - 1);
    name_too_long[sizeof(name_too_long) - 1] = '\0';
    rv = truncate(name_too_long, 0);
    if ((rv != -1) || (errno != ENAMETOOLONG)) {
        test_error("truncate() with name too long (%ld, %d)", rv, errno);
    }

    int fd = open("new_file", O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        test_perror("open");
    }
    if (ftruncate(fd, BUFLEN / 2) < 0) {
        test_perror("ftruncate to BUFLEN / 2");
    }
    rv = lseek(fd, 0, SEEK_END);
    if (rv < 0) {
        test_perror("lseek");
    }
    if (rv != BUFLEN / 2) {
        test_error("unexpected file size %ld", rv);
    }
    close(fd);

    rv = stat("new_file", &s);
    if (rv < 0) {
        test_perror("stat");
    }
    if (s.st_size != BUFLEN / 2) {
        test_error("unexpected file size %ld", s.st_size);
    }
    fd = open("new_file", O_RDWR);
    if (fd < 0) {
        test_perror("open");
    }
    _READ(tmp, BUFLEN);
    if (rv != BUFLEN / 2) {
        test_error("read %ld bytes, expected %d", rv, BUFLEN / 2);
    }
    for (int i = 0; i < BUFLEN / 2; i++) {
        if (tmp[i] != 0) {
            test_error("unexpected data 0x%02x at offset %d", tmp[i], i);
        }
    }
    if (ftruncate(fd, BUFLEN / 2) < 0) {
        test_perror("ftruncate to same length as current length");
    }
    if ((ftruncate(fd, -1) == 0) || (errno != EINVAL)) {
        test_error("negative length truncate test");
    }
    _LSEEK(0, SEEK_SET);
    for (int i = 0; i < BUFLEN / 2; i++) {
        tmp[i] = i;
    }
    _WRITE(tmp, BUFLEN / 2);
    if (ftruncate(fd, BUFLEN / 4) < 0) {
        test_perror("ftruncate to BUFLEN / 4");
    }
    close(fd);

    fd = open("new_file", O_RDWR);
    if (fd < 0) {
        test_perror("open");
    }
    _READ(tmp, BUFLEN);
    if (rv != BUFLEN / 4) {
        test_error("read %ld bytes, expected %d", rv, BUFLEN / 4);
    }
    for (int i = 0; i < BUFLEN / 4; i++) {
        if (tmp[i] != i) {
            test_error("unexpected data 0x%02x at offset %d", tmp[i], i);
        }
    }
    close(fd);

    fd = open("new_file", O_RDWR | O_TRUNC);
    if (fd < 0) {
        test_perror("open(O_TRUNC)");
    }
    if (fstat(fd, &s) < 0) {
        perror("fstat");
        goto out_fail;
    }
    if (s.st_size != 0) {
        printf("O_TRUNC test failed (file size %ld)\n", s.st_size);
        goto out_fail;
    }
    close(fd);

    fd = open("new_file", O_RDONLY);
    if (fd < 0) {
        test_perror("open");
    }
    if ((ftruncate(fd, 0) == 0) || ((errno != EBADF) && (errno != EINVAL))) {
        test_error("read-only file truncate test");
    }
    close(fd);

    if ((ftruncate(fd, 0) == 0) || ((errno != EBADF) && (errno != EINVAL))) {
        test_error("bad file descriptor truncate test");
    }

    if ((truncate("/dev/null", 0) == 0) || (errno != EINVAL)) {
        test_error("non-regular file truncate test");
    }

    if (mkdir("my_dir", S_IRUSR | S_IWUSR) < 0) {
        test_perror("mkdir");
    }
    if ((truncate("my_dir", 0) == 0) || (errno != EISDIR)) {
        test_error("directory truncate test");
    }

    if ((truncate("nonexisting", 0) == 0) || (errno != ENOENT)) {
        test_error("non-existing file truncate test");
    }

    fd = eventfd(0, 0);
    if (fd < 0) {
        test_perror("eventfd");
    }
    if ((ftruncate(fd, 0) == 0) || (errno != EINVAL)) {
        test_error("non-regular file truncate test");
    }
    close(fd);

    if (truncate(prog, 0) == 0) {
        test_error("could truncate program executable file");
    }

    /* Test truncation of a file not linked to the filesystem. */
    fd = open(".", O_TMPFILE | O_RDWR, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        test_perror("open tmpfile");
    }
    _WRITE(tmp, BUFLEN);
    _LSEEK(0, SEEK_CUR);
    if (rv != BUFLEN) {
        test_error("tmpfile lseek returned %ld", rv);
    }
    if (ftruncate(fd, BUFLEN / 2) < 0) {
        test_perror("tmpfile truncate");
    }
    _LSEEK(0, SEEK_END);
    if (rv != BUFLEN / 2) {
        test_error("tmpfile lseek after truncate returned %ld", rv);
    }
    close(fd);

    return;
  out_fail:
    close(fd);
    exit(EXIT_FAILURE);
}

static void write_exec_test(const char *prog)
{
    int fd;

    if (access(prog, W_OK) == 0) {
        test_error("could access program executable file in write mode");
    } else if (errno != EACCES) {
        test_perror("access(prog, W_OK)");
    }
    fd = open(prog, O_RDWR);
    if (fd >= 0) {
        test_error("could open program executable file for writing");
    }
    fd = open(prog, O_WRONLY);
    if (fd >= 0) {
        test_error("could open program executable file in write-only mode");
    }
}

static void write_test_direct(void)
{
    const char *file_name = "test_direct";
    const int alignment = 512;
    const int page_size = 4096;
    int fd = open(file_name, O_CREAT | O_RDWR | O_DIRECT, S_IRUSR | S_IWUSR);
    test_assert(fd >= 0);
    unsigned char wbuf[2 * alignment];
    unsigned char rbuf[2 * alignment];
    unsigned char *wptr, *rptr;

    /* unaligned buffer address: write() may or may not fail with EINVAL (it fails on Nanos and
     * succeeds on Linux with ext4 filesystem) */
    if ((intptr_t)wbuf & (alignment - 1))
        wptr = wbuf;
    else
        wptr = wbuf + 1;
    if (write(fd, wptr, alignment) > 0)
        test_assert(lseek(fd, 0, SEEK_SET) == 0);
    else
        test_assert(errno == EINVAL);

    /* unaligned buffer length */
    wptr = (unsigned char *)((intptr_t)(wbuf - 1) & ~(alignment - 1)) + alignment;
    test_assert((write(fd, wptr, 1) == -1) && (errno == EINVAL));

    /* aligned buffer address and length */
    for (int i = 0; i < alignment; i += sizeof(uint64_t))
        *(uint64_t *)(wptr + i) = i;
    test_assert(write(fd, wptr, alignment) == alignment);

    /* unaligned file offset */
    test_assert(lseek(fd, 1, SEEK_SET) == 1);
    test_assert((write(fd, wptr, alignment) == -1) && (errno == EINVAL));

    /* aligned buffer address and length */
    rptr = (unsigned char *)((intptr_t)(rbuf - 1) & ~(alignment - 1)) + alignment;
    test_assert(pread(fd, rptr, alignment, 0) == alignment);
    test_assert(!memcmp(rptr, wptr, alignment));

    test_assert((pwrite(fd, FAULT_ADDR, alignment, 0) == -1) && (errno == EFAULT));

    size_t map_size = 8 << 20;
    void *wmap = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    void *rmap = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    test_assert((wmap != MAP_FAILED) && (rmap != MAP_FAILED));
    for (int i = 0; i < map_size; i += sizeof(uint64_t))
        *(uint64_t *)(wmap + i) = i;

    /* single page */
    wptr = (unsigned char *)((intptr_t)(wmap - 1) & ~(page_size - 1)) + page_size;
    test_assert(pwrite(fd, wptr, page_size, 0) == page_size);
    test_assert(pread(fd, rmap, page_size, 0) == page_size);
    test_assert(!memcmp(rmap, wptr, page_size));

    /* sub-page range fitting in a single page */
    wptr += alignment;
    test_assert(pwrite(fd, wptr, page_size - alignment, 0) == page_size - alignment);
    test_assert(pread(fd, rmap, page_size - alignment, 0) == page_size - alignment);
    test_assert(!memcmp(rmap, wptr, page_size - alignment));

    /* range straddling 2 pages */
    wptr += alignment;
    test_assert(pwrite(fd, wptr, page_size - alignment, 0) == page_size - alignment);
    test_assert(pread(fd, rmap, page_size - alignment, 0) == page_size - alignment);
    test_assert(!memcmp(rmap, wptr, page_size - alignment));

    test_assert(pwrite(fd, wmap, map_size, 0) == map_size);
    test_assert(pread(fd, rmap, map_size, 0) == map_size);
    test_assert(!memcmp(rmap, wmap, map_size));

    munmap(wmap, map_size);
    munmap(rmap, map_size);
    close(fd);
    unlink(file_name);
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
        test_perror("bulk_write_test: open");
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

static void fs_stress_test() 
{
    int num_files = 1000;
    int fds[num_files];
    char fd_names[num_files][50];

    struct timespec start;
    if (clock_gettime(CLOCK_MONOTONIC, &start) < 0) {
        test_perror("fs_stress_test: clock_gettime");
    }

    /* Creating and writing to new files */
    int i = 0;
    for (; i < num_files; i++) {
        char buf[BUFLEN];
        ssize_t rv;
        sprintf(fd_names[i], "fs_stress_test_%d", i);
        int fd = open(fd_names[i], O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
        fds[i] = fd;

        if (fd < 0) {
            test_perror("open");
        }

        _READ(buf, BUFLEN);

        _LSEEK(0, SEEK_SET);

        ssize_t len = strlen(str);
        _WRITE(str, len);
    }

    /* sync the filesystem */
    sync(); 

    /* Time through the first sync() call */
    struct timespec postwrite;
    if (clock_gettime(CLOCK_MONOTONIC, &postwrite) < 0) {
        perror("fs_stress_test: clock_gettime");
        goto out_fail;
    }
    printf("fs stress test\n");
    print_op_stats("write", &start, &postwrite, 0);

    /* Deleting all files we just created */
    for (i = 0; i < num_files; i++) {
        close(fds[i]);

        /* Confirms file is deleted */
        if (remove(fd_names[i]) != 0) {
            test_perror("file remove");
        }
    }

    /* sync the filesystem again */
    sync(); 

    /* Time of deletion and total time*/
    struct timespec postsync;
    if (clock_gettime(CLOCK_MONOTONIC, &postsync) < 0) {
        test_perror("fs_stress_test: clock_gettime");
    }
    print_op_stats("delete", &postwrite, &postsync, 0);
    print_op_stats("total", &start, &postsync, 0);

    return;

  out_fail:
    for (int index = 0; index <= i; index++)
        close(fds[index]);
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
    int c, op = WRITE_OP_ALL;
    long long size = DEFAULT_BULK_SIZE;
    char *endptr;

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
        sync_write_test();
        truncate_test(argv[0]);
        write_exec_test(argv[0]);
        write_test_direct();
        fs_stress_test();
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
