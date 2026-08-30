#include <errno.h>
#define _GNU_SOURCE
#define __USE_GNU
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../test_utils.h"

static void test_tmpfile(void)
{
    int fd;
    uint8_t buf[8192];

    fd = open(".", O_RDWR | O_TMPFILE, S_IRWXU);
    test_assert(fd > 0);
    test_assert(fallocate(fd, 0, 0, sizeof(buf)) == 0);
    memset(buf, 0xff, sizeof(buf));
    test_assert(write(fd, buf, 1) == 1);
    test_assert(lseek(fd, 0, SEEK_SET) == 0);
    test_assert(read(fd, buf, sizeof(buf)) == sizeof(buf));
    test_assert(buf[0] == 0xff);
    for (int i = 1; i < sizeof(buf); i++)
        test_assert(buf[i] == 0);
    test_assert(close(fd) == 0);
}

#define MEMFD_SIZE  (4 * 1024 * 1024)
#define MEMFD_CHUNK (64 * 1024)

static blkcnt_t blocks_of(int fd)
{
    struct stat st;

    test_assert(fstat(fd, &st) == 0);
    return st.st_blocks;
}

static void memfd_fill(int fd, size_t size)
{
    uint8_t buf[MEMFD_CHUNK];

    memset(buf, 0xa5, sizeof(buf));
    test_assert(lseek(fd, 0, SEEK_SET) == 0);
    for (size_t off = 0; off < size; off += sizeof(buf))
        test_assert(write(fd, buf, sizeof(buf)) == sizeof(buf));

    /* The allocated pages show up in fstat() only once the page cache has committed them. */
    test_assert(fsync(fd) == 0);
}

/* A hole in a memfd gives its blocks back, and reads back as zeroes. */
static void test_memfd_punch(void)
{
    int fd = memfd_create("punch", 0);
    test_assert(fd >= 0);
    test_assert(ftruncate(fd, MEMFD_SIZE) == 0);
    memfd_fill(fd, MEMFD_SIZE);

    blkcnt_t full = blocks_of(fd);
    test_assert(full > 0);

    test_assert(fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 0, MEMFD_SIZE / 2) == 0);
    blkcnt_t holed = blocks_of(fd);
    test_assert(holed < full);

    /* The size is kept, and what the hole covered is zero. */
    test_assert(lseek(fd, 0, SEEK_END) == MEMFD_SIZE);
    uint8_t buf[MEMFD_CHUNK];
    test_assert(lseek(fd, 0, SEEK_SET) == 0);
    test_assert(read(fd, buf, sizeof(buf)) == sizeof(buf));
    for (size_t i = 0; i < sizeof(buf); i++)
        test_assert(buf[i] == 0);

    /* And what it did not cover is untouched. */
    test_assert(lseek(fd, MEMFD_SIZE / 2, SEEK_SET) == MEMFD_SIZE / 2);
    test_assert(read(fd, buf, sizeof(buf)) == sizeof(buf));
    for (size_t i = 0; i < sizeof(buf); i++)
        test_assert(buf[i] == 0xa5);

    test_assert(fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 0, MEMFD_SIZE) == 0);
    test_assert(blocks_of(fd) < holed);

    test_assert(close(fd) == 0);
}

/* Writing over a punched range, and then dropping the file: the pages of the range are pinned by
   the first write, given back by the punch, and pinned again by the second write. */
static void test_memfd_rewrite_after_punch(void)
{
    int fd = memfd_create("rewrite", 0);
    test_assert(fd >= 0);
    test_assert(ftruncate(fd, MEMFD_SIZE) == 0);

    for (int round = 0; round < 4; round++) {
        memfd_fill(fd, MEMFD_SIZE);
        test_assert(fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 0, MEMFD_SIZE) == 0);
        memfd_fill(fd, MEMFD_SIZE);

        uint8_t buf[MEMFD_CHUNK];
        test_assert(lseek(fd, 0, SEEK_SET) == 0);
        test_assert(read(fd, buf, sizeof(buf)) == sizeof(buf));
        for (size_t i = 0; i < sizeof(buf); i++)
            test_assert(buf[i] == 0xa5);
    }

    test_assert(close(fd) == 0);
}

/* A hole punched under a live mapping has to reach the page tables too: what was mapped and
   dirty must read back as zero without the mapping being torn down first. */
static void test_memfd_punch_under_mapping(void)
{
    int fd = memfd_create("mapped", 0);
    test_assert(fd >= 0);
    test_assert(ftruncate(fd, MEMFD_SIZE) == 0);

    uint8_t *p = mmap(NULL, MEMFD_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    test_assert(p != MAP_FAILED);
    memset(p, 0x5a, MEMFD_SIZE);
    test_assert(msync(p, MEMFD_SIZE, MS_SYNC) == 0);

    test_assert(fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 0, MEMFD_SIZE / 2) == 0);
    for (size_t i = 0; i < MEMFD_SIZE / 2; i++)
        test_assert(p[i] == 0);
    for (size_t i = MEMFD_SIZE / 2; i < MEMFD_SIZE; i++)
        test_assert(p[i] == 0x5a);

    /* Written again through the mapping, so the pages come back. */
    memset(p, 0x3c, MEMFD_SIZE / 2);
    for (size_t i = 0; i < MEMFD_SIZE / 2; i++)
        test_assert(p[i] == 0x3c);

    test_assert(munmap(p, MEMFD_SIZE) == 0);
    test_assert(close(fd) == 0);
}

void test_fallocate(int argc, char **argv)
{
    int fd;
    uint8_t buf[8192];
    unsigned long alloc_size, file_size;
    int ret;

    test_assert((fallocate(0, 0, 0, 1) == -1) && (errno == ESPIPE));

    fd = open("my_file", O_RDONLY | O_CREAT, S_IRWXU);
    test_assert(fd > 0);
    test_assert(fallocate(fd, FALLOC_FL_KEEP_SIZE, 0, 1) == -1);
    test_assert(errno == EBADF);    /* the file is open in read-only mode */
    test_assert(close(fd) == 0);

    fd = open("my_file", O_RDWR | O_CREAT, S_IRWXU);
    test_assert(fd > 0);
    test_assert(fallocate(fd, FALLOC_FL_KEEP_SIZE, 0, 1) == 0);
    test_assert(read(fd, buf, sizeof(buf)) == 0);

    test_assert(fallocate(fd, 0, 0, 1) == 0);
    buf[0] = 0xff;
    test_assert((read(fd, buf, sizeof(buf)) == 1) && (buf[0] == 0));

    test_assert(fallocate(fd, 0, 0, sizeof(buf)) == 0);
    memset(buf, 0xff, sizeof(buf));
    test_assert(lseek(fd, 4095, SEEK_SET) == 4095);
    test_assert(write(fd, &buf[4095], 2) == 2);
    test_assert(lseek(fd, 0, SEEK_SET) == 0);
    test_assert(read(fd, buf, sizeof(buf)) == sizeof(buf));
    for (int i = 0; i < 4095; i++) {
        test_assert(buf[i] == 0);
    }
    test_assert((buf[4095] == 0xff) && (buf[4096] == 0xff));
    for (int i = 4097; i < 8192; i++) {
        test_assert(buf[i] == 0);
    }

    alloc_size = 1;
    do {
        alloc_size *= 3;
        ret = fallocate(fd, 0, alloc_size, alloc_size);
        test_assert((ret == 0) || ((ret == -1) && (errno == ENOSPC)));
    } while (ret == 0);
    file_size = lseek(fd, 0, SEEK_END);
    test_assert(file_size == 2 * alloc_size / 3);

    memset(buf, 0xff, sizeof(buf));
    test_assert(lseek(fd, 0, SEEK_SET) == 0);
    test_assert(write(fd, buf, sizeof(buf)) == sizeof(buf));
    for (int hole = 1; hole <= sizeof(buf) - 2; hole *= 3) {
        ret = fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, hole,
                hole);
        test_assert(ret == 0);
        test_assert(lseek(fd, hole - 1, SEEK_SET) == hole - 1);
        test_assert(read(fd, buf, hole + 2) == hole + 2);
        test_assert(buf[0] == 0xff);
        for (int i = 1; i <= hole; i++) {
            test_assert(buf[i] == 0);
        }
        test_assert(buf[hole + 1] == ((hole < sizeof(buf) / 2) ? 0xff : 0x00));
    }

    ret = fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 0,
            file_size);
    test_assert(ret == 0);
    test_assert(read(fd, buf, sizeof(buf)) == sizeof(buf));
    for (int i = 0; i < sizeof(buf); i++) {
        test_assert(buf[i] == 0);
    }

    test_assert(lseek(fd, 0, SEEK_END) == file_size);

    test_assert(close(fd) == 0);

    test_tmpfile();
    test_memfd_punch();
    test_memfd_rewrite_after_punch();
    test_memfd_punch_under_mapping();
}
