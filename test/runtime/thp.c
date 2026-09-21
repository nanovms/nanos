/* A shared mapping of a memory file should be able to be described with 2 MiB block mappings,
   and has to keep working when it cannot be.

   mincore() is what makes the granularity visible from here: it reports a page as resident for
   every page a present entry covers, so one entry over 2 MiB shows up as 512 resident pages
   after a single touch, and a page at a time mapping shows up as one. */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../test_utils.h"

#define HUGE_SIZE   (2 * 1024 * 1024)
#define HUGE_PAGES  (HUGE_SIZE / PAGESIZE)
#define FILE_SIZE   (8 * 1024 * 1024)

#ifndef PAGESIZE
#define PAGESIZE    4096
#endif

/* Pages of the range that some present entry covers. */
static int resident(void *addr, size_t len)
{
    unsigned char vec[FILE_SIZE / PAGESIZE];
    size_t pages = len / PAGESIZE;
    int n = 0;

    test_assert(pages <= sizeof(vec));
    memset(vec, 0, pages);
    test_assert(mincore(addr, len, vec) == 0);
    for (size_t i = 0; i < pages; i++)
        if (vec[i] & 1)
            n++;
    return n;
}

/* A window of address space aligned the way a huge mapping needs, carved out of a
   reservation the way a collector reserves its heap before committing into it. */
static unsigned char *reserve_aligned(size_t len)
{
    unsigned char *p = mmap(NULL, len + HUGE_SIZE, PROT_NONE,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    test_assert(p != MAP_FAILED);
    return (unsigned char *)(((uintptr_t)p + HUGE_SIZE - 1) & ~((uintptr_t)HUGE_SIZE - 1));
}

static int huge_memfd(void)
{
    int fd = memfd_create("huge", 0);
    test_assert(fd >= 0);
    test_assert(ftruncate(fd, FILE_SIZE) == 0);
    return fd;
}

/* One touch of a shared, aligned mapping should bring in the whole window. */
static void test_shared_mapping_is_huge(void)
{
    int fd = huge_memfd();
    unsigned char *base = reserve_aligned(2 * HUGE_SIZE);

    test_assert(mmap(base, 2 * HUGE_SIZE, PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_FIXED, fd, 0) == base);
    test_assert(resident(base, HUGE_SIZE) == 0);

    base[0] = 0x5a;
    test_assert(resident(base, HUGE_SIZE) == HUGE_PAGES);

    /* The window has to hold what was written to it, and read back as zeroes
       everywhere else: it is filled, not merely mapped. */
    test_assert(base[0] == 0x5a);
    for (int off = PAGESIZE; off < HUGE_SIZE; off += PAGESIZE)
        test_assert(base[off] == 0);

    /* A second window of the same mapping is a second entry, still untouched. */
    test_assert(resident(base + HUGE_SIZE, HUGE_SIZE) == 0);
    base[HUGE_SIZE] = 0x3c;
    test_assert(resident(base + HUGE_SIZE, HUGE_SIZE) == HUGE_PAGES);

    test_assert(munmap(base, 2 * HUGE_SIZE) == 0);
    test_assert(close(fd) == 0);
}

/* A file offset that is not congruent with the virtual address cannot be described
   by a block mapping, and must fall back rather than fail. */
static void test_unaligned_offset_falls_back(void)
{
    int fd = huge_memfd();
    unsigned char *base = reserve_aligned(HUGE_SIZE);

    test_assert(mmap(base, HUGE_SIZE, PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_FIXED, fd, PAGESIZE) == base);
    base[0] = 0x11;
    test_assert(resident(base, HUGE_SIZE) == 1);
    test_assert(base[0] == 0x11);

    test_assert(munmap(base, HUGE_SIZE) == 0);
    test_assert(close(fd) == 0);
}

/* A private mapping takes a copy of a page when it is written, which is a per-page
   affair: it must keep being one. */
static void test_private_mapping_stays_small(void)
{
    int fd = huge_memfd();
    unsigned char *base = reserve_aligned(HUGE_SIZE);

    test_assert(mmap(base, HUGE_SIZE, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_FIXED, fd, 0) == base);
    base[0] = 0x22;
    test_assert(resident(base, HUGE_SIZE) == 1);
    test_assert(base[0] == 0x22);

    test_assert(munmap(base, HUGE_SIZE) == 0);
    test_assert(close(fd) == 0);
}

/* The uncommit a collector does: a hole punched inside a window that is mapped as one
   block. The entry cannot survive it, the hole has to read back as zeroes, and the
   range has to be usable again afterwards. */
static void test_punch_inside_huge_window(void)
{
    int fd = huge_memfd();
    unsigned char *base = reserve_aligned(HUGE_SIZE);

    test_assert(mmap(base, HUGE_SIZE, PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_FIXED, fd, 0) == base);
    memset(base, 0x77, HUGE_SIZE);
    test_assert(resident(base, HUGE_SIZE) == HUGE_PAGES);

    /* One page out of the middle. */
    off_t hole = HUGE_SIZE / 2;
    test_assert(fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                          hole, PAGESIZE) == 0);

    test_assert(resident(base, HUGE_SIZE) < HUGE_PAGES); /* the block entry cannot have survived */

    /* The hole reads back as zeroes, through the mapping and through the file. */
    for (int i = 0; i < PAGESIZE; i++)
        test_assert(base[hole + i] == 0);
    unsigned char buf[PAGESIZE];
    test_assert(pread(fd, buf, sizeof(buf), hole) == sizeof(buf));
    for (int i = 0; i < PAGESIZE; i++)
        test_assert(buf[i] == 0);

    /* What was not punched is untouched. */
    test_assert(base[hole - 1] == 0x77);
    test_assert(base[hole + PAGESIZE] == 0x77);

    /* And the range takes a write again. */
    base[hole] = 0x66;
    test_assert(base[hole] == 0x66);
    test_assert(base[hole + 1] == 0);

    test_assert(munmap(base, HUGE_SIZE) == 0);
    test_assert(close(fd) == 0);
}

/* Unmapping part of a window, which is the other way an entry covering many pages has
   to come apart. */
static void test_partial_unmap_of_huge_window(void)
{
    int fd = huge_memfd();
    unsigned char *base = reserve_aligned(HUGE_SIZE);

    test_assert(mmap(base, HUGE_SIZE, PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_FIXED, fd, 0) == base);
    base[0] = 0x44;
    test_assert(resident(base, HUGE_SIZE) == HUGE_PAGES);

    test_assert(munmap(base + HUGE_SIZE / 2, HUGE_SIZE / 2) == 0);
    test_assert(resident(base, HUGE_SIZE / 2) == HUGE_PAGES / 2);
    test_assert(base[0] == 0x44);
    for (int off = PAGESIZE; off < HUGE_SIZE / 2; off += PAGESIZE)
        test_assert(base[off] == 0);

    test_assert(munmap(base, HUGE_SIZE / 2) == 0);
    test_assert(close(fd) == 0);
}

/* A window that already holds pages cannot be taken over by a block mapping, because
   those pages may be mapped: the fault has to fall back instead of overwriting them. */
static void test_populated_window_falls_back(void)
{
    int fd = huge_memfd();
    unsigned char *first = reserve_aligned(HUGE_SIZE);

    /* Bring a single page of the file into the cache through an unaligned mapping,
       which never promotes. */
    test_assert(mmap(first, HUGE_SIZE, PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_FIXED, fd, PAGESIZE) == first);
    first[0] = 0x99;

    /* Now map the same file aligned. The window holds a page already. */
    unsigned char *base = reserve_aligned(HUGE_SIZE);
    test_assert(mmap(base, HUGE_SIZE, PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_FIXED, fd, 0) == base);
    base[0] = 0x88;
    test_assert(resident(base, HUGE_SIZE) < HUGE_PAGES);

    /* Both mappings see the file, and neither lost its page. */
    test_assert(base[0] == 0x88);
    test_assert(base[PAGESIZE] == 0x99);
    test_assert(first[0] == 0x99);

    test_assert(munmap(base, HUGE_SIZE) == 0);
    test_assert(munmap(first, HUGE_SIZE) == 0);
    test_assert(close(fd) == 0);
}

void test_thp(int argc, char **argv)
{
    test_shared_mapping_is_huge();
    test_unaligned_offset_falls_back();
    test_private_mapping_stays_small();
    test_punch_inside_huge_window();
    test_partial_unmap_of_huge_window();
    test_populated_window_falls_back();
}
