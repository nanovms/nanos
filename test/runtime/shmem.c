#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "../test_utils.h"

static void test_memfd(void)
{
    const size_t capacity = 4096;
    int fd;
    char *data;
    volatile char *vdata;
    char buf[capacity];
    struct stat s;

    fd = syscall(__NR_memfd_create, "test", -1);    /* invalid flags */
    test_assert((fd == -1) && (errno == EINVAL));

    fd = syscall(__NR_memfd_create, "test", 0);
    test_assert(fd >= 0);

    test_assert(ftruncate(fd, capacity) == 0);
    data = mmap(NULL, 2 * capacity, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    test_assert(data != MAP_FAILED);
    test_assert(mmap(data, capacity, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0) ==
                data);
    for (int i = 0; i < capacity; i++)
        test_assert(data[i] == '\0');
    test_assert(mmap(data + capacity, capacity, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd,
                     0) == data + capacity);

    /* Check that data written via the first mapping is reflected in the second mapping. */
    vdata = data;
    vdata[0] = 'a';
    test_assert(vdata[capacity] == 'a');

    munmap(data, 2 * capacity);

    test_assert(lseek(fd, 0, SEEK_END) == capacity);
    memset(buf, 'b', sizeof(buf));
    test_assert(write(fd, buf, sizeof(buf)) == sizeof(buf));
    memset(buf, 0, sizeof(buf));
    test_assert(lseek(fd, -sizeof(buf), SEEK_CUR) == capacity);
    test_assert(read(fd, buf, sizeof(buf)) == sizeof(buf));
    for (int i = 0; i < sizeof(buf); i++)
        test_assert(buf[i] == 'b');

    test_assert(fsync(fd) == 0);
    test_assert(fstat(fd, &s) == 0);
    test_assert((s.st_mode & S_IFMT) == S_IFREG);
    test_assert(s.st_size == capacity + sizeof(buf));

    close(fd);
}

static void test_memfd_fallocate(void)
{
    const size_t capacity = 8192;
    char buf[64];
    struct stat s;
    int fd;

    fd = syscall(__NR_memfd_create, "test", 0);
    test_assert(fd >= 0);

    /* Allocating past the end of the file extends it, unless the size is kept. */
    test_assert(fallocate(fd, 0, 0, capacity) == 0);
    test_assert(fstat(fd, &s) == 0);
    test_assert(s.st_size == capacity);
    test_assert(fallocate(fd, FALLOC_FL_KEEP_SIZE, capacity, capacity) == 0);
    test_assert(fstat(fd, &s) == 0);
    test_assert(s.st_size == capacity);

    /* A punched hole reads as zeroes. */
    memset(buf, 'a', sizeof(buf));
    test_assert(pwrite(fd, buf, sizeof(buf), 0) == sizeof(buf));
    test_assert(fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 0, capacity) == 0);
    test_assert(pread(fd, buf, sizeof(buf), 0) == sizeof(buf));
    for (int i = 0; i < sizeof(buf); i++)
        test_assert(buf[i] == '\0');

    /* A negative offset, or a length that allocates nothing, is rejected. */
    test_assert((fallocate(fd, 0, -1, capacity) == -1) && (errno == EINVAL));
    test_assert((fallocate(fd, 0, 0, 0) == -1) && (errno == EINVAL));

    test_assert(close(fd) == 0);
}

static void test_memfd_fallocate_seals(void)
{
    const size_t capacity = 4096;
    int fd;

    fd = syscall(__NR_memfd_create, "test", MFD_ALLOW_SEALING);
    test_assert(fd >= 0);
    test_assert(ftruncate(fd, capacity) == 0);

    /* A grow seal forbids allocating past the end of the file, whether or not
     * the file size is to be updated, and allows everything else. */
    test_assert(fcntl(fd, F_ADD_SEALS, F_SEAL_GROW) == 0);
    test_assert((fallocate(fd, 0, 0, capacity + 1) == -1) && (errno == EPERM));
    test_assert((fallocate(fd, FALLOC_FL_KEEP_SIZE, capacity, capacity) == -1) &&
                (errno == EPERM));
    test_assert(fallocate(fd, 0, 0, capacity) == 0);
    test_assert(fallocate(fd, FALLOC_FL_KEEP_SIZE, 0, capacity) == 0);
    test_assert(fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 0, capacity) == 0);

    /* A write seal forbids punching holes, which changes the file contents,
     * but not allocation, which does not. */
    test_assert(fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE) == 0);
    test_assert((fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 0, capacity) == -1) &&
                (errno == EPERM));
    test_assert(fallocate(fd, 0, 0, capacity) == 0);

    test_assert(close(fd) == 0);
}

int main(int argc, char *argv[])
{
    test_memfd();
    test_memfd_fallocate();
    test_memfd_fallocate_seals();
    printf("Shared memory tests OK\n");
    return EXIT_SUCCESS;
}
