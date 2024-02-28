#include <errno.h>
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

int main(int argc, char *argv[])
{
    test_memfd();
    printf("Shared memory tests OK\n");
    return EXIT_SUCCESS;
}
