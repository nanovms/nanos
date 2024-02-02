#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <runtime.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include "../test_utils.h"

#define EVENTFD_VAL_MAX 0xFFFFFFFFFFFFFFFE

static u64 writtenVal;
static volatile u64 readVal;

static volatile int thread_done;

static void basic_test(int fd)
{
    ssize_t nbytes;

    writtenVal = 1;
    nbytes = write(fd, &writtenVal, sizeof(writtenVal) - 1);
    if ((nbytes != -1) || (errno != EINVAL)) {
        test_error("eventfd basic test: write didn't error out (%ld, %d)", nbytes,
                errno);
    }
    nbytes = write(fd, &writtenVal, sizeof(writtenVal));
    if (nbytes != sizeof(writtenVal)) {
        test_error("eventfd basic test: write returned %ld", nbytes);
    }
    nbytes = read(fd, (u8 *)&readVal, sizeof(readVal) - 1);
    if ((nbytes != -1) || (errno != EINVAL)) {
        test_error("eventfd basic test: read didn't error out (%ld, %d)", nbytes,
                errno);
    }
    nbytes = read(fd, (u8 *)&readVal, sizeof(readVal));
    if (nbytes != sizeof(readVal)) {
        test_error("eventfd basic test: read returned %ld", nbytes);
    }
    if (readVal != writtenVal) {
        test_error("eventfd basic test: read value %lld, should be %lld", readVal,
                writtenVal);
    }
}

static void *blocking_read_test_child(void *arg)
{
    int fd = (long)arg;
    ssize_t nbytes;

    nbytes = read(fd, (u8 *)&readVal, sizeof(readVal));
    thread_done = true;
    if (nbytes != sizeof(readVal)) {
        printf("eventfd blocking read test child: read returned %ld\n", nbytes);
        return (void *)EXIT_FAILURE;
    }
    return (void *)EXIT_SUCCESS;
}

static void blocking_read_test(int fd)
{
    pthread_t pt;
    ssize_t nbytes;
    void *retval;

    thread_done = false;
    if (pthread_create(&pt, NULL, blocking_read_test_child, (void *)(long)fd)) {
        test_error("eventfd blocking read test: cannot create thread");
    }
    usleep(100 * 1000);
    if (thread_done) {
        test_error("eventfd blocking read test: thread didn't block");
    }
    writtenVal = 0xDEADBEEF;
    nbytes = write(fd, &writtenVal, sizeof(writtenVal));
    if (nbytes != sizeof(writtenVal)) {
        test_error("eventfd blocking read test: write returned %ld", nbytes);
    }
    if (pthread_join(pt, &retval)) {
        test_error("eventfd blocking read test: cannot join thread");
    }
    if ((long)retval != EXIT_SUCCESS) {
        test_error("eventfd blocking read test: thread errored out");
    }
    if (readVal != writtenVal) {
        test_error("eventfd blocking read test: unexpected readVal 0x%llX",
                readVal);
    }
}

static void *blocking_write_test_child(void *arg)
{
    int fd = (long)arg;
    ssize_t nbytes;

    writtenVal = EVENTFD_VAL_MAX;
    nbytes = write(fd, (u8 *)&writtenVal, sizeof(writtenVal));
    thread_done = true;
    if (nbytes != sizeof(writtenVal)) {
        printf("eventfd blocking write test child: write returned %ld\n",
                nbytes);
        return (void *)EXIT_FAILURE;
    }
    return (void *)EXIT_SUCCESS;
}

static void blocking_write_test(int fd)
{
    pthread_t pt;
    ssize_t nbytes;
    void *retval;

    writtenVal = EVENTFD_VAL_MAX;
    nbytes = write(fd, &writtenVal, sizeof(writtenVal));
    if (nbytes != sizeof(writtenVal)) {
        test_error("eventfd blocking write test: write returned %ld", nbytes);
    }
    thread_done = false;
    if (pthread_create(&pt, NULL, blocking_write_test_child, (void *)(long)fd))
    {
        test_error("eventfd blocking write test: cannot create thread");
    }
    usleep(100 * 1000);
    if (thread_done) {
        test_error("eventfd blocking write test: thread didn't block");
    }
    nbytes = read(fd, (u8 *)&readVal, sizeof(readVal));
    if (nbytes != sizeof(readVal)) {
        test_error("eventfd blocking write test: read returned %ld", nbytes);
    }
    if (readVal != EVENTFD_VAL_MAX) {
        test_error("eventfd blocking write test: unexpected readVal 0x%llX",
                readVal);
    }
    if (pthread_join(pt, &retval)) {
        test_error("eventfd blocking write test: cannot join thread");
    }
    if ((long)retval != EXIT_SUCCESS) {
        test_error("eventfd blocking write test: thread errored out");
    }

    /* Reset the eventfd counter value. */
    nbytes = read(fd, (u8 *)&readVal, sizeof(readVal));
    if (nbytes != sizeof(readVal)) {
        test_error("eventfd blocking write test: read returned %ld", nbytes);
    }
}

static void fault_test(int fd)
{
    void *fault_addr = FAULT_ADDR;
    ssize_t nbytes;

    nbytes = write(fd, fault_addr, sizeof(writtenVal));
    if ((nbytes != -1) || (errno != EFAULT)) {
        test_error("eventfd fault test write (%ld, %d)", nbytes, errno);
    }

    writtenVal = 1;
    nbytes = write(fd, &writtenVal, sizeof(writtenVal));
    if (nbytes != sizeof(writtenVal)) {
        test_error("eventfd fault test write (%ld, %d)", nbytes, errno);
    }
    nbytes = read(fd, fault_addr, sizeof(readVal));
    if ((nbytes != -1) || (errno != EFAULT)) {
        test_error("eventfd fault test read (%ld, %d)", nbytes, errno);
    }
}

static void nonblocking_test(int fd)
{
    ssize_t nbytes;

    nbytes = read(fd, (u8 *)&readVal, sizeof(readVal));
    if ((nbytes != -1) || (errno != EAGAIN)) {
        test_error("eventfd non-blocking test: read didn't error out (%ld, %d)",
                nbytes, errno);
    }
    writtenVal = EVENTFD_VAL_MAX;
    nbytes = write(fd, &writtenVal, sizeof(writtenVal));
    if (nbytes != sizeof(writtenVal)) {
        test_error("eventfd non-blocking test: write returned %ld", nbytes);
    }
    writtenVal = 1;
    nbytes = write(fd, &writtenVal, sizeof(writtenVal));
    if ((nbytes != -1) || (errno != EAGAIN)) {
        test_error("eventfd non-blocking test: write didn't error out (%ld, %d)",
                nbytes, errno);
    }

    /* Reset the eventfd counter value. */
    nbytes = read(fd, (u8 *)&readVal, sizeof(readVal));
    if (nbytes != sizeof(readVal)) {
        test_error("eventfd non-blocking test: read returned %ld", nbytes);
    }
}

static void semaphore_test(int fd)
{
    ssize_t nbytes;
    int i = 0;

    writtenVal = 8;
    nbytes = write(fd, &writtenVal, sizeof(writtenVal));
    if (nbytes != sizeof(writtenVal)) {
        test_error("eventfd semaphore test: write returned %ld", nbytes);
    }
    i += writtenVal;
    writtenVal = 16;
    nbytes = write(fd, &writtenVal, sizeof(writtenVal));
    if (nbytes != sizeof(writtenVal)) {
        test_error("eventfd semaphore test: write returned %ld", nbytes);
    }
    i += writtenVal;
    for (; i > 0; i--) {
        nbytes = read(fd, (u8 *)&readVal, sizeof(readVal));
        if (nbytes != sizeof(readVal)) {
            test_error("eventfd semaphore test: read returned %ld", nbytes);
        }
        if (readVal != 1) {
            test_error("eventfd semaphore test: read value %lld, should be 1",
                    readVal);
        }
    }
}

static void initval_test(int fd, unsigned int initval)
{
    ssize_t nbytes;

    nbytes = read(fd, (u8 *)&readVal, sizeof(readVal));
    if (nbytes != sizeof(readVal)) {
        test_error("eventfd initval test: read returned %ld", nbytes);
    }
    if (readVal != initval) {
        test_error("eventfd initval test: read value %lld, should be %u",
                readVal, initval);
    }
}

int main(int argc, char **argv)
{
    int fd;

    fd = eventfd(0, 0);
    if (fd < 0) {
        test_perror("eventfd");
    }
    basic_test(fd);
    blocking_read_test(fd);
    blocking_write_test(fd);
    fault_test(fd);
    close(fd);
    fd = eventfd(0, EFD_NONBLOCK);
    if (fd < 0) {
        test_perror("eventfd");
    }
    nonblocking_test(fd);
    close(fd);
    fd = eventfd(0, EFD_SEMAPHORE);
    if (fd < 0) {
        test_perror("eventfd");
    }
    semaphore_test(fd);
    close(fd);
    fd = eventfd(0xDEADBEEF, 0);
    if (fd < 0) {
        test_perror("eventfd");
    }
    initval_test(fd, 0xDEADBEEF);
    close(fd);
    printf("eventfd tests OK\n");
    return EXIT_SUCCESS;
}
