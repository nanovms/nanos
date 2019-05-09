#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <runtime.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <unistd.h>

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
        printf("eventfd basic test: write didn't error out (%ld, %d)\n", nbytes,
                errno);
        exit(EXIT_FAILURE);
    }
    nbytes = write(fd, &writtenVal, sizeof(writtenVal));
    if (nbytes != sizeof(writtenVal)) {
        printf("eventfd basic test: write returned %ld\n", nbytes);
        exit(EXIT_FAILURE);
    }
    nbytes = read(fd, (u8 *)&readVal, sizeof(readVal) - 1);
    if ((nbytes != -1) || (errno != EINVAL)) {
        printf("eventfd basic test: read didn't error out (%ld, %d)\n", nbytes,
                errno);
        exit(EXIT_FAILURE);
    }
    nbytes = read(fd, (u8 *)&readVal, sizeof(readVal));
    if (nbytes != sizeof(readVal)) {
        printf("eventfd basic test: read returned %ld\n", nbytes);
        exit(EXIT_FAILURE);
    }
    if (readVal != writtenVal) {
        printf("eventfd basic test: read value %lld, should be %lld\n", readVal,
                writtenVal);
        exit(EXIT_FAILURE);
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
        printf("eventfd blocking read test: cannot create thread\n");
        exit(EXIT_FAILURE);
    }
    usleep(100 * 1000);
    if (thread_done) {
        printf("eventfd blocking read test: thread didn't block\n");
        exit(EXIT_FAILURE);
    }
    writtenVal = 0xDEADBEEF;
    nbytes = write(fd, &writtenVal, sizeof(writtenVal));
    if (nbytes != sizeof(writtenVal)) {
        printf("eventfd blocking read test: write returned %ld\n", nbytes);
        exit(EXIT_FAILURE);
    }
    if (pthread_join(pt, &retval)) {
        printf("eventfd blocking read test: cannot join thread\n");
        exit(EXIT_FAILURE);
    }
    if ((long)retval != EXIT_SUCCESS) {
        printf("eventfd blocking read test: thread errored out\n");
        exit(EXIT_FAILURE);
    }
    if (readVal != writtenVal) {
        printf("eventfd blocking read test: unexpected readVal 0x%llX\n",
                readVal);
        exit(EXIT_FAILURE);
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
        printf("eventfd blocking write test: write returned %ld\n", nbytes);
        exit(EXIT_FAILURE);
    }
    thread_done = false;
    if (pthread_create(&pt, NULL, blocking_write_test_child, (void *)(long)fd))
    {
        printf("eventfd blocking write test: cannot create thread\n");
        exit(EXIT_FAILURE);
    }
    usleep(100 * 1000);
    if (thread_done) {
        printf("eventfd blocking write test: thread didn't block\n");
        exit(EXIT_FAILURE);
    }
    nbytes = read(fd, (u8 *)&readVal, sizeof(readVal));
    if (nbytes != sizeof(readVal)) {
        printf("eventfd blocking write test: read returned %ld\n", nbytes);
        exit(EXIT_FAILURE);
    }
    if (readVal != EVENTFD_VAL_MAX) {
        printf("eventfd blocking write test: unexpected readVal 0x%llX\n",
                readVal);
        exit(EXIT_FAILURE);
    }
    if (pthread_join(pt, &retval)) {
        printf("eventfd blocking write test: cannot join thread\n");
        exit(EXIT_FAILURE);
    }
    if ((long)retval != EXIT_SUCCESS) {
        printf("eventfd blocking write test: thread errored out\n");
        exit(EXIT_FAILURE);
    }

    /* Reset the eventfd counter value. */
    nbytes = read(fd, (u8 *)&readVal, sizeof(readVal));
    if (nbytes != sizeof(readVal)) {
        printf("eventfd blocking write test: read returned %ld\n", nbytes);
        exit(EXIT_FAILURE);
    }
}

static void nonblocking_test(int fd)
{
    ssize_t nbytes;

    nbytes = read(fd, (u8 *)&readVal, sizeof(readVal));
    if ((nbytes != -1) || (errno != EAGAIN)) {
        printf("eventfd non-blocking test: read didn't error out (%ld, %d)\n",
                nbytes, errno);
        exit(EXIT_FAILURE);
    }
    writtenVal = EVENTFD_VAL_MAX;
    nbytes = write(fd, &writtenVal, sizeof(writtenVal));
    if (nbytes != sizeof(writtenVal)) {
        printf("eventfd non-blocking test: write returned %ld\n", nbytes);
        exit(EXIT_FAILURE);
    }
    writtenVal = 1;
    nbytes = write(fd, &writtenVal, sizeof(writtenVal));
    if ((nbytes != -1) || (errno != EAGAIN)) {
        printf("eventfd non-blocking test: write didn't error out (%ld, %d)\n",
                nbytes, errno);
        exit(EXIT_FAILURE);
    }

    /* Reset the eventfd counter value. */
    nbytes = read(fd, (u8 *)&readVal, sizeof(readVal));
    if (nbytes != sizeof(readVal)) {
        printf("eventfd non-blocking test: read returned %ld\n", nbytes);
        exit(EXIT_FAILURE);
    }
}

static void semaphore_test(int fd)
{
    ssize_t nbytes;
    int i = 0;

    writtenVal = 8;
    nbytes = write(fd, &writtenVal, sizeof(writtenVal));
    if (nbytes != sizeof(writtenVal)) {
        printf("eventfd semaphore test: write returned %ld\n", nbytes);
        exit(EXIT_FAILURE);
    }
    i += writtenVal;
    writtenVal = 16;
    nbytes = write(fd, &writtenVal, sizeof(writtenVal));
    if (nbytes != sizeof(writtenVal)) {
        printf("eventfd semaphore test: write returned %ld\n", nbytes);
        exit(EXIT_FAILURE);
    }
    i += writtenVal;
    for (; i > 0; i--) {
        nbytes = read(fd, (u8 *)&readVal, sizeof(readVal));
        if (nbytes != sizeof(readVal)) {
            printf("eventfd semaphore test: read returned %ld\n", nbytes);
            exit(EXIT_FAILURE);
        }
        if (readVal != 1) {
            printf("eventfd semaphore test: read value %lld, should be 1\n",
                    readVal);
            exit(EXIT_FAILURE);
        }
    }
}

static void initval_test(int fd, unsigned int initval)
{
    ssize_t nbytes;

    nbytes = read(fd, (u8 *)&readVal, sizeof(readVal));
    if (nbytes != sizeof(readVal)) {
        printf("eventfd initval test: read returned %ld\n", nbytes);
        exit(EXIT_FAILURE);
    }
    if (readVal != initval) {
        printf("eventfd initval test: read value %lld, should be %u\n",
                readVal, initval);
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char **argv)
{
    int fd;

    fd = eventfd(0, 0);
    if (fd < 0) {
        perror("eventfd");
        return EXIT_FAILURE;
    }
    basic_test(fd);
    blocking_read_test(fd);
    blocking_write_test(fd);
    close(fd);
    fd = eventfd(0, EFD_NONBLOCK);
    if (fd < 0) {
        perror("eventfd");
        return EXIT_FAILURE;
    }
    nonblocking_test(fd);
    close(fd);
    fd = eventfd(0, EFD_SEMAPHORE);
    if (fd < 0) {
        perror("eventfd");
        return EXIT_FAILURE;
    }
    semaphore_test(fd);
    close(fd);
    fd = eventfd(0xDEADBEEF, 0);
    if (fd < 0) {
        perror("eventfd");
        return EXIT_FAILURE;
    }
    initval_test(fd, 0xDEADBEEF);
    close(fd);
    printf("eventfd tests OK\n");
    return EXIT_SUCCESS;
}
