#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#include <sched.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/eventfd.h>
#include <errno.h>

#include "../test_utils.h"

/* for old libc versions */
#ifndef EPOLLEXCLUSIVE
#define EPOLLEXCLUSIVE  (1 << 28)
#endif

struct test_epoll {
    int efd;
    volatile int wake_count;
};

/* Covers EPOLL_CTL_ADD and EPOLL_CTL_DEL epoll_ctl operations */
void test_ctl()
{
    int efd;
    struct epoll_event event;

    efd = epoll_create1(0);
    if (efd < 0) {
        test_perror("cannot create epoll");
    }

    event.events = 0;
    test_assert((epoll_ctl(efd, EPOLL_CTL_ADD, -1, &event) == -1) && (errno == EBADF));

    int dirfd = open(".", O_RDONLY);
    test_assert(dirfd >= 0);
    test_assert((epoll_ctl(efd, EPOLL_CTL_ADD, dirfd, &event) == -1) && (errno == EPERM));
    close(dirfd);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    event.data.fd = fd;
    event.events = EPOLLIN;

    if ((epoll_ctl(efd, EPOLL_CTL_ADD, fd, NULL) != -1) || (errno != EFAULT)) {
        test_error("NULL event pointer is not allowed for EPOLL_CTL_ADD");
    }

    if (epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event)) {
        test_perror("cannot add descriptor to epoll");
    }

    if ((epoll_ctl(efd, EPOLL_CTL_MOD, fd, NULL) != -1) || (errno != EFAULT)) {
        test_error("NULL event pointer is not allowed for EPOLL_CTL_MOD");
    }

    event.events = EPOLLIN | EPOLLOUT;
    if (epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event)) {
        test_perror("cannot modify epoll settings for existing descriptor");
    }

    close(fd);
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event)) {
        test_perror("cannot re-add descriptor to epoll");
    }

    /* EPOLL_CTL_DEL must accept NULL for the event pointer */
    if (epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL)) {
        test_perror("cannot remove descriptor from epoll");
    }

    if (close(efd)) {
        test_perror("cannot close epoll");
    }

    return;
}

static void test_wait()
{
    int efd;
    int fd;
    struct epoll_event event;
    void *fault_addr = FAULT_ADDR;

    efd = epoll_create1(0);
    test_assert(efd >= 0);
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    event.data.fd = fd;
    event.events = EPOLLOUT;
    test_assert(epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event) == 0);
    test_assert(epoll_wait(efd, &event, 1, -1) == 1);
    test_assert((event.data.fd == fd) && (event.events == EPOLLOUT));

    test_assert((epoll_wait(efd, fault_addr, 1, -1) == -1) && (errno == EFAULT));

    /* Close the writable file descriptor and verify that no more EPOLLOUT events are reported. */
    close(fd);
    test_assert(epoll_wait(efd, &event, 1, 0) == 0);

    close(efd);
}

static void test_edgetrigger()
{
    const int fd_count = 3;
    int efd;
    int fds[fd_count];
    struct epoll_event events[fd_count];

    efd = epoll_create1(0);
    test_assert(efd >= 0);

    for (int i = 0; i < fd_count; i++) {
        /* Register a writable file descriptor on the epoll instance. */
        fds[i] = socket(AF_INET, SOCK_DGRAM, 0);
        events[0].data.fd = fds[i];
        events[0].events = EPOLLOUT | EPOLLET;
        test_assert(epoll_ctl(efd, EPOLL_CTL_ADD, fds[i], events) == 0);

        /* Check that epoll_wait() returns the last registered file descriptor only (previously
         * registered descriptors, while still writable, should not be returned because of edge
         * trigger behavior). */
        test_assert(epoll_wait(efd, events, fd_count, -1) == 1);
        test_assert((events[0].data.fd == fds[i]) && (events[0].events == EPOLLOUT));
    }

    for (int i = 0; i < fd_count; i++) {
        close(fds[i]);
    }
    close(efd);
}

#define EVENTFD_MAX 0xfffffffffffffffeull
void test_eventfd_et()
{
    int efd;
    int evfd;
    struct epoll_event events;
    uint64_t w;

    efd = epoll_create1(0);
    test_assert(efd >= 0);
    evfd = eventfd(0, EFD_NONBLOCK);
    test_assert(evfd >= 0);
    events.data.fd = evfd;
    events.events = EPOLLOUT | EPOLLIN;
    test_assert(epoll_ctl(efd, EPOLL_CTL_ADD, evfd, &events) == 0);

    test_assert(epoll_wait(efd, &events, 1, 100) == 1);
    test_assert((events.data.fd == evfd) && (events.events == EPOLLOUT));
    test_assert(epoll_wait(efd, &events, 1, 100) == 1);
    test_assert((events.data.fd == evfd) && (events.events == EPOLLOUT));

    w = 1;
    test_assert((write(evfd, &w, sizeof(w)) == sizeof(w)));

    test_assert(epoll_wait(efd, &events, 1, 100) == 1);
    test_assert((events.data.fd == evfd) && (events.events == (EPOLLOUT | EPOLLIN)));
    test_assert(epoll_wait(efd, &events, 1, 100) == 1);
    test_assert((events.data.fd == evfd) && (events.events == (EPOLLOUT | EPOLLIN)));

    test_assert((write(evfd, &w, sizeof(w)) == sizeof(w)));

    test_assert(epoll_wait(efd, &events, 1, 100) == 1);
    test_assert((events.data.fd == evfd) && (events.events == (EPOLLOUT | EPOLLIN)));
    test_assert(epoll_wait(efd, &events, 1, 100) == 1);
    test_assert((events.data.fd == evfd) && (events.events == (EPOLLOUT | EPOLLIN)));

    test_assert((read(evfd, &w, sizeof(w)) == sizeof(w) && w == 2));

    test_assert(epoll_wait(efd, &events, 1, 100) == 1);
    test_assert((events.data.fd == evfd) && (events.events == EPOLLOUT));
    test_assert(epoll_wait(efd, &events, 1, 100) == 1);
    test_assert((events.data.fd == evfd) && (events.events == EPOLLOUT));

    w = EVENTFD_MAX;
    test_assert((write(evfd, &w, sizeof(w)) == sizeof(w)));

    test_assert(epoll_wait(efd, &events, 1, 100) == 1);
    test_assert((events.data.fd == evfd) && (events.events == (EPOLLIN)));
    test_assert(epoll_wait(efd, &events, 1, 100) == 1);
    test_assert((events.data.fd == evfd) && (events.events == (EPOLLIN)));

    test_assert((read(evfd, &w, sizeof(w)) == sizeof(w) && w == EVENTFD_MAX));

    /* turn on edge trigger */
    events.events = EPOLLOUT | EPOLLIN | EPOLLET;
    test_assert(epoll_ctl(efd, EPOLL_CTL_MOD, evfd, &events) == 0);

    test_assert(epoll_wait(efd, &events, 1, 100) == 1);
    test_assert((events.data.fd == evfd) && (events.events == EPOLLOUT));
    test_assert(epoll_wait(efd, &events, 1, 100) == 0);

    w = 1;
    test_assert((write(evfd, &w, sizeof(w)) == sizeof(w)));

    test_assert(epoll_wait(efd, &events, 1, 100) == 1);
    test_assert((events.data.fd == evfd) && (events.events == (EPOLLOUT | EPOLLIN)));
    test_assert(epoll_wait(efd, &events, 1, 100) == 0);

    test_assert((write(evfd, &w, sizeof(w)) == sizeof(w)));

    test_assert(epoll_wait(efd, &events, 1, 100) == 1);
    test_assert((events.data.fd == evfd) && (events.events == (EPOLLOUT | EPOLLIN)));
    test_assert(epoll_wait(efd, &events, 1, 100) == 0);

    test_assert((read(evfd, &w, sizeof(w)) == sizeof(w) && w == 2));

    test_assert(epoll_wait(efd, &events, 1, 100) == 1);
    test_assert((events.data.fd == evfd) && (events.events == EPOLLOUT));
    test_assert(epoll_wait(efd, &events, 1, 100) == 0);

    w = EVENTFD_MAX;
    test_assert((write(evfd, &w, sizeof(w)) == sizeof(w)));

    test_assert(epoll_wait(efd, &events, 1, 100) == 1);
    test_assert((events.data.fd == evfd) && (events.events == (EPOLLIN)));
    test_assert(epoll_wait(efd, &events, 1, 100) == 0);

    close(evfd);
    close(efd);
}

static void *epollexclusive_thread(void *arg)
{
    struct test_epoll *t = arg;
    struct epoll_event events;

    test_assert(epoll_wait(t->efd, &events, 1, -1) == 1);
    test_assert(events.events == EPOLLIN);
    __atomic_add_fetch(&t->wake_count, 1, __ATOMIC_ACQUIRE);
    return NULL;
}

static void wait_excl(struct test_epoll *t, int excl_count, int wake_count)
{
    int count;

    do {
        sched_yield();
        count = 0;
        for (int i = 0; i < excl_count; i++)
            count += t[i].wake_count;
    } while (count < wake_count);
}

static void test_epollexclusive(void)
{
    const int efd_count = 8;
    const int excl_count = efd_count / 2;
    const int thread_count = 8;
    int evfd;
    struct test_epoll t[efd_count];
    struct epoll_event events;
    pthread_t threads[efd_count * thread_count];
    int i, j;
    unsigned long w = 1;
    int write_count;

    evfd = eventfd(0, 0);
    test_assert(evfd >= 0);
    events.data.fd = evfd;
    for (i = 0; i < efd_count; i++) {
        t[i].efd = epoll_create1(0);
        test_assert(t[i].efd >= 0);
        if (i < excl_count)
            events.events = EPOLLIN | EPOLLEXCLUSIVE;
        else
            events.events = EPOLLIN;
        test_assert(epoll_ctl(t[i].efd, EPOLL_CTL_ADD, evfd, &events) == 0);
        t[i].wake_count = 0;
        for (j = 0; j < thread_count; j++)
            test_assert(pthread_create(&threads[i * thread_count + j], NULL,
                                       epollexclusive_thread, &t[i]) == 0);
    }

    /* make file descriptor readable */
    test_assert((write(evfd, &w, sizeof(w)) == sizeof(w)));
    write_count = 1;

    /* verify that all non-exclusive waiters are woken up */
    for (i = excl_count; i < efd_count; i++) {
        for (j = 0; j < thread_count; j++)
            test_assert(pthread_join(threads[i * thread_count + j], NULL) == 0);
        test_assert(t[i].wake_count == thread_count);
        close(t[i].efd);
    }

    /* wait until one exclusive waiter is woken up */
    wait_excl(t, excl_count, write_count);

    while (write_count < excl_count * thread_count) {
        /* make file descriptor readable, and wait until one exclusive waiter is woken up */
        test_assert((write(evfd, &w, sizeof(w)) == sizeof(w)));
        wait_excl(t, excl_count, ++write_count);
    }

    /* verify that all exclusive waiters have been woken up */
    for (i = 0; i < excl_count; i++) {
        test_assert(t[i].wake_count == thread_count);
        for (j = 0; j < thread_count; j++)
            test_assert(pthread_join(threads[i * thread_count + j], NULL) == 0);
        close(t[i].efd);
    }

    close(evfd);
}

int main(int argc, char **argv)
{
    test_ctl();
    test_wait();
    test_edgetrigger();
    test_eventfd_et();
    test_epollexclusive();

    printf("test passed\n");
    return EXIT_SUCCESS;
}
