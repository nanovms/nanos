#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/eventfd.h>
#include <errno.h>

#define test_assert(expr) do { \
    if (!(expr)) { \
        printf("Error: %s -- failed at %s:%d\n", #expr, __FILE__, __LINE__); \
        exit(EXIT_FAILURE); \
    } \
} while (0)

/* Covers EPOLL_CTL_ADD and EPOLL_CTL_DEL epoll_ctl operations */
void test_ctl()
{
    int efd;
    struct epoll_event event;

    efd = epoll_create1(0);
    if (efd < 0) {
        printf("Cannot create epoll\n");
        goto fail;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    event.data.fd = fd;
    event.events = EPOLLIN;

    if ((epoll_ctl(efd, EPOLL_CTL_ADD, fd, NULL) != -1) || (errno != EFAULT)) {
        printf("NULL event pointer is not allowed for EPOLL_CTL_ADD\n");
        goto fail;
    }

    if (epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event)) {
        printf("Cannot add descriptor to epoll\n");
        goto fail;
    }

    if ((epoll_ctl(efd, EPOLL_CTL_MOD, fd, NULL) != -1) || (errno != EFAULT)) {
        printf("NULL event pointer is not allowed for EPOLL_CTL_MOD\n");
        goto fail;
    }

    event.events = EPOLLIN | EPOLLOUT;
    if (epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event)) {
        printf("Cannot modify epoll settings for existing descriptor\n");
        goto fail;
    }

    close(fd);
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event)) {
        printf("Cannot re-add descriptor to epoll\n");
        goto fail;
    }

    /* EPOLL_CTL_DEL must accept NULL for the event pointer */
    if (epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL)) {
        printf("Cannot remove descriptor from epoll\n");
        goto fail;
    }

    if (close(efd)) {
        printf("Cannot close epoll\n");
        goto fail;
    }

    return;
  fail:
    printf("test failed\n");
    exit(EXIT_FAILURE);
}

static void test_wait()
{
    int efd;
    int fd;
    struct epoll_event event;

    efd = epoll_create1(0);
    test_assert(efd >= 0);
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    event.data.fd = fd;
    event.events = EPOLLOUT;
    test_assert(epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event) == 0);
    test_assert(epoll_wait(efd, &event, 1, -1) == 1);
    test_assert((event.data.fd == fd) && (event.events == EPOLLOUT));

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

int main(int argc, char **argv)
{
    test_ctl();
    test_wait();
    test_edgetrigger();
    test_eventfd_et();

    printf("test passed\n");
    return EXIT_SUCCESS;
}
