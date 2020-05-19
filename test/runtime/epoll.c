#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <errno.h>

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

int main(int argc, char **argv)
{
    test_ctl();

    printf("test passed\n");
    return EXIT_SUCCESS;
}
