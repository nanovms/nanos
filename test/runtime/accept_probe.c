/* Counts the connections accept() hands out, for a peer that resets some of them first.
 *
 * The peer has to be a real TCP stack, because the connections have to die while they wait in the
 * queue of the listening socket, and this one never sends a reset of its own. So the program only
 * listens and counts: the connections are made, and reset, from outside the machine, by the driver
 * in test/extended_tests.py.
 *
 * It announces itself, leaves the peer time to open and reset its connections, and only then
 * accepts, so that every one of them is waiting in the queue by the time the first accept() runs.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "../test_utils.h"

#define PORT        9090
#define QUIET_USEC  6000000     /* while the peer opens its connections and resets them */

int main(int argc, char **argv)
{
    struct sockaddr_in addr;
    int lfd, accepted = 0;

    lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0)
        test_perror("socket");
    int one = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(PORT);
    if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        test_perror("bind");
    if (listen(lfd, 100) < 0)
        test_perror("listen");

    printf("PROBE READY %d\n", PORT);
    fflush(stdout);

    usleep(QUIET_USEC);

    if (fcntl(lfd, F_SETFL, fcntl(lfd, F_GETFL, 0) | O_NONBLOCK) < 0)
        test_perror("F_SETFL");
    for (;;) {
        int fd = accept(lfd, NULL, NULL);
        if (fd < 0) {
            if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
                break;
            if (errno == ECONNABORTED)      /* a peer that is gone, reported as such */
                continue;
            test_perror("accept");
        }
        accepted++;
        close(fd);
    }
    close(lfd);

    printf("PROBE ACCEPTED %d\n", accepted);
    fflush(stdout);
    return EXIT_SUCCESS;
}
