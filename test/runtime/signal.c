#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>

#include <runtime.h>

#define handle_error(msg) \
       do { perror(msg); exit(EXIT_FAILURE); } while (0)

static int child_tid;

static void * tgkill_test_pause(void * arg)
{
    child_tid = syscall(SYS_gettid);
    printf("dingus\n");
    int rv = pause();
    if (rv < 0) {
        if (errno == EINTR) {
            printf("child received signal\n");
            return (void*)EXIT_SUCCESS;
        } else {
            printf("unexpected errno %d (%s)\n", errno, strerror(errno));
            return (void*)EXIT_FAILURE;
        }
    }
    printf("pause: unexepected retval %d\n", rv);
    return (void*)EXIT_FAILURE;
}

void test_tgkill(void)
{
    int rv;
    pthread_t pt = 0;
    if (pthread_create(&pt, NULL, tgkill_test_pause, NULL))
        handle_error("blocking test pthread_create");

    printf("sleep 1s\n");
    sleep(1);
    if (child_tid == 0) {
        printf("fail; no tid set from child\n");
        exit(EXIT_FAILURE);
    }

    printf("spawned tid %d; sending SIGUSR1\n", child_tid);
    rv = syscall(SYS_tgkill, 1, child_tid, SIGUSR1);
    if (rv < 0) {
        handle_error("tgkill");
        exit(EXIT_FAILURE);
    }

    void * retval;
    if (pthread_join(pt, &retval)) {
        handle_error("blocking test pthread_join");
        exit(EXIT_FAILURE);
    }

    if (retval != (void*)EXIT_SUCCESS) {
        printf("tgkill_test_pause child failed\n");
        exit(EXIT_FAILURE);
    }
}

static void test_signal_catch_handler(int sig)
{
    printf("caught signal %d\n", sig);
}


void test_signal_catch(void)
{
    pthread_t pt = 0;
    if (pthread_create(&pt, NULL, tgkill_test_pause, NULL))
        handle_error("blocking test pthread_create");

    printf("sleep 1s\n");
    sleep(1);
    if (child_tid == 0) {
        printf("fail; no tid set from child\n");
        exit(EXIT_FAILURE);
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = test_signal_catch_handler;
    int rv = sigaction(SIGUSR1, &sa, 0);
    if (rv < 0)
        handle_error("test_signal_catch: sigaction");

    rv = syscall(SYS_tgkill, 1, child_tid, SIGUSR1);
    if (rv < 0)
        handle_error("signal catch tgkill");

    void * retval;
    if (pthread_join(pt, &retval)) {
        handle_error("blocking test pthread_join");
        exit(EXIT_FAILURE);
    }

    if (retval != (void*)EXIT_SUCCESS) {
        printf("tgkill_test_pause child failed\n");
        exit(EXIT_FAILURE);
    }
}
    
table parse_arguments(heap h, int argc, char **argv);

int main(int argc, char * argv[])
{
    setbuf(stdout, NULL);
    heap h = init_process_runtime();
    parse_arguments(h, argc, argv);

    test_tgkill();

    test_signal_catch();

    printf("signal test passed\n");
}
