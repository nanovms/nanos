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

//#define SIGNALTEST_DEBUG
#ifdef SIGNALTEST_DEBUG
#define sigtest_debug(x, ...) do {printf("%s: " x, __func__, ##__VA_ARGS__);} while(0)
#else
#define sigtest_debug(x, ...)
#endif

#define sigtest_err(x, ...) do {printf("%s: " x, __func__, ##__VA_ARGS__);} while(0)

#define fail_perror(msg, ...) do { sigtest_err(msg ": %s (%d)\n", ##__VA_ARGS__, strerror(errno), errno); \
        exit(EXIT_FAILURE); } while(0)

#define fail_error(msg, ...) do { sigtest_err(msg, ##__VA_ARGS__); exit(EXIT_FAILURE); } while(0)

static int child_tid;

static void * tgkill_test_pause(void * arg)
{
    child_tid = syscall(SYS_gettid);
    int rv = syscall(SYS_pause);
    if (rv < 0) {
        if (errno == EINTR) {
            sigtest_debug("child received signal\n");
            return (void*)EXIT_SUCCESS;
        } else {
            fail_perror("pause unexpected errno");
        }
    }
    fail_error("pause: unexpected retval %d\n", rv);
}

void test_tgkill(void)
{
    int rv;
    pthread_t pt = 0;
    if (pthread_create(&pt, NULL, tgkill_test_pause, NULL))
        fail_perror("blocking test pthread_create");

    sleep(1);
    if (child_tid == 0)
        fail_error("fail; no tid set from child\n");

    sigtest_debug("spawned tid %d; sending SIGUSR1\n", child_tid);
    rv = syscall(SYS_tgkill, 1, child_tid, SIGUSR1);
    if (rv < 0)
        fail_perror("tgkill");

    void * retval;
    if (pthread_join(pt, &retval))
        fail_perror("blocking test pthread_join");

    if (retval != (void*)EXIT_SUCCESS)
        fail_error("tgkill_test_pause child failed\n");
}

static void test_signal_catch_handler(int sig)
{
    sigtest_debug("caught signal %d\n", sig);
}

void test_signal_catch(void)
{
    pthread_t pt = 0;
    if (pthread_create(&pt, NULL, tgkill_test_pause, NULL))
        fail_perror("blocking test pthread_create");

    sigtest_debug("sleep 1s\n");
    sleep(1);
    if (child_tid == 0)
        fail_error("fail; no tid set from child\n");

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = test_signal_catch_handler;
    int rv = sigaction(SIGUSR1, &sa, 0);
    if (rv < 0)
        fail_perror("test_signal_catch: sigaction");

    rv = syscall(SYS_tgkill, 1, child_tid, SIGUSR1);
    if (rv < 0)
        fail_perror("signal catch tgkill");

    void * retval;
    if (pthread_join(pt, &retval))
        fail_perror("blocking test pthread_join");

    if (retval != (void*)EXIT_SUCCESS)
        fail_error("tgkill_test_pause child failed\n");
}

#define TEST_RT_NQUEUE  128

static int test_rt_caught = 0;

static void test_rt_signal_queueing_handler(int sig, siginfo_t *si, void *ucontext)
{
    assert(si);
    sigtest_debug("sig %d, si->signo %d, si->errno %d, si->code %d, # %d\n",
                  sig, si->si_signo, si->si_errno, si->si_code, test_rt_caught);
    assert(sig == SIGRTMIN);
    assert(sig == si->si_signo);
    test_rt_caught++;

    sigset_t sigset;

    /* test rt_sigpending */
    long rv = syscall(SYS_rt_sigpending, &sigset);
    if (rv < 0)
        fail_perror("sigpending");

    if (test_rt_caught < TEST_RT_NQUEUE) {
        if (!sigismember(&sigset, sig))
            fail_error("sig %d should still be pending until we serviced the last signal\n", sig);
    } else {
        if (sigismember(&sigset, sig))
            fail_error("sig %d should not be pending; all queued signals have been handled\n", sig);
    }
}

static void * test_rt_signal_child(void * arg)
{
    child_tid = syscall(SYS_gettid);
    for(;;) {
        int rv = syscall(SYS_pause);
        if (rv < 0) {
            if (errno == EINTR) {
                if (test_rt_caught < TEST_RT_NQUEUE)
                    continue;
                return (void*)EXIT_SUCCESS;
            } else {
                sigtest_err("unexpected errno %d (%s)\n", errno, strerror(errno));
                return (void*)EXIT_FAILURE;
            }
        }
        sigtest_err("pause: unexpected retval %d\n", rv);
        return (void*)EXIT_FAILURE;
    }
}

/* test sigaction (siginfo) handler and queued signals */
void test_rt_signal(void)
{
    pthread_t pt = 0;
    if (pthread_create(&pt, NULL, test_rt_signal_child, NULL))
        fail_perror("blocking test pthread_create");

    sigtest_debug("sleep 1s\n");
    sleep(1);
    if (child_tid == 0)
        fail_error("fail; no tid set from child\n");

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = test_rt_signal_queueing_handler;
    sa.sa_flags |= SA_SIGINFO;
    int rv = sigaction(SIGRTMIN, &sa, 0);
    if (rv < 0)
        fail_perror("test_signal_catch: sigaction");

    for (int i = 0; i < TEST_RT_NQUEUE; i++) {
        rv = syscall(SYS_tgkill, 1, child_tid, SIGRTMIN);
        if (rv < 0)
            fail_perror("signal catch tgkill");
    }

    void * retval;
    if (pthread_join(pt, &retval))
        fail_perror("blocking test pthread_join");

    if (retval != (void*)EXIT_SUCCESS)
        fail_error("tgkill_test_pause child failed\n");
}
    
table parse_arguments(heap h, int argc, char **argv);

int main(int argc, char * argv[])
{
    setbuf(stdout, NULL);
    heap h = init_process_runtime();
    parse_arguments(h, argc, argv);

    test_tgkill();

    test_signal_catch();

    test_rt_signal();

    printf("signal test passed\n");
}
