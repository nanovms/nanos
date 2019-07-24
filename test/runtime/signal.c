#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>

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

static volatile int child_tid;

static void yield_for(volatile int * v)
{
    int tries = 128;
    while (!*v && tries-- > 0)
        sched_yield();
    if (!*v)
        fail_error("timed out");
}

static void * tgkill_test_pause(void * arg)
{
    child_tid = syscall(SYS_gettid);
    sigtest_debug("child enter, tid %d\n", child_tid);
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

static void test_signal_catch_handler(int sig)
{
    sigtest_debug("caught signal %d\n", sig);
}

void test_signal_catch(void)
{
    pthread_t pt = 0;
    child_tid = 0;
    if (pthread_create(&pt, NULL, tgkill_test_pause, NULL))
        fail_perror("blocking test pthread_create");

    sigtest_debug("yielding until child tid reported...\n");
    yield_for(&child_tid);

    /* not pretty, but should ensure child gets to pause(2) */
    sleep(1);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = test_signal_catch_handler;
    int rv = sigaction(SIGUSR1, &sa, 0);
    if (rv < 0)
        fail_perror("test_signal_catch: sigaction");

    rv = syscall(SYS_tgkill, getpid(), child_tid, SIGUSR1);
    if (rv < 0)
        fail_perror("signal catch tgkill");

    sigtest_debug("waiting for child to exit...\n");
    void * retval;
    if (pthread_join(pt, &retval))
        fail_perror("blocking test pthread_join");

    if (retval != (void*)EXIT_SUCCESS)
        fail_error("tgkill_test_pause child failed\n");
}

#define TEST_RT_NQUEUE  128

static volatile int test_rt_caught = 0;

static void test_rt_signal_queueing_handler(int sig, siginfo_t *si, void *ucontext)
{
    assert(si);
    sigtest_debug("sig %d, si->signo %d, si->errno %d, si->code %d, # %d\n",
                  sig, si->si_signo, si->si_errno, si->si_code, test_rt_caught);
    assert(sig == SIGRTMIN);
    assert(sig == si->si_signo);
    assert(si->si_code == SI_QUEUE);
    assert(si->si_value.sival_int == test_rt_caught);
    test_rt_caught++;

    sigset_t sigset;

    /* test rt_sigpending */
    long rv = syscall(SYS_rt_sigpending, &sigset, 8);
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

static volatile int test_rt_signal_enable;

static void * test_rt_signal_child(void * arg)
{
    sigset_t ss;
    sigemptyset(&ss);
    sigaddset(&ss, SIGRTMIN);
    int rv = sigprocmask(SIG_BLOCK, &ss, 0);
    if (rv < 0)
        fail_perror("sigprocmask");
    child_tid = syscall(SYS_gettid);

    /* wait for master to queue up signals */
    while (test_rt_signal_enable == 0)
        sched_yield();

    for(;;) {
        sigset_t mask_ss;
        sigemptyset(&mask_ss);
        int rv = syscall(SYS_rt_sigsuspend, &mask_ss, 8);
        if (rv >= 0) {
            sigtest_err("call to rt_sigsuspend rv >= 0");
            return (void*)EXIT_FAILURE;
        }
        if (errno == EINTR) {
            if (test_rt_caught < TEST_RT_NQUEUE)
                continue;
            return (void*)EXIT_SUCCESS;
        } else {
            sigtest_err("sigsuspend: unexpected errno %d (%s)\n", errno, strerror(errno));
            return (void*)EXIT_FAILURE;
        }
        sigtest_err("sigsuspend: unexpected retval %d\n", rv);
        return (void*)EXIT_FAILURE;
    }
}

/* test sigaction (siginfo) handler and queued signals */
void test_rt_signal(void)
{
    pthread_t pt = 0;
    child_tid = 0;
    test_rt_signal_enable = 0;
    if (pthread_create(&pt, NULL, test_rt_signal_child, NULL))
        fail_perror("blocking test pthread_create");

    sigtest_debug("yielding until child tid reported...\n");
    yield_for(&child_tid);

    sigset_t ss;
    sigemptyset(&ss);
    sigaddset(&ss, SIGRTMIN);
    int rv = sigprocmask(SIG_BLOCK, &ss, 0);
    if (rv < 0)
        fail_perror("sigprocmask");
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = test_rt_signal_queueing_handler;
    sa.sa_flags |= SA_SIGINFO;
    rv = sigaction(SIGRTMIN, &sa, 0);
    if (rv < 0)
        fail_perror("test_signal_catch: sigaction");

    for (int i = 0; i < TEST_RT_NQUEUE; i++) {
        union sigval sv;
        sv.sival_int = i;
        rv = sigqueue(getpid(), SIGRTMIN, sv);
        if (rv < 0)
            fail_perror("signal catch sigqueue");
    }

    sigtest_debug("enabling and waiting for child to exit...\n");
    test_rt_signal_enable = 1;
    void * retval;
    if (pthread_join(pt, &retval))
        fail_perror("blocking test pthread_join");

    if (retval != (void*)EXIT_SUCCESS)
        fail_error("tgkill_test_pause child failed\n");
}


static volatile int test_kill_caught;

static void test_kill_handler(int sig, siginfo_t *si, void *ucontext)
{
    assert(si);
    sigtest_debug("sig %d, si->signo %d, si->errno %d, si->code %d\n",
                  sig, si->si_signo, si->si_errno, si->si_code);
    assert(sig == SIGRTMIN);
    assert(sig == si->si_signo);
    test_kill_caught = 1;
}

void test_kill(void)
{
    sigtest_debug("\n");

    test_kill_caught = 0;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = test_kill_handler;
    sa.sa_flags |= SA_SIGINFO;
    int rv = sigaction(SIGRTMIN, &sa, 0);
    if (rv < 0)
        fail_perror("test_signal_catch: sigaction");

    sigset_t ss;
    sigemptyset(&ss);
    sigaddset(&ss, SIGRTMIN);
    rv = sigprocmask(SIG_UNBLOCK, &ss, 0);
    if (rv < 0)
        fail_perror("sigprocmask");

    rv = syscall(SYS_kill, getpid(), SIGRTMIN);
    if (rv < 0)
        fail_perror("signal catch kill");

    if (!test_kill_caught)
        fail_error("signal not caught");
}

void test_rt_sigqueueinfo(void)
{
    sigtest_debug("\n");

    test_kill_caught = 0;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = test_kill_handler;
    sa.sa_flags |= SA_SIGINFO;
    int rv = sigaction(SIGRTMIN, &sa, 0);
    if (rv < 0)
        fail_perror("test_signal_catch: sigaction");

    sigset_t ss;
    sigemptyset(&ss);
    sigaddset(&ss, SIGRTMIN);
    rv = sigprocmask(SIG_UNBLOCK, &ss, 0);
    if (rv < 0)
        fail_perror("sigprocmask");

    siginfo_t si;
    memset(&si, 0, sizeof(siginfo_t));
    si.si_code = SI_MESGQ;
    si.si_pid = getpid();
    si.si_uid = getuid();
    rv = syscall(SYS_rt_sigqueueinfo, getpid(), SIGRTMIN, &si);
    if (rv < 0)
        fail_perror("sigqueueinfo for SIGRTMIN");

    if (!test_kill_caught)
        fail_error("signal not caught");
}

static volatile int rt_sigsuspend_handler_reached;
static volatile int rt_sigsuspend_handler_2_reached;
static volatile int rt_sigsuspend_next_sig;
static volatile int rt_sigsuspend_caught_on_unmask;

static void test_rt_sigsuspend_handler(int sig, siginfo_t *si, void *ucontext)
{
    sigtest_debug("reached\n");
    assert(sig == SIGRTMIN);
    if (!rt_sigsuspend_next_sig) {
        rt_sigsuspend_handler_reached = 1;
    } else {
        fail_error("signal should have been masked");
    }
}

static void test_rt_sigsuspend_handler_2(int sig, siginfo_t *si, void *ucontext)
{
    sigtest_debug("reached\n");
    assert(sig == SIGRTMIN + 1);
    if (rt_sigsuspend_next_sig) {
        rt_sigsuspend_handler_2_reached = 1;
    } else {
        fail_error("signal should have been masked");
    }
}

static void *test_rt_sigsuspend_child(void *arg)
{
    sigtest_debug("start, block SIGRTMIN and SIGRTMIN + 1 with sigprocmask\n");
    sigset_t ss;
    sigemptyset(&ss);
    sigaddset(&ss, SIGRTMIN);
    sigaddset(&ss, SIGRTMIN + 1);
    int rv = sigprocmask(SIG_BLOCK, &ss, 0);
    if (rv < 0)
        fail_perror("sigprocmask");

    child_tid = syscall(SYS_gettid);
    /* test one - handle SIGRTMIN and leave SIGRTMIN + 1 masked */
    sigset_t mask_ss;
    sigemptyset(&mask_ss);
    sigaddset(&mask_ss, SIGRTMIN + 1);
    rv = syscall(SYS_rt_sigsuspend, &mask_ss, 8);
    if (rv >= 0)
        fail_error("call to rt_sigsuspend rv >= 0");
    if (errno != EINTR)
        fail_perror("errno != EINTR");
    if (!rt_sigsuspend_handler_reached)
        fail_error("signal handler not reached");

    rt_sigsuspend_next_sig = 1;

    /* test two - still pending SIGRTMIN + 1 should be handled now */
    sigemptyset(&mask_ss);
    sigaddset(&mask_ss, SIGRTMIN);
    rv = syscall(SYS_rt_sigsuspend, &mask_ss, 8);
    if (rv >= 0)
        fail_error("call to rt_sigsuspend rv >= 0");
    if (errno != EINTR)
        fail_perror("errno != EINTR");
    if (!rt_sigsuspend_handler_2_reached)
        fail_error("signal handler 2 not reached");
    return (void*)EXIT_SUCCESS;
}

void test_rt_sigsuspend(void)
{
    sigtest_debug("\n");

    child_tid = 0;
    rt_sigsuspend_handler_reached = 0;
    rt_sigsuspend_handler_2_reached = 0;
    rt_sigsuspend_next_sig = 0;
    pthread_t pt = 0;
    if (pthread_create(&pt, NULL, test_rt_sigsuspend_child, NULL))
        fail_perror("blocking test pthread_create");

    sigtest_debug("yielding until child tid reported...\n");
    yield_for(&child_tid);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = test_rt_sigsuspend_handler;
    sa.sa_flags |= SA_SIGINFO;
    int rv = sigaction(SIGRTMIN, &sa, 0);
    if (rv < 0)
        fail_perror("test_signal_catch: sigaction");

    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = test_rt_sigsuspend_handler_2;
    sa.sa_flags |= SA_SIGINFO;
    rv = sigaction(SIGRTMIN + 1, &sa, 0);
    if (rv < 0)
        fail_perror("test_signal_catch: sigaction");

    /* queue signal to SIGRTMIN handler; should be caught */
    siginfo_t si;
    memset(&si, 0, sizeof(siginfo_t));
    si.si_code = SI_MESGQ;
    si.si_pid = getpid();
    si.si_uid = getuid();
    rv = syscall(SYS_rt_tgsigqueueinfo, getpid(), child_tid, SIGRTMIN, &si);
    if (rv < 0)
        fail_perror("tgsigqueueinfo for SIGRTMIN");

    /* queue SIGRTMIN + 1; should not be caught until second sigsuspend */
    memset(&si, 0, sizeof(siginfo_t));
    si.si_code = SI_MESGQ;
    si.si_pid = getpid();
    si.si_uid = getuid();
    rv = syscall(SYS_rt_tgsigqueueinfo, getpid(), child_tid, SIGRTMIN + 1, &si);
    if (rv < 0)
        fail_perror("tgsigqueueinfo for SIGRTMIN");

    sigtest_debug("yield while waiting for first sigsuspend test...\n");
    yield_for(&rt_sigsuspend_next_sig);

    /* test two - wait for handler */
    sigtest_debug("yield while waiting for SIGRTMIN + 1 handler...\n");
    yield_for(&rt_sigsuspend_handler_2_reached);

    sigtest_debug("waiting for child to exit...\n");
    void * retval;
    if (pthread_join(pt, &retval))
        fail_perror("pthread_join");

    if (retval != (void*)EXIT_SUCCESS)
        fail_error("child failed\n");
}

int main(int argc, char * argv[])
{
    setbuf(stdout, NULL);

    test_signal_catch();

    test_rt_signal();

    test_kill();

    test_rt_sigqueueinfo();

    test_rt_sigsuspend();

    printf("signal test passed\n");
}
