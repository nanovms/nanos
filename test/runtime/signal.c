#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>

#include <sys/ucontext.h>
#include <sys/signalfd.h>
#include <sys/epoll.h>

/* #970: avoid getpid() with threads unless you know you have a newish glibc */
#define __getpid() syscall(SYS_getpid)

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
    int tries = 100000;
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
        fail_perror("pthread_create");

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

    rv = syscall(SYS_tgkill, __getpid(), child_tid, SIGUSR1);
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

    sigtest_debug("rt_sigpending returned %ld, sigset 0x%lx\n", rv, *(unsigned long *)&sigset);
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

    sigtest_debug("waiting for master to queue up signals\n");
    while (test_rt_signal_enable == 0)
        sched_yield();

    sigtest_debug("capturing %d queued signals\n", TEST_RT_NQUEUE);
    for(;;) {
        sigset_t mask_ss;
        sigemptyset(&mask_ss);
        int rv = syscall(SYS_rt_sigsuspend, &mask_ss, 8);
        if (rv >= 0) {
            sigtest_err("call to rt_sigsuspend rv >= 0\n");
            return (void*)EXIT_FAILURE;
        }
        if (errno == EINTR) {
            if (test_rt_caught < TEST_RT_NQUEUE) {
                sigtest_debug("test_rt_caught = %d, continuing\n", test_rt_caught);
                continue;
            }
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
        fail_perror("pthread_create");

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
        rv = sigqueue(__getpid(), SIGRTMIN, sv);
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

    rv = syscall(SYS_kill, __getpid(), SIGRTMIN);
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
    si.si_pid = __getpid();
    si.si_uid = getuid();
    rv = syscall(SYS_rt_sigqueueinfo, __getpid(), SIGRTMIN, &si);
    if (rv < 0)
        fail_perror("sigqueueinfo for SIGRTMIN");

    if (!test_kill_caught)
        fail_error("signal not caught");
}

static volatile int rt_sigsuspend_handler_reached;
static volatile int rt_sigsuspend_handler_2_reached;
static volatile int rt_sigsuspend_next_sig;

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
        fail_perror("pthread_create");

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
    si.si_pid = __getpid();
    si.si_uid = getuid();
    rv = syscall(SYS_rt_tgsigqueueinfo, __getpid(), child_tid, SIGRTMIN, &si);
    if (rv < 0)
        fail_perror("tgsigqueueinfo for SIGRTMIN");

    /* queue SIGRTMIN + 1; should not be caught until second sigsuspend */
    memset(&si, 0, sizeof(siginfo_t));
    si.si_code = SI_MESGQ;
    si.si_pid = __getpid();
    si.si_uid = getuid();
    rv = syscall(SYS_rt_tgsigqueueinfo, __getpid(), child_tid, SIGRTMIN + 1, &si);
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

#define BAD_LOAD 0xBADF0000
#define BAD_RIP  0x1000BADF

#ifdef SIGNALTEST_DEBUG
static inline void
print_ucontext(void * ucontext)
{
    ucontext_t * context = ucontext;

    printf("ucontext:\n"
        "    R8:      0x%llx\n"
        "    R9:      0x%llx\n"
        "    R10:     0x%llx\n"
        "    R11:     0x%llx\n"
        "    R12:     0x%llx\n"
        "    R13:     0x%llx\n"
        "    R14:     0x%llx\n"
        "    R15:     0x%llx\n"
        "    RDI:     0x%llx\n"
        "    RSI:     0x%llx\n"
        "    RBP:     0x%llx\n"
        "    RDX:     0x%llx\n"
        "    RAX:     0x%llx\n"
        "    RCX:     0x%llx\n"
        "    RSP:     0x%llx\n"
        "    RIP:     0x%llx\n"
        "    EFL:     0x%llx\n"
        "    CSGSFS:  0x%llx\n"
        "    ERR:     0x%llx\n"
        "    TRAPNO:  0x%llx\n"
        "    OLDMASK: 0x%llx\n"
        "    CR2:     0x%llx\n",
        context->uc_mcontext.gregs[REG_R8],
        context->uc_mcontext.gregs[REG_R9],
        context->uc_mcontext.gregs[REG_R10],
        context->uc_mcontext.gregs[REG_R11],
        context->uc_mcontext.gregs[REG_R12],
        context->uc_mcontext.gregs[REG_R13],
        context->uc_mcontext.gregs[REG_R14],
        context->uc_mcontext.gregs[REG_R15],
        context->uc_mcontext.gregs[REG_RDI],
        context->uc_mcontext.gregs[REG_RSI],
        context->uc_mcontext.gregs[REG_RBP],
        context->uc_mcontext.gregs[REG_RDX],
        context->uc_mcontext.gregs[REG_RAX],
        context->uc_mcontext.gregs[REG_RCX],
        context->uc_mcontext.gregs[REG_RSP],
        context->uc_mcontext.gregs[REG_RIP],
        context->uc_mcontext.gregs[REG_EFL],
        context->uc_mcontext.gregs[REG_CSGSFS],
        context->uc_mcontext.gregs[REG_ERR],
        context->uc_mcontext.gregs[REG_TRAPNO],
        context->uc_mcontext.gregs[REG_OLDMASK],
        context->uc_mcontext.gregs[REG_CR2]
    );
}
#endif

static bool
child_should_die(void * ucontext)
{
    ucontext_t * context = ucontext;
    return (context->uc_mcontext.gregs[REG_CR2] == BAD_RIP);
}


static void
sigsegv_sigaction(int signo, siginfo_t * info, void * ucontext)
{

    if (signo != SIGSEGV)
        fail_perror("  childtid: caught non SIGSEGV signal %d\n", signo);  

    if (info->si_signo != signo)
        fail_perror("  childtid: info->si_signo != signo\n");

#ifdef SIGNALTEST_DEBUG
    print_ucontext(ucontext);
#endif

    if ( (unsigned long)info->si_addr != 
         ((ucontext_t *)ucontext)->uc_mcontext.gregs[REG_CR2]
       )
        fail_perror("  childtid: info-si_addr != CR2\n");

    if (child_should_die(ucontext))
        syscall(SYS_exit, 0);
 
    /* update the RIP to something invalid */
    ((ucontext_t *)ucontext)->uc_mcontext.gregs[REG_RIP] = BAD_RIP;
}

static void
sigsegv_handler(int signo)
{
    if (signo != SIGSEGV)
        fail_perror("  childtid: caught non SIGSEGV signal %d\n", signo);

    syscall(SYS_exit, 0);
}

static void * 
sigsegv_thread(void * arg)
{
    child_tid = syscall(SYS_gettid);
    int * v = (int *)BAD_LOAD;

    /* generate sigsegv */
    *v = 1;
    return NULL;
}

static void
test_sigsegv(void)
{
    struct sigaction sa;
    pthread_t pt;
    void * retval;

    /* first test ~SA_INFO */
    {
        memset(&sa, 0, sizeof(struct sigaction));
        sa.sa_handler  = sigsegv_handler;
        sigemptyset(&sa.sa_mask);

        if (sigaction(SIGSEGV, &sa, NULL))
            fail_perror("siggaction for SIGSEGV failed");

        if (pthread_create(&pt, NULL, sigsegv_thread, NULL))
            fail_perror("sigsegv_thread pthread_create");

        sigtest_debug("yielding until child tid reported...\n");
        yield_for(&child_tid);

        if (pthread_join(pt, &retval))
            fail_perror("blocking test pthread_join");
    }

    /* now test SA_INFO */
    {
        memset(&sa, 0, sizeof(struct sigaction));
        sa.sa_sigaction = sigsegv_sigaction;
        sa.sa_flags = SA_SIGINFO; 
        sigemptyset(&sa.sa_mask);

        if (sigaction(SIGSEGV, &sa, NULL))
            fail_perror("siggaction for SIGSEGV failed");

        if (pthread_create(&pt, NULL, sigsegv_thread, NULL))
            fail_perror("sigsegv_thread pthread_create 2");

        sigtest_debug("yielding until child tid reported...\n");
        yield_for(&child_tid);

        if (pthread_join(pt, &retval))
            fail_perror("blocking test pthread_join");
    }

    memset(&sa, 0, sizeof(struct sigaction));
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGSEGV, &sa, NULL))
        fail_perror("siggaction for SIGSEGV failed");
}

static int test_rt_sigtimedwait_handler_reached = 0;

static void test_rt_sigtimedwait_handler(int sig, siginfo_t *si, void *ucontext)
{
    sigtest_debug("reached\n");
    assert(sig == SIGRTMIN);
    if (!test_rt_sigtimedwait_handler_reached) {
        test_rt_sigtimedwait_handler_reached = 1;
        return;
    }
    fail_error("signal should have been dispatched via rt_sigtimedwait "
               "without a call to the handler");
}

static volatile int test_rt_sigtimedwait_intr = 0;
static volatile int test_rt_sigtimedwait_caught = 0;

static void * test_rt_sigtimedwait_child(void *arg)
{
    sigset_t ss;
    siginfo_t si;
    sigemptyset(&ss);

    /* test interrupt by caught signal not in set */
    child_tid = syscall(SYS_gettid);
    sigtest_debug("tid %d, calling rt_sigtimedwait with null set...\n", child_tid);
    int rv = syscall(SYS_rt_sigtimedwait, &ss, &si, 0, 8);
    if (rv < 0 && errno == EINTR) {
        if (!test_rt_sigtimedwait_handler_reached)
            fail_error("rt_sigtimedwait returned EINTR, but handler not reached\n");
        test_rt_sigtimedwait_intr = 1;
        sigtest_debug("   interrupted, as expected\n");
    } else {
        fail_perror("rt_sigtimedwait 1");
    }

    /* test catching signal in set */
    sigaddset(&ss, SIGRTMIN);
    sigtest_debug("calling rt_sigtimedwait to catch signal...\n");
    rv = syscall(SYS_rt_sigtimedwait, &ss, &si, 0, 8);
    if (rv == SIGRTMIN) {
        sigtest_debug("   caught signal\n");
        test_rt_sigtimedwait_caught = 1;
    } else if (rv < 0) {
        fail_perror("rt_sigtimedwait 2");
    }

    /* test poll with nothing pending */
    struct timespec t = { 0, 0 };
    sigtest_debug("calling rt_sigtimedwait to test poll...\n");
    rv = syscall(SYS_rt_sigtimedwait, &ss, &si, &t, 8);
    if (rv < 0 && errno == EAGAIN) {
        sigtest_debug("   EAGAIN, as expected\n");
    } else {
        fail_perror("rt_sigtimedwait 3");
    }

    /* mask sig and set pending */
    rv = sigprocmask(SIG_BLOCK, &ss, 0);
    if (rv < 0)
        fail_perror("sigprocmask");
    memset(&si, 0, sizeof(siginfo_t));
    si.si_code = SI_MESGQ;
    si.si_pid = __getpid();
    si.si_uid = getuid();
    rv = syscall(SYS_rt_tgsigqueueinfo, __getpid(), child_tid, SIGRTMIN, &si);
    if (rv < 0)
        fail_perror("tgsigqueueinfo for SIGRTMIN");

    /* test poll with pending */
    sigtest_debug("calling rt_sigtimedwait to test poll...\n");
    memset(&si, 0, sizeof(siginfo_t));
    rv = syscall(SYS_rt_sigtimedwait, &ss, &si, &t, 8);
    if (rv  == SIGRTMIN) {
        sigtest_debug("   caught signal\n");
    } else {
        fail_perror("rt_sigtimedwait 4");
    }

    /* test timeout */
    t.tv_sec = 1;
    sigtest_debug("calling rt_sigtimedwait to test one second timeout...\n");
    rv = syscall(SYS_rt_sigtimedwait, &ss, &si, &t, 8);
    if (rv < 0 && errno == EAGAIN) {
        sigtest_debug("   EAGAIN, as expected\n");
    } else {
        fail_perror("rt_sigtimedwait 5");
    }

    return (void*)EXIT_SUCCESS;
}

void test_rt_sigtimedwait(void)
{
    sigtest_debug("\n");
    child_tid = 0;
    pthread_t pt = 0;
    if (pthread_create(&pt, NULL, test_rt_sigtimedwait_child, NULL))
        fail_perror("pthread_create");

    sigtest_debug("yielding until child tid reported...\n");
    yield_for(&child_tid);

    /* 10ms delay to allow child to sleep before sending signal... */
    struct timespec t = { 0, 10000000 };
    nanosleep(&t, 0);
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = test_rt_sigtimedwait_handler;
    sa.sa_flags |= SA_SIGINFO;
    int rv = sigaction(SIGRTMIN, &sa, 0);
    if (rv < 0)
        fail_perror("test_signal_catch: sigaction");

    /* queue signal to SIGRTMIN handler; should be caught */
    siginfo_t si;
    memset(&si, 0, sizeof(siginfo_t));
    si.si_code = SI_MESGQ;
    si.si_pid = __getpid();
    si.si_uid = getuid();
    rv = syscall(SYS_rt_tgsigqueueinfo, __getpid(), child_tid, SIGRTMIN, &si);
    if (rv < 0)
        fail_perror("tgsigqueueinfo for SIGRTMIN");

    sigtest_debug("waiting for child to be interrupted...\n");
    yield_for(&test_rt_sigtimedwait_intr);
    nanosleep(&t, 0);

    rv = syscall(SYS_rt_tgsigqueueinfo, __getpid(), child_tid, SIGRTMIN, &si);
    if (rv < 0)
        fail_perror("tgsigqueueinfo for SIGRTMIN");

    sigtest_debug("waiting for child to catch signal...\n");
    yield_for(&test_rt_sigtimedwait_caught);

    sigtest_debug("waiting for child to exit...\n");
    void * retval;
    if (pthread_join(pt, &retval))
        fail_perror("pthread_join");

    if (retval != (void*)EXIT_SUCCESS)
        fail_error("child failed\n");
}

volatile int test_signalfd_caught = 0;

static void test_signalfd_handler(int sig, siginfo_t *si, void *ucontext)
{
    sigtest_debug("reached\n");
    fail_error("signal should have been dispatched to signalfd, not caught by sig handler\n");
}

static void * test_signalfd_child(void *arg)
{
    /* mask signal to make exclusive for signalfd */
    sigset_t ss;
    sigemptyset(&ss);
    sigaddset(&ss, SIGRTMIN);
    int fd = signalfd(-1, &ss, 0);
    if (fd < 0)
        fail_perror("signalfd");

    sigaddset(&ss, SIGRTMIN + 1);
    int rv = sigprocmask(SIG_BLOCK, &ss, 0);
    if (rv < 0)
        fail_perror("sigprocmask");

    /* basic read test */
    child_tid = syscall(SYS_gettid);
    sigtest_debug("enter, tid %d, fd %d\n", child_tid, fd);
    struct signalfd_siginfo si;
    rv = read(fd, &si, sizeof(struct signalfd_siginfo));
    if (rv < 0)
        fail_perror("read");
    if (rv < sizeof(struct signalfd_siginfo))
        fail_error("short read (%d)\n", rv);
    sigtest_debug("read sig %d, errno %d, code %d\n", si.ssi_signo, si.ssi_errno, si.ssi_code);

    /* test non-blocking */
    sigemptyset(&ss);
    sigaddset(&ss, SIGRTMIN);
    int fd2 = signalfd(-1, &ss, SFD_NONBLOCK);
    if (fd2 < 0)
        fail_perror("signalfd 2");
    sigtest_debug("nonblock fd %d, reading...\n", fd2);
    rv = read(fd2, &si, sizeof(struct signalfd_siginfo));
    if (rv >= 0 || errno != EAGAIN)
        fail_error("second read should have returned EAGAIN (rv %d, errno %d)\n", rv, errno);

    /* test mask update */
    sigemptyset(&ss);
    sigaddset(&ss, SIGRTMIN + 1);
    if (signalfd(fd, &ss, 0) < 0)
        fail_perror("signalfd mask update");

    /* poll wait test */
    int epfd = epoll_create(1);
    if (epfd < 0)
        fail_perror("epoll_create");

    struct epoll_event epev;
    epev.events = EPOLLIN;
    epev.data.fd = fd;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &epev) < 0)
        fail_perror("epoll_ctl 1");
    epev.data.fd = fd2;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd2, &epev) < 0)
        fail_perror("epoll_ctl 2");

    test_signalfd_caught = 1;

    int rcvd = 0;
    struct epoll_event rev[2];

    while (rcvd != 3) {
        sigtest_debug("   epoll_wait...\n");
        int nfds = epoll_wait(epfd, rev, 2, 5000);
        if (nfds < 0)
            fail_perror("epoll_wait");
        for (int i=0; i < nfds; i++) {
            sigtest_debug("   fd %d events 0x%x\n", rev[i].data.fd, rev[i].events);
            struct signalfd_siginfo si;
            rv = read(rev[i].data.fd, &si, sizeof(struct signalfd_siginfo));
            if (rv < 0)
                fail_perror("read 2");
            if (rv < sizeof(struct signalfd_siginfo))
                fail_error("short read 2 (%d)\n", rv);
            sigtest_debug("   read sig %d, errno %d, code %d\n", si.ssi_signo, si.ssi_errno, si.ssi_code);
            if (si.ssi_signo == SIGRTMIN && rev[i].data.fd == fd2) {
                sigtest_debug("   SIGRTMIN\n");
                rcvd |= 1;
            } else if (si.ssi_signo == SIGRTMIN + 1 && rev[i].data.fd == fd) {
                sigtest_debug("   SIGRTMIN + 1 (mask update works)\n");
                rcvd |= 2;
            }
        }
    }

    /* events should have cleared */
    sigtest_debug("   test epoll_wait with no events...\n");
    int nfds = epoll_wait(epfd, rev, 2, 0);
    if (nfds != 0)
        fail_error("epoll_wait test with no signal events failed (rv = %d)\n", nfds);

    sigtest_debug("success; child exiting\n");
    return (void *)EXIT_SUCCESS;
}

void test_signalfd(void)
{
    sigtest_debug("\n");
    child_tid = 0;

    pthread_t pt = 0;
    if (pthread_create(&pt, NULL, test_signalfd_child, NULL))
        fail_perror("pthread_create");

    sigtest_debug("yielding until child tid reported...\n");
    yield_for(&child_tid);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = test_signalfd_handler;
    sa.sa_flags |= SA_SIGINFO;
    int rv = sigaction(SIGRTMIN, &sa, 0);
    if (rv < 0)
        fail_perror("test_signal_catch: sigaction");

    /* queue signal to SIGRTMIN handler; should handled via read */
    siginfo_t si;
    memset(&si, 0, sizeof(siginfo_t));
    si.si_code = SI_MESGQ;
    si.si_pid = __getpid();
    si.si_uid = getuid();
    rv = syscall(SYS_rt_tgsigqueueinfo, __getpid(), child_tid, SIGRTMIN, &si);
    if (rv < 0)
        fail_perror("tgsigqueueinfo for SIGRTMIN");

    yield_for(&test_signalfd_caught);
    sigtest_debug("sending signals for poll test...\n");
    memset(&si, 0, sizeof(siginfo_t));
    si.si_code = SI_MESGQ;
    si.si_pid = __getpid();
    si.si_uid = getuid();
    rv = syscall(SYS_rt_tgsigqueueinfo, __getpid(), child_tid, SIGRTMIN, &si);
    if (rv < 0)
        fail_perror("tgsigqueueinfo for SIGRTMIN (poll)");

    memset(&si, 0, sizeof(siginfo_t));
    si.si_code = SI_MESGQ;
    si.si_pid = __getpid();
    si.si_uid = getuid();
    rv = syscall(SYS_rt_tgsigqueueinfo, __getpid(), child_tid, SIGRTMIN + 1, &si);
    if (rv < 0)
        fail_perror("tgsigqueueinfo for SIGRTMIN + 1 (poll)");

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

    test_sigsegv();

    test_signal_catch();

    test_rt_signal();

    test_kill();

    test_rt_sigqueueinfo();

    test_rt_sigsuspend();

    test_rt_sigtimedwait();

    test_signalfd();

    printf("signal test passed\n");
}
