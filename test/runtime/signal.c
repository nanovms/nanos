#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <assert.h>
#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <string.h>
#include <stdbool.h>
#include <pthread.h>

#include <sys/ucontext.h>
#include <sys/signalfd.h>
#include <sys/epoll.h>

#include "../test_utils.h"

/* #970: avoid getpid() with threads unless you know you have a newish glibc */
#define __getpid() syscall(SYS_getpid)

//#define SIGNALTEST_DEBUG
#ifdef SIGNALTEST_DEBUG
#define sigtest_debug(x, ...) do {printf("SIGTEST %s: " x, __func__, ##__VA_ARGS__);} while(0)
#else
#define sigtest_debug(x, ...)
#endif

#define sigtest_err(x, ...) do {printf("sigtest failed, %s: " x, __func__, ##__VA_ARGS__);} while(0)

static volatile int child_tid;

static void yield_for(volatile int * v)
{
    int tries = 100000;
    while (!*v && tries-- > 0)
        sched_yield();
    if (!*v)
        test_error("timed out");
}

static void * tgkill_test_pause(void *use_select)
{
    int rv;
    child_tid = syscall(SYS_gettid);
    sigtest_debug("child enter, tid %d\n", child_tid);
    if (use_select) {
        rv = syscall(SYS_pselect6, 0, NULL, NULL, NULL, NULL, NULL);
    } else {
#ifdef __x86_64__
        rv = syscall(SYS_pause);
#else
        rv = syscall(SYS_ppoll, 0, 0, 0, 0);
#endif
    }
    if (rv < 0) {
        if (errno == EINTR) {
            sigtest_debug("child received signal\n");
            return (void*)EXIT_SUCCESS;
        } else {
            test_perror("pause unexpected errno");
        }
    }
    test_error("pause: unexpected retval %d", rv);
}

static void test_signal_catch_handler(int sig)
{
    sigtest_debug("caught signal %d\n", sig);
}

void test_signal_catch(int use_select)
{
    sigtest_debug("\n");
    pthread_t pt = 0;
    child_tid = 0;
    if (pthread_create(&pt, NULL, tgkill_test_pause, (void*)(long)use_select))
        test_error("pthread_create");

    sigtest_debug("yielding until child tid reported...\n");
    yield_for(&child_tid);

    /* not pretty, but should ensure child gets to pause(2) */
    sleep(1);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = test_signal_catch_handler;
    int rv = sigaction(SIGUSR1, &sa, 0);
    if (rv < 0)
        test_perror("test_signal_catch: sigaction");

    rv = syscall(SYS_tgkill, __getpid(), child_tid, SIGUSR1);
    if (rv < 0)
        test_perror("signal catch tgkill");

    sigtest_debug("waiting for child to exit...\n");
    void * retval;
    if (pthread_join(pt, &retval))
        test_error("test_signal_catch: pthread_join");

    if (retval != (void*)EXIT_SUCCESS)
        test_error("tgkill_test_pause child failed");
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
        test_perror("sigpending");

    sigtest_debug("rt_sigpending returned %ld, sigset 0x%lx\n", rv, *(unsigned long *)&sigset);
    if (test_rt_caught < TEST_RT_NQUEUE) {
        if (!sigismember(&sigset, sig))
            test_error("sig %d should still be pending until we serviced the last signal", sig);
    } else {
        if (sigismember(&sigset, sig))
            test_error("sig %d should not be pending; all queued signals have been handled", sig);
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
        test_perror("sigprocmask");
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
    sigtest_debug("\n");
    pthread_t pt = 0;
    child_tid = 0;
    test_rt_signal_enable = 0;
    if (pthread_create(&pt, NULL, test_rt_signal_child, NULL))
        test_error("pthread_create");

    sigtest_debug("yielding until child tid reported...\n");
    yield_for(&child_tid);

    sigset_t ss;
    sigemptyset(&ss);
    sigaddset(&ss, SIGRTMIN);
    int rv = sigprocmask(SIG_BLOCK, &ss, 0);
    if (rv < 0)
        test_perror("sigprocmask");
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = test_rt_signal_queueing_handler;
    sa.sa_flags |= SA_SIGINFO;
    rv = sigaction(SIGRTMIN, &sa, 0);
    if (rv < 0)
        test_perror("test_rt_signal: sigaction");

    for (int i = 0; i < TEST_RT_NQUEUE; i++) {
        union sigval sv;
        sv.sival_int = i;
        rv = sigqueue(__getpid(), SIGRTMIN, sv);
        if (rv < 0)
            test_perror("signal catch sigqueue");
    }

    sigtest_debug("enabling and waiting for child to exit...\n");
    test_rt_signal_enable = 1;
    void * retval;
    if (pthread_join(pt, &retval))
        test_error("rt_signal pthread_join");

    if (retval != (void*)EXIT_SUCCESS)
        test_error("test_rt_signal child failed");
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
        test_perror("test_kill: sigaction");

    sigset_t ss;
    sigemptyset(&ss);
    sigaddset(&ss, SIGRTMIN);
    rv = sigprocmask(SIG_UNBLOCK, &ss, 0);
    if (rv < 0)
        test_perror("sigprocmask");

    rv = syscall(SYS_kill, __getpid(), SIGRTMIN);
    if (rv < 0)
        test_perror("signal catch kill");

    if (!test_kill_caught)
        test_error("signal not caught");
}

static void queue_sig(int sig)
{
    siginfo_t si;
    memset(&si, 0, sizeof(siginfo_t));
    si.si_code = SI_MESGQ;
    si.si_pid = __getpid();
    si.si_uid = getuid();
    int rv = syscall(SYS_rt_sigqueueinfo, __getpid(), sig, &si);
    if (rv < 0)
        test_perror("test_nested_handler: sigqueueinfo for sig %d", sig);
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
        test_perror("test_rt_sigqueueinfo: sigaction");

    sigset_t ss;
    sigemptyset(&ss);
    sigaddset(&ss, SIGRTMIN);
    rv = sigprocmask(SIG_UNBLOCK, &ss, 0);
    if (rv < 0)
        test_perror("sigprocmask");

    queue_sig(SIGRTMIN);

    if (!test_kill_caught)
        test_error("signal not caught");
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
        test_error("signal should have been masked");
    }
}

static void test_rt_sigsuspend_handler_2(int sig, siginfo_t *si, void *ucontext)
{
    sigtest_debug("reached\n");
    assert(sig == SIGRTMIN + 1);
    if (rt_sigsuspend_next_sig) {
        rt_sigsuspend_handler_2_reached = 1;
    } else {
        test_error("signal should have been masked");
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
        test_perror("sigprocmask");

    child_tid = syscall(SYS_gettid);
    /* test one - handle SIGRTMIN and leave SIGRTMIN + 1 masked */
    sigset_t mask_ss;
    sigemptyset(&mask_ss);
    sigaddset(&mask_ss, SIGRTMIN + 1);
    rv = syscall(SYS_rt_sigsuspend, &mask_ss, 8);
    if (rv >= 0)
        test_error("call to rt_sigsuspend rv >= 0");
    if (errno != EINTR)
        test_perror("errno != EINTR");
    if (!rt_sigsuspend_handler_reached)
        test_error("signal handler not reached");

    rt_sigsuspend_next_sig = 1;

    /* test two - still pending SIGRTMIN + 1 should be handled now */
    sigemptyset(&mask_ss);
    sigaddset(&mask_ss, SIGRTMIN);
    rv = syscall(SYS_rt_sigsuspend, &mask_ss, 8);
    if (rv >= 0)
        test_error("call to rt_sigsuspend rv >= 0");
    if (errno != EINTR)
        test_perror("errno != EINTR");
    if (!rt_sigsuspend_handler_2_reached)
        test_error("signal handler 2 not reached");
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
        test_error("pthread_create");

    sigtest_debug("yielding until child tid reported...\n");
    yield_for(&child_tid);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = test_rt_sigsuspend_handler;
    sa.sa_flags |= SA_SIGINFO;
    int rv = sigaction(SIGRTMIN, &sa, 0);
    if (rv < 0)
        test_perror("test_rt_sigsuspend: sigaction");

    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = test_rt_sigsuspend_handler_2;
    sa.sa_flags |= SA_SIGINFO;
    rv = sigaction(SIGRTMIN + 1, &sa, 0);
    if (rv < 0)
        test_perror("test_rt_sigsuspend: sigaction");

    /* queue signal to SIGRTMIN handler; should be caught */
    siginfo_t si;
    memset(&si, 0, sizeof(siginfo_t));
    si.si_code = SI_MESGQ;
    si.si_pid = __getpid();
    si.si_uid = getuid();
    rv = syscall(SYS_rt_tgsigqueueinfo, __getpid(), child_tid, SIGRTMIN, &si);
    if (rv < 0)
        test_perror("tgsigqueueinfo for SIGRTMIN");

    /* queue SIGRTMIN + 1; should not be caught until second sigsuspend */
    memset(&si, 0, sizeof(siginfo_t));
    si.si_code = SI_MESGQ;
    si.si_pid = __getpid();
    si.si_uid = getuid();
    rv = syscall(SYS_rt_tgsigqueueinfo, __getpid(), child_tid, SIGRTMIN + 1, &si);
    if (rv < 0)
        test_perror("tgsigqueueinfo for SIGRTMIN");

    sigtest_debug("yield while waiting for first sigsuspend test...\n");
    yield_for(&rt_sigsuspend_next_sig);

    /* test two - wait for handler */
    sigtest_debug("yield while waiting for SIGRTMIN + 1 handler...\n");
    yield_for(&rt_sigsuspend_handler_2_reached);

    sigtest_debug("waiting for child to exit...\n");
    void * retval;
    if (pthread_join(pt, &retval))
        test_error("rt_sigsuspend pthread_join");

    if (retval != (void*)EXIT_SUCCESS)
        test_error("child failed");
}

#define BAD_LOAD 0xBADF0000
#define BAD_PC   0x1000BADF

#ifdef SIGNALTEST_DEBUG
#ifdef __x86_64__
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

#ifdef __aarch64__
static inline void
print_ucontext(void * ucontext)
{
    ucontext_t * context = ucontext;
    printf("ucontext:\n");
    for (int i = 0; i < 31; i++)
        printf("    X%d:\t0x%llx\n", i, context->uc_mcontext.regs[i]);
    printf("    SP:\t0x%llx\n", context->uc_mcontext.sp);
    printf("    PC:\t0x%llx\n", context->uc_mcontext.pc);
    printf("    PSTATE:\t0x%llx\n", context->uc_mcontext.pstate);
    printf("    FLTADR:\t0x%llx\n", context->uc_mcontext.fault_address);
}
#endif

#endif

#ifdef __x86_64__
static inline unsigned long get_fault_address(ucontext_t *context)
{
    return context->uc_mcontext.gregs[REG_CR2];
}

static inline void set_pc(ucontext_t *context, unsigned long pc)
{
    context->uc_mcontext.gregs[REG_RIP] = pc;
}
#endif

#ifdef __aarch64__
static inline unsigned long get_fault_address(ucontext_t *context)
{
    return context->uc_mcontext.fault_address;
}

static inline void set_pc(ucontext_t *context, unsigned long pc)
{
    context->uc_mcontext.pc = pc;
}
#endif

#ifdef __riscv
static inline void set_pc(ucontext_t *context, unsigned long pc)
{
    context->uc_mcontext.__gregs[0] = pc;
}
#endif

static bool
child_should_die(siginfo_t * info)
{
    return (unsigned long long)info->si_addr == BAD_PC;
}

static void
sigsegv_sigaction(int signo, siginfo_t * info, void * ucontext)
{
    static int iter = 0;

    if (info->si_code != (iter == 0 ? SI_KERNEL : SEGV_MAPERR))
        test_error("childtid: wrong si_code %d for iter %d", info->si_code, iter);

    if (signo != SIGSEGV)
        test_error("childtid: caught non SIGSEGV signal %d", signo);

    if (info->si_signo != signo)
        test_error("childtid: info->si_signo != signo");

#ifdef SIGNALTEST_DEBUG
    print_ucontext(ucontext);
#endif

#ifndef __riscv
    if (iter == 1 && (unsigned long)info->si_addr != get_fault_address((ucontext_t *)ucontext))
        test_error("childtid: fault address not info-si_addr");
#endif
    iter++;

    if (child_should_die(info))
        syscall(SYS_exit, 0);
 
    /* update the RIP to something invalid */
    set_pc((ucontext_t *)ucontext, BAD_PC);
}

static void
sigsegv_handler(int signo)
{
    if (signo != SIGSEGV)
        test_error("childtid: caught non SIGSEGV signal %d", signo);

    syscall(SYS_exit, 0);
}

static void * 
sigsegv_thread(void * arg)
{
    int * volatile v;
    child_tid = syscall(SYS_gettid);
    switch ((long)arg) {
    case 0:
        v = (int *)BAD_LOAD;

        /* generate sigsegv */
        *v = 1;
        break;
    case 1:
        v = (int *)0x8;

        /* generate sigsegv on zero page access */
        *v = 1;
        break;
    case 2:
#if defined(__x86_64__) || defined(__aarch64__) || defined(__riscv)
        v = (int *)0xffffffff80000000ull;

        /* generate sigsegv on kernel page access */
        *v = 1;
#endif
        break;
    case 3:
        /* should cause sigsegv as a result of general protection fault */
#ifdef __x86_64__
        asm volatile("hlt");
#endif
#ifdef __aarch64__
        asm volatile("wfi");
#endif
        break;
    }
    return NULL;
}

static void
test_sigsegv(void)
{
    sigtest_debug("\n");
    struct sigaction sa;
    pthread_t pt;
    void * retval;

    /* first test ~SA_INFO */
    {
        memset(&sa, 0, sizeof(struct sigaction));
        sa.sa_handler = sigsegv_handler;
        sigemptyset(&sa.sa_mask);

        if (sigaction(SIGSEGV, &sa, NULL))
            test_perror("sigaction for SIGSEGV");

        for (long i = 0; i < 3; i++) {
            if (pthread_create(&pt, NULL, sigsegv_thread, (void *)i))
                test_error("sigsegv_thread pthread_create");

            sigtest_debug("calling pthread_join...\n");
            if (pthread_join(pt, &retval))
                test_error("sigsegv pthread_join");
        }
        sigtest_debug("done\n");
    }

    /* test SA_INFO, illegal instruction / GP fault and bad RIP in ucontext */
    {
        memset(&sa, 0, sizeof(struct sigaction));
        sa.sa_sigaction = sigsegv_sigaction;
        sa.sa_flags = SA_SIGINFO; 
        sigemptyset(&sa.sa_mask);

        if (sigaction(SIGSEGV, &sa, NULL))
            test_perror("sigaction for SIGSEGV");

        if (pthread_create(&pt, NULL, sigsegv_thread, (void *)3))
            test_error("sigsegv_thread pthread_create 2");

        sigtest_debug("calling pthread_join...\n");
        if (pthread_join(pt, &retval))
            test_error("sigsegv pthread_join 2");
        sigtest_debug("done\n");
    }

    memset(&sa, 0, sizeof(struct sigaction));
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGSEGV, &sa, NULL))
        test_perror("sigaction for SIGSEGV");
}

static void *sigill_thread(void *arg)
{

    child_tid = syscall(SYS_gettid);

    /* generate sigill */
#if defined(__x86_64__)
    asm volatile ("ud2");
#elif defined(__aarch64__) || defined(__riscv)
    asm volatile (".word 0");
#endif
    return NULL;
}

static void sigill_handler(int signo, siginfo_t *info, void *ucontext)
{
    if (signo != SIGILL)
        test_error("childtid: caught non SIGILL signal %d", signo);

    if (info->si_code != ILL_ILLOPC)
        test_error("childtid: si_code for SIGILL should be ILL_ILLOPC, not %d",
                    info->si_code);

    if (info->si_addr - (void*)sigill_thread > 4096)
        test_error("childtid: si_addr (%p) not within page of sigill_thread start (%p)",
                    info->si_addr, sigill_thread);

#if defined(__x86_64__)
    if (*(unsigned char *)info->si_addr != 0x0f ||
        *(unsigned char *)(info->si_addr + 1) != 0x0b)
        test_error("childtid: memory at si_addr (%p) is not a UD2 instruction", info->si_addr);
#elif defined(__aarch64__) || defined(__riscv)
    if (*(unsigned int *)info->si_addr != 0)
        test_error("childtid: memory at si_addr (%p) is not a zero word", info->si_addr);
#endif
    syscall(SYS_exit, 0);
}

static void test_sigill(void)
{
    struct sigaction sa;
    pthread_t pt;
    void *retval;

    memset(&sa, 0, sizeof(struct sigaction));
    sa.sa_sigaction = sigill_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGILL, &sa, NULL))
        test_perror("sigaction for SIGILL");

    if (pthread_create(&pt, NULL, sigill_thread, (void *)0))
        test_error("sigill_thread pthread_create");

    if (pthread_join(pt, &retval))
        test_error("sigill_thread pthread_join");

    memset(&sa, 0, sizeof(struct sigaction));
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGILL, &sa, NULL))
        test_perror("sigaction for SIGILL");
}

static void sigtrap_handler(int signo)
{
    if (signo != SIGTRAP)
        test_error("childtid: caught non SIGTRAP signal %d", signo);

    syscall(SYS_exit, 0);
}

static void *sigtrap_thread(void *arg)
{

    child_tid = syscall(SYS_gettid);

    /* generate sigtrap */
#if defined(__x86_64__)
    asm volatile ("int3");
#elif defined(__aarch64__)
    asm volatile ("brk #1000");
#elif defined(__riscv)
    asm volatile ("ebreak");
#endif
    return NULL;
}

static void test_sigtrap(void)
{
    struct sigaction sa;
    pthread_t pt;
    void *retval;

    memset(&sa, 0, sizeof(struct sigaction));
    sa.sa_handler = sigtrap_handler;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGTRAP, &sa, NULL))
        test_perror("sigaction for SIGTRAP");

    if (pthread_create(&pt, NULL, sigtrap_thread, (void *)0))
        test_error("sigtrap_thread pthread_create");

    if (pthread_join(pt, &retval))
        test_error("sigtrap_thread pthread_join");

    memset(&sa, 0, sizeof(struct sigaction));
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGTRAP, &sa, NULL))
        test_perror("sigaction for SIGTRAP");
}

/* XXX sort out arm counterpart - possibly don't even have integer div by zero exception - but have fp? */
#ifdef __x86_64__
static void sigfpe_handler(int signo)
{
    if (signo != SIGFPE)
        test_error("childtid: caught non SIGFPE signal %d", signo);

    syscall(SYS_exit, 0);
}

static void *sigfpe_thread(void *arg)
{

    child_tid = syscall(SYS_gettid);

    /* generate sigfpe */
    asm volatile("push    %rax \t\n\
                xor     %rax, %rax \t\n\
                idiv    %rax \t\n\
                pop     %rax\t\n\
                ");
    return NULL;
}

static void test_sigfpe(void)
{
    struct sigaction sa;
    pthread_t pt;
    void *retval;

    memset(&sa, 0, sizeof(struct sigaction));
    sa.sa_handler = sigfpe_handler;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGFPE, &sa, NULL))
        test_perror("sigaction for SIGFPE");

    if (pthread_create(&pt, NULL, sigfpe_thread, (void *)0))
        test_error("sigfpe_thread pthread_create");

    if (pthread_join(pt, &retval))
        test_error("sigfpe_thread pthread_join");

    memset(&sa, 0, sizeof(struct sigaction));
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGFPE, &sa, NULL))
        test_perror("sigaction for SIGFPE");
}
#endif

static int test_rt_sigtimedwait_handler_reached = 0;

static void test_rt_sigtimedwait_handler(int sig, siginfo_t *si, void *ucontext)
{
    sigtest_debug("reached\n");
    assert(sig == SIGRTMIN);
    if (!test_rt_sigtimedwait_handler_reached) {
        test_rt_sigtimedwait_handler_reached = 1;
        return;
    }
    test_error("signal should have been dispatched via rt_sigtimedwait "
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
            test_error("rt_sigtimedwait returned EINTR, but handler not reached");
        test_rt_sigtimedwait_intr = 1;
        sigtest_debug("   interrupted, as expected\n");
    } else {
        test_perror("rt_sigtimedwait 1");
    }

    /* test catching signal in set */
    sigaddset(&ss, SIGRTMIN);
    sigtest_debug("calling rt_sigtimedwait to catch signal...\n");
    rv = syscall(SYS_rt_sigtimedwait, &ss, &si, 0, 8);
    if (rv == SIGRTMIN) {
        sigtest_debug("   caught signal\n");
        test_rt_sigtimedwait_caught = 1;
    } else if (rv < 0) {
        test_perror("rt_sigtimedwait 2");
    }

    /* test poll with nothing pending */
    struct timespec t = { 0, 0 };
    sigtest_debug("calling rt_sigtimedwait to test poll...\n");
    rv = syscall(SYS_rt_sigtimedwait, &ss, &si, &t, 8);
    if (rv < 0 && errno == EAGAIN) {
        sigtest_debug("   EAGAIN, as expected\n");
    } else {
        test_perror("rt_sigtimedwait 3");
    }

    /* mask sig and set pending */
    rv = sigprocmask(SIG_BLOCK, &ss, 0);
    if (rv < 0)
        test_perror("sigprocmask");
    memset(&si, 0, sizeof(siginfo_t));
    si.si_code = SI_MESGQ;
    si.si_pid = __getpid();
    si.si_uid = getuid();
    rv = syscall(SYS_rt_tgsigqueueinfo, __getpid(), child_tid, SIGRTMIN, &si);
    if (rv < 0)
        test_perror("tgsigqueueinfo for SIGRTMIN");

    /* test poll with pending */
    sigtest_debug("calling rt_sigtimedwait to test poll...\n");
    memset(&si, 0, sizeof(siginfo_t));
    rv = syscall(SYS_rt_sigtimedwait, &ss, &si, &t, 8);
    if (rv  == SIGRTMIN) {
        sigtest_debug("   caught signal\n");
    } else {
        test_perror("rt_sigtimedwait 4");
    }

    /* test delivery of ignored signal */
    sigtest_debug("blocking, raising and then waiting for ignored signal...\n");
    sigaddset(&ss, SIGCHLD);
    sigprocmask(SIG_BLOCK, &ss, 0);
    raise(SIGCHLD);
    rv = sigwait(&ss, &si.si_signo);
    if (rv) {
        test_error("sigwait error %d", rv);
    }
    if (si.si_signo != SIGCHLD) {
        test_error("sigwait returned unexpected signal number %d", si.si_signo);
    }

    /* test timeout */
    t.tv_sec = 1;
    sigtest_debug("calling rt_sigtimedwait to test one second timeout...\n");
    rv = syscall(SYS_rt_sigtimedwait, &ss, &si, &t, 8);
    if (rv < 0 && errno == EAGAIN) {
        sigtest_debug("   EAGAIN, as expected\n");
    } else {
        test_perror("rt_sigtimedwait 5");
    }

    return (void*)EXIT_SUCCESS;
}

void test_rt_sigtimedwait(void)
{
    sigtest_debug("\n");
    child_tid = 0;
    pthread_t pt = 0;
    if (pthread_create(&pt, NULL, test_rt_sigtimedwait_child, NULL))
        test_error("pthread_create");

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
        test_perror("test_rt_sigtimedwait: sigaction");

    /* queue signal to SIGRTMIN handler; should be caught */
    siginfo_t si;
    memset(&si, 0, sizeof(siginfo_t));
    si.si_code = SI_MESGQ;
    si.si_pid = __getpid();
    si.si_uid = getuid();
    rv = syscall(SYS_rt_tgsigqueueinfo, __getpid(), child_tid, SIGRTMIN, &si);
    if (rv < 0)
        test_perror("tgsigqueueinfo for SIGRTMIN");

    sigtest_debug("waiting for child to be interrupted...\n");
    yield_for(&test_rt_sigtimedwait_intr);
    nanosleep(&t, 0);

    rv = syscall(SYS_rt_tgsigqueueinfo, __getpid(), child_tid, SIGRTMIN, &si);
    if (rv < 0)
        test_perror("tgsigqueueinfo for SIGRTMIN");

    sigtest_debug("waiting for child to catch signal...\n");
    yield_for(&test_rt_sigtimedwait_caught);

    sigtest_debug("waiting for child to exit...\n");
    void * retval;
    if (pthread_join(pt, &retval))
        test_error("pthread_join");

    if (retval != (void*)EXIT_SUCCESS)
        test_error("child failed");
}

volatile int test_signalfd_caught = 0;

static void test_signalfd_handler(int sig, siginfo_t *si, void *ucontext)
{
    sigtest_debug("reached\n");
    test_error("signal should have been dispatched to signalfd, not caught by sig handler");
}

static void * test_signalfd_child(void *arg)
{
    /* mask signal to make exclusive for signalfd */
    sigset_t ss;
    sigemptyset(&ss);
    sigaddset(&ss, SIGRTMIN);
    int fd = signalfd(-1, &ss, 0);
    if (fd < 0)
        test_perror("signalfd");

    sigaddset(&ss, SIGRTMIN + 1);
    int rv = sigprocmask(SIG_BLOCK, &ss, 0);
    if (rv < 0)
        test_perror("sigprocmask");

    /* basic read test */
    child_tid = syscall(SYS_gettid);
    sigtest_debug("enter, tid %d, fd %d\n", child_tid, fd);
    struct signalfd_siginfo si;
    rv = read(fd, &si, sizeof(struct signalfd_siginfo));
    if (rv < 0)
        test_perror("read");
    if (rv < sizeof(struct signalfd_siginfo))
        test_error("short read (%d)", rv);
    sigtest_debug("read sig %d, errno %d, code %d\n", si.ssi_signo, si.ssi_errno, si.ssi_code);

    /* test non-blocking */
    sigemptyset(&ss);
    sigaddset(&ss, SIGRTMIN);
    int fd2 = signalfd(-1, &ss, SFD_NONBLOCK);
    if (fd2 < 0)
        test_perror("signalfd 2");
    sigtest_debug("nonblock fd %d, reading...\n", fd2);
    rv = read(fd2, &si, sizeof(struct signalfd_siginfo));
    if (rv >= 0 || errno != EAGAIN)
        test_error("second read should have returned EAGAIN (rv %d, errno %d)", rv, errno);

    /* test mask update */
    sigemptyset(&ss);
    sigaddset(&ss, SIGRTMIN + 1);
    if (signalfd(fd, &ss, 0) < 0)
        test_perror("signalfd mask update");

    /* poll wait test */
    int epfd = epoll_create(1);
    if (epfd < 0)
        test_perror("epoll_create");

    struct epoll_event epev;
    epev.events = EPOLLIN;
    epev.data.fd = fd;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &epev) < 0)
        test_perror("epoll_ctl 1");
    epev.data.fd = fd2;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd2, &epev) < 0)
        test_perror("epoll_ctl 2");

    test_signalfd_caught = 1;

    int rcvd = 0;
    struct epoll_event rev[2];

    while (rcvd != 3) {
        sigtest_debug("   epoll_wait...\n");
        int nfds = epoll_wait(epfd, rev, 2, 5000);
        if (nfds < 0)
            test_perror("epoll_wait");
        for (int i=0; i < nfds; i++) {
            sigtest_debug("   fd %d events 0x%x\n", rev[i].data.fd, rev[i].events);
            struct signalfd_siginfo si;
            rv = read(rev[i].data.fd, &si, sizeof(struct signalfd_siginfo));
            if (rv < 0)
                test_perror("read 2");
            if (rv < sizeof(struct signalfd_siginfo))
                test_error("short read 2 (%d)", rv);
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
        test_error("epoll_wait test with no signal events failed (rv = %d)", nfds);

    sigtest_debug("   test delivery of ignored signal...\n");
    sigaddset(&ss, SIGCHLD);
    sigprocmask(SIG_BLOCK, &ss, 0);
    rv = signalfd(fd, &ss, 0);
    if (rv < 0)
        test_perror("signalfd(%d)", fd);
    raise(SIGCHLD);
    rv = read(fd, &si, sizeof(struct signalfd_siginfo));
    if (rv != sizeof(struct signalfd_siginfo))
        test_error("read from signalfd returned %d", rv);
    if (si.ssi_signo != SIGCHLD)
        test_error("unexpected signal %d read from signalfd", si.ssi_signo);

    rv = close(fd2);
    if (rv < 0)
        test_perror("close fd2");
    rv = close(fd);
    if (rv < 0)
        test_perror("close fd");

    rv = signalfd(0, &ss, 0);
    if ((rv != -1) || (errno != EINVAL))
        test_error("signalfd() with invalid fd returned %d, errno %d (%s)", rv, errno,
            strerror(errno));

    sigtest_debug("success; child exiting\n");
    return (void *)EXIT_SUCCESS;
}

void test_signalfd(void)
{
    sigtest_debug("\n");
    child_tid = 0;

    pthread_t pt = 0;
    if (pthread_create(&pt, NULL, test_signalfd_child, NULL))
        test_error("pthread_create");

    sigtest_debug("yielding until child tid reported...\n");
    yield_for(&child_tid);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = test_signalfd_handler;
    sa.sa_flags |= SA_SIGINFO;
    int rv = sigaction(SIGRTMIN, &sa, 0);
    if (rv < 0)
        test_perror("test_signalfd: sigaction");

    /* queue signal to SIGRTMIN handler; should handled via read */
    siginfo_t si;
    memset(&si, 0, sizeof(siginfo_t));
    si.si_code = SI_MESGQ;
    si.si_pid = __getpid();
    si.si_uid = getuid();
    rv = syscall(SYS_rt_tgsigqueueinfo, __getpid(), child_tid, SIGRTMIN, &si);
    if (rv < 0)
        test_perror("tgsigqueueinfo for SIGRTMIN");

    yield_for(&test_signalfd_caught);
    sigtest_debug("sending signals for poll test...\n");
    memset(&si, 0, sizeof(siginfo_t));
    si.si_code = SI_MESGQ;
    si.si_pid = __getpid();
    si.si_uid = getuid();
    rv = syscall(SYS_rt_tgsigqueueinfo, __getpid(), child_tid, SIGRTMIN, &si);
    if (rv < 0)
        test_perror("tgsigqueueinfo for SIGRTMIN (poll)");

    memset(&si, 0, sizeof(siginfo_t));
    si.si_code = SI_MESGQ;
    si.si_pid = __getpid();
    si.si_uid = getuid();
    rv = syscall(SYS_rt_tgsigqueueinfo, __getpid(), child_tid, SIGRTMIN + 1, &si);
    if (rv < 0)
        test_perror("tgsigqueueinfo for SIGRTMIN + 1 (poll)");

    sigtest_debug("waiting for child to exit...\n");
    void * retval;
    if (pthread_join(pt, &retval))
        test_error("pthread_join");

    if (retval != (void*)EXIT_SUCCESS)
        test_error("child failed");
}

#define MAX_MINSIGSTKSZ 5120 /* aarch64 */
static uint8_t altstack[MAX_MINSIGSTKSZ];

static void test_sigaltstack_handler(int sig)
{
    stack_t ss, oss;

    if (sigaltstack(NULL, &oss) < 0)
        test_perror("sigaltstack(NULL, &oss)");
    if (!oss.ss_sp)
        test_error("oss.ss_sp 0");
    if (!oss.ss_size)
        test_error("oss.ss_size 0");

    ss.ss_flags = 0;
    ss.ss_sp = altstack;
    ss.ss_size = sizeof(altstack);
    switch (sig) {
    case SIGUSR1:
        if (oss.ss_flags)
            test_error("SIGUSR1: flags 0x%x", oss.ss_flags);
        if (sigaltstack(&ss, NULL) < 0)
            test_perror("sigaltstack(&ss, NULL)");
        break;
    case SIGUSR2:
        if (oss.ss_flags != SS_ONSTACK)
            test_error("SIGUSR2: flags 0x%x", oss.ss_flags);
        if (sigaltstack(&ss, NULL) == 0)
            test_error("sigaltstack() didn't fail");
        if (errno != EPERM)
            test_perror("unexpected errno");
        break;
    }
}

void test_sigaltstack(void)
{
    sigtest_debug("\n");
    stack_t ss, oss;
    struct sigaction sa;

    if (sigaltstack(NULL, &oss) < 0)
        test_perror("sigaltstack(NULL, &oss)");
    if (!(oss.ss_flags & SS_DISABLE))
        test_error("oss.ss_flags 0x%x", oss.ss_flags);

    ss.ss_flags = 0;
    ss.ss_sp = altstack;
    ss.ss_size = sizeof(altstack);
    if (sigaltstack(&ss, NULL) < 0)
        test_perror("sigaltstack(&ss, NULL)");
    if (sigaltstack(NULL, &oss) < 0)
        test_perror("sigaltstack(NULL, &oss)");
    if (oss.ss_flags)
        test_error("oss.ss_flags 0x%x", oss.ss_flags);
    if (oss.ss_sp != altstack)
        test_error("oss.ss_sp %p", oss.ss_sp);
    if (oss.ss_size != sizeof(altstack))
        test_error("oss.ss_size %lu", oss.ss_size);

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = test_sigaltstack_handler;
    if (sigaction(SIGUSR1, &sa, NULL) < 0)
        test_perror("sigaction(SIGUSR1)");
    if (kill(__getpid(), SIGUSR1) < 0)
        test_perror("raise(SIGUSR1)");

    sa.sa_flags |= SA_ONSTACK;
    if (sigaction(SIGUSR2, &sa, NULL) < 0)
        test_perror("sigaction(SIGUSR2)");
    if (kill(__getpid(), SIGUSR2))
        test_perror("raise(SIGUSR2)");

    ss.ss_flags = SS_DISABLE;
    if (sigaltstack(&ss, NULL) < 0)
        test_perror("sigaltstack(&ss, NULL)");
    if (sigaltstack(NULL, &oss) < 0)
        test_perror("sigaltstack(NULL, &oss)");
    if (!(oss.ss_flags & SS_DISABLE))
        test_error("oss.ss_flags 0x%x", oss.ss_flags);

    ss.ss_flags = ~SS_DISABLE;
    if (sigaltstack(&ss, NULL) == 0)
        test_error("sigaltstack() with invalid flags");
    if (errno != EINVAL)
        test_perror("sigaltstack() with invalid flags");

    ss.ss_flags = 0;
    ss.ss_size = 1;
    if (sigaltstack(&ss, NULL) == 0)
        test_error("sigaltstack() with small size");
    if (errno != ENOMEM)
        test_perror("sigaltstack() with small size");
}

static void test_restart_handler(int sig)
{
    sigtest_debug("caught signal %d\n", sig);
    assert(sig == SIGUSR1);
}

static void *test_restart_child(void *arg)
{
    int fd = (long)arg;
    char buf[8];
    int rv;

    child_tid = syscall(SYS_gettid);
    sigtest_debug("child enter, tid %d\n", child_tid);

    /* Here read() should be restarted after the signal handler is run. */
    rv = read(fd, buf, sizeof(buf));
    if (rv < 0)
        test_perror("test_restart_child: read");
    assert(rv == sizeof(buf));

    child_tid = syscall(SYS_gettid);

    /* Here read() should be interrupted by the signal. */
    rv = read(fd, buf, sizeof(buf));
    if (rv < 0) {
        if (errno != EINTR)
            test_perror("test_restart_child: unexpected errno");
    } else {
        test_error("test_restart_child: read() was not interrupted");
    }

    return NULL;
}

void test_restart(void)
{
    sigtest_debug("\n");
    int fds[2] = {0,0};
    int status;
    pthread_t pt;
    struct sigaction sa;
    int rv;
    char buf[8];

    status = pipe(fds);
    if (status < 0)
        test_perror("pipe");
    child_tid = 0;
    if (pthread_create(&pt, NULL, test_restart_child, (void *)(long)fds[0]))
        test_error("pthread_create");
    sigtest_debug("yielding until child tid reported...\n");
    yield_for(&child_tid);

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = test_restart_handler;
    sa.sa_flags = SA_RESTART;
    rv = sigaction(SIGUSR1, &sa, 0);
    if (rv < 0)
        test_perror("test_restart: sigaction");
    rv = syscall(SYS_tgkill, __getpid(), child_tid, SIGUSR1);
    if (rv < 0)
        test_perror("test_restart tgkill");
    child_tid = 0;
    rv = write(fds[1], buf, sizeof(buf));
    if (rv < 0)
        test_perror("test_restart: write");
    assert(rv == sizeof(buf));

    /* Wait for child thread to call read() again. */
    yield_for(&child_tid);

    sa.sa_flags &= ~SA_RESTART;
    rv = sigaction(SIGUSR1, &sa, 0);
    if (rv < 0)
        test_perror("test_restart: sigaction");
    rv = syscall(SYS_tgkill, __getpid(), child_tid, SIGUSR1);
    if (rv < 0)
        test_perror("test_restart tgkill");

    if (pthread_join(pt, NULL))
        test_error("test_restart pthread_join");
    assert((close(fds[0]) == 0) && (close(fds[1]) == 0));
}

sigjmp_buf test_sigsetjmp_env;
int test_sigsetjmp_var = 0;

static void test_sigsetjmp_handler(int sig, siginfo_t *si, void *ucontext)
{
    assert(si);
    sigtest_debug("sig %d, si->signo %d, si->errno %d, si->code %d\n",
                  sig, si->si_signo, si->si_errno, si->si_code);
    assert(sig == SIGRTMIN);
    assert(sig == si->si_signo);
    test_sigsetjmp_var++;

    sigset_t ss;
    sigprocmask(SIG_SETMASK /* ignored */, NULL, &ss);

    /* SIGUSR2 should be blocked for the first signal delivery. */
    if (test_sigsetjmp_var == 1)
        assert(!sigismember(&ss, SIGUSR2));
    else
        assert(sigismember(&ss, SIGUSR2));

    siglongjmp(test_sigsetjmp_env, 1);
}

void test_sigsetjmp(void)
{
    sigset_t ss;
    sigtest_debug("\n");

    /* Mask only SIGUSR2 so we can later test that it will be restored after the siglongjmp. */
    sigemptyset(&ss);
    sigaddset(&ss, SIGUSR2);
    sigprocmask(SIG_SETMASK, &ss, NULL);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = test_sigsetjmp_handler;
    sa.sa_flags |= SA_SIGINFO;
    int rv = sigaction(SIGRTMIN, &sa, 0);
    if (rv < 0)
        test_perror("test_sigsetjmp: sigaction");

    /* In the old signal delivery scheme in Nanos, this first siglongjmp would
       succeed, but the thread would resume running on the dedicated
       "sighandler_frame," bypassing the call to rt_sigreturn. With the thread
       then running on the sighandler frame, the second signal delivery would
       then fail. With everything running on a single frame for the thread,
       this second signal and siglongjmp should work - as it does in Linux
       (and now in Nanos). */
    rv = sigsetjmp(test_sigsetjmp_env, 1);
    if (rv > 0) {
        sigtest_debug("siglongjmp target reached, var %d\n", test_sigsetjmp_var);

        /* Validate that the saved mask has been restored. */
        sigprocmask(SIG_SETMASK /* ignored */, NULL, &ss);
        assert(sigismember(&ss, SIGUSR2));

        if (test_sigsetjmp_var == 2)
            return;             /* success */
    } else {
        if (rv != 0)
            test_perror("test_sigsetjmp: sigsetjmp");

        /* Now unmask SIGUSR2 so we can later test that the saved mask was restored. */
        sigemptyset(&ss);
        sigaddset(&ss, SIGUSR2);
        sigprocmask(SIG_UNBLOCK, &ss, NULL);
    }

    queue_sig(SIGRTMIN);
    test_error("test_sigsetjmp: signal catch and siglongjmp did not occur");
}

static volatile int test_nested_count;

#define TEST_NESTED_LEVELS 10

static void test_nested_handler(int sig, siginfo_t *si, void *ucontext)
{
    assert(si);
    sigtest_debug("sig %d, si->signo %d, si->errno %d, si->code %d\n",
                  sig, si->si_signo, si->si_errno, si->si_code);
    if (test_nested_count < TEST_NESTED_LEVELS - 1) {
        assert(sig == SIGRTMIN + test_nested_count);
        test_nested_count++;
        queue_sig(SIGRTMIN + test_nested_count);
        assert(test_nested_count == TEST_NESTED_LEVELS);
    } else {
        assert(sig == SIGRTMIN + TEST_NESTED_LEVELS - 1);
        test_nested_count++;
    }
    assert(sig == si->si_signo);
}

void test_nested_handling(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = test_nested_handler;
    sa.sa_flags |= SA_SIGINFO;
    int rv;
    for (int i = 0; i < TEST_NESTED_LEVELS; i++) {
        rv = sigaction(SIGRTMIN + i, &sa, 0);
        if (rv < 0)
            test_perror("test_nested_handler: sigaction");
    }
    test_nested_count = 0;
    queue_sig(SIGRTMIN);
    assert(test_nested_count == TEST_NESTED_LEVELS);
}

static void sigusr1_handler(int signo)
{
    if (signo != SIGUSR1)
        test_error("childtid: caught non SIGUSR1 signal %d", signo);
}

void *smp_thread(void *a)
{
    volatile int *r = a;
    pid_t pid = getpid();
    while (*r)
        kill(pid, SIGUSR1);
    return 0;
}

#define NTHREADS 4
void test_smp_sig_handling(void)
{
    pthread_t t[NTHREADS];
    int running = true;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigusr1_handler;
    assert(sigaction(SIGUSR1, &sa, 0) == 0);

    for (int i = 0; i < NTHREADS; i++)
        pthread_create(&t[i], 0, smp_thread, &running);
    sleep(1);
    running = false;
    for (int i = 0; i < NTHREADS; i++)
        pthread_join(t[i], 0);
}

static void test_fault(void)
{
    sigset_t ss;
    union sigval sv = {0};
    siginfo_t info;
    int fd;

    assert((syscall(SYS_rt_sigpending, BAD_LOAD, 8) == -1) && (errno == EFAULT));
    assert((syscall(SYS_rt_sigaction, SIGUSR1, NULL, BAD_LOAD, 8) == -1) && (errno == EFAULT));
    assert((syscall(SYS_rt_sigaction, SIGUSR1, BAD_LOAD, NULL, 8) == -1) && (errno == EFAULT));
    assert(syscall(SYS_rt_sigprocmask, SIG_BLOCK, (sigset_t *)BAD_LOAD, NULL, 8) == -1);
    assert(errno == EFAULT);
    assert((sigprocmask(SIG_BLOCK, NULL, (sigset_t *)BAD_LOAD) == -1) && (errno == EFAULT));
    assert((sigsuspend((sigset_t *)BAD_LOAD) == -1) && (errno == EFAULT));
    assert((sigaltstack((stack_t *)BAD_LOAD, NULL) == -1) && (errno == EFAULT));
    assert((sigaltstack(NULL, (stack_t *)BAD_LOAD) == -1) && (errno == EFAULT));
    assert(syscall(SYS_rt_sigqueueinfo, __getpid(), SIGRTMIN, BAD_LOAD) == -1);
    assert(errno == EFAULT);

    sigemptyset(&ss);
    sigaddset(&ss, SIGRTMIN);
    assert(sigprocmask(SIG_BLOCK, &ss, 0) == 0);
    assert(sigqueue(__getpid(), SIGRTMIN, sv) == 0);
    assert((sigwaitinfo(&ss, (siginfo_t *)BAD_LOAD) == -1) && (errno == EFAULT));
    assert((sigtimedwait(&ss, &info, (struct timespec *)BAD_LOAD) == -1) && (errno == EFAULT));

    assert((signalfd(-1, (sigset_t *)BAD_LOAD, 0) == -1) && (errno == EINVAL));
    fd = signalfd(-1, &ss, 0);
    assert(fd >= 0);
    assert((signalfd(fd, (sigset_t *)BAD_LOAD, 0) == -1) && (errno == EINVAL));
    assert(sigqueue(__getpid(), SIGRTMIN, sv) == 0);
    assert(read(fd, (void *)BAD_LOAD, sizeof(struct signalfd_siginfo)) == -1);
    assert(errno == EFAULT);
    close(fd);
}

int main(int argc, char * argv[])
{
#ifdef __x86_64__
    test_sigfpe();
#endif

    test_sigsegv();

    test_sigill();

    test_sigtrap();

    test_signal_catch(0);

    test_signal_catch(1);

    test_rt_signal();

    test_kill();

    test_rt_sigqueueinfo();

    test_rt_sigsuspend();

    test_rt_sigtimedwait();

    test_signalfd();

    test_sigaltstack();

    test_restart();

    test_sigsetjmp();

    test_nested_handling();

    test_smp_sig_handling();

    test_fault();

    printf("signal test passed\n");
}
