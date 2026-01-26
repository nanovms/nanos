#define _GNU_SOURCE
#include <sys/time.h>
#include <sys/times.h>
#include <sys/timex.h>
#include <sys/syscall.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/timerfd.h>
#include <sys/epoll.h>
#include <signal.h>
#include <sched.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/stat.h>

#include "../test_utils.h"

#ifndef TFD_TIMER_CANCEL_ON_SET /* old glibc */
#define TFD_TIMER_CANCEL_ON_SET (1 << 1)
#endif

//#define TIMETEST_DEBUG

#define timetest_msg(x, ...) do {printf("%s: " x, __func__, ##__VA_ARGS__);} while(0)

#ifdef TIMETEST_DEBUG
#define timetest_debug(x, ...) timetest_msg(x, ##__VA_ARGS__)
#else
#define timetest_debug(x, ...)
#endif

#define SECOND_NSEC 1000000000ull
#define SECOND_USEC 1000000ull
#define N_INTERVALS 5
/* with CPU time timers, test short intervals only (otherwise tests would take too long) */
#define N_INTERVALS_CPUTIME 3
#define N_CLOCKS 2
#define N_CLOCKS_CPUTIME    2

static unsigned long long test_intervals[N_INTERVALS] = { 1, 1000, 1000000, SECOND_NSEC, 2 * SECOND_NSEC };
static clockid_t test_clocks[N_CLOCKS] = { CLOCK_MONOTONIC, CLOCK_REALTIME };
static clockid_t test_clocks_with_cputime[N_CLOCKS + N_CLOCKS_CPUTIME] = {
    CLOCK_MONOTONIC, CLOCK_REALTIME, CLOCK_PROCESS_CPUTIME_ID, CLOCK_THREAD_CPUTIME_ID,
};

static inline void timespec_from_nsec(struct timespec *ts, unsigned long long nsec)
{
    ts->tv_sec = nsec ? nsec / SECOND_NSEC : 0;
    ts->tv_nsec = nsec ? (nsec % SECOND_NSEC) : 0;
}

static inline void timespec_add_nsec(struct timespec *dest, struct timespec *op,
                                     unsigned long long nsec)
{
    timespec_from_nsec(dest, op->tv_nsec + nsec);
    dest->tv_sec += op->tv_sec;
}

static void print_timespec(struct timespec * ts)
{
    printf("%lld.%.9ld", (long long)ts->tv_sec, ts->tv_nsec);
}

static inline void timeval_from_nsec(struct timeval *tv, unsigned long long nsec)
{
    tv->tv_sec = nsec ? nsec / SECOND_NSEC : 0;
    tv->tv_usec = nsec ? (nsec % SECOND_NSEC) / 1000 : 0;
}

static inline long long delta_nsec(struct timespec *start, struct timespec *finish)
{
    long long delta;
    delta = finish->tv_nsec - start->tv_nsec;
    delta += (finish->tv_sec - start->tv_sec) * SECOND_NSEC;
    return delta;
}

static long long validate_interval(struct timespec * start, struct timespec * finish,
                                   unsigned long long intervals, unsigned long long nsec)
{
    timetest_debug("%s: intervals %lld, nsec %lld\n", __func__, intervals, nsec);
    long long duration = delta_nsec(start, finish);
    if (duration < 0) {
        timetest_msg("failed; negative duration: start ");
        print_timespec(start);
        printf(", end ");
        print_timespec(finish);
        printf("\n");
        return -1;
    }

    timetest_debug("duration %lld nsec, %lld intervals\n", duration, intervals);
    long long delta = (duration / intervals) - nsec;
    if (delta < 0)
        timetest_msg("failed; negative delta (%lld nsec)\n", delta);
    return delta;
}

static void test_clock_nanosleep(clockid_t clock_id, unsigned long long nsec)
{
    struct timespec start, end, req, rem;
    timetest_msg("clock_id %d, nsec %lld\n", clock_id, nsec);

    /* check relative interval */
    timetest_debug("relative test\n");
    if (clock_gettime(clock_id, &start) < 0)
        test_perror("clock_gettime");
    timespec_from_nsec(&req, nsec);
    if (clock_nanosleep(clock_id, 0, &req, &rem) < 0)
        test_perror("clock_nanosleep");
    if (clock_gettime(clock_id, &end) < 0)
        test_perror("clock_gettime");

    long long delta = validate_interval(&start, &end, 1, nsec);
    if (delta < 0)
        test_error("interval validation");
    timetest_msg("relative test passed, delta %lld nsec\n", delta);

    /* check absolute interval */
    timetest_debug("absolute test\n");
    if (clock_gettime(clock_id, &start) < 0)
        test_perror("clock_gettime");
    timespec_add_nsec(&req, &start, nsec);
    if (clock_nanosleep(clock_id, TIMER_ABSTIME, &req, &rem) < 0)
        test_perror("clock_nanosleep");
    if (clock_gettime(clock_id, &end) < 0)
        test_perror("clock_gettime");

    delta = validate_interval(&start, &end, 1, nsec);
    if (delta < 0)
        test_error("interval validation");
    timetest_msg("absolute test passed, delta %lld nsec\n", delta);

    /* XXX need test for interrupt / check remaining */
}

static void test_nanosleep(unsigned long long nsec)
{
    struct timespec start, end, req, rem;
    timetest_msg("nsec %lld\n", nsec);

    /* Linux nanosleep measures against CLOCK_MONOTONIC (see nanosleep(2) man page) */
    if (clock_gettime(CLOCK_MONOTONIC, &start) < 0)
        test_perror("clock_gettime");
    timespec_from_nsec(&req, nsec);
    if (nanosleep(&req, &rem) < 0)
        test_perror("nanosleep");
    if (clock_gettime(CLOCK_MONOTONIC, &end) < 0)
        test_perror("clock_gettime");

    long long delta = validate_interval(&start, &end, 1, nsec);
    if (delta < 0)
        test_error("interval validation");
    timetest_msg("test passed, delta %lld nsec\n", delta);

    /* XXX need test for interrupt / check remaining */
}

void test_time_and_times(void)
{
    struct tms tms, tms_prev;
    clock_t uptime, uptime_prev = 0;
    memset(&tms_prev, 0, sizeof(tms_prev));

    for (int i = 0; i < 4; i++) {
        time_t t = time(NULL);
        assert(t != (time_t)-1);

        time_t t2;
        t = time(&t2);
        assert(t == t2);
        timetest_msg("%s", asctime(localtime(&t)));

        struct timeval tv;
        gettimeofday(&tv, NULL);
        timetest_msg("gettimeofday: %lu.%.6lu\n", tv.tv_sec, tv.tv_usec);

        uptime = times(&tms);
        if ((tms.tms_utime < tms_prev.tms_utime) ||
            (tms.tms_stime < tms_prev.tms_stime) ||
            (tms.tms_cutime < tms_prev.tms_cutime) ||
            (tms.tms_cstime < tms_prev.tms_cstime) || (uptime < uptime_prev)) {
            test_error("non-monotonic values");
        }
        memcpy(&tms_prev, &tms, sizeof(tms));
        uptime_prev = uptime;

        struct timespec tp;
        timetest_msg("CLOCK_MONOTONIC: ");
        if (clock_gettime(CLOCK_MONOTONIC, &tp) < 0)
            test_perror("clock_gettime");
        print_timespec(&tp);
        printf("\n");
        timetest_msg("CLOCK_REALTIME: ");
        if (clock_gettime(CLOCK_REALTIME, &tp) < 0)
            test_perror("clock_gettime");
        print_timespec(&tp);
        printf("\n");
        usleep(250000);
    }
}

static void test_cputime(void)
{
    struct timespec thread_ts, proc_ts, tmp_ts;
    long long thread_delta, proc_delta;
    clockid_t cid;
    int rv;

    if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &thread_ts) < 0)
        test_perror("clock_gettime(CLOCK_THREAD_CPUTIME_ID)");
    if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &proc_ts) < 0)
        test_perror("clock_gettime(CLOCK_PROCESS_CPUTIME_ID)");
    if (delta_nsec(&thread_ts, &proc_ts) < 0)
        test_error("%s: process CPU time < thread CPU time", __func__);
    do {
        if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &tmp_ts) < 0)
            test_perror("clock_gettime(CLOCK_THREAD_CPUTIME_ID)");
        thread_delta = delta_nsec(&thread_ts, &tmp_ts);
        if (thread_delta < 0)
            test_error("%s: thread_delta %lld", __func__, thread_delta);
        thread_ts = tmp_ts;
        if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &tmp_ts) < 0)
            test_perror("clock_gettime(CLOCK_PROCESS_CPUTIME_ID)");
        proc_delta = delta_nsec(&proc_ts, &tmp_ts);
        if (proc_delta < 0)
            test_error("%s: proc_delta %lld", __func__, proc_delta);
        proc_ts = tmp_ts;
        if (delta_nsec(&thread_ts, &proc_ts) < 0)
            test_error("%s: process CPU time < thread CPU time", __func__);
    } while ((thread_delta == 0) || (proc_delta == 0));

    rv = clock_getcpuclockid(0xbad0bad, &cid);
    if (rv != ESRCH)
        test_error("clock_getcpuclockid with invalid pid returned %d", rv);
    rv = clock_gettime(~0 << 3, &tmp_ts);
    if ((rv != -1) || (errno != EINVAL))
        test_error("clock_gettime with invalid clock type returned %d (errno %d)", rv, errno);
    rv = clock_gettime((~0xbad0bad << 3) | 0x2, &tmp_ts);
    if ((rv != -1) || (errno != EINVAL))
        test_error("clock_gettime with invalid process id returned %d (errno %d)", rv, errno);
    rv = clock_gettime((~0xbad0bad << 3) | 0x4 | 0x2, &tmp_ts);
    if ((rv != -1) || (errno != EINVAL))
        test_error("clock_gettime with invalid thread id returned %d (errno %d)", rv, errno);

    rv = pthread_getcpuclockid(pthread_self(), &cid);
    if (rv != 0)
        test_error("thread_getcpuclockid for the current thread returned %d", rv);
    if (clock_gettime(cid, &thread_ts) < 0)
        test_perror("clock_gettime(pthread_getcpuclockid())");

    rv = clock_getcpuclockid(0, &cid);
    if (rv != 0)
        test_error("clock_getcpuclockid for the current process returned %d", rv);
    if (clock_gettime(cid, &proc_ts) < 0)
        test_perror("clock_gettime(clock_getcpuclockid())");

    if (delta_nsec(&thread_ts, &proc_ts) < 0)
        test_error("process CPU time < thread CPU time");
}

static void test_getres_clk(clockid_t clk_id)
{
    struct timespec res;

    if ((clock_getres(clk_id, NULL) < 0) || (clock_getres(clk_id, &res) < 0))
        test_perror("failed to get resolution for clock %d", clk_id);
    if ((res.tv_sec == 0) && (res.tv_nsec == 0))
        test_error("zero resolution for clock %d", clk_id);
}

static void test_getres(void)
{
    test_getres_clk(CLOCK_REALTIME);
    test_getres_clk(CLOCK_MONOTONIC);
    test_getres_clk(CLOCK_PROCESS_CPUTIME_ID);
    test_getres_clk(CLOCK_THREAD_CPUTIME_ID);
    test_getres_clk(CLOCK_MONOTONIC_RAW);
    test_getres_clk(CLOCK_REALTIME_COARSE);
    test_getres_clk(CLOCK_MONOTONIC_COARSE);
    test_getres_clk(CLOCK_BOOTTIME);
}

#define pertest_msg(x, ...) timetest_msg("test %d: " x, test->test_id, ##__VA_ARGS__);
#define pertest_debug(x, ...) timetest_debug("test %d: " x, test->test_id, ##__VA_ARGS__);
#define pertest_fail_perror(x, ...) test_perror("test %d: " x, test->test_id, ##__VA_ARGS__);
#define pertest_fail_error(x, ...)  test_error("test %d: " x, test->test_id, ##__VA_ARGS__);

struct timer_test {
    /* test parameters */
    int test_id;
    clockid_t clock;
    unsigned long long nsec;
    long long overruns;
    int absolute;

    /* state */
    union {
        int fd;
        int timerid;
    };
    pthread_t pt;
    long long total_overruns;
    struct timespec start;
    struct timespec finish;
};

static inline void timerfd_set(clockid_t clock_id, int fd, unsigned long long value,
                               unsigned long long interval, int absolute)
{
    struct itimerspec its;
    if (absolute) {
        struct timespec n;
        if (clock_gettime(clock_id, &n) < 0)
            test_perror("clock_gettime");
        timespec_add_nsec(&its.it_value, &n, value);
    } else {
        timespec_from_nsec(&its.it_value, value);
    }
    timespec_from_nsec(&its.it_interval, interval);
    if (timerfd_settime(fd, absolute ? TFD_TIMER_ABSTIME : 0, &its, 0) < 0)
        test_perror("timerfd_settime");
}

static inline void timerfd_check_disarmed(int fd)
{
    struct itimerspec its;
    int rv = timerfd_gettime(fd, &its);
    if (rv < 0)
        test_perror("timerfd_gettime");
    if (its.it_value.tv_sec != 0 || its.it_value.tv_nsec != 0)
        test_error("timerfd_gettime should have returned zero it_value for disarmed timer");
}

static void timerfd_test_start(struct timer_test *test)
{
    test->total_overruns = 0;
    if (clock_gettime(test->clock, &test->start) < 0)
        pertest_fail_perror("failed: clock_gettime");
    timerfd_set(test->clock, test->fd, test->nsec,
                test->overruns > 1 ? test->nsec : 0, test->absolute);
}

static void timerfd_test_finish(struct timer_test *test)
{
    if (clock_gettime(test->clock, &test->finish) < 0)
        pertest_fail_perror("clock_gettime");
    if (test->overruns > 1)
        timerfd_set(test->clock, test->fd, 0, 0, 0);
    timerfd_check_disarmed(test->fd);
    long long delta = validate_interval(&test->start, &test->finish,
                                        test->total_overruns, test->nsec);
    if (delta < 0)
        pertest_fail_error("interval validation");
    timetest_msg("%s clock id %d, nsec %lld, overruns %lld passed "
                 "with delta %lld nsec\n", test->absolute ? "absolute" : "relative",
                 test->clock, test->nsec, test->overruns, delta);
}

static int test_timerfd_fd_service(struct timer_test *test)
{
    unsigned long long overruns = 0;
    int rv = read(test->fd, &overruns, sizeof(overruns));
    if (rv < 0) {
        if (errno == EINTR) {
            pertest_debug("read returned with EINTR; continue\n");
            return 0;
        }
        pertest_fail_perror("read");
    }
    if (rv != sizeof(overruns))
        pertest_fail_error("read returned unexpected value: %d", rv);
    if (overruns == 0)
        pertest_fail_error("read zero overruns");
    test->total_overruns += overruns;
    pertest_debug("read %lld overruns, total %lld\n", overruns, test->total_overruns);
    return test->total_overruns >= test->overruns;
}

static void * test_timerfd_thread(void * arg)
{
    struct timer_test *test = arg;
    pertest_debug("enter: fd %d, clock %d, %lld nsec, %s, overruns %lld\n",
                  test->fd, test->clock, test->nsec, test->absolute ? "absolute" : "relative",
                  test->overruns);

    timerfd_test_start(test);
    while (test_timerfd_fd_service(test) == 0);
    timerfd_test_finish(test);
    pertest_debug("success\n");
    return EXIT_SUCCESS;
}

static void test_timerfd(void)
{
    int ntests = N_CLOCKS * N_INTERVALS * 2 /* one shot, periodic */ * 2 /* absolute, relative */;
    struct timer_test tests[N_CLOCKS][N_INTERVALS][2][2];

    timetest_msg("testing interface");
    int fd = timerfd_create(CLOCK_MONOTONIC /* matters not for interface test */, 0);
    if (fd < 0)
        test_perror("timerfd_create");

    int rv = timerfd_gettime(fd, 0);
    if (rv >= 0 || errno != EFAULT) {
        test_error("timerfd_gettime with null curr_value should have failed with "
                   "EFAULT (rv %d, errno %d)", rv, errno);
    }

    timerfd_check_disarmed(fd);
    close(fd);

    timetest_msg("starting blocking read tests\n");
    int id = 0;
    for (int i = 0; i < N_CLOCKS; i++) {
        for (int j = 0; j < N_INTERVALS; j++) {
            for (int k = 0; k < 2; k++) {
                for (int l = 0; l < 2; l++) {
                    struct timer_test *test = &tests[i][j][k][l];
                    test->test_id = id++;
                    test->clock = test_clocks[i];
                    test->nsec = test_intervals[j];
                    test->overruns = k == 0 ? 1 : 3 /* XXX */;
                    test->absolute = l;
                    timetest_debug("starting test #%d: clock %d, nsec %lld, overruns %lld, absolute %d\n",
                                   test->test_id, test->clock, test->nsec, test->overruns, test->absolute);
                    test->fd = timerfd_create(test->clock, 0);
                    if (test->fd < 0)
                        pertest_fail_perror("timerfd_create");
                    if (pthread_create(&test->pt, NULL, test_timerfd_thread, test))
                        pertest_fail_error("pthread_create");
                }
            }
        }
    }

    /* wait for threads to finish - don't care about order */
    for (int i = 0; i < ntests; i++) {
        struct timer_test *test = ((struct timer_test *)tests) + i;
        void * retval;
        if (pthread_join(test->pt, &retval))
            pertest_fail_error("pthread_join");
    }
    timetest_msg("all blocking read tests passed\n");

    /* leave fds open and re-use */
    timetest_msg("starting poll read tests\n");
    int epfd = epoll_create(1);
    if (epfd < 0)
        test_perror("epoll_create");

    for (int i = 0; i < ntests; i++) {
        struct timer_test *test = ((struct timer_test *)tests) + i;
        struct epoll_event epev;
        epev.events = EPOLLIN;
        epev.data.ptr = test;
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, test->fd, &epev) < 0)
            test_perror("epoll_ctl");
        timerfd_test_start(test);
    }

    int tests_finished = 0;
    while (tests_finished < ntests) {
        struct epoll_event rev;
        int nfds = epoll_wait(epfd, &rev, 1, 20000);
        if (nfds < 0)
            test_perror("epoll_wait");
        if (nfds == 0)
            test_error("epoll_wait timed out");

        struct timer_test *test = rev.data.ptr;
        if (rev.events & EPOLLIN) {
            if (test_timerfd_fd_service(test)) {
                timerfd_test_finish(test);
                close(test->fd);
                tests_finished++;
            }
        }
    }
    timetest_msg("all poll read tests passed\n");
    close(epfd);
}

static volatile int posix_timers_finished;

static void posix_timer_set(clockid_t clock_id, int timerid, unsigned long long value,
                            unsigned long long interval, struct timespec *abs_start)
{
    struct itimerspec its;
    timespec_from_nsec(&its.it_interval, interval);
    if (abs_start) {
        timespec_add_nsec(&its.it_value, abs_start, value);
    } else {
        timespec_from_nsec(&its.it_value, value);
    }
    timetest_debug("timer_settime: timerid %d, absolute %d, value %ld s, %ld ns, interval %ld s, %ld ns\n",
                   timerid, abs_start != 0, its.it_value.tv_sec, its.it_value.tv_nsec,
                   its.it_interval.tv_sec, its.it_interval.tv_nsec);
    if (syscall(SYS_timer_settime, timerid, abs_start ? TIMER_ABSTIME : 0, &its, 0) < 0)
        test_perror("timer_settime");
}

static inline void posix_timer_check_disarmed(struct timer_test *test)
{
    struct itimerspec its;
    int rv = syscall(SYS_timer_gettime, test->timerid, &its);
    if (rv < 0)
        pertest_fail_perror("timer_gettime");
    if (its.it_value.tv_sec != 0 || its.it_value.tv_nsec != 0)
        pertest_fail_error("timer_gettime should have returned zero it_value for disarmed timer");
}

static void posix_test_start(struct timer_test *test)
{
    test->total_overruns = 0;
    if (clock_gettime(test->clock, &test->start) < 0)
        pertest_fail_perror("clock_gettime");
    posix_timer_set(test->clock, test->timerid, test->nsec,
                    test->overruns > 1 ? test->nsec : 0,
                    test->absolute ? &test->start : 0);
}

static void posix_timer_cancel(struct timer_test *test)
{
    pertest_debug("cancel timerid %d\n", test->timerid);
    struct itimerspec its;
    memset(&its, 0, sizeof(struct itimerspec));
    if (syscall(SYS_timer_settime, test->timerid, 0, &its, 0) < 0)
        pertest_fail_perror("timer_settime");
}

static void posix_test_finish(struct timer_test *test)
{
    if (test->overruns > 1)
        posix_timer_cancel(test);
    if (clock_gettime(test->clock, &test->finish) < 0)
        pertest_fail_perror("clock_gettime");
    posix_timer_check_disarmed(test);
    long long delta = validate_interval(&test->start, &test->finish,
                                        test->total_overruns, test->nsec);
    if (delta < 0)
        pertest_fail_error("interval validation");
    if (syscall(SYS_timer_delete, test->timerid) < 0)
        pertest_fail_perror("timer_delete");
    pertest_msg("%s clock id %d, nsec %lld, overruns %lld passed "
                "with delta %lld nsec\n", test->absolute ? "absolute" : "relative",
                test->clock, test->nsec, test->overruns, delta);
}

static void posix_timers_sighandler(int sig, siginfo_t *si, void *ucontext)
{
    assert(si);
    timetest_debug("sig %d, si->errno %d, si->code %d, tid %d, overrun %d\n",
                   sig, si->si_errno, si->si_code, si->si_timerid, si->si_overrun);
    assert(sig == SIGRTMIN);
    assert(sig == si->si_signo);
    assert(si->si_code == SI_TIMER);
    struct timer_test *test = si->si_value.sival_ptr;
    if (test->total_overruns < 0) {
        pertest_debug("expiry after cancel; ignore\n");
        return;
    }
    test->total_overruns += si->si_overrun + 1;
    pertest_debug("read %d overruns, total %lld\n", si->si_overrun, test->total_overruns);
    if (test->total_overruns >= test->overruns) {
        posix_test_finish(test);
        test->total_overruns = -1;
        posix_timers_finished++;
        pertest_debug("finished (total finished %d)\n", posix_timers_finished);
    }
}

void test_posix_timers(void)
{
    int ntests = (N_CLOCKS * N_INTERVALS + N_CLOCKS_CPUTIME * N_INTERVALS_CPUTIME) *
            2 /* one shot, periodic */ * 2 /* absolute, relative */;
    struct timer_test tests[N_CLOCKS + N_CLOCKS_CPUTIME][N_INTERVALS][2][2];

    timetest_msg("testing interface\n");
    int rv = syscall(SYS_timer_create, CLOCK_MONOTONIC, 0, 0);
    if (rv >= 0 || errno != EFAULT)
        test_error("timer_create with null timerid should have failed with "
                   "EFAULT (rv %d, errno %d)", rv, errno);

    int dummy_id;
    if (syscall(SYS_timer_create, CLOCK_MONOTONIC, 0, &dummy_id) < 0)
        test_perror("timer_create with null sev");

    rv = syscall(SYS_timer_gettime, dummy_id, 0);
    if (rv >= 0 || errno != EFAULT)
        test_error("timer_gettime with null curr_value should have failed with "
                   "EFAULT (rv %d, errno %d)", rv, errno);

    rv = syscall(SYS_timer_settime, dummy_id, 0, 0, 0);
    if (rv >= 0 || errno != EINVAL)
        test_error("timer_settime with null new_value should have failed with "
                   "EINVAL (rv %d, errno %d)", rv, errno);

    if (syscall(SYS_timer_delete, dummy_id) < 0)
        test_perror("timer_delete");

    clockid_t cid;
    timer_t timer_id;
    struct itimerspec its;

    rv = clock_getcpuclockid(0, &cid);
    if (rv != 0 )
        test_error("clock_getcpuclockid error %d", rv);
    if (timer_create(cid, 0, &timer_id) < 0)
        test_perror("timer_create with process CPU time");
    rv = timer_gettime(timer_id, &its);
    if (rv < 0)
        test_perror("timer_gettime with process CPU time");
    rv = timer_delete(timer_id);
    if (rv < 0)
        test_perror("timer_delete with process CPU time");

    rv = pthread_getcpuclockid(pthread_self(), &cid);
    if (rv != 0 )
        test_error("pthread_getcpuclockid error %d (%s)", rv, strerror(rv));
    if (timer_create(cid, 0, &timer_id) < 0)
        test_perror("timer_create with thread CPU time");
    rv = timer_gettime(timer_id, &its);
    if (rv < 0)
        test_perror("timer_gettime with thread CPU time");
    rv = timer_delete(timer_id);
    if (rv < 0)
        test_perror("timer_delete with thread CPU time");

    posix_timers_finished = 0;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = posix_timers_sighandler;
    sa.sa_flags |= SA_SIGINFO;
    rv = sigaction(SIGRTMIN, &sa, 0);
    if (rv < 0)
        test_perror("test_posix_timers: sigaction");

    sigset_t ss;
    sigemptyset(&ss);
    sigaddset(&ss, SIGRTMIN);
    rv = sigprocmask(SIG_UNBLOCK, &ss, 0);
    if (rv < 0)
        test_perror("sigprocmask");

    timetest_msg("starting signal test\n");
    int id = 0;
    for (int i = 0; i < N_CLOCKS + N_CLOCKS_CPUTIME; i++) {
        for (int j = 0; j < ((i < N_CLOCKS) ? N_INTERVALS : N_INTERVALS_CPUTIME); j++) {
            for (int k = 0; k < 2; k++) {
                for (int l = 0; l < 2; l++) {
                    struct timer_test *test = &tests[i][j][k][l];
                    test->test_id = id++;
                    test->clock = test_clocks_with_cputime[i];
                    test->nsec = test_intervals[j];
                    test->overruns = k == 0 ? 1 : 3 /* XXX */;
                    test->absolute = l;
                    struct sigevent sev;
                    sev.sigev_notify = SIGEV_SIGNAL;
                    sev.sigev_signo = SIGRTMIN;
                    sev.sigev_value.sival_ptr = test;
                    if (syscall(SYS_timer_create, test->clock, &sev, &test->timerid) < 0)
                        test_perror("timer_create");
                    timetest_debug("test #%d starting: timerid %d, clock %d, nsec %lld, "
                                   "overruns %lld, absolute %d\n", test->test_id,
                                   test->timerid, test->clock, test->nsec,
                                   test->overruns, test->absolute);
                    posix_test_start(test);
                }
            }
        }
    }

    while (posix_timers_finished < ntests)
        usleep(500000);

    timetest_msg("signal test passed\n");

    sigemptyset(&ss);
    sigaddset(&ss, SIGRTMIN);
    rv = sigprocmask(SIG_BLOCK, &ss, 0);
    if (rv < 0)
        test_perror("sigprocmask");
}

/* XXX only ITIMER_REAL and ITIMER_PROF right now */
#define N_WHICH 2

static int itimer_types[N_WHICH] = { ITIMER_REAL, ITIMER_PROF };
static int itimer_signals[N_WHICH] = { SIGALRM, SIGPROF };
clockid_t itimer_clockids[N_WHICH] = { CLOCK_REALTIME, CLOCK_PROCESS_CPUTIME_ID };
volatile int itimer_expect, itimer_which;
volatile struct timespec itimer_finished;

static void itimers_sighandler(int sig, siginfo_t *si, void *ucontext)
{
    assert(si);
    timetest_debug("sig %d, si->errno %d, si->code %d\n", sig, si->si_errno, si->si_code);
    assert(sig == itimer_signals[itimer_which]);
    assert(sig == si->si_signo);
    assert(si->si_code == SI_KERNEL);
    if (itimer_expect > 0) {
        if (itimer_expect == 1) {
            struct itimerval itv;
            memset(&itv, 0, sizeof(struct itimerval));
            if (syscall(SYS_setitimer, itimer_types[itimer_which], &itv, 0 /* XXX check old val */) < 0)
                test_perror("setitimer");
            if (clock_gettime(itimer_clockids[itimer_which], (struct timespec*)&itimer_finished) < 0)
                test_perror("clock_gettime");
        }
        itimer_expect--;
    } else {
        timetest_debug("spurious signal\n");
    }
}

void test_itimers(void)
{
    timetest_msg("testing itimer interface\n");

    int rv = syscall(SYS_setitimer, ITIMER_REAL, 0, 0);
    if (rv != 0)
        test_perror("setitimer with null new_value");

    rv = syscall(SYS_getitimer, ITIMER_REAL, 0);
    if (rv >= 0 || errno != EFAULT)
        test_error("getitimer with null curr_value should have failed with "
                   "EFAULT (rv %d, errno %d)", rv, errno);

    struct itimerval itv;
    memset(&itv, 0, sizeof(struct itimerval));
    rv = syscall(SYS_setitimer, 3, &itv, 0);
    if (rv >= 0 || errno != EINVAL)
        test_error("setitimer with invalid which should have failed with "
                   "EINVAL (rv %d, errno %d)", rv, errno);

    rv = syscall(SYS_getitimer, 3, &itv);
    if (rv >= 0 || errno != EINVAL)
        test_error("getitimer with invalid which should have failed with "
                   "EINVAL (rv %d, errno %d)", rv, errno);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = itimers_sighandler;
    sa.sa_flags |= SA_SIGINFO;
    for (int i = 0; i < N_WHICH; i++) {
        rv = syscall(SYS_getitimer, itimer_types[i], &itv);
        if (rv < 0)
            test_perror("test_itimers: getitimer (%d)", i);
        rv = sigaction(itimer_signals[i], &sa, 0);
        if (rv < 0)
            test_perror("test_itimers: sigaction (%d)", i);
    }

    sigset_t ss;
    sigemptyset(&ss);
    sigaddset(&ss, SIGALRM);
    rv = sigprocmask(SIG_UNBLOCK, &ss, 0);
    if (rv < 0)
        test_perror("sigprocmask");

    timetest_msg("starting itimer test\n");
    for (int i = 0; i < N_WHICH; i++) {
        for (int j = 1 /* skip 1ns */;
             j < ((itimer_types[i] == ITIMER_REAL) ? N_INTERVALS : N_INTERVALS_CPUTIME); j++) {
            for (int k = 0; k < 2; k++) {
                struct timespec start;
                timeval_from_nsec(&itv.it_value, test_intervals[j]);
                timeval_from_nsec(&itv.it_interval, k == 0 ? 0 : test_intervals[j]);
                timetest_msg("starting: which %d, interval %lld nsec, %s\n",
                               i, test_intervals[j], k == 0 ? "one-shot" : "periodic");
                int overruns = k == 0 ? 1 : 3 /* XXX */;
                itimer_which = i;
                itimer_expect = overruns;
                if (clock_gettime(itimer_clockids[i], &start) < 0)
                    test_perror("clock_gettime");
                if (syscall(SYS_setitimer, itimer_types[i], &itv, 0 /* XXX check old val */) < 0)
                    test_perror("setitimer");
                while (itimer_expect > 0)
                    usleep(50000); /* XXX ugh ... also need timeout */

                long long delta = validate_interval(&start, (struct timespec*)&itimer_finished,
                                                    overruns, test_intervals[j]);
                if (delta < 0)
                    test_error("interval validation");
                timetest_msg("test passed; delta %lld nsec\n", delta);
            }
        }
    }
    timetest_msg("itimer test passed\n");
}

volatile int alarm_received;
volatile struct timespec alarm_finished;

static void alarm_sighandler(int sig, siginfo_t *si, void *ucontext)
{
    assert(si);
    timetest_debug("sig %d, si->errno %d, si->code %d\n", sig, si->si_errno, si->si_code);
    assert(sig == SIGALRM);
    assert(sig == si->si_signo);
    assert(si->si_code == SI_KERNEL);
    if (clock_gettime(CLOCK_REALTIME, (struct timespec*)&alarm_finished) < 0)
        test_perror("clock_gettime");
    alarm_received = 1;
}

void test_alarm(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = alarm_sighandler;
    sa.sa_flags |= SA_SIGINFO;
    int rv = sigaction(SIGALRM, &sa, 0);
    if (rv < 0)
        test_perror("test_signal_catch: sigaction");

    sigset_t ss;
    sigemptyset(&ss);
    sigaddset(&ss, SIGALRM);
    rv = sigprocmask(SIG_UNBLOCK, &ss, 0);
    if (rv < 0)
        test_perror("sigprocmask");

    alarm_received = 0;
    unsigned int old = alarm(3);
    timetest_debug("...old %d\n", old);
    if (old != 0)
        test_error("alarm timer should have been disarmed");

    usleep(1000000);
    struct timespec start;
    if (clock_gettime(CLOCK_REALTIME, &start) < 0)
        test_perror("clock_gettime");
    old = alarm(1);
    if (old == 0)
        test_error("alarm timer should still be armed after usleep");

    while (!alarm_received)
        usleep(50000); /* XXX as above */

    long long delta = validate_interval(&start, (struct timespec*)&alarm_finished,
                                        1, SECOND_NSEC);
    if (delta < 0)
        test_error("interval validation");
    timetest_msg("test passed; delta %lld nsec\n", delta);
}

static void test_utime(void)
{
    const char *filename = "utime_test";
    int fd;
    struct timespec times[2];
    int rv;
    int success = 0;

    fd = timerfd_create(CLOCK_MONOTONIC, 0);
    if (fd < 0)
        test_perror("timerfd_create");
    rv = futimens(fd, NULL);
    close(fd);
    if ((rv != -1) || (errno != EACCES))
        test_error("rv %d, errno %d", rv, errno);
    rv = futimens(-1, NULL);
    if ((rv != -1) || (errno != EBADF))
        test_error("rv %d, errno %d", rv, errno);
    rv = utimensat(-1, filename, NULL, 0);
    if ((rv != -1) || (errno != EBADF))
        test_error("rv %d, errno %d", rv, errno);
    rv = utimes(filename, NULL);
    if ((rv != -1) || (errno != ENOENT))
        test_error("rv %d, errno %d", rv, errno);
    fd = creat(filename, S_IRUSR | S_IWUSR);
    if (fd < 0)
        test_perror("creat(\"%s\")", filename);
    times[0].tv_nsec = 0;
    times[1].tv_nsec = 999999999;
    if (futimens(fd, times) < 0) {
        timetest_msg("failed at %d (%d)\n", __LINE__, errno);
        goto close_fd;
    }
    times[1].tv_nsec++;
    rv = futimens(fd, times);
    if ((rv != -1) || (errno != EINVAL)) {
        timetest_msg("failed at %d (%d, %d)\n", __LINE__, rv, errno);
        goto close_fd;
    }
    times[0].tv_nsec = UTIME_NOW;
    times[1].tv_nsec = UTIME_OMIT;
    if (futimens(fd, times) < 0) {
        timetest_msg("failed at %d (%d)\n", __LINE__, errno);
        goto close_fd;
    }
    if (utimensat(AT_FDCWD, filename, times, 0) < 0) {
        timetest_msg("failed at %d (%d)\n", __LINE__, errno);
        goto close_fd;
    }
    rv = utimensat(AT_FDCWD, filename, times, -1);  /* invalid flags */
    if ((rv != -1) || (errno != EINVAL)) {
        timetest_msg("failed at %d (%d, %d)\n", __LINE__, rv, errno);
        goto close_fd;
    }
    rv = utimensat(AT_FDCWD, "foo", times, 0);
    if ((rv != -1) || (errno != ENOENT)) {
        timetest_msg("failed at %d (%d, %d)\n", __LINE__, rv, errno);
        goto close_fd;
    }
    rv = futimens(fd, FAULT_ADDR);
    if ((rv != -1) || (errno != EFAULT)) {
        timetest_msg("failed at %d (%d, %d)\n", __LINE__, rv, errno);
        goto close_fd;
    }
    if (futimens(fd, NULL) < 0) {
        timetest_msg("failed at %d (%d)\n", __LINE__, errno);
        goto close_fd;
    }
    success = 1;
  close_fd:
    close(fd);
    unlink(filename);
    if (!success)
        exit(EXIT_FAILURE);
}

static void test_fault(void)
{
    void *fault_addr = FAULT_ADDR;
    int fd;
    struct itimerspec ts;
    struct itimerval tv;
    timer_t timerid;

    fd = timerfd_create(CLOCK_MONOTONIC, 0);
    if (fd < 0)
        test_perror("timerfd_create");

    if ((timerfd_gettime(fd, fault_addr) != -1) || (errno != EFAULT))
        test_error("timerfd_gettime() with faulting address test");
    if ((timerfd_settime(fd, 0, fault_addr, NULL) != -1) || (errno != EFAULT))
        test_error("timerfd_settime() with faulting new value test");
    memset(&ts, 0, sizeof(ts));
    if ((timerfd_settime(fd, 0, &ts, fault_addr) != -1) || (errno != EFAULT))
        test_error("timerfd_settime() with faulting old value test");

    ts.it_value.tv_nsec = 1;
    if (timerfd_settime(fd, 0, &ts, NULL) < 0)
        test_perror("timerfd_settime()");
    if ((read(fd, fault_addr, sizeof(unsigned long)) != -1) || (errno != EFAULT))
        test_error("timerfd read() with faulting buffer test");

    close(fd);

    if ((syscall(SYS_timer_create, CLOCK_MONOTONIC, NULL, fault_addr) != -1) || (errno != EFAULT))
        test_error("timer_create() with faulting timerid test");
    if ((syscall(SYS_timer_create, CLOCK_MONOTONIC, fault_addr, &timerid) != -1) ||
        (errno != EFAULT))
        test_error("timer_create() with faulting sigevent test");

    if (timer_create(CLOCK_MONOTONIC, NULL, &timerid) < 0)
        test_perror("timer_create()");
    if ((timer_gettime(timerid, fault_addr) != -1) || (errno != EFAULT))
        test_error("timer_gettime() with faulting address test");
    if ((timer_settime(timerid, 0, fault_addr, NULL) != -1) || (errno != EFAULT))
        test_error("timer_settime() with faulting new value test");
    ts.it_value.tv_sec = 1;
    if ((timer_settime(timerid, 0, &ts, fault_addr) != -1) || (errno != EFAULT))
        test_error("timer_settime() with faulting old value test");
    timer_delete(timerid);

    if ((getitimer(ITIMER_REAL, fault_addr) != -1) || (errno != EFAULT))
        test_error("getitimer() with faulting address test");
    if ((setitimer(ITIMER_REAL, fault_addr, NULL) != -1) || (errno != EFAULT))
        test_error("setitimer() with faulting new value test");
    memset(&tv, 0, sizeof(tv));
    if ((setitimer(ITIMER_REAL, &tv, fault_addr) != -1) || (errno != EFAULT))
        test_error("setitimer() with faulting old value test");

    if ((syscall(SYS_gettimeofday, fault_addr, NULL) != -1) || (errno != EFAULT))
        test_error("gettimeofday() with faulting address test");
    if ((syscall(SYS_settimeofday, fault_addr, NULL) != -1) || (errno != EFAULT))
        test_error("settimeofday() with faulting address test");
    if ((syscall(SYS_times, fault_addr) != -1) || (errno != EFAULT))
        test_error("times() with faulting address test");
    if ((syscall(SYS_clock_gettime, CLOCK_REALTIME, fault_addr) != -1) || (errno != EFAULT))
        test_error("clock_gettime() with faulting address test");
    if ((syscall(SYS_clock_settime, CLOCK_REALTIME, fault_addr) != -1) || (errno != EFAULT))
        test_error("clock_settime() with faulting address test");
    if ((syscall(SYS_clock_getres, CLOCK_REALTIME, fault_addr) != -1) || (errno != EFAULT))
        test_error("clock_getres() with faulting address test");

    if ((syscall(SYS_nanosleep, fault_addr, NULL) != -1) || (errno != EFAULT))
        test_error("nanosleep() with faulting address test");
    if ((syscall(SYS_clock_nanosleep, CLOCK_MONOTONIC, 0, fault_addr, NULL) != -1) || (errno != EFAULT))
        test_error("clock_nanosleep() with faulting address test");

    test_assert((ntp_adjtime(fault_addr) == -1) && (errno == EFAULT));
}

static void test_settime(void)
{
    struct timespec n;
    struct itimerspec ts;
    struct timeval tv;
    unsigned long overruns;
    int ret;
    int fd = timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK);
    if (fd < 0)
        test_perror("timerfd_create");
    if (clock_gettime(CLOCK_REALTIME, &n) < 0)
        test_perror("clock_gettime(CLOCK_REALTIME)");
    ts.it_interval.tv_sec = ts.it_interval.tv_nsec = 0;

    ts.it_value.tv_sec = 1;
    ts.it_value.tv_nsec = 0;
    if (timerfd_settime(fd, 0, &ts, NULL) < 0)
        test_perror("timerfd_settime");
    n.tv_sec++;
    if (clock_settime(CLOCK_REALTIME, &n))
        test_perror("clock_settime");
    if (timerfd_gettime(fd, &ts) < 0)
        test_perror("timerfd_gettime");
    if ((ts.it_value.tv_sec == 0) && (ts.it_value.tv_nsec == 0))
        test_error("relative timer was affected by change to real-time clock");

    n.tv_sec++;
    ts.it_value.tv_sec = n.tv_sec + 1;
    ts.it_value.tv_nsec = n.tv_nsec;
    if (timerfd_settime(fd, TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET, &ts, NULL) < 0)
        test_perror("timerfd_settime(TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET)");
    if (clock_settime(CLOCK_REALTIME, &n))
        test_perror("clock_settime");
    ret = read(fd, &overruns, sizeof(overruns));
    if ((ret >= 0) || (errno != ECANCELED))
        test_error("absolute timer was not canceled by change to real-time clock (%d)",
                   (ret >= 0) ? ret : -errno);
    ret = read(fd, &overruns, sizeof(overruns));
    if ((ret >= 0) || (errno != EAGAIN))
        test_error("unexpected result from second read after timer canceled (%d)",
                   (ret >= 0) ? ret : -errno);

    /* test removal of timer from list of cancelable timers */
    if (timerfd_settime(fd, TFD_TIMER_ABSTIME, &ts, NULL) < 0)
        test_perror("timerfd_settime(TFD_TIMER_ABSTIME)");
    if (clock_settime(CLOCK_REALTIME, &n))
        test_perror("clock_settime");
    ret = read(fd, &overruns, sizeof(overruns));
    if ((ret >= 0) || (errno != EAGAIN))
        test_error("unexpected read result from non-cancelable timer after change to real-time "
                   "clock (%d)", (ret >= 0) ? ret : -errno);

    /* undo changes to real-time clock */
    n.tv_sec -= 2;
    if (clock_settime(CLOCK_REALTIME, &n))
        test_perror("clock_settime");

    close(fd);

    tv.tv_sec = n.tv_sec;
    tv.tv_usec = n.tv_nsec / 1000;
    if (settimeofday(&tv, NULL))
        test_perror("settimeofday");

    /* test setting of non-settable clock types */
    ret = clock_settime(CLOCK_REALTIME_COARSE, &n);
    if ((ret == 0) || (errno != EINVAL))
        test_error("unexpected result from clock_settime(CLOCK_REALTIME_COARSE) (%d)",
                   (ret == 0) ? ret : -errno);
}

static void test_adjtimex_offset(bool positive, bool nano)
{
    long offset = positive ? LONG_MAX : -LONG_MAX;
    long clamped_max = positive ? 500000000 : -500000000;
    struct timex tx;

    tx.modes = MOD_OFFSET | (nano ? MOD_NANO : MOD_MICRO);
    tx.offset = offset;
    test_assert(ntp_adjtime(&tx) >= 0);
    if (nano) {
        test_assert(tx.status & STA_NANO);
    } else {
        test_assert(!(tx.status & STA_NANO));
        clamped_max /= 1000;
    }
    test_assert(tx.offset == clamped_max);

    for (int i = 0; i < 1000; i++) {
        tx.modes = nano ? MOD_NANO : MOD_MICRO;
        test_assert(ntp_adjtime(&tx) >= 0);
        if (positive)
            test_assert((tx.offset >= 0) && (tx.offset <= clamped_max));
        else
            test_assert((tx.offset <= 0) && (tx.offset >= clamped_max));
        if (tx.offset != clamped_max)
            return;
        usleep(1000);
    }
    test_error("offset did not decrease (%ld)", tx.offset);
}

static void test_adjtimex_freq(bool positive)
{
    long freq = positive ? INT_MAX : -INT_MAX;
    long clamped_max = positive ? 500 * 0x10000 : -500 * 0x10000;
    struct timex tx;

    tx.modes = MOD_FREQUENCY;
    tx.freq = freq;
    test_assert(ntp_adjtime(&tx) >= 0);
    /* allow for some precision loss due to conversion from/to internal format */
    test_assert((tx.freq >= clamped_max - 10) && (tx.freq <= clamped_max + 10));
    test_assert(tx.tolerance == abs(clamped_max));
}

static void test_adjtimex_status(void)
{
    struct timex tx;

    tx.modes = MOD_STATUS;
    tx.status = STA_UNSYNC;
    test_assert((ntp_adjtime(&tx) == TIME_ERROR) && (tx.status & STA_UNSYNC));
    tx.status = 0;
    test_assert((ntp_adjtime(&tx) == TIME_OK) && !(tx.status & STA_UNSYNC));
}

static void test_adjtimex_setoffset(bool positive, bool nano)
{
    const int offset_frac = 500000; /* microseconds */
    const int offset_nsec = SECOND_NSEC + offset_frac * 1000;
    struct timex tx;
    struct timespec ts_before, ts_after;
    long long delta;

    if (clock_gettime(CLOCK_REALTIME, &ts_before) < 0)
        test_perror("clock_gettime");
    tx.modes = ADJ_SETOFFSET | (nano ? ADJ_NANO : ADJ_MICRO);
    tx.time.tv_sec = positive ? 1 : -2;
    tx.time.tv_usec = nano ? offset_frac * 1000 : offset_frac;
    test_assert(adjtimex(&tx) >= 0);
    ts_after.tv_sec = tx.time.tv_sec;
    ts_after.tv_nsec = nano ? tx.time.tv_usec : (tx.time.tv_usec * 1000);
    delta = delta_nsec(&ts_before, &ts_after);
    if (positive)
        test_assert(delta >= offset_nsec);
    else
        test_assert((delta >= -offset_nsec) && (delta < -offset_nsec + 100000000));
    if (clock_gettime(CLOCK_REALTIME, &ts_after) < 0)
        test_perror("clock_gettime");
    delta = delta_nsec(&ts_before, &ts_after);
    if (positive)
        test_assert(delta >= offset_nsec);
    else
        test_assert((delta >= -offset_nsec) && (delta < -offset_nsec + 100000000));
}

static void test_adjtimex(int opt_settime)
{
    struct timex tx;
    struct timespec ts_before, ts_after;

    if (clock_gettime(CLOCK_REALTIME, &ts_before) < 0)
        test_perror("clock_gettime");
    tx.modes = 0;
    test_assert(ntp_adjtime(&tx) >= 0);
    ts_after.tv_sec = tx.time.tv_sec;
    ts_after.tv_nsec = (tx.status & STA_NANO) ? tx.time.tv_usec : (tx.time.tv_usec * 1000);
    test_assert(delta_nsec(&ts_before, &ts_after) >= 0);

    if (opt_settime) {
        test_adjtimex_offset(true, true);
        test_adjtimex_offset(true, false);
        test_adjtimex_offset(false, true);
        test_adjtimex_offset(false, false);
        test_adjtimex_freq(true);
        test_adjtimex_freq(false);

        tx.modes = ADJ_OFFSET_SINGLESHOT;
        tx.offset = 200000; /* microseconds */
        test_assert(ntp_adjtime(&tx) >= 0);
        tx.modes = ADJ_OFFSET_SS_READ;
        test_assert(adjtimex(&tx) >= 0);
        test_assert((tx.offset > 100000) && (tx.offset <= 200000));

        test_adjtimex_status();

        test_adjtimex_setoffset(true, true);
        test_adjtimex_setoffset(true, false);
        test_adjtimex_setoffset(false, true);
        test_adjtimex_setoffset(false, false);
    }

    test_assert((clock_adjtime(CLOCK_MONOTONIC, &tx) == -1) && (errno == EOPNOTSUPP));
    test_assert((clock_adjtime(INT_MAX, &tx) == -1) && (errno == EINVAL));
}

int main(int argc, char *argv[])
{
    int opt_settime = 0;
    int c;
    while ((c = getopt(argc, argv, "s")) != EOF) {
        switch (c) {
        case 's':
            opt_settime = 1;
            break;
        }
    }
    test_time_and_times();
    for (int i = 0; i < N_INTERVALS; i++) {
        test_nanosleep(test_intervals[i]);
        for (int j = 0; j < N_CLOCKS; j++)
            test_clock_nanosleep(test_clocks[j], test_intervals[i]);
    }
    test_timerfd();
    test_posix_timers();
    test_itimers();
    test_cputime();
    test_getres();
    test_alarm();
    test_utime();
    test_fault();
    if (opt_settime)
        test_settime();
    test_adjtimex(opt_settime);
    printf("time test passed\n");
    return EXIT_SUCCESS;
}
