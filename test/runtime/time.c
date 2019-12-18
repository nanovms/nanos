#include <sys/time.h>
#include <sys/times.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <sys/timerfd.h>
#include <sys/epoll.h>
#include <signal.h>
#include <sched.h>
#include <pthread.h>

#define TIMETEST_DEBUG
#ifdef TIMETEST_DEBUG
#define timetest_debug(x, ...) do {printf("%s: " x, __func__, ##__VA_ARGS__);} while(0)
#else
#define timetest_debug(x, ...)
#define pertest_debug(x, ...)
#endif

#define timetest_err(x, ...) do {printf("%s: " x, __func__, ##__VA_ARGS__);} while(0)

#define fail_perror(msg, ...) do { timetest_err(msg ": %s (%d)\n", ##__VA_ARGS__, strerror(errno), errno); \
        exit(EXIT_FAILURE); } while(0)

#define fail_error(msg, ...) do { timetest_err(msg, ##__VA_ARGS__); exit(EXIT_FAILURE); } while(0)

#define BILLION 1000000000ull
#define N_INTERVALS 5
#define N_CLOCKS 2

static unsigned long long test_intervals[N_INTERVALS] = { 1, 1000, 1000000, BILLION, 2 * BILLION };
static clockid_t test_clocks[N_CLOCKS] = { CLOCK_MONOTONIC, CLOCK_REALTIME };

static inline void timespec_from_nsec(struct timespec *ts, unsigned long long nsec)
{
    ts->tv_sec = nsec ? nsec / BILLION : 0;
    ts->tv_nsec = nsec ? (nsec % BILLION) + 1 : 0;
}

static inline unsigned long long nsec_from_timespec(struct timespec *ts)
{
    return ts->tv_sec * BILLION + ts->tv_nsec;
}

static void print_timespec(struct timespec * ts)
{
    printf("%lld.%.9ld", (long long)ts->tv_sec, ts->tv_nsec);
}

/* XXX combine with below */
static void validate_interval(unsigned long long nsec, struct timespec * start, struct timespec * end)
{
    if (end->tv_sec < start->tv_sec ||
        (end->tv_sec == start->tv_sec && end->tv_nsec < start->tv_nsec)) {
        printf("failure; time went backwards: start ");
        print_timespec(start);
        printf(", end ");
        print_timespec(end);
        printf("\n");
        exit(EXIT_FAILURE);
    }

    long long elapsed = (end->tv_sec - start->tv_sec) * BILLION + (end->tv_nsec - start->tv_nsec);
    if (elapsed < nsec) {
        printf("failure; measured interval (%lld) less than requested (%lld)\n", elapsed, nsec);
        exit(EXIT_FAILURE);
    }
    printf("   measured delta +%lld ns\n", elapsed - nsec);
}

static void test_clock_nanosleep(clockid_t clock_id, unsigned long long nsec)
{
    struct timespec start, end, req, rem;

    /* check relative interval */
    if (clock_gettime(clock_id, &start) < 0)
        goto out_clock_gettime_fail;
    printf("%s, clock_id %d, nsec %lld\n   relative test, start: ", __func__, clock_id, nsec);
    print_timespec(&start);

    timespec_from_nsec(&req, nsec);
    printf("\n      calling clock_nanosleep with req = ");
    print_timespec(&req);
    printf("\n");
    if (clock_nanosleep(clock_id, 0, &req, &rem) < 0)
        goto out_clock_nanosleep_fail;

    if (clock_gettime(clock_id, &end) < 0)
        goto out_clock_gettime_fail;

    validate_interval(nsec, &start, &end);

    /* check absolute interval */
    if (clock_gettime(clock_id, &start) < 0)
        goto out_clock_gettime_fail;
    printf("   absolute test, start: ");
    print_timespec(&start);

    unsigned long long ti = start.tv_nsec + nsec;
    req.tv_nsec = ti % BILLION;
    req.tv_sec = start.tv_sec + (ti / BILLION);
    printf("\n      calling clock_nanosleep with absolute req = ");
    print_timespec(&req);
    printf("\n");

    if (clock_nanosleep(clock_id, TIMER_ABSTIME, &req, &rem) < 0)
        goto out_clock_nanosleep_fail;

    if (clock_gettime(clock_id, &end) < 0)
        goto out_clock_gettime_fail;

    validate_interval(nsec, &start, &end);
    return;
  out_clock_gettime_fail:
    printf("   clock_gettime (id %d) failed: %d (%s)\n", clock_id, errno, strerror(errno));
    exit(EXIT_FAILURE);
  out_clock_nanosleep_fail:
    printf("   clock_nanosleep (id %d) failed: %d (%s)\n", clock_id, errno, strerror(errno));
    exit(EXIT_FAILURE);
}

static void test_nanosleep(unsigned long long nsec)
{
    struct timespec start, end, req, rem;

    /* Linux nanosleep measures against CLOCK_MONOTONIC (see nanosleep(2) man page) */
    if (clock_gettime(CLOCK_MONOTONIC, &start) < 0)
        goto out_clock_gettime_fail;
    printf("%s, nsec %lld\n   relative test, start: ", __func__, nsec);
    print_timespec(&start);

    timespec_from_nsec(&req, nsec);
    printf("\n      calling clock_nanosleep with req = ");
    print_timespec(&req);
    printf("\n");
    if (nanosleep(&req, &rem) < 0)
        goto out_nanosleep_fail;

    if (clock_gettime(CLOCK_MONOTONIC, &end) < 0)
        goto out_clock_gettime_fail;

    validate_interval(nsec, &start, &end);
    return;
  out_clock_gettime_fail:
    printf("   clock_gettime failed: %d (%s)\n", errno, strerror(errno));
    exit(EXIT_FAILURE);
  out_nanosleep_fail:
    printf("   nanosleep failed: %d (%s)\n", errno, strerror(errno));
    exit(EXIT_FAILURE);
}

void test_time_and_times(void)
{
    struct tms tms, tms_prev;
    clock_t uptime, uptime_prev = 0;
    int i;
    memset(&tms_prev, 0, sizeof(tms_prev));

    for (i = 0; i < 3; i++) {
        time_t t = time(NULL);
        assert(t != (time_t)-1);

        time_t t2;
        t = time(&t2);
        assert(t == t2);
        printf("%s", asctime(localtime(&t)));

        struct timeval tv;
        gettimeofday(&tv, NULL);
        printf("   gettimeofday: %lu.%.6lu, ", tv.tv_sec, tv.tv_usec);

        uptime = times(&tms);
        if ((tms.tms_utime < tms_prev.tms_utime) ||
            (tms.tms_stime < tms_prev.tms_stime) ||
            (tms.tms_cutime < tms_prev.tms_cutime) ||
            (tms.tms_cstime < tms_prev.tms_cstime) || (uptime < uptime_prev)) {
            printf("times: non-monotonic values\n");
            exit(EXIT_FAILURE);
        }
        memcpy(&tms_prev, &tms, sizeof(tms));
        uptime_prev = uptime;

        struct timespec tp;
        printf("CLOCK_MONOTONIC: ");
        if (clock_gettime(CLOCK_MONOTONIC, &tp) < 0)
            goto out_clock_gettime_fail;
        print_timespec(&tp);

        printf(", CLOCK_REALTIME: ");
        if (clock_gettime(CLOCK_REALTIME, &tp) < 0)
            goto out_clock_gettime_fail;
        print_timespec(&tp);
        printf("\n");
        sleep(1);
    }
    return;
  out_clock_gettime_fail:
    printf("clock_gettime (CLOCK_REALTIME) failed: %d (%s)\n", errno, strerror(errno));
    exit(EXIT_FAILURE);
}

#define pertest_debug(x, ...) timetest_debug("test %d: " x, test_id, ##__VA_ARGS__);
#define pertest_fail_perror(x, ...) fail_perror("test %d: " x, test_id, ##__VA_ARGS__);
#define pertest_fail_error(x, ...) fail_error("test %d: " x, test_id, ##__VA_ARGS__);

static inline long long delta_nsec(struct timespec *start, struct timespec *finish)
{
    long long delta;
    delta = finish->tv_nsec - start->tv_nsec;
    delta += (finish->tv_sec - start->tv_sec) * BILLION;
    return delta;
}

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

static inline void timerfd_set(int test_id, clockid_t clock_id, int fd, unsigned long long value,
                               unsigned long long interval, int absolute)
{
    struct itimerspec its;
    if (absolute) {
        struct timespec n;
        if (clock_gettime(clock_id, &n) < 0)
            pertest_fail_perror("clock_gettime");
        timespec_from_nsec(&its.it_value, value + n.tv_nsec);
        its.it_value.tv_sec += n.tv_sec;
    } else {
        timespec_from_nsec(&its.it_value, value);
    }
    timespec_from_nsec(&its.it_interval, interval);
    if (timerfd_settime(fd, absolute ? TFD_TIMER_ABSTIME : 0, &its, 0) < 0)
        pertest_fail_perror("timerfd_settime");
}

static inline void timerfd_check_disarmed(int fd)
{
    struct itimerspec its;
    int rv = timerfd_gettime(fd, &its);
    if (rv < 0)
        fail_perror("timerfd_gettime");
    if (its.it_value.tv_sec != 0 || its.it_value.tv_nsec != 0)
        fail_error("timerfd_gettime should have returned zero it_value for disarmed timer.\n");
}

static void timerfd_test_start(struct timer_test *test)
{
    int test_id = test->test_id;
    test->total_overruns = 0;
    if (clock_gettime(test->clock, &test->start) < 0)
        pertest_fail_perror("failed: clock_gettime");
    timerfd_set(test->test_id, test->clock, test->fd, test->nsec,
                test->overruns > 1 ? test->nsec : 0, test->absolute);
}

static void timerfd_test_finish(struct timer_test *test)
{
    int test_id = test->test_id;
    if (clock_gettime(test->clock, &test->finish) < 0)
        pertest_fail_perror("clock_gettime");
    if (test->overruns > 1)
        timerfd_set(test->test_id, test->clock, test->fd, 0, 0, 0);
    timerfd_check_disarmed(test->fd);
    long long duration = delta_nsec(&test->start, &test->finish);
    assert(duration > 0);
    long long per = duration / test->total_overruns;
    long long delta = per - test->nsec;
    pertest_debug("%lld overruns, delta %lld nsec\n", test->total_overruns, delta);
    if (delta < 0)
        pertest_fail_error("failed; negative delta (%lld nsec)\n", delta);
}

static int test_timerfd_fd_service(struct timer_test *test)
{
    int test_id = test->test_id;
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
        pertest_fail_error("read returned unexpected value: %d\n", rv);
    if (overruns == 0)
        pertest_fail_error("read zero overruns\n");
    test->total_overruns += overruns;
    pertest_debug("read %lld overruns, total %lld\n", overruns, test->total_overruns);
    return test->total_overruns >= test->overruns;
}

static void * test_timerfd_thread(void * arg)
{
    struct timer_test *test = arg;
    int test_id = test->test_id;
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

    timetest_debug("%s\n", __func__);

    int fd = timerfd_create(CLOCK_MONOTONIC /* matters not for interface test */, 0);
    if (fd < 0)
        fail_perror("timerfd_create");

    int rv = timerfd_gettime(fd, 0);
    if (rv >= 0 || errno != EFAULT) {
        fail_error("timerfd_gettime with null curr_value should have failed with "
                   "EFAULT (rv %d, errno %d)\n", rv, errno);
    }

    timerfd_check_disarmed(fd);
    close(fd);

    timetest_debug("starting thread read test\n");
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
                        fail_perror("test #%d failed: timerfd_create", test->test_id);
                    if (pthread_create(&test->pt, NULL, test_timerfd_thread, test))
                        fail_perror("pthread_create");
                }
            }
        }
    }

    /* wait for threads to finish - don't care about order */
    for (int i = 0; i < ntests; i++) {
        struct timer_test *test = ((struct timer_test *)tests) + i;
        void * retval;
        if (pthread_join(test->pt, &retval))
            fail_perror("pthread_join");
    }

    /* leave fds open and re-use */
    timetest_debug("thread read test passed; starting poll test\n");
    int epfd = epoll_create(1);
    if (epfd < 0)
        fail_perror("epoll_create");

    for (int i = 0; i < ntests; i++) {
        struct timer_test *test = ((struct timer_test *)tests) + i;
        struct epoll_event epev;
        epev.events = EPOLLIN;
        epev.data.ptr = test;
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, test->fd, &epev) < 0)
            fail_perror("epoll_ctl");
        timerfd_test_start(test);
    }

    int tests_finished = 0;
    while (tests_finished < ntests) {
        struct epoll_event rev;
        int nfds = epoll_wait(epfd, &rev, 1, 20000);
        if (nfds < 0)
            fail_perror("epoll_wait");
        if (nfds == 0)
            fail_error("epoll_wait timed out\n");

        struct timer_test *test = rev.data.ptr;
        int test_id = test->test_id;
        if (rev.events & EPOLLIN) {
            if (test_timerfd_fd_service(test)) {
                pertest_debug("passed\n");
                close(test->fd);
                tests_finished++;
            }
        }
    }
    timetest_debug("passed\n");
    close(epfd);
}

static volatile int posix_timers_finished;

static void posix_timer_set(int test_id, clockid_t clock_id, int timerid, unsigned long long value,
                            unsigned long long interval, struct timespec *abs_start)
{
    struct itimerspec its;
    timespec_from_nsec(&its.it_interval, interval);
    if (abs_start) {
        timespec_from_nsec(&its.it_value, value + abs_start->tv_nsec);
        its.it_value.tv_sec += abs_start->tv_sec;
    } else {
        timespec_from_nsec(&its.it_value, value);
    }
#if 0
    pertest_debug("timer_settime: timerid %d, absolute %d, value %ld s, %ld ns, interval %ld s, %ld ns\n",
                  timerid, abs_start != 0, its.it_value.tv_sec, its.it_value.tv_nsec,
                  its.it_interval.tv_sec, its.it_interval.tv_nsec);
#endif
    if (syscall(SYS_timer_settime, timerid, abs_start ? TIMER_ABSTIME : 0, &its, 0) < 0)
        pertest_fail_perror("timer_settime");
}

static inline void posix_timer_check_disarmed(struct timer_test *test)
{
    int test_id = test->test_id;
    struct itimerspec its;
    int rv = syscall(SYS_timer_gettime, test->timerid, &its);
    if (rv < 0)
        pertest_fail_perror("timer_gettime");
    if (its.it_value.tv_sec != 0 || its.it_value.tv_nsec != 0)
        pertest_fail_error("timer_gettime should have returned zero it_value for disarmed timer.\n");
}

static void posix_test_start(struct timer_test *test)
{
    int test_id = test->test_id;
    test->total_overruns = 0;
    if (clock_gettime(test->clock, &test->start) < 0)
        pertest_fail_perror("failed: clock_gettime");
    posix_timer_set(test->test_id, test->clock, test->timerid, test->nsec,
                    test->overruns > 1 ? test->nsec : 0, test->absolute ? &test->start : 0);
}

static void posix_timer_cancel(struct timer_test *test)
{
    int test_id = test->test_id;
    pertest_debug("cancel timerid %d\n", test->timerid);
    struct itimerspec its;
    memset(&its, 0, sizeof(struct itimerspec));
    if (syscall(SYS_timer_settime, test->timerid, 0, &its, 0) < 0)
        pertest_fail_perror("timer_settime");
}

static void posix_test_finish(struct timer_test *test)
{
    int test_id = test->test_id;
    pertest_debug("a\n");
    pertest_debug("b\n");
    if (test->overruns > 1)
        posix_timer_cancel(test);
    if (clock_gettime(test->clock, &test->finish) < 0)
        pertest_fail_perror("clock_gettime");
    pertest_debug("c\n");
    posix_timer_check_disarmed(test);
    pertest_debug("d\n");
    long long duration = delta_nsec(&test->start, &test->finish);
    assert(duration > 0);
    long long per = duration / test->total_overruns;
    long long delta = per - test->nsec;
    pertest_debug("duration %lld nsec, per %lld nsec\n", duration, per);
    pertest_debug("%lld overruns, delta %lld nsec\n", test->total_overruns, delta);
    if (delta < 0)
        pertest_fail_error("failed; negative delta (%lld nsec)\n", delta);
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
    int test_id = test->test_id;
    if (test->total_overruns < 0) {
        pertest_debug("expiry after cancel; ignore\n");
        return;
    }
    test->total_overruns += si->si_overrun;
    pertest_debug("read %d overruns, total %lld\n", si->si_overrun, test->total_overruns);
    if (test->total_overruns >= test->overruns) {
        posix_test_finish(test);
        posix_timers_finished++;
        pertest_debug("finished (total finished %d)\n", posix_timers_finished);
        test->total_overruns = -1;
    }
}

void test_posix_timers(void)
{
    int ntests = N_CLOCKS * N_INTERVALS * 2 /* one shot, periodic */ * 2 /* absolute, relative */;
    struct timer_test tests[N_CLOCKS][N_INTERVALS][2][2];

    timetest_debug("%s\n", __func__);
    posix_timers_finished = 0;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = posix_timers_sighandler;
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

    timetest_debug("starting signal test\n");
    int id = 0;
    for (int i = 0; i < N_CLOCKS; i++) {
        for (int j = 0; j < N_INTERVALS; j++) {
            for (int k = 0; k < 2; k++) {
                for (int l = 0; l < 2; l++) {
                    struct timer_test *test = &tests[i][j][k][l];
                    int test_id = id++;
                    test->test_id = test_id;
                    test->clock = test_clocks[i];
                    test->nsec = test_intervals[j];
                    test->overruns = k == 0 ? 1 : 3 /* XXX */;
                    test->absolute = l;
                    struct sigevent sev;
                    sev.sigev_notify = SIGEV_SIGNAL;
                    sev.sigev_signo = SIGRTMIN;
                    sev.sigev_value.sival_ptr = test;
                    if (syscall(SYS_timer_create, test->clock, &sev, &test->timerid) < 0)
                        fail_perror("timer_create");
                    pertest_debug("starting: timerid %d, clock %d, nsec %lld, overruns %lld, absolute %d\n",
                                  test->timerid, test->clock, test->nsec, test->overruns, test->absolute);
                    posix_test_start(test);
                }
            }
        }
    }

    while (posix_timers_finished < ntests)
        usleep(500000);

    /* XXX somehow suppress output from spurious signals after test finish... */
    timetest_debug("signal test passed\n");
}

int
main()
{
    setbuf(stdout, NULL);
    test_time_and_times();
    for (int i = 0; i < N_INTERVALS; i++) {
        test_nanosleep(test_intervals[i]);
        for (int j = 0; j < N_CLOCKS; j++)
            test_clock_nanosleep(test_clocks[j], test_intervals[i]);
    }
    test_timerfd();
    test_posix_timers();
    printf("time test passed\n");
    return EXIT_SUCCESS;
}
