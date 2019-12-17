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

//#define TIMETEST_DEBUG
#ifdef TIMETEST_DEBUG
#define timetest_debug(x, ...) do {printf("%s: " x, __func__, ##__VA_ARGS__);} while(0)
#else
#define timetest_debug(x, ...)
#endif

#define timetest_err(x, ...) do {printf("%s: " x, __func__, ##__VA_ARGS__);} while(0)

#define fail_perror(msg, ...) do { timetest_err(msg ": %s (%d)\n", ##__VA_ARGS__, strerror(errno), errno); \
        exit(EXIT_FAILURE); } while(0)

#define fail_error(msg, ...) do { timetest_err(msg, ##__VA_ARGS__); exit(EXIT_FAILURE); } while(0)

#define BILLION 1000000000ull

static void print_timespec(struct timespec * ts)
{
    printf("%lld.%.9ld", (long long)ts->tv_sec, ts->tv_nsec);
}

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

static inline void timespec_from_nsec(struct timespec *ts, unsigned long long nsec)
{
    ts->tv_sec = nsec / BILLION;
    ts->tv_nsec = nsec % BILLION;
}

static inline unsigned long long nsec_from_timespec(struct timespec *ts)
{
    return ts->tv_sec * BILLION + ts->tv_nsec;
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

static inline void timerfd_check_disarmed(int fd)
{
    struct itimerspec its;
    int rv = timerfd_gettime(fd, &its);
    if (rv < 0)
        fail_perror("timerfd_gettime");
    if (its.it_value.tv_sec != 0 || its.it_value.tv_nsec != 0)
        fail_error("timerfd_gettime should have returned zero it_value for disarmed timer.\n");
}

static inline void timerfd_set(int fd, unsigned long long value, unsigned long long interval)
{
    struct itimerspec its;
    timespec_from_nsec(&its.it_interval, interval);
    timespec_from_nsec(&its.it_value, value);
    if (timerfd_settime(fd, 0, &its, 0) < 0)
        fail_perror("timerfd_settime");
}

/* XXX test absolute */
void test_timerfd(clockid_t clkid, unsigned long long nsec)
{
    printf("%s for clkid %d, %lld nsec\n", __func__, clkid, nsec);
    int fd = timerfd_create(clkid, 0);
    if (fd < 0)
        fail_perror("timerfd_create");

    int rv = timerfd_gettime(fd, 0);
    if (rv >= 0 || errno != EFAULT) {
        fail_error("timerfd_gettime with null curr_value should have failed with "
                   "EFAULT (rv %d, errno %d)\n", rv, errno);
    }

    timerfd_check_disarmed(fd);

    timetest_debug("   one shot test...\n");
    unsigned long long expirations = 0;
    timerfd_set(fd, nsec, 0);

    rv = read(fd, &expirations, sizeof(expirations));
    printf("rv %d, errno %d\n", rv, errno);
    if (rv < 0)
        fail_perror("read");
    if (rv != sizeof(expirations))
        fail_error("read returned unexpected value: %d\n", rv);
    if (expirations == 0)
        fail_error("read zero expirations\n");
    timetest_debug("   + %lld\n", expirations);

    timerfd_check_disarmed(fd);

    timetest_debug("   periodic test...\n");
    struct itimerspec its;
    timerfd_set(fd, nsec, nsec);

    int nexpired = 0;
    while (nexpired < 3) {
        rv = timerfd_gettime(fd, &its);
        if (rv < 0)
            fail_perror("timerfd_gettime");
        timetest_debug("   read at ");
#ifdef TIMETEST_DEBUG
        print_timespec(&its.it_value);
        printf("\n");
#endif
        if (nsec_from_timespec(&its.it_value) > nsec)
            fail_error("timer value greater than duration.\n");
        rv = read(fd, &expirations, sizeof(expirations));
        if (rv < sizeof(expirations))
            fail_perror("read");
        if (expirations == 0)
            fail_error("read zero expirations\n");
        timetest_debug("   + %lld\n", expirations);
        nexpired += expirations;
    }

    timerfd_set(fd, 0, 0);
    timerfd_check_disarmed(fd);

    timetest_debug("   poll wait test...\n");
    int epfd = epoll_create(1);
    if (epfd < 0)
        fail_perror("epoll_create");

    struct epoll_event epev;
    epev.events = EPOLLIN;
    epev.data.fd = fd;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &epev) < 0)
        fail_perror("epoll_ctl 1");

    struct epoll_event rev;

    timerfd_set(fd, nsec, nsec);

    nexpired = 0;
    while (nexpired < 3) {
        timetest_debug("   epoll_wait...\n");
        int nfds = epoll_wait(epfd, &rev, 1, 5000);
        if (nfds < 0)
            fail_perror("epoll_wait");
        if (nfds == 0)
            fail_error("epoll_wait timed out\n");
        timetest_debug("   fd %d events 0x%x\n", rev.data.fd, rev.events);
        rv = timerfd_gettime(fd, &its);
        if (rv < 0)
            fail_perror("timerfd_gettime");
        timetest_debug("   read at ");
#ifdef TIMETEST_DEBUG
        print_timespec(&its.it_value);
        printf("\n");
#endif
        rv = read(fd, &expirations, sizeof(expirations));
        if (rv < sizeof(expirations))
            fail_perror("read");
        if (expirations == 0)
            fail_error("read zero expirations\n");
        nexpired += expirations;
    }

    timerfd_set(fd, 0, 0);
    timerfd_check_disarmed(fd);
    close(epfd);
    close(fd);
}

void posix_timer_set(timer_t id, unsigned long long value, unsigned long long interval)
{
    struct itimerspec its;
    timespec_from_nsec(&its.it_interval, interval);
    timespec_from_nsec(&its.it_value, value);
    if (timer_settime(id, 0, &its, 0) < 0)
        fail_perror("timer_settime");
}

static volatile int test_posix_timers_caught = 0;

static void test_posix_timers_handler(int sig, siginfo_t *si, void *ucontext)
{
    assert(si);
    timetest_debug("sig %d, si->signo %d, si->errno %d, si->code %d, tid %d, overrun %d\n",
                   sig, si->si_signo, si->si_errno, si->si_code, si->si_timerid, si->si_overrun);
    assert(sig == SIGRTMIN);
    assert(sig == si->si_signo);
    assert(si->si_code == SI_TIMER);
    test_posix_timers_caught = si->si_value.sival_int;
}

static void yield_for(volatile int * v)
{
    /* XXX add timeout */
    while (!*v)
        sched_yield();
}

void test_posix_timers(clockid_t clkid, unsigned long long nsec)
{
    printf("%s for clkid %d, %lld nsec\n", __func__, clkid, nsec);
    timer_t id;

    test_posix_timers_caught = 0;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = test_posix_timers_handler;
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

    rv = syscall(SYS_timer_create, clkid, 0, 0);
    if (rv >= 0 || errno != EFAULT)
        fail_error("timer_create with null timerid should have failed with EFAULT (rv %d, errno %d)\n", rv, errno);

    timetest_debug("   process signal test...\n");
    struct sigevent sev;
    sev.sigev_notify = SIGEV_SIGNAL;
    sev.sigev_signo = SIGRTMIN;
    sev.sigev_value.sival_int = 1;
    if (timer_create(clkid, &sev, &id) < 0)
        fail_perror("timer_create");

    posix_timer_set(id, nsec, 0);
    timetest_debug("   waiting for signal catch...\n");
    yield_for(&test_posix_timers_caught);
    timetest_debug("   caught\n");
    if (test_posix_timers_caught != 1)
        fail_error("timer sig caught but unexpected value (%d)\n", test_posix_timers_caught);

    /* XXX test default (null) sigevent */

    /* XXX test absolute */
}

int
main()
{
    setbuf(stdout, NULL);
    test_time_and_times();
    unsigned long long intervals[] = { 1, 1000, 1000000, BILLION, 2 * BILLION, -1 };
    for (int i = 0; intervals[i] != -1; i++) {
        test_nanosleep(intervals[i]);
        test_clock_nanosleep(CLOCK_MONOTONIC, intervals[i]);
        test_clock_nanosleep(CLOCK_REALTIME, intervals[i]);
        test_timerfd(CLOCK_MONOTONIC, intervals[i]);
        test_timerfd(CLOCK_REALTIME, intervals[i]);
        test_timerfd(CLOCK_MONOTONIC, intervals[i]);
        test_posix_timers(CLOCK_MONOTONIC, intervals[i]);
        test_posix_timers(CLOCK_REALTIME, intervals[i]);
    }
    printf("time test passed\n");
    return EXIT_SUCCESS;
}
