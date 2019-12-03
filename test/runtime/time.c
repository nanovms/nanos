#include <sys/time.h>
#include <sys/times.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

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

static void test_clock_nanosleep(clockid_t clock_id, unsigned long long nsec)
{
    struct timespec start, end, req, rem;

    /* check relative interval */
    if (clock_gettime(clock_id, &start) < 0)
        goto out_clock_gettime_fail;
    printf("%s, clock_id %d, nsec %lld\n   relative test, start: ", __func__, clock_id, nsec);
    print_timespec(&start);

    req.tv_sec = nsec / BILLION;
    req.tv_nsec = nsec % BILLION;
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

    req.tv_sec = nsec / BILLION;
    req.tv_nsec = nsec % BILLION;
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

int
main()
{
    setbuf(stdout, NULL);
    test_time_and_times();
    unsigned long long intervals[] = { 0, BILLION / 2, BILLION, -1 };
    for (int i = 0; intervals[i] != -1; i++) {
        test_nanosleep(intervals[i]);
        test_clock_nanosleep(CLOCK_MONOTONIC, intervals[i]);
        test_clock_nanosleep(CLOCK_REALTIME, intervals[i]);
    }
    printf("time test passed\n");
    return EXIT_SUCCESS;
}
