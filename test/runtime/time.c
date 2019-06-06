#include <sys/time.h>
#include <sys/times.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

int
main()
{
    struct tms tms, tms_prev;
    clock_t uptime, uptime_prev;
    int i;

    memset(&tms_prev, 0, sizeof(tms_prev));
    uptime_prev = 0;
    for (i = 0; i < 10; i++) {
        struct timeval tv;
        time_t t, t2;

        gettimeofday(&tv, NULL);
        printf("gettimeofday: tv_sec = %lu, tv_usec = %lu\n", tv.tv_sec, tv.tv_usec);

        t = time(NULL);
        printf("time: retval = %ld\n", t);

        t = time(&t2);
        printf("time: retval = %ld, out = %ld\n", t, t2);

        uptime = times(&tms);
        if ((tms.tms_utime < tms_prev.tms_utime) ||
                (tms.tms_stime < tms_prev.tms_stime) ||
                (tms.tms_cutime < tms_prev.tms_cutime) ||
                (tms.tms_cstime < tms_prev.tms_cstime) || (uptime < uptime_prev)) {
            printf("times: non-monotonic values\n");
            return EXIT_FAILURE;
        }
        memcpy(&tms_prev, &tms, sizeof(tms));
        uptime_prev = uptime;

        sleep(1);
    }

    return 0;
}
