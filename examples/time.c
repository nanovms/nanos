#include <sys/time.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

int
main()
{
    int i;

    for (i = 0; i < 10; i++) {
        struct timeval tv;
        time_t t, t2;

        gettimeofday(&tv, NULL);
        printf("gettimeofday: tv_sec = %lu, tv_usec = %lu\n", tv.tv_sec, tv.tv_usec);

        t = time(NULL);
        printf("time: retval = %ld\n", t);

        t = time(&t2);
        printf("time: retval = %ld, out = %ld\n", t, t2);

        sleep(1);
    }

    return 0;
}
