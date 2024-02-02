/* vsyscall test */

#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#define VSYSCALL_BASE                 0xffffffffff600000ull
#define VSYSCALL_OFFSET_VGETTIMEOFDAY 0x000
#define VSYSCALL_OFFSET_VTIME         0x400
#define VSYSCALL_OFFSET_VGETCPU       0x800

typedef long (*gettimeofday_fn)(struct timeval *tv, struct timezone *tz);
typedef long (*time_fn)(time_t *);
typedef long (*getcpu_fn)(unsigned *, unsigned *, void *);

static gettimeofday_fn vgettimeofday = (gettimeofday_fn)(VSYSCALL_BASE + VSYSCALL_OFFSET_VGETTIMEOFDAY);
static time_fn vtime = (time_fn)(VSYSCALL_BASE + VSYSCALL_OFFSET_VTIME);
static getcpu_fn vgetcpu = (getcpu_fn)(VSYSCALL_BASE + VSYSCALL_OFFSET_VGETCPU);

int main(int argc, char * argv[])
{
    unsigned cpu = 0, node = 0;
    if (vgetcpu(&cpu, &node, NULL) != 0) {
        printf("vgetcpu failed: %s (%d)\n", strerror(errno), errno);
        return EXIT_FAILURE;
    }
    printf("vgetcpu: cpu %d, node %d\n", cpu, node);

    for (int i = 0; i < 3; i++) {
        struct timeval tv;
        time_t t1, t2;

        vgettimeofday(&tv, NULL);
        printf("vgettimeofday: tv_sec = %lu, tv_usec = %lu\n", tv.tv_sec, tv.tv_usec);

        t1 = vtime(NULL);
        if (t1 == -1) {
            printf("vtime #1 failed: %s (%d)\n", strerror(errno), errno);
            return EXIT_FAILURE;
        }
        printf("vtime with null arg: returned %lu\n", t1);

        t1 = vtime(&t2);
        if (t1 == -1) {
            printf("vtime #2 failed: %s (%d)\n", strerror(errno), errno);
            return EXIT_FAILURE;
        }
        printf("vtime with arg: returned %lu, stored %lu\n", t1, t2);
        if (t1 != t2) {
            printf("failure: return val and stored time mismatch\n");
            return EXIT_FAILURE;
        }

        sleep(1);
    }

    return EXIT_SUCCESS;
}
