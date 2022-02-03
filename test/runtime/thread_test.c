#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <math.h>

typedef unsigned long long word;
#define true 1
#define false 0

#define NNUMS 2048
#define NTHREADS 32

static int nthreads = NTHREADS;

static word pipe_exit = (word)-1;

typedef int boolean;
typedef struct pipelock {
    pthread_mutex_t m;
    pthread_cond_t c;
    boolean full;
    word v;
    int readers;
    int readers_serviced;
} *pipelock;

pipelock create_pipelock(int readers)
{
    pipelock p = malloc(sizeof(struct pipelock));
    pthread_mutex_init(&p->m, 0);
    pthread_cond_init(&p->c, 0);
    p->readers = readers;
    p->full = false;
    return p;
}

void pipelock_write(pipelock p, word w)
{
    pthread_mutex_lock(&p->m);
    if (p->full) pthread_cond_wait(&p->c, &p->m);
    p->v = w;
    p->full = true;
    pthread_cond_signal(&p->c);
    p->readers_serviced = 0;
    pthread_mutex_unlock(&p->m);
}

word pipelock_read(pipelock p)
{
    pthread_mutex_lock(&p->m);
    if (!p->full) pthread_cond_wait(&p->c, &p->m);
    word k = p->v;
    p->readers_serviced++;
    if (p->readers_serviced == p->readers) {
        p->full = false;
        pthread_cond_signal(&p->c);
    }
    pthread_mutex_unlock(&p->m);
    return k;
}

typedef struct loopy_activation_record {
    pipelock *p;
    int id;
} *loopy_activation_record;

void *loopy(void *z)
{
    loopy_activation_record a = z;
    while (1) {
        word v = pipelock_read(a->p[0]);
        if (v == pipe_exit) {
            pipelock_write(a->p[1], v);
            pthread_exit(0);
        }
        pipelock_write(a->p[1], v+a->id);
    }
}

void halt(char *message)
{
    fputs(message, stderr);
    exit(-1);
}

word expected_sum(word n, word nt)
{
    word tsum = (nt) * (0 + (nt - 1)) / 2;
    n -= 1;
    return n * (n + 1) * (2 * n + 1) / 6 + tsum * n;
}

boolean check_expected_float_sum(word n, word nt, double expected)
{
    /* if floating registers aren't saved the difference will be huge */
    return fabs(expected - (double)expected_sum(n, nt)) < 1e-1;
}

void *terminus(void *k)
{
    word x = 0, v;
    double y = 0.0;
    pipelock p= k;
    while ((v = pipelock_read(p)) != pipe_exit) {
        x += v;
        y += (double)v;
    }
    if (x == expected_sum(NNUMS, nthreads) && check_expected_float_sum(NNUMS, nthreads, y)) {
        printf("passed\n");
        exit(0);
    }
    printf("%lld %f\n", x, y);
    exit(-1);

}

static void test_affinity(void)
{
    cpu_set_t set;

    if ((sched_setaffinity(0, sizeof(set), NULL) == 0) || (errno != EFAULT))
        halt("sched_setaffinity() missing EFAULT\n");
    if ((sched_getaffinity(0, sizeof(set), NULL) == 0) || (errno != EFAULT))
        halt("sched_getaffinity() missing EFAULT\n");
    if ((sched_getaffinity(0, sizeof(unsigned long) - 1, &set) == 0) || (errno != EINVAL))
        halt("sched_getaffinity() missing EINVAL\n");
    CPU_ZERO(&set);
    CPU_SET(0, &set);
    if (sched_setaffinity(0, sizeof(set), &set) < 0)
        halt("sched_setaffinity() failed\n");
    CPU_ZERO(&set);
    if (sched_getaffinity(0, sizeof(set), &set) < 0)
        halt("sched_getaffinity() failed\n");
    if (!CPU_ISSET(0, &set))
        halt("test_affinity: CPU 0 not set\n");
    for (int i = 1; i < sizeof(set) * 8; i++)
        if (CPU_ISSET(i, &set))
            halt("test_affinity: CPU set\n");
}

// parse threads from command line
// reader and shutdown
int main(int argc, char **argv)
{
    test_affinity();
    if (argc >= 2 && atoi(argv[1]) > 0)
        nthreads = atoi(argv[1]);
    printf("nthreads=%d\n", nthreads);
    int npipes = nthreads+1 ;
    pipelock *locks = malloc(sizeof(pipelock *)*npipes);
    pthread_t *threads = malloc(sizeof(pthread_t)*nthreads);
    pthread_t term;

    for (int i = 0; i < npipes; i++)
        locks[i] = create_pipelock(1);
    pthread_create(&term , 0, terminus, locks[npipes-1]);
    for (int i = 0; i < nthreads; i ++)  {
        loopy_activation_record a = malloc(sizeof (loopy_activation_record));
        a->p = locks+i;
        a->id = i;
        int r = pthread_create(threads + i , 0, loopy, a);
        if (r != 0)  {
            halt("pthread create error");
        }
    }

    for (int i = 1; i < NNUMS; i ++)
        pipelock_write(locks[0], i*i);

    pipelock_write(locks[0], pipe_exit);
    pause();
}
