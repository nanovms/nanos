#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

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

word expected_sum(word n, word nt) {
    word tsum = (nt) * (0 + (nt - 1)) / 2;
    n -= 1;
    return n * (n + 1) * (2 * n + 1) / 6 + tsum * n;
}

void *terminus(void *k)
{
    word x = 0, v;
    pipelock p= k;
    while ((v = pipelock_read(p)) != pipe_exit) {
        x += v;
    }
    if (x == expected_sum(NNUMS, nthreads)) {
        printf("passed\n");
        exit(0);
    }
    printf("%lld\n", x);
    exit(-1);

}

// parse threads from command line
// reader and shutdown
int main(int argc, char **argv)
{
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
