#define _GNU_SOURCE
#include <pthread.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>

#include "../test_utils.h"

pthread_mutex_t mut, mut2;
uint32_t val;

#define INCS 1000
#define BADLUCK 765
#define MAX_THREADS 4

static void
acquire_mutex(pthread_mutex_t *m)
{
    int err = pthread_mutex_lock(m);
    switch (err) {
    case 0:
        break;
    case EOWNERDEAD:
        pthread_mutex_consistent(m);
        break;
    default:
        test_error("got unexpected value from mutex: %d", err);
    }
}

void *
worker(void *v)
{
    int myincs = 0;
    int done = 0;
    unsigned int seed = time(NULL);
    void *self = (void *)pthread_self();
    for (;;) {
        usleep(rand_r(&seed) % 1000);
        acquire_mutex(&mut);
        usleep(rand_r(&seed) % 1000);
        if (val == BADLUCK) {
            val++;
            printf("worker %p aborting after %d increments\n", self, myincs);
            return NULL;
        }
        if (val > INCS)
            done = 1;
        else {
            val++;
            myincs++;
        }
        pthread_mutex_unlock(&mut);
        if (done)
            break;
    }
    printf("worker %p completed %d increments\n", self, myincs);
    return NULL;
}

void *
worker2(void *v)
{
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
    int sleepus = *(int *)v;
    printf("worker2 (%d) start\n", sleepus);
    acquire_mutex(&mut);
    acquire_mutex(&mut2);
    printf("worker2 (%d) acquired locks\n", sleepus);
    usleep(sleepus);
    printf("worker2 (%d) complete\n", sleepus);
    pthread_mutex_unlock(&mut2);
    pthread_mutex_unlock(&mut);
    return NULL;
}

int
main(int argc, char **argv)
{
    pthread_t threads[MAX_THREADS];

    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr); /* initialize the attributes object */
    pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST); /* set robustness */
    pthread_mutex_init(&mut, &attr);
    pthread_mutex_init(&mut2, &attr);

    /* alarm to fail test if things get stuck */
    alarm(10);

    printf("*** test: clean exit with mutex held ***\n");
    for (int i = 0; i < MAX_THREADS; i++) {
        pthread_create(&threads[i], NULL, worker, NULL);
    }
    for (int i = 0; i < MAX_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    for (int i = 0; i < 2; i++) {
        printf("\n*** test %d: aborted exit with mutex held ***\n", i);
        int sleepus = 1000000;
        pthread_create(&threads[0], NULL, worker2, &sleepus);
        usleep(10000);
        sleepus = 10000;
        pthread_create(&threads[1], NULL, worker2, &sleepus);
        usleep(10000);
        printf("canceling thread...\n");
        pthread_cancel(threads[0]);
        pthread_join(threads[0], NULL);
        pthread_join(threads[1], NULL);
    }
    exit(EXIT_SUCCESS);
}
