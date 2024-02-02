#define _GNU_SOURCE
#include <string.h>
#include <sys/sysinfo.h>
#include <sched.h>
#include <pthread.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>
#include <signal.h>
#include <setjmp.h>

#include "../test_utils.h"

#define MAX_CPUS 16
#define PAGESIZE 4096
#define NBYTES 256

pthread_t threads[MAX_CPUS];
sigjmp_buf jbs[MAX_CPUS];
volatile uint8_t *m;
volatile int stage;
int np;

int kidcnt;
pthread_cond_t kid_cv;
pthread_cond_t sync_cv;
pthread_mutex_t sync_mut;

void
wait_for_sync(void)
{
    pthread_mutex_lock(&sync_mut);
    kidcnt++;
    pthread_cond_signal(&kid_cv);
    pthread_cond_wait(&sync_cv, &sync_mut);
    pthread_mutex_unlock(&sync_mut);
}

void *cpu_thread(void *v)
{
    int i, id;

    id = (int)((uintptr_t)v);
    wait_for_sync();

    if (sigsetjmp(jbs[id], 1)) {
        if (stage == 0) {
            test_error("thread %d failed expected memory access", id);
        }
        return NULL;
    }
    /* this one is expected to succeed */
    for (i = PAGESIZE * id; i < PAGESIZE * id + NBYTES; i++)
        m[i] += id;
    wait_for_sync();
    /* this one is expected to fail and generated SIGSEGV */
    for (i = PAGESIZE * id; i < PAGESIZE * id + NBYTES; i++)
        m[i] += id;
    test_error("thread %d on cpu %d accessed unmapped memory without segfault", id, sched_getcpu());

    return NULL;
}

void handle_sigbuf(int sig, siginfo_t *si, void *uctxt)
{
    // printf("** received %s: sig %d, si_errno %d, si_code %d, addr 0x%lx\n",
    //     strsignal(sig), sig, si->si_errno, si->si_code, (unsigned long)si->si_addr);
    pthread_t self = pthread_self();
    int id = -1;
    for (int i = 0; i < MAX_CPUS; i++) {
        if (self == threads[i]) {
            id = i;
            break;
        }
    }
    if (id < 0) {
        test_error("unable to get thread id in sighandler");
    }
    siglongjmp(jbs[id], si->si_code);
}

void
wait_for_children(void)
{
    pthread_mutex_lock(&sync_mut);
    while (kidcnt != np) {
        pthread_cond_wait(&kid_cv, &sync_mut);
    }
    kidcnt = 0;
    pthread_mutex_unlock(&sync_mut);
}

void
wake_children(void)
{
    pthread_cond_broadcast(&sync_cv);
}

int main(int argc, char **argv)
{
    int loops;
    struct sigaction sa;

    pthread_cond_init(&kid_cv, NULL);
    pthread_cond_init(&sync_cv, NULL);
    pthread_mutex_init(&sync_mut, NULL);

    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = handle_sigbuf;
    sa.sa_flags |= SA_SIGINFO;
    if (sigaction(SIGSEGV, &sa, 0) < 0) {
        test_perror("failed to set signal handler");
    }

    np = get_nprocs();
    printf("There are %d processors available\n", np);

    for (loops = 0; loops < 1000; loops++) {
        stage = 0;
        m = mmap(NULL, PAGESIZE * np, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, 0, 0);
        if (m == (void *)-1) {
            test_perror("mmap");
        }
        memset((void *)m, 0, PAGESIZE * np);
        for (long i = 0; i < np; i++) {
            pthread_create(&threads[i], NULL, cpu_thread, (void *)i);
        }
        wait_for_children();
        wake_children();    /* trigger children to check for good memory access */

        wait_for_children();
        stage = 1;
        munmap((void *)m, PAGESIZE * np);
        wake_children();    /* trigger children to check for page fault */

        for (int i = 0; i < np; i++)
            pthread_join(threads[i], NULL);
    }
    printf("%s passed\n", argv[0]);
    exit(EXIT_SUCCESS);
}
