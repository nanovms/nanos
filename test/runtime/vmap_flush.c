/* More than one thread giving pages back at the same time, while others fault
   on them and the file they came from is synced.

   tlbshootdown covers the neighbouring case: one thread unmaps while the others
   read, and each of them takes the fault it should. What it never has is two
   threads returning pages at once, and that is what closes a cycle -- madvise
   takes the process's vmap lock with interrupts disabled and then unmaps, which
   opens a shootdown every processor may have to join synchronously; a second
   thread waiting for that same lock with interrupts disabled never services the
   shootdown, so it never joins, so the first never finishes and never lets the
   lock go.

   Two processors are enough. */

#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sysinfo.h>
#include <unistd.h>

#include "../test_utils.h"

#define MAX_CPUS    16
#define PAGESIZE    4096
#define MAP_PAGES   2048
#define MAP_BYTES   (MAP_PAGES * PAGESIZE)
#define ROUNDS      64

static pthread_t threads[MAX_CPUS];
static volatile uint8_t *m;
static volatile int done;
static int np;

static int kidcnt;
static pthread_cond_t kid_cv;
static pthread_cond_t sync_cv;
static pthread_mutex_t sync_mut;

static void wait_for_sync(void)
{
    pthread_mutex_lock(&sync_mut);
    kidcnt++;
    pthread_cond_signal(&kid_cv);
    pthread_cond_wait(&sync_cv, &sync_mut);
    pthread_mutex_unlock(&sync_mut);
}

static void wait_for_children(void)
{
    pthread_mutex_lock(&sync_mut);
    while (kidcnt < np)
        pthread_cond_wait(&kid_cv, &sync_mut);
    kidcnt = 0;
    pthread_mutex_unlock(&sync_mut);
}

static void wake_children(void)
{
    pthread_mutex_lock(&sync_mut);
    pthread_cond_broadcast(&sync_cv);
    pthread_mutex_unlock(&sync_mut);
}

/* Bring a chunk of the mapping in, then give it back: it takes both, because a
   range that is already gone is unmapped without a shootdown. */
static void *cpu_thread(void *v)
{
    int id = (int)((uintptr_t)v);
    size_t share = MAP_BYTES / np;
    size_t base = share * id;

    while (!done) {
        wait_for_sync();
        if (done)
            break;
        for (size_t off = base; off < base + share; off += PAGESIZE)
            m[off] = (uint8_t)(id + 1);
        test_assert(madvise((void *)(m + base), share, MADV_DONTNEED) == 0);
    }
    return NULL;
}

void test_vmap_flush(int argc, char *argv[])
{
    np = get_nprocs();
    if (np > MAX_CPUS)
        np = MAX_CPUS;
    if (np < 2)
        /* With one processor there is nobody to wait for the lock, and the
           cycle cannot exist. */
        return;

    pthread_cond_init(&kid_cv, NULL);
    pthread_cond_init(&sync_cv, NULL);
    pthread_mutex_init(&sync_mut, NULL);

    int fd = memfd_create("vmap_flush", 0);
    test_assert(fd >= 0);
    test_assert(ftruncate(fd, MAP_BYTES) == 0);
    m = mmap(NULL, MAP_BYTES, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    test_assert(m != MAP_FAILED);

    for (long i = 0; i < np; i++)
        test_assert(pthread_create(&threads[i], NULL, cpu_thread, (void *)i) == 0);

    for (int round = 0; round < ROUNDS; round++) {
        wait_for_children();
        wake_children();
        /* The other way into the shootdown, from this thread, while they are in
           the middle of theirs. */
        test_assert(msync((void *)m, MAP_BYTES, MS_SYNC) == 0);
        test_assert(fsync(fd) == 0);
    }

    wait_for_children();
    done = 1;
    wake_children();
    for (int i = 0; i < np; i++)
        test_assert(pthread_join(threads[i], NULL) == 0);

    test_assert(munmap((void *)m, MAP_BYTES) == 0);
    test_assert(close(fd) == 0);
}
