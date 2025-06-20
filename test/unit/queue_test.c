#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <runtime.h>

#include "../test_utils.h"

//#define PRINT_STATS
//#define QUEUETEST_DEBUG
#ifdef QUEUETEST_DEBUG
#define queuetest_debug(x, ...) do { printf("%s: " x, __func__, ##__VA_ARGS__); } while(0)
#else
#define queuetest_debug(x, ...)
#endif

#define QUEUE_ORDER             (10)
#define QUEUE_SIZE              (1ull << QUEUE_ORDER)
#define RESULTS_VEC_SIZE        (2 * QUEUE_SIZE)
#define N_THREADS               8
#define INVALID                 (-1ull)
#define THREAD_TEST_DURATION_US (5 << 20)
#define MAX_CONSECUTIVE_OPS     (QUEUE_SIZE / 2)

static u64 total_overflow = 0;
static u64 total_underrun = 0;
static u64 total_queued = 0;
static u64 total_dequeued = 0;
static u64 results[RESULTS_VEC_SIZE];
static heap test_heap;

static volatile boolean drain_and_exit;
static volatile u64 vec_count;

/* we don't have a thread-safe id allocator, settle for brute force search */
static u64 find_free(void)
{
    u64 n, start = random() % RESULTS_VEC_SIZE;
    u64 i = start;
    while ((n = __atomic_exchange_n(&results[i], 1, __ATOMIC_ACQUIRE)) == 1) {
        i = (i + 1) % RESULTS_VEC_SIZE;
        if (i == start)         /* full */
            return INVALID;
    }
    u64 o = fetch_and_add((u64*)&vec_count, -1);
    test_assert(o > 0);
    return i;
}

static void release(u64 n)
{
    u64 o = fetch_and_add((u64*)&vec_count, 1);
    test_assert(o < RESULTS_VEC_SIZE);
    u64 v = __atomic_exchange_n(&results[n], 0, __ATOMIC_RELEASE);
    if (v != 1)
        test_error("dequeued already-freed item");
}

/* take care - a lot of runtime isn't threadsafe */
static void * test_child(void *arg)
{
    queue q = (queue)arg;

    do {
        if (!drain_and_exit) {
            int n_enqueue = random() % MAX_CONSECUTIVE_OPS;
            queuetest_debug("enqueue %d...\n", n_enqueue);
            for (int i = 0; i < n_enqueue; i++) {
                u64 n = find_free();
                /* Allow enqueue failure here - even with an atomic
                   occupancy count, we can't be certain of the full
                   condition without taking a lock on the queue. Likewise,
                   if the enqueue fails, we can't verify full occupancy. */
                if (n == INVALID) {
                    printf("id underrun\n");
                    break;
                }
                if (!enqueue(q, (void *)n)) {
                    fetch_and_add((u64*)&total_overflow, 1);
                    release(n);
                    break;
                }
                fetch_and_add((u64*)&total_queued, 1);
            }
            queuetest_debug("...done\n");
        }

        int n_dequeue = random() % MAX_CONSECUTIVE_OPS;
        queuetest_debug("dequeue %d...\n", n_dequeue);
        for (int i = 0; i < n_dequeue; i++) {
            /* ...same with empty condition */
            u64 n = (u64)dequeue(q);
            if (n == INVALID) {
                if (drain_and_exit) {
                    queuetest_debug("finished\n");
                    return (void *)EXIT_SUCCESS;
                } else {
                    fetch_and_add((u64*)&total_underrun, 1);
                    break;
                }
            }
            test_assert(n < RESULTS_VEC_SIZE);
            release(n);
            fetch_and_add((u64*)&total_dequeued, 1);
        }
        queuetest_debug("...done\n");
    } while(1);
}

static void thread_test(void)
{
    pthread_t threads[N_THREADS];
    queue q = allocate_queue(test_heap, QUEUE_SIZE);

    /* spawn threads */
    vec_count = RESULTS_VEC_SIZE;
    zero(results, RESULTS_VEC_SIZE * sizeof(u64));
    drain_and_exit = false;
    smp_write_barrier();
    queuetest_debug("spawning threads...\n");
    for (int i = 0; i < N_THREADS; i++) {
        if (pthread_create(&threads[i], NULL, test_child, q))
            test_error("pthread_create");
    }

    usleep(THREAD_TEST_DURATION_US);
    drain_and_exit = true;

    queuetest_debug("waiting for threads to exit...\n");
    for (int i = 0; i < N_THREADS; i++) {
        void * retval;
        if (pthread_join(threads[i], &retval))
            test_error("pthread_create");
        if (retval != (void *)EXIT_SUCCESS)
            test_error("child %d failed", i);
    }
    test_assert(vec_count == RESULTS_VEC_SIZE);
    test_assert(total_queued == total_dequeued);
#ifdef PRINT_STATS
    printf("total queued %lld\n", total_queued);
    printf("total dequeued %lld\n", total_dequeued);
    printf("total overflow %lld\n", total_overflow);
    printf("total underrun %lld\n", total_underrun);
#endif
}

static inline boolean test_enqueue(queue q, u64 i, boolean multi) {
    return multi ? enqueue(q, (void *)i) : enqueue_single(q, (void *)i);
}

static inline u64 test_dequeue(queue q, boolean multi) {
    return (u64)(multi ? dequeue(q) : dequeue_single(q));
}

static void n_test(void)
{
    queuetest_debug("");
    queue q = allocate_queue(test_heap, QUEUE_SIZE);
    test_assert(q != INVALID_ADDRESS);
    void **buf = allocate(test_heap, QUEUE_SIZE * sizeof(u64));
    for (int n = QUEUE_SIZE; n > 1; n >>= 1) {
        int items = QUEUE_SIZE / n;
        for (u64 x = 0; x < items; x++) {
            for (int y = 0; y < n; y++)
                buf[y] = (void *)x;
            test_assert(enqueue_n(q, buf, n));
        }
        for (u64 x = 0; x < items; x++) {
            test_assert(dequeue_n(q, buf, n));
            for (int y = 0; y < n; y++) {
                test_assert(buf[y] == (void *)x);
            }
        }
    }
    /* dequeue should fail here */
    test_assert(queue_empty(q));
    test_assert(queue_length(q) == 0);
    deallocate_queue(q);
}

#define BASIC_TEST_RANDOM_PASSES 512
static void basic_test(boolean multi)
{
    queuetest_debug("%s\n", multi ? "multi" : "single");
    zero(results, QUEUE_SIZE * sizeof(u64));
    queue q = allocate_queue(test_heap, QUEUE_SIZE);
    test_assert(q != INVALID_ADDRESS);
    test_assert(queue_empty(q));
    test_assert(queue_length(q) == 0);
    for (u64 i = 0; i < QUEUE_SIZE; i++) {
        test_assert(test_enqueue(q, i, multi));
        results[i] = 1;
    }
    test_assert(queue_full(q));
    test_assert(queue_length(q) == QUEUE_SIZE);

    /* enqueue should fail here */
    test_assert(!test_enqueue(q, 0, multi));

    /* drain and check */
    for (u64 i = 0; i < QUEUE_SIZE; i++) {
        test_assert((u64)queue_peek(q) == i);
        u64 n = test_dequeue(q, multi);
        test_assert(n != INVALID);
        test_assert(n == i);
        test_assert(results[n] == 1);
        results[n] = 0;
    }

    /* dequeue should fail here */
    test_assert(test_dequeue(q, multi) == INVALID);
    test_assert(queue_empty(q));
    test_assert(queue_length(q) == 0);

    /* some number of randomized passes to test ring wrap */
    vec_count = QUEUE_SIZE;
    for (int pass = 0; pass < BASIC_TEST_RANDOM_PASSES; pass++) {
        u64 n_enqueue = random() % vec_count;
        for (u64 i = 0; i < n_enqueue; i++) {
            u64 n = find_free();
            assert(n != INVALID);
            test_assert(test_enqueue(q, n, multi));
        }
        test_assert(queue_length(q) == QUEUE_SIZE - vec_count);
        u64 n_dequeue = pass < (BASIC_TEST_RANDOM_PASSES - 1) ?
            random() % queue_length(q) : queue_length(q);
        for (u64 i = 0; i < n_dequeue; i++) {
            u64 n = test_dequeue(q, multi);
            test_assert(n != INVALID);
            test_assert(results[n] == 1);
            results[n] = 0;
            vec_count++;
        }
    }
    test_assert(vec_count == QUEUE_SIZE);
    test_assert(queue_length(q) == 0);
    test_assert(test_dequeue(q, multi) == INVALID);
    test_assert(queue_peek(q) == INVALID_ADDRESS);
    test_assert(queue_empty(q));
    test_assert(!queue_full(q));
    deallocate_queue(q);
}

int main(int argc, char **argv)
{
    setbuf(stdout, NULL);
    test_heap = init_process_runtime();
    basic_test(false);
    basic_test(true);
    thread_test();
    n_test();
    queuetest_debug("queue test passed\n");
    return EXIT_SUCCESS;
}

