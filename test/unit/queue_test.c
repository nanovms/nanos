#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <runtime.h>

//#define QUEUETEST_DEBUG
#ifdef QUEUETEST_DEBUG
#define queuetest_debug(x, ...) do { rprintf("%s: " x, __func__, ##__VA_ARGS__); } while(0)
#else
#define queuetest_debug(x, ...)
#endif

#define QUEUETEST_ASSERT(x) do { if (!(x)) {                    \
            rprintf("%s: assertion %s failed\n", __func__, #x); \
            exit(EXIT_FAILURE); } } while(0)

#define QUEUETEST_FAIL(x, ...)                                      \
    do {                                                            \
        rprintf("%s: failed: " x "\n", __func__, ##__VA_ARGS__);    \
        exit(EXIT_FAILURE);                                         \
    } while(0)

#define QUEUE_ORDER     (10) /* 1K */
#define QUEUE_SIZE      (1ull << QUEUE_ORDER)

static u8 results[QUEUE_SIZE];
static heap test_heap;

/* just a brute force search for an unused number */
static u64 find_free(void)
{
    static u64 next = 0;
    for (u64 i = 0; i < QUEUE_SIZE; i++) {
        u64 n = (next + i) % QUEUE_SIZE;
        if (results[n])
            continue;
        results[n] = 1;
        next = (n + 1) % QUEUE_SIZE;
        return n;
    }

    QUEUETEST_FAIL("results vector full\n");
}

static inline boolean test_enqueue(queue q, u64 i, boolean multi) {
    return multi ? enqueue(q, (void *)i) : enqueue_single(q, (void *)i);
}

static inline u64 test_dequeue(queue q, boolean multi) {
    return (u64)(multi ? dequeue(q) : dequeue_single(q));
}

#define INVALID (-1ull)
#define BASIC_TEST_RANDOM_PASSES 512
static void basic_test(boolean multi)
{
    zero(results, QUEUE_SIZE);
    queue q = allocate_queue(test_heap, QUEUE_SIZE);
    QUEUETEST_ASSERT(q != INVALID_ADDRESS);
    QUEUETEST_ASSERT(queue_empty(q));
    QUEUETEST_ASSERT(queue_length(q) == 0);
    for (u64 i = 0; i < QUEUE_SIZE; i++) {
        QUEUETEST_ASSERT(test_enqueue(q, i, multi));
        results[i] = 1;
    }
    QUEUETEST_ASSERT(queue_full(q));
    QUEUETEST_ASSERT(queue_length(q) == QUEUE_SIZE);

    /* enqueue should fail here */
    QUEUETEST_ASSERT(!test_enqueue(q, 0, multi));

    /* drain and check */
    for (u64 i = 0; i < QUEUE_SIZE; i++) {
        QUEUETEST_ASSERT((u64)queue_peek(q) == i);
        u64 n = test_dequeue(q, multi);
        QUEUETEST_ASSERT(n != INVALID);
        QUEUETEST_ASSERT(n == i);
        QUEUETEST_ASSERT(results[n] == 1);
        results[n] = 0;
    }

    /* dequeue should fail here */
    QUEUETEST_ASSERT(test_dequeue(q, multi) == INVALID);
    QUEUETEST_ASSERT(queue_empty(q));
    QUEUETEST_ASSERT(queue_length(q) == 0);

    /* some number of randomized passes to test ring wrap */
    s64 occupancy = 0;
    for (int pass = 0; pass < BASIC_TEST_RANDOM_PASSES; pass++) {
        u64 n_enqueue = random_u64() % (QUEUE_SIZE - occupancy);
        for (u64 i = 0; i < n_enqueue; i++) {
            u64 n = find_free();
            QUEUETEST_ASSERT(test_enqueue(q, n, multi));
            occupancy++;
        }
        QUEUETEST_ASSERT(queue_length(q) == occupancy);
        u64 n_dequeue = pass < (BASIC_TEST_RANDOM_PASSES - 1) ?
            random_u64() % queue_length(q) : queue_length(q);
        for (u64 i = 0; i < n_dequeue; i++) {
            u64 n = test_dequeue(q, multi);
            QUEUETEST_ASSERT(n != INVALID);
            QUEUETEST_ASSERT(results[n] == 1);
            results[n] = 0;
            occupancy--;
        }
    }
    QUEUETEST_ASSERT(occupancy == 0);
    QUEUETEST_ASSERT(queue_length(q) == 0);
    QUEUETEST_ASSERT(test_dequeue(q, multi) == INVALID);
    QUEUETEST_ASSERT(queue_peek(q) == INVALID_ADDRESS);
    QUEUETEST_ASSERT(queue_empty(q));
    QUEUETEST_ASSERT(!queue_full(q));
}

int main(int argc, char **argv)
{
    test_heap = init_process_runtime();
    setbuf(stdout, NULL);
    basic_test(false);
    basic_test(true);
    queuetest_debug("queue test passed\n");
    return EXIT_SUCCESS;
}

