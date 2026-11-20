#include <unistd.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <runtime.h>
#include <linux/futex.h>
#include <limits.h>
#include <time.h>
#include <errno.h>

#include "../test_utils.h"

#define FUTEX_INITIALIZER 11
#define WAKE_OP_VAL3(op, oparg, cmp, cmparg) \
                        (((op & 0xf) << 28) | \
                        ((cmp & 0xf) << 24) | \
                        ((oparg & 0xfff) << 12) | \
                        (cmparg & 0xfff))

/* Test Global Variables */
int wake_test_futex = FUTEX_INITIALIZER;
int empty_futex = FUTEX_INITIALIZER;
int wait_test_futex = FUTEX_INITIALIZER;
int wait_bitset_test_futex = FUTEX_INITIALIZER;
int cmp_requeue_test_futex_1 = FUTEX_INITIALIZER;
int cmp_requeue_test_futex_2 = FUTEX_INITIALIZER;
/* requeue_testN_*: the words used by FUTEX_REQUEUE test N */
int requeue_test1_futex_1 = FUTEX_INITIALIZER;
int requeue_test1_futex_2 = FUTEX_INITIALIZER;
int requeue_test2_futex_1 = FUTEX_INITIALIZER;
int requeue_test2_futex_2 = FUTEX_INITIALIZER;
int requeue_test3_futex = FUTEX_INITIALIZER;
int requeue_test4_futex = FUTEX_INITIALIZER;
int requeue_stress_futex_1 = 0;
int requeue_stress_futex_2 = 0;
volatile int requeue_stress_started;
int wake_op_test_futex_1 = FUTEX_INITIALIZER;
int wake_op_test_futex_2 = FUTEX_INITIALIZER;

/* Helper Thread Function Declarations */
static void *futex_wake_test_thread(void *arg);
static void *futex_cmp_requeue_test_thread(void *arg);
static void *futex_requeue_test_thread(void *arg);
static void *futex_requeue_stress_thread(void *arg);
static void *futex_wake_op_test_thread(void *arg);

/* FUTEX_WAKE test: Creates num_to_wake threads which wait
on uaddr and then wakes up all the threads */
static boolean futex_wake_test(int *uaddr, int num_to_wake, int expected_result) 
{
    pthread_t threads[num_to_wake];

    for (int index = 0; index < num_to_wake; index++) {
        if (pthread_create(&(threads[index]), NULL, futex_wake_test_thread, (void*)(uaddr))) {
            printf("Unable to create thread.\n");
            return false;
        }
    }
    
    sleep(1); /* for main thread */
    int ret = syscall(SYS_futex, uaddr, FUTEX_WAKE, num_to_wake, 0, NULL, 0);

    /* pthread_join all the threads to check
    that they've been woken up */
    for(int i = 0; i < num_to_wake; i++) {
        if(pthread_join(threads[i], NULL) != 0) {
            printf("Unable to join thread.\n");
            return false;
        }
    }
    if (ret == expected_result)
        return true; /* success */
    return false; /* error */
}

/* Thread function called from futex_wake_test
which sets wake_test_futex's value to 1 and blocks */
static void *futex_wake_test_thread(void *arg) 
{
    int new_val = 1;
    wake_test_futex = new_val;
    syscall(SYS_futex, (int*)(arg), FUTEX_WAIT, new_val, 0, NULL, 0);
    return NULL;
}

/* FUTEX_WAIT test 1: Check for error -1 because
value at uaddr doesn't match val */
static boolean futex_wait_test_1() 
{
    int *uaddr = (int*)(&wait_test_futex);
    int val = 20;
    int expected_result = -1; /* error */
    int ret = syscall(SYS_futex, uaddr, FUTEX_WAIT, val, 0, NULL, 0);
    if (ret == expected_result) {
        printf("wait test 1: passed\n");
        return true;
    }
    printf("wait test 1: failed\n");
    return false;
}

/* FUTEX_WAIT test 2: Success case where value at
uaddr matches val. Check that the call waits for
the given amount of time and then times out */
static boolean futex_wait_test_2() 
{
    int *uaddr = (int*)(&wait_test_futex);
    int val = FUTEX_INITIALIZER; /* value at uaddr */
    int expected_result = -1;

    /* timeout of 0.3 sec */
    struct timespec timeout = {.tv_sec = 0, .tv_nsec = 300000000};
    int ret = syscall(SYS_futex, uaddr, FUTEX_WAIT, val, &timeout, NULL, 0);
    
    /* Check timeout by checking value of errno */
    if ((errno == ETIMEDOUT) && (ret == expected_result)) {
        printf("wait test 2: passed\n");
        return true;
    }
    printf("wait test 2: failed\n");
    return false;
}

/* FUTEX_WAIT_BITSET test 1: Check for error -1
because the value at uaddr and val do not match */
static boolean futex_wait_bitset_test_1() 
{
    int *uaddr = (int*)(&wait_bitset_test_futex);
    int val = 20;
    int bitset = 0xffffffff;
    int expected_result = -1; 

    int ret = syscall(SYS_futex, uaddr, FUTEX_WAIT_BITSET, val, 0, NULL, bitset);
    if (ret == expected_result) {
        printf("wait_bitset test 1: passed\n");
        return true;
    }
    printf("wait_bitset test 1: failed\n");
    return false;
}

/* FUTEX_WAIT_BITSET test 2: Success case where
the value at uaddr and val do match. Check that the 
call waits for the given amount of time 
and then times out */
static boolean futex_wait_bitset_test_2() 
{
    int *uaddr = (int*)(&wait_bitset_test_futex);
    int val = FUTEX_INITIALIZER; /* value at uaddr */
    int bitset = 0xffffffff;
    int expected_result = -1; 

    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);

    /* Ensure that timeout.tv_nsec is in the range 0 to 999999999
    and transfer the remainder to tv_sec field */
    struct timespec timeout = {.tv_sec = start.tv_sec, .tv_nsec = 0};
    long timeout_nsec = 300000000; /* timeout of 0.3 seconds */
    long total_nsec = start.tv_nsec + timeout_nsec; 
    long max_nsec = 1000000000;
    if (total_nsec >= max_nsec) {
        timeout.tv_nsec += (total_nsec % max_nsec);
        timeout.tv_sec += (total_nsec/max_nsec);
    }
    else
        timeout.tv_nsec = total_nsec;

    int ret = syscall(SYS_futex, uaddr, FUTEX_WAIT_BITSET, val, &timeout, NULL, bitset);

    /* Check timeout by checking value of errno */
    if ((errno == ETIMEDOUT) && (ret == expected_result)) {
        printf("wait_bitset test 2: passed\n");
        return true;
    }
    printf("wait_bitset test 2: failed\n");
    return false;
}

/* FUTEX_CMP_REQUEUE test 1: Check for error -1 because
the value at uaddr does not match val3 */
static boolean futex_cmp_requeue_test_1() 
{
    int *uaddr = (int*)(&empty_futex);
    int *uaddr2 = (int*)(&empty_futex);
    int val = 1; /* number of waiters to wake up that are waiting on uaddr */
    u64 val2 = 1; /* number of waiters to move from uaddr queue to uaddr2 queue */
    int val3 = 20; /* compared against value at uaddr */
    int expected_result = -1; 

    int ret = syscall(SYS_futex, uaddr, FUTEX_CMP_REQUEUE, val, val2, uaddr2, val3);
    if (ret == expected_result) {
        printf("cmp_requeue test 1: passed\n");
        return true;
    }
    printf("cmp_requeue test 1: failed\n");
    return false;
}

/* FUTEX_CMP_REQUEUE test 2: Success case where val threads that are
waiting on uaddr are woken up and the rest waiting on uaddr are moved
to uaddr2's queue. The test wakes up the threads which are moved to uaddr2's
queue as well, to check that the correct number of threads were requeued. */
static boolean futex_cmp_requeue_test_2() 
{
    int *uaddr = (int*)(&cmp_requeue_test_futex_1);
    int *uaddr2 = (int*)(&cmp_requeue_test_futex_2);
    int val = 3; /* number of waiters to wake up that are waiting on uaddr */

    /* After waking up val waiters waiting on uaddr, 
    move the rest to uaddr2's queue */
    u64 val2 = INT_MAX; 
    int val3 = 5; /* value at uaddr in the thread function */

    /* Create num_threads threads which wait on uaddr */
    int num_threads = 50;
    pthread_t threads[num_threads];
    for (int index = 0; index < num_threads; index++) {
        if (pthread_create(&(threads[index]), NULL, futex_cmp_requeue_test_thread, (void*)(uaddr))) {
            printf("Unable to create thread. cmp_requeue test 2 failed.\n");
            return false;
        }
    }
    
    sleep(1); /* for main thread */

    /* Wake up val threads that are waiting on uaddr and requeue the
    remaining threads to wait on uaddr2 */
    int changed = syscall(SYS_futex, uaddr, FUTEX_CMP_REQUEUE, val, val2, uaddr2, val3);
    if (changed != num_threads) {
        printf("Incorrect number of woken up or requeued threads. cmp_requeue test 2: failed.\n");
        return false;
    }

    /* Wake up remaining threads waiting on uaddr2 
    that haven't been woken up by FUTEX_CMP_REQUEUE */
    int remaining = syscall(SYS_futex, uaddr2, FUTEX_WAKE, INT_MAX, 0, NULL, 0);
    if (remaining != num_threads-val) {
        /* Correct number of threads not requeued */
        printf("Incorrect number of requeued threads. cmp_requeue test 2: failed.\n");
        return false;
    }

    /* pthread_join all the threads to check
    that they've been woken up */
    for (int i = 0; i < num_threads; i++) {
        if(pthread_join(threads[i], NULL) != 0) {
            printf("Unable to join thread. cmp_requeue test 2: failed.\n");
            return false;
        }
    }
    printf("cmp_requeue test 2: passed\n");
    return true;
}

/* Thread function called from futex_cmp_requeue_test_2
which changes the value of cmp_requeue_test_futex_1 and blocks on it */
static void *futex_cmp_requeue_test_thread(void *arg) 
{
    int new_val = 5;
    cmp_requeue_test_futex_1 = new_val;
    syscall(SYS_futex, (int*)(arg), FUTEX_WAIT, new_val, 0, NULL, 0);
    return NULL;
}

/* Thread function called from the FUTEX_REQUEUE tests: blocks on the futex
passed as argument, whose value is FUTEX_INITIALIZER */
static void *futex_requeue_test_thread(void *arg)
{
    syscall(SYS_futex, (int*)(arg), FUTEX_WAIT, FUTEX_INITIALIZER, 0, NULL, 0);
    return NULL;
}

static boolean futex_requeue_join(pthread_t *threads, int num_threads)
{
    for (int i = 0; i < num_threads; i++) {
        if (pthread_join(threads[i], NULL) != 0) {
            printf("Unable to join thread. requeue test: failed.\n");
            return false;
        }
    }
    return true;
}

static boolean futex_requeue_create(pthread_t *threads, int num_threads, int *uaddr)
{
    for (int index = 0; index < num_threads; index++) {
        if (pthread_create(&(threads[index]), NULL, futex_requeue_test_thread, (void*)(uaddr))) {
            printf("Unable to create thread. requeue test: failed.\n");
            return false;
        }
    }
    sleep(1); /* for the threads to block */
    return true;
}

/* FUTEX_REQUEUE test 1: val threads waiting on uaddr are woken up and the
rest are moved to uaddr2's queue, without any comparison of the value at uaddr.
Waking uaddr2 then releases the requeued threads. */
static boolean futex_requeue_test_1()
{
    int *uaddr = (int*)(&requeue_test1_futex_1);
    int *uaddr2 = (int*)(&requeue_test1_futex_2);
    int val = 3;
    u64 val2 = INT_MAX;
    int num_threads = 10;
    pthread_t threads[num_threads];

    if (!futex_requeue_create(threads, num_threads, uaddr))
        return false;

    int changed = syscall(SYS_futex, uaddr, FUTEX_REQUEUE, val, val2, uaddr2, 0);
    if (changed != num_threads) {
        printf("Incorrect number of woken up or requeued threads (%d). requeue test 1: failed.\n", changed);
        return false;
    }

    int remaining = syscall(SYS_futex, uaddr2, FUTEX_WAKE, INT_MAX, 0, NULL, 0);
    if (remaining != num_threads - val) {
        printf("Incorrect number of requeued threads (%d). requeue test 1: failed.\n", remaining);
        return false;
    }
    if (!futex_requeue_join(threads, num_threads))
        return false;
    printf("requeue test 1: passed\n");
    return true;
}

/* FUTEX_REQUEUE test 2: only val2 of the threads that are left are moved,
the others stay on uaddr */
static boolean futex_requeue_test_2()
{
    int *uaddr = (int*)(&requeue_test2_futex_1);
    int *uaddr2 = (int*)(&requeue_test2_futex_2);
    int num_threads = 6;
    pthread_t threads[num_threads];

    if (!futex_requeue_create(threads, num_threads, uaddr))
        return false;

    int changed = syscall(SYS_futex, uaddr, FUTEX_REQUEUE, 1, 2, uaddr2, 0);
    if (changed != 3) {
        printf("Incorrect number of woken up or requeued threads (%d). requeue test 2: failed.\n", changed);
        return false;
    }
    int moved = syscall(SYS_futex, uaddr2, FUTEX_WAKE, INT_MAX, 0, NULL, 0);
    if (moved != 2) {
        printf("Incorrect number of requeued threads (%d). requeue test 2: failed.\n", moved);
        return false;
    }
    int stayed = syscall(SYS_futex, uaddr, FUTEX_WAKE, INT_MAX, 0, NULL, 0);
    if (stayed != 3) {
        printf("Incorrect number of threads left on uaddr (%d). requeue test 2: failed.\n", stayed);
        return false;
    }
    if (!futex_requeue_join(threads, num_threads))
        return false;
    printf("requeue test 2: passed\n");
    return true;
}

/* FUTEX_REQUEUE test 3: uaddr and uaddr2 are the same address. The call must
return, with and without waiters. The woken thread is counted, and so is the
waiter that stays on the queue. */
static boolean futex_requeue_test_3()
{
    int *uaddr = (int*)(&requeue_test3_futex);
    int num_threads = 2;
    pthread_t threads[num_threads];

    int changed = syscall(SYS_futex, uaddr, FUTEX_REQUEUE, 1, 1, uaddr, 0);
    if (changed != 0) {
        printf("Incorrect result without waiters (%d). requeue test 3: failed.\n", changed);
        return false;
    }
    if (!futex_requeue_create(threads, num_threads, uaddr))
        return false;
    changed = syscall(SYS_futex, uaddr, FUTEX_REQUEUE, 1, 1, uaddr, 0);
    if (changed != 2) {
        printf("Incorrect number of woken up or requeued threads (%d). requeue test 3: failed.\n", changed);
        return false;
    }
    int remaining = syscall(SYS_futex, uaddr, FUTEX_WAKE, INT_MAX, 0, NULL, 0);
    if (remaining != 1) {
        printf("Incorrect number of threads left on uaddr (%d). requeue test 3: failed.\n", remaining);
        return false;
    }
    if (!futex_requeue_join(threads, num_threads))
        return false;
    printf("requeue test 3: passed\n");
    return true;
}

/* FUTEX_REQUEUE test 4: negative counts are rejected */
static boolean futex_requeue_test_4()
{
    int *uaddr = (int*)(&empty_futex);
    int *uaddr2 = (int*)(&requeue_test4_futex);

    int ret = syscall(SYS_futex, uaddr, FUTEX_REQUEUE, -1, 0, uaddr2, 0);
    if ((ret != -1) || (errno != EINVAL)) {
        printf("Negative val not rejected (%d %d). requeue test 4: failed.\n", ret, errno);
        return false;
    }
    ret = syscall(SYS_futex, uaddr, FUTEX_REQUEUE, 0, (u64)0xffffffff, uaddr2, 0);
    if ((ret != -1) || (errno != EINVAL)) {
        printf("Negative val2 not rejected (%d %d). requeue test 4: failed.\n", ret, errno);
        return false;
    }
    printf("requeue test 4: passed\n");
    return true;
}

/* Thread function called from futex_requeue_test_5: waits on the futex while
its value is still 0 */
static void *futex_requeue_stress_thread(void *arg)
{
    requeue_stress_started = 1;
    syscall(SYS_futex, (int*)(arg), FUTEX_WAIT, 0, 0, NULL, 0);
    return NULL;
}

/* FUTEX_REQUEUE test 5: a thread that starts waiting while the value is
changed and the waiters are requeued without waking anybody (the way musl
does) must not be left asleep, wherever it is in FUTEX_WAIT. The race window
is narrow, so this test does not fail reliably on a kernel that loses the
waiter. The race needs more than one vcpu (the runtime test runs with several
vcpus only in some configurations): on one vcpu this only exercises the EAGAIN
and requeued paths. It is a smoke test, not a proof. */
static boolean futex_requeue_test_5()
{
    int *uaddr = (int*)(&requeue_stress_futex_1);
    int *uaddr2 = (int*)(&requeue_stress_futex_2);

    for (int i = 0; i < 100; i++) {
        pthread_t thread;
        *uaddr = 0;
        requeue_stress_started = 0;
        if (pthread_create(&thread, NULL, futex_requeue_stress_thread, (void*)uaddr)) {
            printf("Unable to create thread. requeue test 5: failed.\n");
            return false;
        }
        while (!requeue_stress_started)
            ;
        __atomic_store_n(uaddr, 1, __ATOMIC_SEQ_CST);
        if (syscall(SYS_futex, uaddr, FUTEX_REQUEUE, 0, 1, uaddr2, 0) < 0) {
            printf("Requeue failed. requeue test 5: failed.\n");
            return false;
        }
        /* the waiter either is on uaddr2 now, or has been woken up, or has
        not blocked because the value changed */
        syscall(SYS_futex, uaddr2, FUTEX_WAKE, 1, 0, NULL, 0);
        if (pthread_join(thread, NULL) != 0) {
            printf("Unable to join thread. requeue test 5: failed.\n");
            return false;
        }
    }
    printf("requeue test 5: passed\n");
    return true;
}

/* FUTEX_WAKE_OP test: Creates group of threads to wait on uaddr
and another group to wait on uaddr2. Performs FUTEX_WAKE_OP with
uaddr and uaddr2 and checks that correct number of threads are woken up.
If wake_uaddr2 == false, then the threads waiting on 
uaddr2 will not be woken up. */
static boolean futex_wake_op_test(boolean wake_uaddr2) 
{
    int *uaddr = (int*)(&wake_op_test_futex_1);
    int *uaddr2 = (int*)(&wake_op_test_futex_2);
    int num_uaddr_threads = 50; 
    int num_uaddr2_threads = 25;

    /* Create num_uaddr_threads threads to wait on uaddr */
    pthread_t uaddr_threads[num_uaddr_threads];
    for (int index = 0; index < num_uaddr_threads; index++) {
        if (pthread_create(&(uaddr_threads[index]), NULL, futex_wake_op_test_thread, (void*)(uaddr))) {
            printf("Unable to create thread.\n");
            return false;
        }
    }

    /* Create num_uaddr2_threads threads to wait on uaddr2 */
    pthread_t uaddr2_threads[num_uaddr2_threads];
    for (int index = 0; index < num_uaddr2_threads; index++) {
        if (pthread_create(&(uaddr2_threads[index]), NULL, futex_wake_op_test_thread, (void*)(uaddr2))) {
            printf("Unable to create thread.\n");
            return false;
        }
    }

    /* FUTEX_WAKE_OP syscall arguments */
    int oparg = wake_op_test_futex_2+1; /* uaddr2 value + 1 */
    int cmparg = wake_op_test_futex_2; /* uaddr2 value */
    int expected_result = num_uaddr_threads+num_uaddr2_threads; /* wake up all threads */
    if (!wake_uaddr2) {
        /* Change cmparg to not be the same as the uaddr2 value
        so now only threads waiting on uaddr should wake up */
        cmparg = wake_op_test_futex_2+1;
        expected_result = num_uaddr_threads; 
    }
    /* assignment (=) as operation and equals (==) as comparator */
    int val3 = WAKE_OP_VAL3(FUTEX_OP_SET, oparg, FUTEX_OP_CMP_EQ, cmparg);

    sleep(1);

    int val = INT_MAX; /* max number of threads waiting on uaddr to wake up */
    int val2 = INT_MAX; /* max number of threads waiting on uaddr2 to wake up */
    int ret = syscall(SYS_futex, uaddr, FUTEX_WAKE_OP, val, val2, uaddr2, val3);
    
    /* pthread_join all the threads to check
    that they've been woken up */
    for (int i = 0; i < num_uaddr_threads; i++) {
        if(pthread_join(uaddr_threads[i], NULL) != 0) {
            printf("Unable to join thread.\n");
            return false;
        }
    }
    if (wake_uaddr2) {
        for (int i = 0; i < num_uaddr2_threads; i++) {
            if(pthread_join(uaddr2_threads[i], NULL) != 0) {
                printf("Unable to join thread.\n");
                return false;
            }
        }
    }

    if (ret == expected_result)
        return true;
    return false;
}

/* Thread function called by futex_wake_op_test which
changes the value of the passed in futex and blocks on it */
static void *futex_wake_op_test_thread(void *arg) 
{
    int new_val = 5;
    *((int*)arg) = new_val;
    syscall(SYS_futex, (int*)(arg), FUTEX_WAIT, new_val, 0, NULL, 0);
    return NULL;
} 

static boolean futex_fault_test(void)
{
    const void *fault_addr = FAULT_ADDR;
    int ret;

    ret = syscall(SYS_futex, fault_addr, FUTEX_WAIT, 0, 0, NULL, 0);
    if ((ret != -1) || (errno != EFAULT)) {
        printf("FUTEX_WAIT fault test error (%d %d)\n", ret, errno);
        return false;
    }
    ret = syscall(SYS_futex, fault_addr, FUTEX_CMP_REQUEUE, 0, 0, NULL, 0);
    if ((ret != -1) || (errno != EFAULT)) {
        printf("FUTEX_CMP_REQUEUE fault test error (%d %d)\n", ret, errno);
        return false;
    }
    ret = syscall(SYS_futex, fault_addr, FUTEX_WAKE_OP, 0, 0, NULL, 0);
    if ((ret != -1) || (errno != EFAULT)) {
        printf("FUTEX_WAKE_OP fault test error (%d %d)\n", ret, errno);
        return false;
    }
    ret = syscall(SYS_futex, fault_addr, FUTEX_WAIT_BITSET, 0, 0, NULL, 0xffffffff);
    if ((ret != -1) || (errno != EFAULT)) {
        printf("FUTEX_WAIT_BITSET fault test error (%d %d)\n", ret, errno);
        return false;
    }
    ret = syscall(SYS_futex, &wait_test_futex, FUTEX_WAIT, FUTEX_INITIALIZER, fault_addr, NULL, 0);
    test_assert((ret == -1) && (errno == EFAULT));
    return true;
}

/* Method to run all tests */
boolean basic_test() 
{
    int num_failed = 0;

    printf("---FUTEX_WAKE TESTS--- \n");
    /* Wake test 1: empty_futex is not being
    waited on by the threads made in the 
    futex_wake_test() so no threads 
    should be woken up */
    int *uaddr = (int*)(&empty_futex);
    int num_to_wake = 50;
    int expected_result = 0;
    if (!futex_wake_test(uaddr, num_to_wake, expected_result)) {
        num_failed++;
        printf("wake test 1: failed\n");
    }
    else
        printf("wake test 1: passed\n");

    /* Wake test 2: wake_test_futex is being waited on
    by all the threads made in futex_wake_test() so
    all 50 threads should be woken up */
    uaddr = (int*)(&wake_test_futex);
    num_to_wake = 50;
    expected_result = 50;
    if (!futex_wake_test(uaddr, num_to_wake, expected_result)) {
        num_failed++;
        printf("wake test 2: failed\n");
    }
    else
        printf("wake test 2: passed\n");

    /* Wait tests */
    printf("---FUTEX_WAIT TESTS--- \n");
    if (!futex_wait_test_1())
        num_failed++;
    if (!futex_wait_test_2()) 
        num_failed++;

    /* Wait_Bitset Tests */
    printf("---FUTEX_WAIT_BITSET TESTS--- \n");
    if (!futex_wait_bitset_test_1()) 
        num_failed++; 
    if (!futex_wait_bitset_test_2())
        num_failed++;

    /* Cmp_Requeue Tests */
    printf("---FUTEX_CMP_REQUEUE TESTS--- \n");
    if (!futex_cmp_requeue_test_1())
        num_failed++;
    if (!futex_cmp_requeue_test_2())
        num_failed++;

    /* Requeue Tests */
    printf("---FUTEX_REQUEUE TESTS--- \n");
    if (!futex_requeue_test_1())
        num_failed++;
    if (!futex_requeue_test_2())
        num_failed++;
    if (!futex_requeue_test_3())
        num_failed++;
    if (!futex_requeue_test_4())
        num_failed++;
    if (!futex_requeue_test_5())
        num_failed++;

    /* Wake_Op Tests: pass in true to wake up threads 
    waiting on uaddr2 or false otherwise */
    printf("---FUTEX_WAKE_OP TESTS--- \n");
    if (!futex_wake_op_test(true)) {
        num_failed++;
        printf("wake_op test 1: failed\n");
    }
    else
        printf("wake_op test 1: passed\n");
    if (!futex_wake_op_test(false)) {
        num_failed++;
        printf("wake_op test 2: failed\n");
    }
    else
        printf("wake_op test 2: passed\n");
    
    if (!futex_fault_test())
        num_failed++;

    if (num_failed > 0)
        return false;
    return true;
}

int main (int argc, char **argv) 
{
    if (basic_test()) {
        printf("---All futex tests passed---\n");
        exit(EXIT_SUCCESS);
    }
    else
        exit(EXIT_FAILURE);
}
