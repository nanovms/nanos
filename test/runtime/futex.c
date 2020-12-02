#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include <pthread.h>
#include <runtime.h>
#include <linux/futex.h>
#include <limits.h>

#define EXIT_FAILURE 1
#define EXIT_SUCCESS 0
#define FUTEX_INITIALIZER 0

/* Test Global Variables */
int wake_test_futex = FUTEX_INITIALIZER;
int empty_futex = FUTEX_INITIALIZER;
int wait_test_futex = FUTEX_INITIALIZER;
int wait_bitset_test_futex = FUTEX_INITIALIZER;
int cmp_requeue_test_futex_1 = FUTEX_INITIALIZER;
int cmp_requeue_test_futex_2 = FUTEX_INITIALIZER;

/* Helper Function Declarations */
static void *futex_wake_test_thread(void *arg);
static void *futex_cmp_requeue_test_thread(void *arg);

/* FUTEX_WAKE test, creates num_to_wake threads which wait
on uaddr and then wakes up all the threads */
static boolean futex_wake_test(int *uaddr, int num_to_wake, int expected_result) 
{
    pthread_t threads[num_to_wake];

    for (int index = 0; index < num_to_wake; index++) {
        if (pthread_create(&(threads[index]), NULL, futex_wake_test_thread, (void*)(uaddr))) {
            printf("Unable to create thread\n");
            return false;
        }
    }
    
    sleep(1); /* for main thread */
    int ret = syscall(SYS_futex, uaddr, FUTEX_WAKE, num_to_wake, 0, NULL, 0);

    /* pthread_join all the threads to check
    that they've been woken up */
    for(int i = 0; i < num_to_wake; i++) {
        if(pthread_join(threads[i], NULL) != 0)
            return false;
    }
    if (ret == expected_result)
        return true; /* success */
    else
        return false; /* error */
}

/* Thread function called from futex_wake_test
which sets wake_test_futex's value to 1 and blocks */
static void *futex_wake_test_thread(void *arg) 
{
    int val = 1;
    wake_test_futex = val;
    syscall(SYS_futex, (int*)(arg), FUTEX_WAIT, val, 0, NULL, 0);
    return NULL;
}

/* FUTEX_WAIT test: waits on uaddr with value of val
and compares the result, used to check error case where ret=-1 */
static boolean futex_wait_test(int *uaddr, int val, int expected_result) 
{
    int ret = syscall(SYS_futex, uaddr, FUTEX_WAIT, val, 0, NULL, 0);
    if (ret == expected_result)
        return true;
    return false;
}

/* FUTEX_WAIT_BITSET test: waits on uaddr with value of val
and compares the result, provides bitset as a mask to kernel */
static boolean futex_wait_bitset_test(int *uaddr, int val, int bitset, int expected_result) 
{
    int ret = syscall(SYS_futex, uaddr, FUTEX_WAIT_BITSET, val, 0, NULL, bitset);
    if (ret == expected_result)
        return true;
    return false;
}

static boolean futex_cmp_requeue_test_1(int *uaddr, int val, u64 val2, 
    int *uaddr2, int val3, int expected_result) 
{
    int ret = syscall(SYS_futex, uaddr, FUTEX_CMP_REQUEUE, val, val2, uaddr2, val3);
    if (ret == expected_result)
        return true;
    return false;
}

// val = 1, uaddr = cmp_requeue_futex_1, val3 = *cmp_requeue_futex_1,
// uaddr2 = cmp_requeue_futex_2, val2 = INT_MAX
static boolean futex_cmp_requeue_test_2(int *uaddr, int val, u64 val2, 
    int *uaddr2, int val3, int num_threads, int expected_result) 
{
    pthread_t threads[num_threads];

    for (int index = 0; index < num_threads; index++) {
        if (pthread_create(&(threads[index]), NULL, futex_cmp_requeue_test_thread, (void*)(uaddr))) {
            printf("Unable to create thread\n");
            return false;
        }
    }
    
    sleep(1); /* for main thread */
    int ret = syscall(SYS_futex, uaddr, FUTEX_CMP_REQUEUE, val, val2, uaddr2, val3);

    if (ret == expected_result)
        return true; /* success */
    else {
        printf("ret: %d\n", ret);
        return false; /* error */
    }
}

/* Thread function called from futex_wake_test
which sets wake_test_futex's value to 1 and blocks */
static void *futex_cmp_requeue_test_thread(void *arg) 
{
    int val = 1;
    cmp_requeue_test_futex_1 = val;
    syscall(SYS_futex, (int*)(arg), FUTEX_WAIT, val, 0, NULL, 0);
    return NULL;
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
        printf("Wake test 1: failed\n");
    }
    else
        printf("Wake test 1: passed\n");

    /* Wake test 2: wake_test_futex is being waited on
    by all the threads made in futex_wake_test() so
    all 50 threads should be woken up */
    uaddr = (int*)(&wake_test_futex);
    num_to_wake = 50;
    expected_result = 50;
    if (!futex_wake_test(uaddr, num_to_wake, expected_result)) {
        num_failed++;
        printf("Wake test 2: failed\n");
    }
    else
        printf("Wake test 2: passed\n");

    printf("---FUTEX_WAIT TESTS--- \n");

    /* Wait test: val and the value 
    in wait_test_futex (0) do not match 
    so return error */
    uaddr = (int*)(&wait_test_futex);
    int val = 20;
    expected_result = -1;
    if (!futex_wait_test(uaddr, val, expected_result)) {
        num_failed++;
        printf("Wait test 1: failed\n");
    }
    else
        printf("Wait test 1: passed\n");

    printf("---FUTEX_WAIT_BITSET TESTS--- \n");

    /* Wait_bitset test: providing bitset
    as a mask to the kernel, val and the value 
    in wait_bitset_test_futex (0) do not match 
    so return error */
    uaddr = (int*)(&wait_bitset_test_futex);
    val = 20;
    int bitset = 0xffffffff;
    expected_result = -1; 
    if (!futex_wait_bitset_test(uaddr, val, bitset, expected_result)) {
        num_failed++;
        printf("Wait_bitset test 1: failed\n");
    }
    else
        printf("Wait_bitset test 1: passed\n");

    printf("---FUTEX_CMP_REQUEUE TESTS--- \n");

    /* Cmp_requeue error check, where
    value at uaddr is not val3 */
    uaddr = (int*)(&empty_futex);
    val = 1;
    u64 val2 = 1;
    int val3 = 20;
    expected_result = -1; 
    if (!futex_cmp_requeue_test_1(uaddr, val, val2, uaddr, val3, expected_result)) {
        num_failed++;
        printf("Cmp_requeue test 1: failed\n");
    }
    else
        printf("Cmp_requeue test 1: passed\n");

    /* Cmp_requeue success case */
    uaddr = (int*)(&cmp_requeue_test_futex_1);
    val = 1;
    val2 = INT_MAX;
    int *uaddr2 = (int*)(&cmp_requeue_test_futex_2);
    val3 = 1;
    int num_threads = 50;
    expected_result = 50;
    if (!futex_cmp_requeue_test_2(uaddr, val, val2, uaddr2, val3, num_threads, expected_result)) {
        num_failed++;
        printf("Cmp_requeue test 2: failed\n");
    }
    else
        printf("Cmp_requeue test 2: passed\n");

    if (num_failed > 0)
        return false;
    return true;
}

int main (int argc, char **argv) 
{
    if (basic_test()) {
        printf("All futex tests passed\n");
        exit(EXIT_SUCCESS);
    }
    else
        exit(EXIT_FAILURE);
}