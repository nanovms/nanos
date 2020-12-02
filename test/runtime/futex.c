#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include <pthread.h>
#include <runtime.h>
#include <linux/futex.h>
#include <limits.h>
#include <time.h>

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
// static void *futex_cmp_requeue_test_thread(void *arg);

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
static boolean futex_wait_test_1() 
{
    int *uaddr = (int*)(&wait_test_futex);
    int val = 20;
    int expected_result = -1;
    int ret = syscall(SYS_futex, uaddr, FUTEX_WAIT, val, 0, NULL, 0);
    if (ret == expected_result) {
        printf("wait test 1: passed\n");
        return true;
    }
    printf("wait test 1: failed\n");
    return false;
}

static boolean futex_wait_test_2() 
{
    struct timespec timeout = {.tv_sec = 10, .tv_nsec = 0};
    int *uaddr = (int*)(&wait_test_futex);
    int val = 0;
    int expected_result = -1;

    time_t start, end;
    time(&start);
    int ret = syscall(SYS_futex, uaddr, FUTEX_WAIT, val, &timeout, NULL, 0);
    time(&end);

    time_t total_time = end-start;
    if ((total_time==timeout.tv_sec) && (ret == expected_result)) {
        printf("wait test 2: passed\n");
        return true;
    }
    printf("wait test 2: failed\n");
    return false;
}

/* Wait_bitset test: providing bitset
    as a mask to the kernel, val and the value 
    in wait_bitset_test_futex (0) do not match 
    so return error */
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

/* Wait_bitset test 2: success case */
static boolean futex_wait_bitset_test_2() 
{
    int *uaddr = (int*)(&wait_bitset_test_futex);
    int val = 0;
    int bitset = 0xffffffff;
    int expected_result = -1; 

    struct timespec start;
    struct timespec end;
    time_t time_given = 10;
    clock_gettime(CLOCK_MONOTONIC, &start);
    struct timespec timeout = {.tv_sec = time_given+start.tv_sec, .tv_nsec = 0};
    int ret = syscall(SYS_futex, uaddr, FUTEX_WAIT_BITSET, val, &timeout, NULL, bitset);
    clock_gettime(CLOCK_MONOTONIC, &end);

    time_t total_time = end.tv_sec - start.tv_sec;

    if ((total_time == time_given) && (ret == expected_result)) {
        printf("wait_bitset test 2: passed\n");
        return true;
    }
    printf("wait_bitset test 2: failed\n");
    return false;
}

/* Cmp_requeue error check, where
    value at uaddr is not val3 */
static boolean futex_cmp_requeue_test_1() 
{
    int *uaddr = (int*)(&empty_futex);
    int *uaddr2 = (int*)(&empty_futex);
    int val = 1;
    u64 val2 = 1;
    int val3 = 20;
    int expected_result = -1; 

    int ret = syscall(SYS_futex, uaddr, FUTEX_CMP_REQUEUE, val, val2, uaddr2, val3);
    if (ret == expected_result) {
        printf("cmp_requeue test 1: passed\n");
        return true;
    }
    printf("cmp_requeue test 1: failed\n");
    return false;
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

    /* Wait Bitset Tests */
    printf("---FUTEX_WAIT_BITSET TESTS--- \n");
    if (!futex_wait_bitset_test_1()) 
        num_failed++; 
    if (!futex_wait_bitset_test_2())
        num_failed++;

    /* Cmp_Requeue Tests */
    printf("---FUTEX_CMP_REQUEUE TESTS--- \n");
    if (!futex_cmp_requeue_test_1())
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