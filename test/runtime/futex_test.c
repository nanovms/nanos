#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include <pthread.h>
#include <runtime.h>

#define EXIT_FAILURE 1
#define EXIT_SUCCESS 0
#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
#define NUM_WAKE_TESTS 2
#define NUM_WAIT_TESTS 1

/* A FUTEX_WAKE testcase */
struct wake_testcase {
    int *uaddr;
    int num_to_wake;  /* Number of threads to wake up */
    int expected_result; /* Expected return for FUTEX_WAKE */
};

int wake_futex;
int empty_futex; /* Value is never set */

/* Array of FUTEX_WAKE testcases */
struct wake_testcase wake_testcases [] = {

    /* Test case 1: no threads wait on empty_futex
    so 0 threads should be woken up */
    {(int*)(&empty_futex), 50, 0},

    /* Test case 2: 50 threads wait on wake_futex
    so 50 threads should be woken up */
    {(int*)(&wake_futex), 50, 50}
};

int wait_futex = 0;

/* A FUTEX_WAIT testcase */
struct wait_testcase {
    int *uaddr;
    int val;
    int expected_result;
};

/* Array of FUTEX_WAIT testcases */
struct wait_testcase wait_testcases [] = {

    /* Test case 1: value of wait_futex
    matches val (0), expected success */
    // {(int*)(&wait_futex), 0, 0},

    /* Test case 2: value of wait_futex
    is not 20, expected failure */
    {(int*)(&wait_futex), 20, -1}
};

/* FUTEX_WAIT test with passed-in struct */
static int futex_wait_test(struct wait_testcase test) {
    int ret = syscall(SYS_futex, test.uaddr, FUTEX_WAIT, test.val, 0, NULL, 0);
    if (ret == test.expected_result)
        ret = 0;
    return ret;
}

/* Thread function called from futex_wake_test */
static void * futex_wake_test_thread(void *arg) {
    /* Set value of wake_futex within this thread */
    wake_futex = 1;

    /* Call wait - block while value of address
    passed in is 1 */
    int wait_val = 1;
    syscall(SYS_futex, (int*)(arg), FUTEX_WAIT, wait_val, 0, NULL, 0);
    return NULL;
}

/* Runs a FUTEX_WAKE test on the provided testcase */
static int futex_wake_test(struct wake_testcase test) {
    pthread_t threads[test.num_to_wake];
    int ret;
    int index;

    /* Create multiple threads */
    for (index = 0; index < test.num_to_wake; index++) {
        if (pthread_create(&(threads[index]), NULL, futex_wake_test_thread, (void*)(test.uaddr))) {
            printf("Unable to create thread\n");
            return -1;
        }
    }
    
    /* Put the main thread to sleep */
    sleep(1); 

    /* Wake up the threads waiting on test.uaddr */
    ret = syscall(SYS_futex, test.uaddr, FUTEX_WAKE, test.num_to_wake, 0, NULL, 0);
        

    /* Check that correct number of threads are woken up. */
    if (ret == test.expected_result)
        ret = 0; /* success */
    else
        ret = -1; /* error */

    return ret;
}

/* Method to run all tests */
boolean basic_test() {

    int num_failed = 0;
    int i;
    printf("---FUTEX_WAKE TESTS--- \n");
    for (i = 0; i < NUM_WAKE_TESTS; i++) {
        int ret = futex_wake_test(wake_testcases[i]);
        if (ret != 0) {
            printf("Wake test %d: failed\n", i);
            num_failed++;
        }
        else {
            printf("Wake test %d: passed\n", i);
        }
    }

    printf("---FUTEX_WAIT TESTS--- \n");
    for (i = 0; i < NUM_WAIT_TESTS; i++) {
        int ret = futex_wait_test(wait_testcases[i]);
        if (ret != 0) {
            printf("Wait test %d: failed\n", i);
            num_failed++;
        }
        else {
            printf("Wait test %d: passed\n", i);
        }
    }

    if (num_failed > 0)
        return false;
    return true;
}

int main (int argc, char* argv[]) {
    if (basic_test()) {
        printf("All futex tests passed\n");
        exit(EXIT_SUCCESS);
    }
    else {
        exit(EXIT_FAILURE);
    }
}