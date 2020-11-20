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

/* A FUTEX_WAKE testcase */
struct wake_testcase {
    int *uaddr;
	int num_to_wake;  /* Number of threads to wake up */
	int expected_result; /* Expected return for FUTEX_WAKE */
};

int futex;
int empty_futex; /* Value is never set */

/* Array of FUTEX_WAKE testcases */
struct wake_testcase wake_testcases [] = {

    /* Test case 1: no threads wait on "empty_futex"
    so 0 threads should be woken up */
    {(int*)(&empty_futex), 50, 0},

    /* Test case 2: 50 threads wait on "futex"
    so 50 threads should be woken up */
    {(int*)(&futex), 50, 50}
};

/* Thread function called from futex_wake_test */
static void * futex_wake_test_thread(void *arg) {
    /* Set value of "futex" within this thread */
    futex = 1;

    /* Call wait with the address of "futex" and
    a value of 1 - block while value of "futex" is 1 */
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
    for (int i = 0; i < NUM_WAKE_TESTS; i++) {
        int ret = futex_wake_test(wake_testcases[i]);
        if (ret != 0) {
            printf("Wake test %d: failed\n", i);
            num_failed++;
        }
        else {
            printf("Wake test %d: passed\n", i);
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