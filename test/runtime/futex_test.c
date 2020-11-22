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

/* Test Global Variables */
int wake_test_futex;
int empty_futex;
int wait_test_futex = 0;

/* Helper Function Declarations */
static void * futex_wake_test_thread(void *arg);

/* FUTEX_WAKE test, creates num_to_wake threads which wait
on uaddr and then wakes up all the threads */
static boolean futex_wake_test(int* uaddr, int num_to_wake, int expected_result) {
    pthread_t threads[num_to_wake];

    for (int index = 0; index < num_to_wake; index++) {
        if (pthread_create(&(threads[index]), NULL, futex_wake_test_thread, (void*)(uaddr))) {
            printf("Unable to create thread\n");
            return false;
        }
    }
    
    sleep(1); /* for main thread */
    int ret = syscall(SYS_futex, uaddr, FUTEX_WAKE, num_to_wake, 0, NULL, 0);
    if (ret == expected_result)
        return true; /* success */
    else
        return false; /* error */

    return ret;
}

/* Thread function called from futex_wake_test
which sets wake_test_futex's value to 1 and blocks */
static void * futex_wake_test_thread(void *arg) {
    int val = 1;
    wake_test_futex = val;
    syscall(SYS_futex, (int*)(arg), FUTEX_WAIT, val, 0, NULL, 0);
    return NULL;
}

/* FUTEX_WAIT test 1: waits on uaddr with value of val
and compares the result, used to check error case where ret=-1 */
static boolean futex_wait_test(int* uaddr, int val, int expected_result) {
    int ret = syscall(SYS_futex, uaddr, FUTEX_WAIT, val, 0, NULL, 0);
    if (ret == expected_result)
        return true;
    return false;
}

/* Method to run all tests */
boolean basic_test() {
    
    int num_failed = 0;
    printf("---FUTEX_WAKE TESTS--- \n");

    /* Wake test 1: empty_futex is not being
    waited on by the threads made in the 
    futex_wake_test method so no threads 
    should be woken up */
    int* uaddr = (int*)(&empty_futex);
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
    if (!futex_wake_test(uaddr, num_to_wake, expected_result)){
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
        return false;
    }
    printf("Wait test 1: passed\n");

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