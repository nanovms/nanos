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

int futex_address;

static void * futex_wake_test_thread(void *arg) {
    /* set value of futex_address to 0 within this thread */
    futex_address = 0;
    
    /* call wait with the address of futex_address and
    a value of 0 - block while value at futex_address is 0 */
    int wait_val = 0;
    syscall(SYS_futex, (int*)(&futex_address), FUTEX_WAIT, wait_val, 0, NULL, 0);
    return NULL;
}

static int futex_wake_test() {
    pthread_t threads[50];
    int ret;

    /* create new threads */
    for (int index = 0; index < 50; index++) {
        if (pthread_create(&(threads[index]), NULL, futex_wake_test_thread, NULL)) {
            printf("unable to create thread\n");
            return -1;
        }
    }
        /* put the main thread to sleep */
        sleep(1); 

        /* after main thread is done sleeping, call wake on the 50
        threads that are waiting on &futex_address */
        int num_to_wake_up = 50;
        ret = syscall(SYS_futex, (int*)(&futex_address), FUTEX_WAKE, num_to_wake_up, 0, NULL, 0);
        
        /* check that 50 threads have been woken up */
        if (ret == num_to_wake_up)
            ret = 0;

    return ret; /* 0 on success */
}

/* method to run all tests */
boolean basic_test() {
    int ret = futex_wake_test();
    if (ret != 0) 
        return false;

    return true;
}

int main (int argc, char* argv[]) {
    if (basic_test()) {
        printf("futex tests passed\n");
        exit(EXIT_SUCCESS);
    }
    else {
        printf("futex tests failed\n");
        exit(EXIT_FAILURE);
    }
}