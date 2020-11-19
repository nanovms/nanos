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

static void * basic_test_thread(void *arg) {
    return (void *)EXIT_SUCCESS;
}

static int futex_wake_test() {
    pthread_t pt;
    int ret;
    if (pthread_create(&pt, NULL, basic_test_thread, NULL)) {
        printf("unable to create thread\n");
        ret = -1;
    }
    else {
        ret = syscall(SYS_futex, (int*)(&pt), FUTEX_WAKE, pt, 0, (int*)(&pt), 0);
    }
    return ret;
}

boolean basic_test() {
    if (futex_wake_test() != 0) {
        return false;
    }

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