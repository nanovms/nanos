#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>
#include <pthread.h>

void handler(int signo)
{
    switch (signo) {
    case SIGUSR1:
        break;
    case SIGABRT:
        break;
    default:
        break;
    }
    abort();
}

void *thread(void *a)
{
    usleep(1000*1000);
    return 0;
}

int main(int argc, char **argv)
{
    pthread_t pt;

    printf("expecting signal stack overflow to segfault...\n");
    pid_t pid = getpid();
    pthread_create(&pt, NULL, thread, 0);
    assert(signal(SIGUSR1, handler) != SIG_ERR);
    assert(signal(SIGABRT, handler) != SIG_ERR);
    kill(pid, SIGUSR1);
    pthread_join(pt, 0);
    return 0;
}

