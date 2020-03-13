#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/mman.h>
#include <sys/signal.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>

typedef unsigned long long word;

int n;
void *m;
void *flags;
int faults =0;

typedef struct cb {
    int id;
}    *cb;    

#define PAGESIZE 4096
#define LINESIZE 64
#define flag(__i) ((word *)(flags  + __i * LINESIZE))


static inline word fetch_and_add(word *variable, word value)
{
    asm volatile("lock; xadd %0, %1" : "+r" (value), "+m" (*variable) :: "memory", "cc");
    return value;
}

int ncpus()
{
    cpu_set_t c;
    if (sched_getaffinity(0, sizeof(cpu_set_t), &c))
        return -1;
    unsigned int  *x = (void *)&c;
    int result = 0;
    for (int i =0; i < sizeof(cpu_set_t)/sizeof(unsigned int); i ++ ){
        result += __builtin_popcount (x[i]);
    }
    return result;
}

void handler(int sig, siginfo_t *si, void *unused)
{
    faults++;
    printf("Got SIGSEGV at address: 0x%lx\n",(long) si->si_addr);
    mprotect((void *)( (word)si->si_addr & ~(PAGESIZE-1)), PAGESIZE, PROT_READ|PROT_WRITE);    
    // i cn remap this and continue
    //exit(EXIT_FAILURE);
}


void *agency(void *z)
{
    cb c = z;
    int count = 0;
    for (int i =0 ; 1; i = (i +1)%n) {
        if (!((count++) % 10000)) printf("progress %d %d %d\n", c->id, count, faults);
       if ((c->id == i) &&  !*flag(i)) {
           printf("disable");
           mprotect(m + i*PAGESIZE, PAGESIZE, PROT_NONE);
           fetch_and_add(flag(i), 1);
       } else{
           if (!*flag(i)) {
               *(word *)(m + i*PAGESIZE) = 1;
           }
       }
   }
    return 0;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    struct sigaction sa;

    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = handler;
    if (sigaction(SIGSEGV, &sa, NULL) == -1)
        printf("sigaction error");
    
    n = ncpus();
    flags = malloc(n * LINESIZE);
    memset(flags, 0, n * LINESIZE);
    m = mmap(NULL, PAGESIZE * n, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    printf("base %p\n", m);

    for (int i = 1 ; i < n; i++ ){
        cb c= malloc(sizeof(struct cb));
        c->id = i;
        pthread_t p;
        pthread_create(&p, 0, agency, c);
    }
    cb c= malloc(sizeof(struct cb));
    c->id = 0;    
    agency(c);
}

    
