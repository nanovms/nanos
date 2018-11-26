//definitions as per man page of getrandom(2)
#define MAX_ENTROPY_POOL 4096
#define GRND_NONBLOCK 1
#define GRND_RANDOM 2
#define MAX_RANDOM_ENTROPY_COUNT 256

int rand (void);
int getrandom(void *buf,int bufLength,unsigned int flags);

