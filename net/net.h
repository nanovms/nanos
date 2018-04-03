typedef u64 socklen_t;

#define NET_SYSCALLS 1

typedef struct sockaddr {
    u32 family;
} *sockaddr;

int net_syscall(int f, u64 *a);

// only for people who interact directly with lwip
#include "lwip/init.h"
#include "lwip/debug.h"
#include "lwip/stats.h"
#include "lwip/apps/fs.h"
#include "lwip/def.h"
#include "lwip/ip.h"
#include "lwip/tcp.h"
