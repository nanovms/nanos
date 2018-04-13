#include <net.h>

// only for people who interact directly with lwip
#include "lwip/init.h"
#include "lwip/debug.h"
#include "lwip/stats.h"
#include "lwip/apps/fs.h"
#include "lwip/def.h"
#include "lwip/ip.h"
#include "lwip/tcp.h"


struct sockaddr_in {
    u16 family;
    u16 port;
    u32 address;
} *sockaddr_in;
    
struct sockaddr {
    u16 family;
} *sockaddr;
    
