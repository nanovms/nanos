#include <lwip/init.h>
#include <lwip/debug.h>
#include <lwip/stats.h>
#include <lwip/apps/fs.h>
#include <lwip/def.h>
#include <lwip/ip.h>
#include <lwip/tcp.h>
#include <lwip/timeouts.h>
#include <lwip/ip4_frag.h>
#include <lwip/etharp.h>
#include <lwip/dhcp.h>
#include <lwip/dns.h>

#define MAX_LWIP_ALLOC_ORDER 16

status direct_connect(heap h, ip_addr_t *addr, u16 port, connection_handler ch);

struct netif *netif_get_default(void);

u16 ifflags_from_netif(struct netif *netif);
void netif_name_cpy(char *dest, struct netif *netif);

#define netif_is_loopback(netif)    (((netif)->name[0] == 'l') && ((netif)->name[1] == 'o'))
