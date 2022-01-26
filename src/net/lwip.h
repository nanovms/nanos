#include <lwip/init.h>
#include <lwip/debug.h>
#include <lwip/stats.h>
#include <lwip/apps/fs.h>
#include <lwip/def.h>
#include <lwip/ip.h>
#include <lwip/tcp.h>
#include <lwip/timeouts.h>
#include <lwip/ip4_frag.h>
#include <lwip/ip6_frag.h>
#include <lwip/etharp.h>
#include <lwip/ethip6.h>
#include <lwip/dhcp.h>
#include <lwip/dhcp6.h>
#include <lwip/dns.h>
#include <lwip/mld6.h>
#include <lwip/nd6.h>

#define MAX_LWIP_ALLOC_ORDER 16

status direct_connect(heap h, ip_addr_t *addr, u16 port, connection_handler ch);

struct netif *netif_get_default(void);

u16 ifflags_from_netif(struct netif *netif);
boolean ifflags_to_netif(struct netif *netif, u16 flags); /* do not call with lwIP lock held */
void netif_name_cpy(char *dest, struct netif *netif);

#define netif_is_loopback(netif)    (((netif)->name[0] == 'l') && ((netif)->name[1] == 'o'))

extern mutex lwip_mutex;

static inline void lwip_lock(void)
{
    mutex_lock(lwip_mutex);
}

static inline void lwip_unlock(void)
{
    mutex_unlock(lwip_mutex);
}
