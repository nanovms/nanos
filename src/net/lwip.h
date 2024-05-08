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

status direct_connect(heap h, ip_addr_t *addr, u16 port, connection_handler ch);

closure_type(netif_dev_setup, boolean, tuple config);

typedef struct netif_dev {
    struct netif n;
    closure_struct(netif_dev_setup, setup);
} *netif_dev;

static inline void netif_dev_init(netif_dev dev)
{
    dev->setup.__apply = 0;
}

u16 ifflags_from_netif(struct netif *netif);
boolean ifflags_to_netif(struct netif *netif, u16 flags); /* do not call with lwIP lock held */
bytes netif_name_cpy(char *dest, struct netif *netif);

#define netif_is_loopback(netif)    (((netif)->name[0] == 'l') && ((netif)->name[1] == 'o'))

#define netif_get_type(netif)   (netif_is_loopback(netif) ? ARPHRD_LOOPBACK :                   \
                                 netif_is_flag_set(netif, NETIF_FLAG_ETHARP) ? ARPHRD_ETHER :   \
                                 ARPHRD_VOID)

extern int (*net_ip_input_filter)(struct pbuf *pbuf, struct netif *input_netif);
