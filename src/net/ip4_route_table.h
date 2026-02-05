/*
 * IPv4 static route table for DHCP Option 121 (Classless Static Routes)
 *
 * Provides a static routing table for IPv4 with longest-prefix-match lookups.
 * Primarily used to store routes learned from DHCP Option 121 (RFC 3442).
 */

#ifndef __IP4_ROUTE_TABLE_H__
#define __IP4_ROUTE_TABLE_H__

#include <lwip/ip4_addr.h>
#include <lwip/err.h>
#include <lwip/netif.h>

/* Maximum number of static routes (fixed-size to avoid dynamic allocation) */
#ifndef LWIP_IPV4_NUM_ROUTE_ENTRIES
#define LWIP_IPV4_NUM_ROUTE_ENTRIES     16
#endif

#define IP4_MAX_PREFIX_LEN              32

/* Route entry flags */
#define IP4_ROUTE_FLAG_NONE             0x00
#define IP4_ROUTE_FLAG_DHCP             0x01  /* Route learned from DHCP Option 121 */
#define IP4_ROUTE_FLAG_STATIC           0x02  /* Manually configured static route */

struct ip4_route_entry {
    ip4_addr_t dest;        /* Destination network address (masked) */
    ip4_addr_t gateway;     /* Next-hop gateway IP address */
    u8_t prefix_len;        /* CIDR prefix length (0-32) */
    u8_t flags;             /* Route flags (IP4_ROUTE_FLAG_*) */
    struct netif *netif;    /* Associated network interface (NULL = unused entry) */
};

/* Compute netmask from prefix length in network byte order */
u32_t ip4_prefix_to_mask(u8_t prefix_len);

/* Initialize the route table - must be called before other functions */
void ip4_route_table_init(void);

/*
 * Add a route to the static route table.
 * Table is kept sorted by prefix length (longest first) for LPM lookups.
 * Returns ERR_OK on success, ERR_MEM if table full, ERR_ARG if invalid args.
 */
err_t ip4_route_add(const ip4_addr_t *dest, u8_t prefix_len,
                    const ip4_addr_t *gateway, struct netif *netif, u8_t flags);

/* Remove a specific route from the table */
void ip4_route_remove(const ip4_addr_t *dest, u8_t prefix_len, struct netif *netif);

/* Remove all routes associated with a network interface */
void ip4_route_remove_netif(struct netif *netif);

/* Remove all DHCP-learned routes for a network interface */
void ip4_route_remove_dhcp(struct netif *netif);

/*
 * Find the best matching route for a destination address (longest prefix match).
 * Copies route entry to out_entry if found.
 * Returns true if route found, false otherwise.
 */
boolean ip4_route_find(const ip4_addr_t *dest, struct ip4_route_entry *out_entry);

/*
 * Route lookup hook for lwIP integration (LWIP_HOOK_IP4_ROUTE_SRC).
 * Returns network interface to use, or NULL if no static route matches.
 */
struct netif *ip4_static_route(const ip4_addr_t *src, const ip4_addr_t *dest);

/*
 * Get the gateway address for a destination from the static route table.
 * Copies gateway to out_gateway if found.
 * Returns true if route found, false otherwise.
 */
boolean ip4_get_gateway(const ip4_addr_t *dest, ip4_addr_t *out_gateway);

/* Get read-only access to route table for debugging/netlink reporting */
const struct ip4_route_entry *ip4_get_route_table(int *count);

/* Get the number of active routes in the table */
int ip4_route_count(void);

#endif /* __IP4_ROUTE_TABLE_H__ */
