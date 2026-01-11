/*
 * DHCP Option 121 (Classless Static Routes) Parser - RFC 3442
 *
 * Parses DHCP Option 121 responses and populates the IPv4 static route
 * table with classless static routes provided by the DHCP server.
 */

#ifndef __DHCP_OPTION121_H__
#define __DHCP_OPTION121_H__

#include <lwip/pbuf.h>
#include <lwip/netif.h>
#include <lwip/err.h>

/* DHCP Option 121 - Classless Static Route (RFC 3442) */
#define DHCP_OPTION_CLASSLESS_STATIC_ROUTE  121

/*
 * Maximum number of network interfaces we track for Option 121 state.
 * Should match or exceed the number of interfaces in the system.
 */
#ifndef DHCP_OPTION121_MAX_NETIFS
#define DHCP_OPTION121_MAX_NETIFS           16
#endif

/* Initialize the Option 121 module - must be called before other functions */
void dhcp_option121_init(void);

/*
 * Parse DHCP Option 121 data and add routes to the static route table.
 *
 * Parses variable-length encoding per RFC 3442:
 *   1 byte:  prefix length (0-32)
 *   N bytes: significant octets of destination (N = ceil(prefix_len/8))
 *   4 bytes: gateway IP address
 *
 * Routes are added with IP4_ROUTE_FLAG_DHCP flag. Existing DHCP routes
 * for the interface are cleared first.
 *
 * Returns number of routes successfully added (>= 0), or negative error.
 */
int dhcp_parse_option121(struct netif *netif, struct pbuf *p,
                         u16_t offset, u8_t len);

/*
 * Check if Option 121 was received for an interface.
 * Per RFC 3442, if Option 121 is present, Option 3 (Router) must be ignored.
 */
boolean dhcp_option121_received(struct netif *netif);

/*
 * Clear Option 121 state and routes for a network interface.
 * Called when DHCP lease is released, interface is removed, etc.
 */
void dhcp_option121_clear(struct netif *netif);

/*
 * lwIP DHCP option parse hook (LWIP_HOOK_DHCP_PARSE_OPTION).
 * Called by lwIP for each unknown DHCP option, parses Option 121.
 */
struct dhcp;
struct dhcp_msg;

void nanos_dhcp_parse_option_hook(struct netif *netif, struct dhcp *dhcp,
                                   u8_t state, struct dhcp_msg *msg,
                                   u8_t msg_type, u8_t option, u8_t len,
                                   struct pbuf *p, u16_t offset);

#endif /* __DHCP_OPTION121_H__ */
