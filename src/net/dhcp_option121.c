/*
 * DHCP Option 121 (Classless Static Routes) Parser - RFC 3442
 *
 * Parses classless static routes from DHCP responses and populates
 * the IPv4 static route table.
 */

#include <kernel.h>
#include <lwip.h>
#include <lwip/prot/dhcp.h>
#include <dhcp_option121.h>
#include <ip4_route_table.h>

/*
 * Global to track the current netif during DHCP receive processing.
 * Set by dhcp_recv() before calling dhcp_parse_reply() so that
 * ip_current_netif() can return the correct value for hooks.
 *
 * This is needed because nanos's lwIP modifications pass ip_data
 * as a parameter rather than using a global, but the DHCP option
 * hook still uses ip_current_netif().
 *
 * Safe because lwIP runs in single-threaded context (NO_SYS=1) and
 * DHCP packets are processed sequentially in the network timer context.
 */
struct netif *nanos_dhcp_current_netif;

/* Per-interface tracking of whether Option 121 was received */
static u8_t option121_received[DHCP_OPTION121_MAX_NETIFS];

/* Spinlock for thread-safe access to option121_received state */
static struct spinlock option121_lock;

/* Get a safe index for the option121_received array, returns -1 if out of bounds */
static inline int get_netif_idx(struct netif *netif)
{
    if (netif == NULL)
        return -1;
    u8_t idx = netif_get_index(netif);
    if (idx == 0 || idx > DHCP_OPTION121_MAX_NETIFS)
        return -1;
    return idx - 1;
}

/* Calculate significant octets for a prefix length: ceil(prefix_len / 8) */
static inline u8_t prefix_to_octets(u8_t prefix_len)
{
    return (prefix_len + 7) / 8;
}

void dhcp_option121_init(void)
{
    spin_lock_init(&option121_lock);
    runtime_memset(option121_received, 0, sizeof(option121_received));
}

int dhcp_parse_option121(struct netif *netif, struct pbuf *p,
                         u16_t offset, u8_t len)
{
    int routes_parsed = 0;
    u16_t pos = offset;
    u16_t end;
    int netif_idx;

    if (netif == NULL || p == NULL)
        return ERR_ARG;  /* ERR_ARG is already negative */

    netif_idx = get_netif_idx(netif);
    if (netif_idx < 0)
        return ERR_ARG;

    /* overflow check */
    if (offset > 0xFFFF - len)
        return ERR_ARG;
    end = offset + len;

    /* empty option is valid but contains no routes */
    if (len == 0)
        return 0;

    /*
     * Clear any existing DHCP routes for this interface first.
     * This ensures we replace old routes with new ones on lease renewal.
     */
    ip4_route_remove_dhcp(netif);

    /*
     * Parse each route entry in the option.
     * Format per RFC 3442:
     *   1 byte:  prefix length (0-32)
     *   N bytes: significant octets of destination (N = ceil(prefix_len/8))
     *   4 bytes: gateway IP address
     */
    while (pos < end) {
        u8_t prefix_len;
        u8_t significant_octets;
        ip4_addr_t dest;
        ip4_addr_t gateway;
        u8_t dest_bytes[4] = {0, 0, 0, 0};

        /* read prefix length */
        if (pbuf_copy_partial(p, &prefix_len, 1, pos) != 1)
            break;
        pos++;

        if (prefix_len > 32)
            break;

        significant_octets = prefix_to_octets(prefix_len);

        /* check we have enough data remaining */
        if (pos + significant_octets + 4 > end)
            break;

        /* read destination network (significant octets only) */
        if (significant_octets > 0) {
            if (pbuf_copy_partial(p, dest_bytes, significant_octets, pos)
                    != significant_octets)
                break;
        }
        pos += significant_octets;

        /*
         * Reconstruct destination address.
         * The significant octets are the high-order bytes of the address.
         * dest_bytes is already zero-initialized for non-significant octets.
         */
        dest.addr = (dest_bytes[0] << 24) | (dest_bytes[1] << 16) |
                    (dest_bytes[2] << 8) | dest_bytes[3];
        dest.addr = lwip_htonl(dest.addr);

        /* apply mask to ensure destination is properly masked (RFC 3442) */
        dest.addr &= ip4_prefix_to_mask(prefix_len);

        /* read gateway address - already in network byte order */
        if (pbuf_copy_partial(p, &gateway.addr, 4, pos) != 4)
            break;
        pos += 4;

        /*
         * Validate gateway address:
         * - Reject multicast/broadcast (invalid as next-hop)
         * - 0.0.0.0 is valid per RFC 3442: means destination is on-link
         *   (directly reachable on this interface without a gateway)
         */
        if (ip4_addr_ismulticast(&gateway) ||
            ip4_addr_isbroadcast(&gateway, netif))
            continue;

        /* add route to table */
        if (ip4_route_add(&dest, prefix_len, &gateway, netif,
                          IP4_ROUTE_FLAG_DHCP) == ERR_OK) {
            routes_parsed++;
        }
    }

    /*
     * Mark that this interface received Option 121.
     * This is used to determine whether to ignore Option 3 (Router).
     */
    if (routes_parsed > 0) {
        spin_lock(&option121_lock);
        option121_received[netif_idx] = 1;
        spin_unlock(&option121_lock);
    }

    return routes_parsed;
}

boolean dhcp_option121_received(struct netif *netif)
{
    boolean result = false;
    int netif_idx = get_netif_idx(netif);

    if (netif_idx < 0)
        return false;

    spin_lock(&option121_lock);
    result = (option121_received[netif_idx] != 0);
    spin_unlock(&option121_lock);

    return result;
}

void dhcp_option121_clear(struct netif *netif)
{
    int netif_idx = get_netif_idx(netif);

    if (netif_idx < 0)
        return;

    spin_lock(&option121_lock);
    option121_received[netif_idx] = 0;
    spin_unlock(&option121_lock);

    ip4_route_remove_dhcp(netif);
}

void nanos_dhcp_parse_option_hook(struct netif *netif, struct dhcp *dhcp,
                                   u8_t state, struct dhcp_msg *msg,
                                   u8_t msg_type, u8_t option, u8_t len,
                                   struct pbuf *p, u16_t offset)
{
    LWIP_UNUSED_ARG(dhcp);
    LWIP_UNUSED_ARG(state);
    LWIP_UNUSED_ARG(msg);

    /* only process Option 121 from DHCP ACK messages */
    if (option == DHCP_OPTION_CLASSLESS_STATIC_ROUTE &&
        msg_type == DHCP_ACK) {
        dhcp_parse_option121(netif, p, offset, len);
    }
}
