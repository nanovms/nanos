/*
 * IPv4 static route table implementation
 *
 * Provides a fixed-size routing table with longest-prefix-match lookup,
 * primarily for DHCP Option 121 (RFC 3442) classless static routes.
 */

#include <kernel.h>
#include <lwip.h>
#include <ip4_route_table.h>

/* Route table storage - sorted by prefix_len descending for LPM */
static struct ip4_route_entry route_table[LWIP_IPV4_NUM_ROUTE_ENTRIES];

/* Spinlock for thread-safe access */
static struct spinlock route_lock;

/* Number of active entries in the table */
static int route_entry_count;

/* Compute netmask from prefix length in network byte order */
u32_t ip4_prefix_to_mask(u8_t prefix_len)
{
    if (prefix_len == 0)
        return 0;
    if (prefix_len >= 32)
        return 0xFFFFFFFF;
    return PP_HTONL(~((1UL << (32 - prefix_len)) - 1));
}

/* Check if a destination address matches a route entry */
static inline int route_matches(const struct ip4_route_entry *entry,
                                const ip4_addr_t *dest)
{
    u32_t mask = ip4_prefix_to_mask(entry->prefix_len);
    return (dest->addr & mask) == (entry->dest.addr & mask);
}

/* Find insertion point to maintain sorted order (descending prefix_len) */
static int find_insert_position(u8_t prefix_len)
{
    int i;
    for (i = 0; i < route_entry_count; i++) {
        if (prefix_len > route_table[i].prefix_len)
            return i;
    }
    return route_entry_count;
}

/* Find an existing route matching dest/prefix_len/netif, returns index or -1 */
static int find_existing_route(const ip4_addr_t *dest, u8_t prefix_len,
                               struct netif *netif)
{
    u32_t mask = ip4_prefix_to_mask(prefix_len);
    u32_t masked_dest = dest->addr & mask;

    for (int i = 0; i < route_entry_count; i++) {
        if (route_table[i].prefix_len == prefix_len &&
            (route_table[i].dest.addr & mask) == masked_dest &&
            (netif == NULL || route_table[i].netif == netif)) {
            return i;
        }
    }
    return -1;
}

void ip4_route_table_init(void)
{
    spin_lock_init(&route_lock);
    runtime_memset((u8 *)route_table, 0, sizeof(route_table));
    route_entry_count = 0;
}

err_t ip4_route_add(const ip4_addr_t *dest, u8_t prefix_len,
                    const ip4_addr_t *gateway, struct netif *netif, u8_t flags)
{
    err_t ret = ERR_OK;

    if (dest == NULL || gateway == NULL || netif == NULL)
        return ERR_ARG;
    if (prefix_len > IP4_MAX_PREFIX_LEN)
        return ERR_ARG;

    spin_lock(&route_lock);

    /* check for existing route with same dest/prefix/netif and update it */
    int existing = find_existing_route(dest, prefix_len, netif);
    if (existing >= 0) {
        ip4_addr_copy(route_table[existing].gateway, *gateway);
        route_table[existing].flags = flags;
        goto out;
    }

    if (route_entry_count >= LWIP_IPV4_NUM_ROUTE_ENTRIES) {
        ret = ERR_MEM;
        goto out;
    }

    /* find insertion point to maintain sorted order */
    int pos = find_insert_position(prefix_len);

    /* shift entries down to make room */
    for (int i = route_entry_count; i > pos; i--) {
        runtime_memcpy(&route_table[i], &route_table[i - 1],
                       sizeof(struct ip4_route_entry));
    }

    /* insert new entry */
    u32_t mask = ip4_prefix_to_mask(prefix_len);
    route_table[pos].dest.addr = dest->addr & mask;
    ip4_addr_copy(route_table[pos].gateway, *gateway);
    route_table[pos].prefix_len = prefix_len;
    route_table[pos].flags = flags;
    route_table[pos].netif = netif;
    route_entry_count++;

out:
    spin_unlock(&route_lock);
    return ret;
}

void ip4_route_remove(const ip4_addr_t *dest, u8_t prefix_len, struct netif *netif)
{
    if (dest == NULL || prefix_len > IP4_MAX_PREFIX_LEN)
        return;

    spin_lock(&route_lock);

    int idx = find_existing_route(dest, prefix_len, netif);
    if (idx >= 0) {
        for (int i = idx; i < route_entry_count - 1; i++) {
            runtime_memcpy(&route_table[i], &route_table[i + 1],
                           sizeof(struct ip4_route_entry));
        }
        runtime_memset((u8 *)&route_table[route_entry_count - 1], 0,
                       sizeof(struct ip4_route_entry));
        route_entry_count--;
    }

    spin_unlock(&route_lock);
}

void ip4_route_remove_netif(struct netif *netif)
{
    if (netif == NULL)
        return;

    spin_lock(&route_lock);

    int i = 0;
    while (i < route_entry_count) {
        if (route_table[i].netif == netif) {
            for (int j = i; j < route_entry_count - 1; j++) {
                runtime_memcpy(&route_table[j], &route_table[j + 1],
                               sizeof(struct ip4_route_entry));
            }
            runtime_memset((u8 *)&route_table[route_entry_count - 1], 0,
                           sizeof(struct ip4_route_entry));
            route_entry_count--;
        } else {
            i++;
        }
    }

    spin_unlock(&route_lock);
}

void ip4_route_remove_dhcp(struct netif *netif)
{
    if (netif == NULL)
        return;

    spin_lock(&route_lock);

    int i = 0;
    while (i < route_entry_count) {
        if (route_table[i].netif == netif &&
            (route_table[i].flags & IP4_ROUTE_FLAG_DHCP)) {
            for (int j = i; j < route_entry_count - 1; j++) {
                runtime_memcpy(&route_table[j], &route_table[j + 1],
                               sizeof(struct ip4_route_entry));
            }
            runtime_memset((u8 *)&route_table[route_entry_count - 1], 0,
                           sizeof(struct ip4_route_entry));
            route_entry_count--;
        } else {
            i++;
        }
    }

    spin_unlock(&route_lock);
}

boolean ip4_route_find(const ip4_addr_t *dest, struct ip4_route_entry *out_entry)
{
    boolean found = false;

    if (dest == NULL)
        return false;

    spin_lock(&route_lock);

    /*
     * Table is sorted by prefix_len descending, so the first match
     * is the longest prefix match.
     */
    for (int i = 0; i < route_entry_count; i++) {
        if (route_table[i].netif != NULL && route_matches(&route_table[i], dest)) {
            if (out_entry != NULL)
                runtime_memcpy(out_entry, &route_table[i], sizeof(*out_entry));
            found = true;
            break;
        }
    }

    spin_unlock(&route_lock);
    return found;
}

struct netif *ip4_static_route(const ip4_addr_t *src, const ip4_addr_t *dest)
{
    struct ip4_route_entry entry;
    LWIP_UNUSED_ARG(src);

    if (ip4_route_find(dest, &entry))
        return entry.netif;
    return NULL;
}

boolean ip4_get_gateway(const ip4_addr_t *dest, ip4_addr_t *out_gateway)
{
    struct ip4_route_entry entry;

    if (ip4_route_find(dest, &entry)) {
        if (out_gateway != NULL)
            ip4_addr_copy(*out_gateway, entry.gateway);
        return true;
    }
    return false;
}

/*
 * Get read-only access to route table for debugging/netlink.
 * Note: Caller must not hold route_lock. The returned pointer is valid
 * but entries may change if routes are modified concurrently.
 */
const struct ip4_route_entry *ip4_get_route_table(int *count)
{
    if (count != NULL)
        *count = route_entry_count;
    return route_table;
}

int ip4_route_count(void)
{
    int count;
    spin_lock(&route_lock);
    count = route_entry_count;
    spin_unlock(&route_lock);
    return count;
}
