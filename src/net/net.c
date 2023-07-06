#include <kernel.h>
#include <lwip.h>
#include <lwip/priv/tcp_priv.h>

/* Network interface flags */
#define IFF_UP          (1 << 0)
#define IFF_BROADCAST   (1 << 1)
#define IFF_LOOPBACK    (1 << 3)
#define IFF_RUNNING     (1 << 6)
#define IFF_NOARP       (1 << 7)
#define IFF_MULTICAST   (1 << 12)

BSS_RO_AFTER_INIT static heap lwip_heap;
BSS_RO_AFTER_INIT int (*net_ip_input_filter)(struct pbuf *pbuf, struct netif *input_netif);

declare_closure_struct(0, 2, void, net_timeout_handler, u64, expiry, u64, overruns);

static struct {
    status_handler ip4_complete;
    struct timer timeout;
    closure_struct(net_timeout_handler, timeout_handler);
} net;

/* Pretty silly. LWIP offers lwip_cyclic_timers for use elsewhere, but
   says to use LWIP_ARRAYSIZE(), which isn't possible with an
   incomplete type. Plus there's no terminator to the array. So we
   just have to manually create our own here. Check
   lwip/src/core/timeouts.c if we switch on any other LWIP components
   and add an entry here accordingly. Barf */

struct net_lwip_timer {
    u64 interval_ms;
    lwip_cyclic_timer_handler handler;
    char * name;
    struct timer t;
};

static struct net_lwip_timer net_lwip_timers[] = {
    {TCP_TMR_INTERVAL, tcp_tmr, "tcp"},
    {IP_TMR_INTERVAL, ip_reass_tmr, "ip"},
    {ARP_TMR_INTERVAL, etharp_tmr, "arp"},
    {DHCP_COARSE_TIMER_MSECS, dhcp_coarse_tmr, "dhcp coarse"},
    {DHCP_FINE_TIMER_MSECS, dhcp_fine_tmr, "dhcp fine"},
    {DNS_TMR_INTERVAL, dns_tmr, "dns"},
    {ND6_TMR_INTERVAL, nd6_tmr, "nd6"},
    {IP6_REASS_TMR_INTERVAL, ip6_reass_tmr, "ip6 reass"},
    {MLD6_TMR_INTERVAL, mld6_tmr, "mld6"},
    {DHCP6_TIMER_MSECS, dhcp6_tmr, "dhcp6"},
};

closure_function(2, 2, void, dispatch_lwip_timer,
                 lwip_cyclic_timer_handler, handler, const char *, name,
                 u64, expiry, u64, overruns)
{
#ifdef LWIP_DEBUG
    lwip_debug("dispatching timer for %s\n", bound(name));
#endif
    if (overruns == timer_disabled)
        closure_finish();
    else
        bound(handler)();
}

void sys_timeouts_init(void)
{
    int n = sizeof(net_lwip_timers) / sizeof(struct net_lwip_timer);
    for (int i = 0; i < n; i++) {
        struct net_lwip_timer * t = (struct net_lwip_timer *)&net_lwip_timers[i];
        init_timer(&t->t);
        timestamp interval = milliseconds(t->interval_ms);
        register_timer(kernel_timers, &t->t, CLOCK_ID_MONOTONIC_RAW, interval, false, interval,
                       closure(lwip_heap, dispatch_lwip_timer, t->handler, t->name));
#ifdef LWIP_DEBUG
        lwip_debug("registered %s timer with period of %ld ms\n", t->name, t->interval_ms);
#endif
    }
}

void lwip_debug(char * format, ...)
{
    vlist a;
    vstart(a, format);
    log_vprintf("LWIP", format, &a);
}

void *lwip_allocate(u64 size)
{
    void *p = allocate(lwip_heap, size);
    return ((p != INVALID_ADDRESS) ? p : 0);
}

void lwip_deallocate(void *x)
{
    /* no size info; mcache won't care */
    deallocate(lwip_heap, x, -1ull);
}

static boolean netif_ready(struct netif *n)
{
    return !ip_addr_isany(netif_ip_addr4(n));
}

static void check_netif_ready(struct netif *netif)
{
    struct netif *default_n = netif_get_default();
    if (default_n) {
        if ((!netif || (netif == default_n)) && netif_ready(default_n))
            remove_timer(kernel_timers, &net.timeout, 0);
        netif_unref(default_n);
    }
}

static void lwip_ext_callback(struct netif* netif, netif_nsc_reason_t reason,
                              const netif_ext_callback_args_t* args)
{
    char ifname[4];
    netif_name_cpy(ifname, netif);
    if (reason & LWIP_NSC_IPV4_ADDRESS_CHANGED) {
        u8 *n = (u8 *)&netif->ip_addr;
        rprintf("%s: assigned %d.%d.%d.%d\n", ifname, n[0], n[1], n[2], n[3]);
        check_netif_ready(netif);
    }
    if ((reason & LWIP_NSC_IPV6_ADDR_STATE_CHANGED) &&
            (netif_ip6_addr_state(netif, args->ipv6_addr_state_changed.addr_index) & IP6_ADDR_VALID))
        rprintf("%s: assigned %s\n", ifname, ipaddr_ntoa(args->ipv6_addr_state_changed.address));
}

u32_t lwip_rand(void)
{
    return random_u64();
}

/* unsigned only ... don't imagine we'd have negative interface numbers! */
int lwip_atoi(const char *p)
{
    u64 i;
    return u64_from_value(alloca_wrap_cstring(p), &i) ? i : -1;
}

/* mildly unfortunate to add another level of indirection to resolve types
   that are equivalent ... maybe a runtime types.h would be in order */
void lwip_memcpy(void *a, const void *b, unsigned long len)
{
    runtime_memcpy(a, b, len);
}

int lwip_strlen(char *a)
{
    return runtime_strlen(a);
}

void lwip_memset(void *x, unsigned char v, unsigned long len)
{
    runtime_memset(x, v, len);
}

int lwip_memcmp(const void *x, const void *y, unsigned long len)
{
    return runtime_memcmp(x, y, len);
}

int lwip_strcmp(const char *x, const char *y)
{
    return runtime_strcmp(x, y);
}

int lwip_strncmp(const char *x, const char *y, unsigned long len)
{
    for (int i = 0; i < len; i++) {
        if ((*x) != (*y)) return -1;
        if ((!*x) || (!*y)) return -1;
    }
    return 0;
}

u16 ifflags_from_netif(struct netif *netif)
{
    u16 flags = 0;
    if (netif_is_up(netif))
        flags |= IFF_UP;
    if (netif->flags & NETIF_FLAG_BROADCAST)
        flags |= IFF_BROADCAST;
    if (netif_is_loopback(netif))
        flags |= IFF_LOOPBACK;
    if (netif_is_link_up(netif))
        flags |= IFF_RUNNING;
    if (!(netif->flags & NETIF_FLAG_ETHARP))
        flags |= IFF_NOARP;
    if (netif->flags & NETIF_FLAG_IGMP)
        flags |= IFF_MULTICAST;
    return flags;
}

boolean ifflags_to_netif(struct netif *netif, u16 flags)
{
    u16 diff = ifflags_from_netif(netif) ^ flags;
    if (diff & ~(IFF_UP | IFF_RUNNING)) { /* attempt to modify read-only flags */
        return false;
    }
    if (flags & IFF_UP)
        netif_set_up(netif);
    else
        netif_set_down(netif);
    if (flags & IFF_RUNNING)
        netif_set_link_up(netif);
    else
        netif_set_link_down(netif);
    return true;
}

void netif_name_cpy(char *dest, struct netif *netif)
{
    runtime_memcpy(dest, netif->name, sizeof(netif->name));
    dest[sizeof(netif->name)] = '0' + netif->num;
    dest[sizeof(netif->name) + 1] = '\0';
}

#define MAX_ADDR_LEN 20

#define MAX_IP6_ADDR_LEN    39

static boolean get_config_addr(tuple root, symbol s, ip4_addr_t *addr)
{
    string v = get_string(root, s);
    if (!v)
        return false;
    int len = MIN(buffer_length(v), MAX_ADDR_LEN);
    char str[MAX_ADDR_LEN + 1];
    runtime_memcpy(str, buffer_ref(v, 0), len);
    str[len] = '\0';
    if (ip4addr_aton(str, addr) == 1)
        return true;
    return false;
}

static boolean get_static_config(tuple t, struct netif *n, const char *ifname, boolean trace) {
    ip4_addr_t ip;
    ip4_addr_t netmask;
    ip4_addr_t gw;

    if (!get_config_addr(t, sym(ipaddr), &ip))
        return false;

    if (!get_config_addr(t, sym(netmask), &netmask))
        ip4_addr_set_u32(&netmask, lwip_htonl(0xffffff00)); // 255.255.255.0

    if (!get_config_addr(t, sym(gateway), &gw)) {
        // common best practices are: network + 1 or broadcast - 1,
        // so we will use latter if former is in use.
        u32_t ip_after_network = (netmask.addr & ip.addr) + lwip_htonl(1);
        if (ip_after_network == ip.addr)
            ip4_addr_set_u32(&gw, (~(netmask.addr) | ip.addr) - lwip_htonl(1));
        else
            ip4_addr_set_u32(&gw, ip_after_network);
    }

    if (trace) {
        rprintf("NET: static IP config for interface %s:\n", ifname);
        rprintf(" address\t%s\n", ip4addr_ntoa(&ip));
        rprintf(" netmask\t%s\n", ip4addr_ntoa(&netmask));
        rprintf(" gateway\t%s\n", ip4addr_ntoa(&gw));
    }

    netif_set_addr(n, &ip, &netmask, &gw);
    netif_set_up(n);
    return true;
}

static boolean get_static_ip6_config(tuple t, struct netif *n, const char *ifname, boolean trace)
{
    string b = get_string(t, sym(ip6addr));
    if (b && (buffer_length(b) <= MAX_IP6_ADDR_LEN)) {
        bytes len = buffer_length(b);
        char str[len + 1];
        runtime_memcpy(str, buffer_ref(b, 0), len);
        str[len] = '\0';
        ip6_addr_t ip6;
        if (ip6addr_aton(str, &ip6)) {
            if (trace)
                rprintf("NET: static IPv6 address for interface %s: %s\n", ifname, str);
            netif_add_ip6_address(n, &ip6, 0);
            return true;
        }
    }
    return false;
}

define_closure_function(0, 2, void, net_timeout_handler,
                 u64, expiry, u64, overruns)
{
    status_handler sh;
    sh = net.ip4_complete;
    net.ip4_complete = 0;
    if (sh)
        apply(sh, STATUS_OK);
}

void ip4_when_ready(status_handler complete, timestamp timeout)
{
    if (timeout == 0 || timeout > seconds(180))
        timeout = seconds(5);
    assert(net.ip4_complete == 0);
    net.ip4_complete = complete;
    register_timer(kernel_timers, &net.timeout, CLOCK_ID_MONOTONIC,
        timeout, false, 0, init_closure(&net.timeout_handler, net_timeout_handler));
    check_netif_ready(0);
}

void init_network_iface(tuple root) {
    struct netif *n;
    struct netif *default_iface = 0;
    boolean trace = !!(trace_get_flags(get(root, sym(trace))) & TRACE_OTHER);

    /* NETIF_FOREACH traverses interfaces in reverse order...so go by index */
    for (int i = 1; (n = netif_get_by_index(i)); i++) {
        if (netif_is_loopback(n)) {
            netif_unref(n);
            continue;
        }

        char ifname[4];
        netif_name_cpy(ifname, n);

        tuple t = get_tuple(root, sym_this(ifname));
        if (!t) {
            /* If this is the first interface and there is no config tuple
               under its name, default to looking for static config at the
               root level. This usage should be deprecated. */
            if (!runtime_memcmp(ifname, "en1", 3))
                t = root;
        }

        u64 mtu;
        if (t) {
            if (get_u64(t, sym(mtu), &mtu)) {
                if (mtu < U64_FROM_BIT(16)) {
                    if (trace)
                        rprintf("NET: setting MTU for interface %s to %ld\n", ifname, mtu);
                    n->mtu = mtu;
                } else {
                    rprintf("NET: invalid MTU %ld for interface %s; ignored\n", mtu, ifname);
                }
            }

            if (get(t, sym(default))) {
                rprintf("NET: setting interface %s as default\n", ifname);
                default_iface = n;
            }
        }

        n->output_ip6 = ethip6_output;
        netif_create_ip6_linklocal_address(n, 1);
        netif_set_flags(n, NETIF_FLAG_MLD6);
        if (!default_iface)
            default_iface = n;

        if (!t || !get_static_config(t, n, ifname, trace)) {
            if (trace)
                rprintf("NET: starting DHCP for interface %s\n", ifname);
            dhcp_start(n);
        }
        if (!t || !get_static_ip6_config(t, n, ifname, trace)) {
            if (trace)
                rprintf("NET: starting DHCPv6 for interface %s\n", ifname);
            dhcp6_enable_stateful(n);
        }
        netif_unref(n);
    }

    if (default_iface) {
        netif_set_default(default_iface);

        /* Set a default DNS server for any kernel (or klib) code that may need to resolve host
         * names. The DNS server can be overwritten via DHCP. */
        ip_addr_t dns_server = IPADDR4_INIT_BYTES(1, 1, 1, 1);
        dns_setserver(0, &dns_server);
    } else {
        rprintf("NET: no network interface found\n");
    }
}

extern void lwip_init();

void init_net(kernel_heaps kh)
{
    heap h = heap_general(kh);
    heap backed = (heap)heap_linear_backed(kh);
    boolean is_lowmem = is_low_memory_machine();
    int lwip_alloc_order = is_lowmem ? MAX_LOWMEM_LWIP_ALLOC_ORDER : MAX_LWIP_ALLOC_ORDER;
    bytes pagesize = is_lowmem ? U64_FROM_BIT(lwip_alloc_order + 1) : PAGESIZE_2M;
    lwip_heap = allocate_mcache(h, backed, 5, lwip_alloc_order, pagesize);
    assert(lwip_heap != INVALID_ADDRESS);
    lwip_heap = locking_heap_wrapper(h, lwip_heap);
    assert(lwip_heap != INVALID_ADDRESS);
    init_timer(&net.timeout);
    lwip_init();
    BSS_RO_AFTER_INIT NETIF_DECLARE_EXT_CALLBACK(netif_callback);
    netif_add_ext_callback(&netif_callback, lwip_ext_callback);
}
