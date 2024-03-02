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

typedef struct net_complete {
    struct list l;
    struct netif *netif;
    boolean ipv6;
    status_handler complete;
    struct timer timeout;
    closure_struct(timer_handler, timeout_handler);
} *net_complete;

static struct list net_complete_list;

static struct spinlock net_lock;

/* Pretty silly. LWIP offers lwip_cyclic_timers for use elsewhere, but
   says to use LWIP_ARRAYSIZE(), which isn't possible with an
   incomplete type. Plus there's no terminator to the array. So we
   just have to manually create our own here. Check
   lwip/src/core/timeouts.c if we switch on any other LWIP components
   and add an entry here accordingly. Barf */

struct net_lwip_timer {
    u64 interval_ms;
    lwip_cyclic_timer_handler handler;
#ifdef LWIP_DEBUG
    sstring name;
#endif
    struct timer t;
    closure_struct(timer_handler, timer_func);
};

#ifdef LWIP_DEBUG
#define NET_LWIP_TIMER_INIT(interval, func, name)   {interval, func, ss_static_init(name)}
#else
#define NET_LWIP_TIMER_INIT(interval, func, name)   {interval, func}
#endif

static struct net_lwip_timer net_lwip_timers[] = {
    NET_LWIP_TIMER_INIT(TCP_TMR_INTERVAL, tcp_tmr, "tcp"),
    NET_LWIP_TIMER_INIT(IP_TMR_INTERVAL, ip_reass_tmr, "ip"),
    NET_LWIP_TIMER_INIT(ARP_TMR_INTERVAL, etharp_tmr, "arp"),
    NET_LWIP_TIMER_INIT(DHCP_COARSE_TIMER_MSECS, dhcp_coarse_tmr, "dhcp coarse"),
    NET_LWIP_TIMER_INIT(DHCP_FINE_TIMER_MSECS, dhcp_fine_tmr, "dhcp fine"),
    NET_LWIP_TIMER_INIT(DNS_TMR_INTERVAL, dns_tmr, "dns"),
    NET_LWIP_TIMER_INIT(ND6_TMR_INTERVAL, nd6_tmr, "nd6"),
    NET_LWIP_TIMER_INIT(IP6_REASS_TMR_INTERVAL, ip6_reass_tmr, "ip6 reass"),
    NET_LWIP_TIMER_INIT(MLD6_TMR_INTERVAL, mld6_tmr, "mld6"),
    NET_LWIP_TIMER_INIT(DHCP6_TIMER_MSECS, dhcp6_tmr, "dhcp6"),
};

closure_func_basic(timer_handler, void, dispatch_lwip_timer,
                   u64 expiry, u64 overruns)
{
    struct net_lwip_timer *lt = struct_from_field(closure_self(), struct net_lwip_timer *,
                                                  timer_func);
#ifdef LWIP_DEBUG
    lwip_debug("dispatching timer for %s\n", lt->name);
#endif
    if (overruns == timer_disabled)
        closure_finish();
    else
        lt->handler();
}

void sys_timeouts_init(void)
{
    int n = sizeof(net_lwip_timers) / sizeof(struct net_lwip_timer);
    for (int i = 0; i < n; i++) {
        struct net_lwip_timer * t = (struct net_lwip_timer *)&net_lwip_timers[i];
        init_timer(&t->t);
        timestamp interval = milliseconds(t->interval_ms);
        register_timer(kernel_timers, &t->t, CLOCK_ID_MONOTONIC_RAW, interval, false, interval,
                       init_closure_func(&t->timer_func, timer_handler, dispatch_lwip_timer));
#ifdef LWIP_DEBUG
        lwip_debug("registered %s timer with period of %ld ms\n", t->name, t->interval_ms);
#endif
    }
}

void lwip_debug_sstring(sstring format, ...)
{
    vlist a;
    vstart(a, format);
    log_vprintf(ss("LWIP"), format, &a);
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

static boolean netif_ready(struct netif *n, boolean ipv6)
{
    if (!ipv6)
        return !ip_addr_isany(netif_ip_addr4(n));
    for (int i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++)
        if ((netif_ip6_addr_state(n, i) & IP6_ADDR_VALID) &&
            ip6_addr_isglobal(netif_ip6_addr(n, i)))
            return true;
    return false;
}

static void check_netif_ready(struct netif *netif, boolean ipv6)
{
    spin_lock(&net_lock);
    list_foreach(&net_complete_list, elem) {
        net_complete c = struct_from_field(elem, net_complete, l);
        if ((netif == c->netif) && (ipv6 == c->ipv6)) {
            if (netif_ready(netif, ipv6)) {
                list_delete(elem);
                spin_unlock(&net_lock);
                remove_timer(kernel_timers, &c->timeout, 0);
                deallocate(lwip_heap, c, sizeof(*c));
                return;
            }
            break;
        }
    }
    spin_unlock(&net_lock);
}

static void lwip_ext_callback(struct netif* netif, netif_nsc_reason_t reason,
                              const netif_ext_callback_args_t* args)
{
    char ifname_array[3];
    sstring ifname = {
        .ptr = ifname_array,
    };
    ifname.len = netif_name_cpy(ifname.ptr, netif);
    if (reason & LWIP_NSC_IPV4_ADDRESS_CHANGED) {
        u8 *n = (u8 *)&netif->ip_addr;
        rprintf("%s: assigned %d.%d.%d.%d\n", ifname, n[0], n[1], n[2], n[3]);
        check_netif_ready(netif, false);
    }
    if ((reason & LWIP_NSC_IPV6_ADDR_STATE_CHANGED) &&
       (netif_ip6_addr_state(netif, args->ipv6_addr_state_changed.addr_index) & IP6_ADDR_VALID)) {
        char addr[IP6ADDR_STRLEN_MAX];
        rprintf("%s: assigned %s\n", ifname,
                isstring(addr, ipaddr_ntoa_r(args->ipv6_addr_state_changed.address,
                                              addr, sizeof(addr))));
        check_netif_ready(netif, true);
    }
}

u32_t lwip_rand(void)
{
    return random_u64();
}

/* unsigned only ... don't imagine we'd have negative interface numbers! */
int lwip_atoi(sstring p)
{
    u64 i;
    return u64_from_value(alloca_wrap_sstring(p), &i) ? i : -1;
}

/* mildly unfortunate to add another level of indirection to resolve types
   that are equivalent ... maybe a runtime types.h would be in order */
void lwip_memcpy(void *a, const void *b, unsigned long len)
{
    runtime_memcpy(a, b, len);
}

void lwip_memset(void *x, unsigned char v, unsigned long len)
{
    runtime_memset(x, v, len);
}

int lwip_memcmp(const void *x, const void *y, unsigned long len)
{
    return runtime_memcmp(x, y, len);
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

bytes netif_name_cpy(char *dest, struct netif *netif)
{
    runtime_memcpy(dest, netif->name, sizeof(netif->name));
    dest[sizeof(netif->name)] = '0' + netif->num;
    return sizeof(netif->name) + 1;
}

static boolean get_config_addr(tuple root, symbol s, ip4_addr_t *addr)
{
    string v = get_string(root, s);
    if (!v)
        return false;
    if (ip4addr_aton(buffer_to_sstring(v), addr) == 1)
        return true;
    return false;
}

static boolean get_static_config(tuple t, struct netif *n, sstring ifname, boolean trace) {
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
        char addr[IP4ADDR_STRLEN_MAX];
        rprintf("NET: static IP config for interface %s:\n", ifname);
        rprintf(" address\t%s\n", isstring(addr, ip4addr_ntoa_r(&ip, addr, sizeof(addr))));
        rprintf(" netmask\t%s\n", isstring(addr, ip4addr_ntoa_r(&netmask, addr, sizeof(addr))));
        rprintf(" gateway\t%s\n", isstring(addr, ip4addr_ntoa_r(&gw, addr, sizeof(addr))));
    }

    netif_set_addr(n, &ip, &netmask, &gw);
    netif_set_up(n);
    return true;
}

static boolean get_static_ip6_config(tuple t, struct netif *n, sstring ifname, boolean trace)
{
    string b = get_string(t, sym(ip6addr));
    if (b) {
        sstring str = buffer_to_sstring(b);
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

closure_func_basic(timer_handler, void, net_timeout_handler,
                   u64 expiry, u64 overruns)
{
    net_complete c = struct_from_field(closure_self(), net_complete, timeout_handler);
    apply(c->complete, STATUS_OK);
    if (overruns == timer_disabled)
        return;
    spin_lock(&net_lock);
    if (list_inserted(&c->l)) {
        list_delete(&c->l);
        deallocate(lwip_heap, c, sizeof(*c));
    }
    spin_unlock(&net_lock);
}

static void net_complete_cfg(tuple t, symbol opt, struct netif *n, boolean ipv6, merge m)
{
    value v = get(t, opt);
    if (!v)
        return;
    u64 timeout;
    if (!u64_from_value(v, &timeout)) {
        rprintf("option '%b' has invalid time, ignoring\n", symbol_string(opt));
        return;
    }
    if (timeout == 0 || timeout > 180)
        timeout = 5;
    net_complete c = allocate(lwip_heap, sizeof(*c));
    assert(c != INVALID_ADDRESS);
    c->netif = n;
    c->ipv6 = ipv6;
    c->complete = apply_merge(m);
    spin_lock(&net_lock);
    list_push_back(&net_complete_list, &c->l);
    init_timer(&c->timeout);
    register_timer(kernel_timers, &c->timeout, CLOCK_ID_MONOTONIC, seconds(timeout), false, 0,
                   init_closure_func(&c->timeout_handler, rmnode_handler, net_timeout_handler));
    spin_unlock(&net_lock);
    check_netif_ready(n, ipv6);
}

void init_network_iface(tuple root, merge m) {
    struct netif *n;
    struct netif *default_iface = 0;
    boolean trace = !!(trace_get_flags(get(root, sym(trace))) & TRACE_OTHER);

    /* NETIF_FOREACH traverses interfaces in reverse order...so go by index */
    for (int i = 1; (n = netif_get_by_index(i)); i++) {
        if (netif_is_loopback(n)) {
            netif_unref(n);
            continue;
        }

        char ifname_array[3];
        sstring ifname = {
            .ptr = ifname_array,
        };
        ifname.len = netif_name_cpy(ifname.ptr, n);

        tuple t = get_tuple(root, sym_sstring(ifname));
        if (!t) {
            /* If this is the first interface and there is no config tuple
               under its name, default to looking for static config at the
               root level. This usage should be deprecated. */
            if (!runtime_memcmp(ifname.ptr, "en1", 3))
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
        if (t) {
            net_complete_cfg(t, sym_this("exec_wait_for_ip4_secs"), n, false, m);
            net_complete_cfg(t, sym_this("exec_wait_for_ip6_secs"), n, true, m);
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
    lwip_heap = kh->malloc;
    list_init(&net_complete_list);
    lwip_init();
    BSS_RO_AFTER_INIT NETIF_DECLARE_EXT_CALLBACK(netif_callback);
    netif_add_ext_callback(&netif_callback, lwip_ext_callback);
}
