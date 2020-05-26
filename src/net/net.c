#include <kernel.h>
#include <lwip.h>
#include <lwip/priv/tcp_priv.h>

static heap lwip_heap;

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
};

static struct net_lwip_timer net_lwip_timers[] = {
    {TCP_TMR_INTERVAL, tcp_tmr, "tcp"},
    {IP_TMR_INTERVAL, ip_reass_tmr, "ip"},
    {ARP_TMR_INTERVAL, etharp_tmr, "arp"},
    {DHCP_COARSE_TIMER_MSECS, dhcp_coarse_tmr, "dhcp coarse"},
    {DHCP_FINE_TIMER_MSECS, dhcp_fine_tmr, "dhcp fine"},
};

closure_function(2, 1, void, dispatch_lwip_timer,
                 lwip_cyclic_timer_handler, handler, const char *, name,
                 u64, overruns /* ignored */)
{
#ifdef LWIP_DEBUG
    lwip_debug("dispatching timer for %s\n", bound(name));
#endif
    bound(handler)();
}

void sys_timeouts_init(void)
{
    int n = sizeof(net_lwip_timers) / sizeof(struct net_lwip_timer);
    for (int i = 0; i < n; i++) {
        struct net_lwip_timer * t = (struct net_lwip_timer *)&net_lwip_timers[i];
        timestamp interval = milliseconds(t->interval_ms);
        register_timer(runloop_timers, CLOCK_ID_MONOTONIC, interval, false, interval,
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
    void *p = allocate_zero(lwip_heap, size);
    return ((p != INVALID_ADDRESS) ? p : 0);
}

void lwip_deallocate(void *x)
{
    /* no size info; mcache won't care */
    deallocate(lwip_heap, x, -1ull);
}

void lwip_status_callback(struct netif *netif)
{
    u8 *n = (u8 *)&netif->ip_addr;
    rprintf("assigned: %d.%d.%d.%d\n", n[0], n[1], n[2], n[3]);
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

int lwip_strncmp(const char *x, const char *y, unsigned long len)
{
    for (int i = 0; i < len; i++) {
        if ((*x) != (*y)) return -1;
        if ((!*x) || (!*y)) return -1;
    }
    return 0;
}

#define MAX_ADDR_LEN 20
static boolean get_config_addr(tuple root, symbol s, ip4_addr_t *addr)
{
    value v = table_find(root, s);
    if (!v || tagof(v) == tag_tuple)
        return false;
    int len = MIN(buffer_length((buffer)v), MAX_ADDR_LEN);
    char str[MAX_ADDR_LEN + 1];
    runtime_memcpy(str, buffer_ref((buffer)v, 0), len);
    str[len] = '\0';
    if (ip4addr_aton(str, addr) == 1)
        return true;
    return false;
}

static boolean get_static_config(tuple root, struct netif *n, boolean trace) {
    ip4_addr_t ip;
    ip4_addr_t netmask;
    ip4_addr_t gw;

    if (!get_config_addr(root, sym(ipaddr), &ip) ||
        !get_config_addr(root, sym(gateway), &gw) ||
        !get_config_addr(root, sym(netmask), &netmask))
        return false;

    if (trace) {
        rprintf("NET: static IP config:\n");
        rprintf(" address\t%s\n", ip4addr_ntoa(&ip));
        rprintf(" netmask\t%s\n", ip4addr_ntoa(&netmask));
        rprintf(" gateway\t%s\n", ip4addr_ntoa(&gw));
    }
    netif_set_addr(n, &ip, &netmask, &gw);
    netif_set_up(n);
    return true;
}

void init_network_iface(tuple root) {
    struct netif *n = netif_find("en1");
    if (!n) {
        rprintf("no network interface found\n");
        return;
    }

    boolean trace = table_find(root, sym(trace)) != 0;
    value v = table_find(root, sym(mtu));
    if (v) {
        u64 mtu;
        if (u64_from_value(v, &mtu)) {
            if (mtu < U64_FROM_BIT(16)) {
                if (trace)
                    rprintf("NET: setting MTU for interface %c%c%d to %ld\n",
                            n->name[0], n->name[1], n->num, mtu);
                n->mtu = mtu;
            } else {
                msg_err("invalid MTU %ld; ignored\n", mtu);
            }
        }
    }

    netif_set_default(n);
    if (!get_static_config(root, n, trace)) {
        dhcp_start(n);
    }
}

extern void lwip_init();

void init_net(kernel_heaps kh)
{
    heap h = heap_general(kh);
    heap backed = heap_backed(kh);
    lwip_heap = allocate_mcache(h, backed, 5, 11, PAGESIZE);
    lwip_init();
}
