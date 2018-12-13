#include <runtime.h>
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

/* We could dispatch lwip timer callbacks as thunks, but breaking it
   out here gives us a single point of entry for debugging. */
static CLOSURE_2_0(dispatch_lwip_timer, void, lwip_cyclic_timer_handler, const char *);
void dispatch_lwip_timer(lwip_cyclic_timer_handler handler, const char * name)
{
#ifdef LWIP_DEBUG
    lwip_debug("dispatching timer for %s\n", name);
#endif
    handler();
}

void sys_timeouts_init(void)
{
    int n = sizeof(net_lwip_timers) / sizeof(struct net_lwip_timer);
    for (int i = 0; i < n; i++) {
        struct net_lwip_timer * t = (struct net_lwip_timer *)&net_lwip_timers[i];
        register_periodic_timer(milliseconds(t->interval_ms),
                                closure(lwip_heap, dispatch_lwip_timer, t->handler, t->name));
#ifdef LWIP_DEBUG
        lwip_debug("registered %s timer with period of %d ms\n", t->name, t->interval_ms);
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
    return allocate_zero(lwip_heap, size);
}

void lwip_deallocate(void *x)
{
    /* no size info; mcache won't care */
    deallocate(lwip_heap, x, -1ull);
}

extern void lwip_init();

void init_net(kernel_heaps kh)
{
    heap h = heap_general(kh);
    heap backed = heap_backed(kh);
    lwip_heap = allocate_mcache(h, backed, 5, 11, PAGESIZE);
    lwip_init();
}
