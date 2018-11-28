#include <runtime.h>
#include <lwip.h>
#include <lwip/priv/tcp_priv.h>

static heap lwip_heap;

// ok, this is quite sad. lwip is happy to let you use your own timers,
// but the registration is done using this array. if you add components,
// check here

#if 0
CLOSURE_0_0(tcp_tmr, void);
CLOSURE_0_0(ip_reass_tmr, void);
CLOSURE_0_0(etharp_tmr, void);
CLOSURE_0_0(dhcp_coarse_tmr, void);
CLOSURE_0_0(dhcp_fine_tmr, void);
#endif

static CLOSURE_1_0(dispatch_lwip_timer, void, lwip_cyclic_timer_handler);
void dispatch_lwip_timer(lwip_cyclic_timer_handler handler)
{
    lwip_debug("lwip timer dispatch %p\n", handler);
    handler();
}

void sys_timeouts_init(void)
{
    register_periodic_timer(milliseconds(TCP_TMR_INTERVAL), closure(lwip_heap, dispatch_lwip_timer, tcp_tmr));
    register_periodic_timer(milliseconds(IP_TMR_INTERVAL), closure(lwip_heap, dispatch_lwip_timer, ip_reass_tmr));
    register_periodic_timer(milliseconds(ARP_TMR_INTERVAL), closure(lwip_heap, dispatch_lwip_timer, etharp_tmr));
    register_periodic_timer(milliseconds(DHCP_COARSE_TIMER_MSECS), closure(lwip_heap, dispatch_lwip_timer, dhcp_coarse_tmr));
    register_periodic_timer(milliseconds(DHCP_FINE_TIMER_MSECS), closure(lwip_heap, dispatch_lwip_timer, dhcp_fine_tmr));
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
