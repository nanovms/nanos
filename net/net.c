#include <runtime.h>
#include <lwip.h>

static heap lwip_heap;

// xx this is getting hit twice?
static CLOSURE_0_0(timeout, void);
static void timeout()
{
    netif_poll_all();
    sys_check_timeouts();
}


void *lwip_allocate(u64 size)
{
    return allocate_zero(lwip_heap, size);
}

void lwip_deallocate(void *x)
{
    /* no size info; mcache won't care */
    //    deallocate(lwip_heap, x, -1ull);
}

extern void lwip_init();

void init_net(kernel_heaps kh)
{
    heap h = heap_general(kh);
    heap backed = heap_backed(kh);
    lwip_heap = allocate_mcache(h, backed, 5, 11, PAGESIZE);
    lwip_init();
    register_periodic_timer(milliseconds(500), closure(h, timeout));
}
