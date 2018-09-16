#include <runtime.h>
#include "lwip/timeouts.h"


static heap lwip_heap;

static CLOSURE_0_0(timeout, void);
static void timeout()
{
    static int c;
    sys_check_timeouts();
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

void init_net(heap h, heap page_allocator)
{
    rprintf("init net page alloc %p\n", page_allocator);
    lwip_heap = allocate_mcache(h, page_allocator, 5, 11);
    lwip_init();
    register_periodic_timer(milliseconds(500), closure(h, timeout));
}
