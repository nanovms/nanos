#include <runtime.h>
#include <x86_64.h>
#include <page.h>

#define XENNET_DEBUG
#ifdef XENNET_DEBUG
#define xennet_debug(x, ...) do {rprintf("XNET: " x "\n", ##__VA_ARGS__);} while(0)
#else
#define xennet_debug(x, ...)
#endif

#include "xen_internal.h"

#define memset runtime_memset   /* for ring init in ring.h */
#include "io/netif.h"

/*
  - grant calls

  
  - interface
  init
  probe
  attach
  detach
  resume
  - initialize rings
  - set up grant table entries for rings
  - allocate event channel
  - 
  suspend
*/

/* We're going to attempt to manage the "xenbus" device initialization
   sequence using synchronous updates of the device's status tuple. In
   other words, we're aiming to avoid using an asynchronous process
   based on XS_WATCH notifications. This means that we will miss any
   sort of hotplug-type events for network devices. Given our short
   term needs, there appears to be no need to support such
   configuration changes. We can always revisit this later and mimic
   the more robust xenbus state machine used in Linux and NetBSD,
   though it is doubtful at this point that we'll ever care to. */

#define MAC_LEN 6 // XXX
typedef struct xennet_dev {
    int if_id;
    domid_t backend_id;
    buffer backend;

    u8 mac[MAC_LEN];
    netif_tx_front_ring_t tx_ring;
    netif_rx_front_ring_t rx_ring;

    u32 evtchn;
    grant_ref_t tx_ring_gntref;
    grant_ref_t rx_ring_gntref;

    /* XXX will need a lock if updated via xenstore watch */
    tuple meta;
} *xennet_dev;

#if 0
static boolean xennet_resume(xennet_dev dev)
{
    dev->rx_ring_gntref = -1;
    dev->tx_ring_gntref = -1;

    zero(dev->rx_ring.sring, PAGESIZE);
    SHARED_RING_INIT(dev->rx_ring.sring);
    FRONT_RING_INIT(&dev->rx_ring, dev->rx_ring.sring, PAGESIZE);

    zero(dev->tx_ring.sring, PAGESIZE);
    SHARED_RING_INIT(dev->tx_ring.sring);
    FRONT_RING_INIT(&dev->tx_ring, dev->tx_ring.sring, PAGESIZE);

    u64 phys = physical_from_virtual(dev->rx_ring.sring);
    dev->rx_ring_gntref = xen_grant_access(0, phys, false);
    phys = physical_from_virtual(dev->tx_ring.sring);
    dev->tx_ring_gntref = xen_grant_access(0, phys, false);
    if (dev->rx_ring_gntref == 0 || dev->tx_ring_gntref == 0) {
        msg_err("failed to obtain grant references for rings\n");
        return false;
    }

    return true;
}
#endif

/* policy: meta becomes property of driver (unless failure status) */
static status xennet_attach(kernel_heaps kh, int id, tuple meta)
{
    heap h = heap_general(kh);
    xennet_dev xd;
    value v;
    status s = STATUS_OK;

    xd = allocate(h, sizeof(struct xennet_dev));
    assert(xd != INVALID_ADDRESS);

    xd->if_id = id;

    u64 val = infinity;
    v = table_find(meta, sym(backend-id));
    if (v)
        u64_from_value(v, &val);
    if (val == infinity) {
        s = timm("result", "unable to parse backend-id");
        goto out_dealloc_xd;
    }
    xd->backend_id = val;
    xennet_debug("backend id is %d", xd->backend_id);

    v = table_find(meta, sym(backend));
    if (!v || tagof(v) == tag_tuple) {
        s = timm("result", "unable to parse backend path");
        goto out_dealloc_xd;
    }
    xd->backend = (buffer)v;
    xennet_debug("backend path is %b", xd->backend);

    /* allocate shared rings */
    assert((xd->rx_ring.sring = allocate(heap_backed(kh), PAGESIZE)) != INVALID_ADDRESS);
    assert((xd->tx_ring.sring = allocate(heap_backed(kh), PAGESIZE)) != INVALID_ADDRESS);
    
    /* get MAC address */
    
    /* initialize rx buffers */

    return s;
  out_dealloc_xd:
    deallocate(h, xd, sizeof(struct xennet_dev));
    return s;
}
    
static CLOSURE_1_2(xennet_probe, boolean, kernel_heaps, int, tuple);
static boolean xennet_probe(kernel_heaps kh, int id, tuple meta)
{
    xennet_debug("probe for id %d, meta: %v\n", id, meta);
    status s = xennet_attach(kh, id, meta);
    if (!is_ok(s)) {
        msg_err("attach failed with status %v\n", s);
        return false;
    }
    return true;
}

void init_xen_network(kernel_heaps kh)
{
    register_xen_driver("vif", closure(heap_general(kh), xennet_probe, kh));
}
