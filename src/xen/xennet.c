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
#define xen_wmb write_barrier
#define xen_mb memory_barrier
#include "io/netif.h"
#undef memset

#include "lwip/opt.h"
#include "lwip/def.h"
#include "lwip/mem.h"
#include "lwip/pbuf.h"
#include "lwip/etharp.h"
#include "lwip/snmp.h"
#include "netif/ethernet.h"

#define GRANT_INVALID -1

#define XENNET_RX_RING_SIZE                                                \
  (__RD32(((PAGESIZE) - __builtin_offsetof(struct netif_rx_sring, ring)) / \
          sizeof(((struct netif_rx_sring *)0)->ring[0])))
#define XENNET_TX_RING_SIZE                                                \
  (__RD32(((PAGESIZE) - __builtin_offsetof(struct netif_tx_sring, ring)) / \
          sizeof(((struct netif_tx_sring *)0)->ring[0])))

struct xennet_dev;

typedef struct xennet_dev *xennet_dev;

typedef struct xennet_rxbuf {
    struct pbuf_custom p;       /* must be first field */
    struct list l;              /* rx_free or rx_inuse */
    xennet_dev xd;
    void * buf;                 /* virtual */
    u64 paddr;
    u16 idx;
    grant_ref_t gntref;
} *xennet_rxbuf;

typedef struct xennet_txbuf {
    struct pbuf *p;
    struct list l;
    u16 frags_queued;
    u16 start_idx;
    u16 npages;
    u16 nextpage;
    buffer pages;               /* array of xennet_txpages */
} *xennet_txbuf;

typedef struct xennet_txpage {
    xennet_txbuf txb;
    u64 paddr;
    u16 offset;
    u16 len;
    u16 idx;
    boolean end;                /* of frame */
    grant_ref_t gntref;
} *xennet_txpage;
    
struct xennet_dev {
    heap h;
    heap contiguous;                /* physically */
    int if_id;
    domid_t backend_id;
    buffer frontend;
    buffer backend;

    u8 mac[ETHARP_HWADDR_LEN];
    u16 mtu;
    netif_rx_front_ring_t rx_ring;
    netif_tx_front_ring_t tx_ring;

    xennet_rxbuf  rxbufs[XENNET_RX_RING_SIZE];
    xennet_txpage txpages[XENNET_TX_RING_SIZE];

    evtchn_port_t evtchn;
    grant_ref_t tx_ring_gntref;
    grant_ref_t rx_ring_gntref;

    /* lwIP */
    struct netif *netif;
    u16 rxbuflen;

    /* XXX need locks / int disable for now */
    struct list rx_free;
    struct list rx_inuse;
    struct list tx_pending;     /* awaiting ring queueing (head may be partial) */
    struct list tx_queued;      /* complete request made; awaiting completion */
    struct list tx_free;
};

static status xennet_inform_backend(xennet_dev xd)
{
    status s = STATUS_OK;
    xennet_debug("%s: dev id %d", __func__, xd->if_id);

    u32 tx_id;
    boolean again = false;
    char *node;
    do {
        s = xenstore_transaction_start(&tx_id);
        if (!is_ok(s))
            return s;

        node = "vifname";
        s = xenstore_sync_printf(tx_id, xd->frontend, node, "vif%d", xd->if_id);
        if (!is_ok(s))
            goto abort;

        node = "rx-ring-ref";
        s = xenstore_sync_printf(tx_id, xd->frontend, node, "%d", xd->rx_ring_gntref);
        if (!is_ok(s))
            goto abort;

        node = "tx-ring-ref";
        s = xenstore_sync_printf(tx_id, xd->frontend, node, "%d", xd->tx_ring_gntref);
        if (!is_ok(s))
            goto abort;

        node = "request-rx-copy";
        s = xenstore_sync_printf(tx_id, xd->frontend, node, "%d", 1);
        if (!is_ok(s))
            goto abort;

        node = "feature-rx-notify";
        s = xenstore_sync_printf(tx_id, xd->frontend, node, "%d", 1);
        if (!is_ok(s))
            goto abort;

        node = "event-channel";
        s = xenstore_sync_printf(tx_id, xd->frontend, node, "%d", xd->evtchn);
        if (!is_ok(s))
            goto abort;

        s = xenstore_transaction_end(tx_id, false);
        if (!is_ok(s)) {
            /* XXX check for EAGAIN */
            goto abort;
        }
    } while (again);
    return s;
  abort:
    xenstore_transaction_end(tx_id, true);
    return timm("result", "%s: transaction aborted; interim error \"%v\""
                " while writing to node \"%s\"", __func__, s, node);
}

static void xennet_return_txbuf(xennet_dev xd, xennet_txbuf txb)
{
    txb->p = 0;
    txb->frags_queued = 0;
    txb->start_idx = -1;
    txb->npages = 0;
    txb->nextpage = 0;
    vector_clear(txb->pages);
    u64 flags = irq_disable_save();
    list_delete(&txb->l);
    list_insert_before(&xd->tx_free, &txb->l);
    irq_restore(flags);
}

void xennet_transmit_reclaim(xennet_dev xd)
{
    int more;

    do {
        RING_IDX cons = xd->tx_ring.rsp_cons;
        RING_IDX prod = xd->tx_ring.sring->rsp_prod;
        read_barrier();
        xennet_debug("%s: cons %d, prod %d", __func__, cons, prod);

        while (cons < prod) {
            u16 idx = cons & (XENNET_TX_RING_SIZE - 1);
            netif_tx_response_t *tx = RING_GET_RESPONSE(&xd->tx_ring, cons);
            xennet_txpage txp = xd->txpages[idx];
            assert(txp);
            assert(txp->gntref != GRANT_INVALID);
            xd->txpages[idx] = 0;
            xen_revoke_page_access(txp->gntref);
            txp->gntref = GRANT_INVALID;

            if (txp->end) {
                pbuf_free(txp->txb->p);
                xennet_return_txbuf(xd, txp->txb);
            }

            assert(tx->id == idx);
            if (tx->status != NETIF_RSP_OKAY) {
                /* XXX error, drop counters */
                rprintf("tx resp id %d, status %d\n", idx, tx->status);
            }

            cons++;
        }
        write_barrier();
        xd->tx_ring.rsp_cons = cons;
        RING_FINAL_CHECK_FOR_RESPONSES(&xd->tx_ring, more);
    } while (more);
}

static xennet_txpage xennet_fill_tx_request(xennet_dev xd, netif_tx_request_t *tx, u16 idx)
{
    /* XXX spin lock */
    list l = list_get_next(&xd->tx_pending);
    if (!l)
        return 0;
    xennet_txbuf txb = struct_from_list(l, xennet_txbuf, l);
    xennet_txpage txp = buffer_ref(txb->pages, sizeof(struct xennet_txpage) * txb->nextpage);
    tx->offset = txp->offset;
    tx->flags = txp->end ? 0 : NETTXF_more_data;
    tx->id = idx;
    tx->size = txp->len;
    tx->gref = xen_grant_page_access(xd->backend_id, txp->paddr, true);
    assert(tx->gref);          /* XXX */

    if (txp->end) {
        u64 flags = irq_disable_save();
        list_delete(l);
        list_insert_before(&xd->tx_queued, l);
        irq_restore(flags);
    } else {
        txb->nextpage++;
        assert(txb->nextpage < txb->npages);
    }
    return txp;
}

static void xennet_service_tx_ring(xennet_dev xd)
{
    xennet_transmit_reclaim(xd);

    RING_IDX prod = xd->tx_ring.req_prod_pvt;
    RING_IDX prod_end = xd->tx_ring.rsp_cons + XENNET_TX_RING_SIZE;

    xennet_debug("%s: prod %d, prod_end %d", __func__, prod, prod_end);
    while (prod < prod_end) {
        u16 idx = prod & (XENNET_TX_RING_SIZE - 1);
        netif_tx_request_t *tx = RING_GET_REQUEST(&xd->tx_ring, prod);
        assert(!xd->txpages[idx]);
        xd->txpages[idx] = xennet_fill_tx_request(xd, tx, idx);
        if (!xd->txpages[idx])
            break;
        rprintf("prod %d: txp %p, offset %d, size %d, id %d, flags %x, gref %d\n",
                prod, xd->txpages[idx], tx->offset, tx->size, tx->id, tx->flags, tx->gref);
        rprintf("cons %d\n", xd->tx_ring.rsp_cons);
        prod++;
    }
    xd->tx_ring.req_prod_pvt = prod;
    xennet_debug("queueing done");
    rprintf("cons %d\n", xd->tx_ring.rsp_cons);

    write_barrier();

    int notify;
    RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&xd->tx_ring, notify);
    if (notify) {
        rprintf("tx notify\n");
        xen_notify_evtchn(xd->evtchn);
    }
}

static xennet_txbuf xennet_get_txbuf(xennet_dev xd)
{
    u64 flags = irq_disable_save();
    list l = list_get_next(&xd->tx_free);
    if (l) {
        list_delete(l);
        irq_restore(flags);
        return struct_from_list(l, xennet_txbuf, l);
    }
    irq_restore(flags);

    /* allocate new buffer */
    xennet_txbuf txb = allocate(xd->h, sizeof(struct xennet_txbuf));
    if (txb == INVALID_ADDRESS)
        return txb;
    txb->p = 0;
    list_init(&txb->l);
    txb->frags_queued = 0;
    txb->start_idx = -1;
    txb->npages = 0;
    txb->nextpage = 0;
    txb->pages = allocate_buffer(xd->h, sizeof(struct xennet_txpage) * 4);
    return txb;
}

/* We could just walk the pages using pointers in the txb, but we need
   somewhere to stash the phys addrs and grant references anyway, so
   just build an array of page descriptors.
*/
static void xennet_txbuf_add_pages(xennet_txbuf txb, struct pbuf *p)
{
    for (struct pbuf *q = p; q != 0; q = q->next) {
        u64 va = u64_from_pointer(q->payload);
        u64 remain = q->len;
        u64 vpage = va & ~PAGEMASK;
        u64 offset = va & PAGEMASK;
        u64 len = MIN(PAGESIZE - offset, remain);

        xennet_txpage txp;
        do {
            assert ((vpage & (PAGESIZE - 1)) == 0); // XXX temp
            extend_total(txb->pages, sizeof(struct xennet_txpage) * (txb->npages + 1));
            txp = buffer_ref(txb->pages, sizeof(struct xennet_txpage) * txb->npages);
            txp->txb = txb;
            txp->paddr = physical_from_virtual(pointer_from_u64(vpage));
            assert(txp->paddr != INVALID_PHYSICAL);
            txp->offset = offset;
            txp->len = len;
            txb->npages++;
            vpage += PAGESIZE;
            offset = 0;
            remain -= len;
            len = MIN(PAGESIZE, remain);
        } while (remain > 0);
        txp->end = true;
    }
}

/* enqueue tx buffer for subsequent ring processing */
static err_t xennet_linkoutput(struct netif *netif, struct pbuf *p)
{
    xennet_dev xd = (xennet_dev)netif->state;
    xennet_debug("%s: id %d, pbuf %p", __func__, xd->if_id, p);

#if 0
    XenbusState state;
    status s = xenbus_get_state(xd->backend, &state);
    if (is_ok(s)) {
        xennet_debug("backend state: %d", state);
    }
#endif

    xennet_txbuf txb = xennet_get_txbuf(xd);
    pbuf_ref(p);
    txb->p = p;
    xennet_txbuf_add_pages(txb, p);

    u64 flags = irq_disable_save();
    list_insert_before(&xd->tx_pending, &txb->l);
    irq_restore(flags);
    
    MIB2_STATS_NETIF_ADD(netif, ifoutoctets, p->tot_len);
    if (((u8_t *)p->payload)[0] & 1) {
        /* broadcast or multicast packet*/
        MIB2_STATS_NETIF_INC(netif, ifoutnucastpkts);
    } else {
        /* unicast packet */
        MIB2_STATS_NETIF_INC(netif, ifoutucastpkts);
    }
    /* increase ifoutdiscards or ifouterrors on error */

    LINK_STATS_INC(link.xmit);

    xennet_service_tx_ring(xd);

    return ERR_OK;
}

/* XXX make common? */
static void status_callback(struct netif *netif)
{
    u8 *n = (u8 *)&netif->ip_addr;
    rprintf("assigned: %d.%d.%d.%d\n", n[0], n[1], n[2], n[3]);
}

static err_t xennet_netif_init(struct netif *netif)
{
    xennet_dev xd = (xennet_dev)netif->state;
    netif->hostname = "uniboot"; // XXX fix in virtio too
    netif->name[0] = 'e';
    netif->name[1] = 'n';
    netif->output = etharp_output;
    netif->linkoutput = xennet_linkoutput;
    netif->hwaddr_len = ETHARP_HWADDR_LEN;
    netif->status_callback = status_callback;
    runtime_memcpy(netif->hwaddr, xd->mac, ETHARP_HWADDR_LEN);
    netif->mtu = xd->mtu;

    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP | NETIF_FLAG_UP;

    return ERR_OK;
}

static void xennet_return_rxbuf(struct pbuf *p)
{
    xennet_rxbuf xrp = (xennet_rxbuf)p;
    /* XXX reset fields */
    u64 flags = irq_disable_save();
    list_delete(&xrp->l);
    list_insert_before(&xrp->xd->rx_free, &xrp->l);
    irq_restore(flags);
}

static void xennet_service_rx_ring(xennet_dev xd)
{
    int more;

    do {
        RING_IDX cons = xd->rx_ring.rsp_cons;
        RING_IDX prod = xd->rx_ring.sring->rsp_prod;
        read_barrier();
        xennet_debug("%s: cons %d, prod %d", __func__, cons, prod);
    
        while (cons < prod) {
            u16 idx = cons & (XENNET_RX_RING_SIZE - 1);
            netif_rx_response_t *rx = RING_GET_RESPONSE(&xd->rx_ring, cons);
            xennet_rxbuf rxb = xd->rxbufs[idx];
            assert(rxb);
            assert(rxb->gntref != GRANT_INVALID);
            xd->rxbufs[idx] = 0;
            xen_revoke_page_access(rxb->gntref);
            rxb->gntref = GRANT_INVALID;

            assert(rx->id == idx);
            assert(rx->status >= 0);
            assert(rx->offset + rx->status <= PAGESIZE);

            rprintf("RX flags %x, status %d, offset %d, buf:\n%X",
                    rx->flags, rx->status, rx->offset,
                    alloca_wrap_buffer(rxb->p.pbuf.payload, rx->status + rx->offset));
            rxb->p.pbuf.len = rx->status;
            rxb->p.pbuf.tot_len = rx->status;
            rxb->p.pbuf.payload += rx->offset;

            if (xd->netif->input(&rxb->p.pbuf, xd->netif) != ERR_OK) {
                msg_err("rx drop by stack\n");
                xennet_return_rxbuf(&rxb->p.pbuf);
            }

            cons++;
        }
        write_barrier();
        xd->rx_ring.rsp_cons = cons;
        RING_FINAL_CHECK_FOR_RESPONSES(&xd->rx_ring, more);
    } while (more);
}

static xennet_rxbuf xennet_get_rxbuf(xennet_dev xd)
{
    u64 flags = irq_disable_save();
    list l = list_get_next(&xd->rx_free);
    if (l) {
        list_delete(l);
        list_insert_before(&xd->rx_inuse, l);
        irq_restore(flags);
        /* XXX reset headers / lwIP */
        return struct_from_list(l, xennet_rxbuf, l);
    }
    irq_restore(flags);

    /* allocate new buffer */
    xennet_rxbuf rxb = allocate(xd->h, sizeof(struct xennet_rxbuf));
    if (rxb == INVALID_ADDRESS)
        return rxb;
    rxb->xd = xd;
    rxb->buf = allocate(xd->contiguous, PAGESIZE); /* XXX multiple for large mtu */
    if (rxb->buf == INVALID_ADDRESS) {
        deallocate(xd->h, rxb, sizeof(struct xennet_rxbuf));
        return INVALID_ADDRESS;
    }
    rxb->paddr = physical_from_virtual(rxb->buf);
    assert(rxb->paddr != INVALID_PHYSICAL);
    rxb->idx = -1;
    rxb->gntref = GRANT_INVALID;
    rxb->p.custom_free_function = xennet_return_rxbuf;
    pbuf_alloced_custom(PBUF_RAW,
                        xd->rxbuflen,
                        PBUF_REF,
                        &rxb->p,
                        rxb->buf,
                        xd->rxbuflen);
    flags = irq_disable_save();
    list_insert_before(&xd->rx_inuse, &rxb->l);
    irq_restore(flags);
    return rxb;
}

static void xennet_populate_rx_ring(xennet_dev xd)
{
    RING_IDX prod = xd->rx_ring.req_prod_pvt;
    RING_IDX prod_end = xd->rx_ring.rsp_cons + XENNET_RX_RING_SIZE;

    xennet_debug("%s: prod %d, prod_end %d", __func__, prod, prod_end);
    while (prod < prod_end) {
        xennet_rxbuf rxb = xennet_get_rxbuf(xd);
        assert(rxb != INVALID_ADDRESS); /* XXX */

        u16 idx = prod & (XENNET_RX_RING_SIZE - 1);
        assert(!xd->rxbufs[idx]);
        xd->rxbufs[idx] = rxb;
        rxb->idx = idx;
        rxb->gntref = xen_grant_page_access(xd->backend_id, rxb->paddr, false);
        assert(rxb->gntref);    /* XXX how to handle depletion? */

        netif_rx_request_t *rx = RING_GET_REQUEST(&xd->rx_ring, prod);
        rx->id = idx;
        rx->pad = 0;
        rx->gref = rxb->gntref;
        
        prod++;
    }
    xd->rx_ring.req_prod_pvt = prod;
    xennet_debug("fill done");

    write_barrier();

    int notify;
    RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&xd->rx_ring, notify);
    if (notify) {
        rprintf("rx notify\n");
        xen_notify_evtchn(xd->evtchn);
    }
}

static CLOSURE_1_0(xennet_event_handler, void, xennet_dev);
static void xennet_event_handler(xennet_dev xd)
{
    xennet_service_rx_ring(xd);
    xennet_populate_rx_ring(xd);
    int rv = xen_unmask_evtchn(xd->evtchn);
    if (rv != 0) {
        rprintf("%s: failed to unmask evtchn %d, rv %d\n", xd->evtchn, rv);
    }
}

static status xennet_enable(xennet_dev xd)
{
    status s = STATUS_OK;
    xennet_debug("%s: dev id %d", __func__, xd->if_id);

    u64 val;
    s = xenstore_read_u64(0, xd->backend, "feature-rx-copy", &val);
    if (!is_ok(s)) {
        s = timm("result", "failed to verify presence of rx-copy feature: %v", s);
        return s;
    }

    if (!val) {
        s = timm("result", "rx-copy not supported by backend");
        return s;
    }

    xd->rx_ring_gntref = GRANT_INVALID;
    xd->tx_ring_gntref = GRANT_INVALID;

    /* allocate shared rings */
    netif_rx_sring_t *rx_ring = allocate_zero(xd->contiguous, PAGESIZE);
    netif_tx_sring_t *tx_ring = allocate_zero(xd->contiguous, PAGESIZE);
    assert(rx_ring != INVALID_ADDRESS);
    assert(tx_ring != INVALID_ADDRESS);
    
    SHARED_RING_INIT(rx_ring);
    FRONT_RING_INIT(&xd->rx_ring, rx_ring, PAGESIZE);
    SHARED_RING_INIT(tx_ring);
    FRONT_RING_INIT(&xd->tx_ring, tx_ring, PAGESIZE);

    zero(xd->rxbufs, sizeof(xd->rxbufs));
    zero(xd->txpages, sizeof(xd->txpages));
    
    u64 phys = physical_from_virtual(rx_ring);
    xd->rx_ring_gntref = xen_grant_page_access(xd->backend_id, phys, false);
    phys = physical_from_virtual(tx_ring);
    xd->tx_ring_gntref = xen_grant_page_access(xd->backend_id, phys, false);
    if (xd->rx_ring_gntref == 0 || xd->tx_ring_gntref == 0) {
        s = timm("result", "failed to obtain grant references for rings");
        goto out_dealloc;
    }

    s = xen_allocate_evtchn(xd->backend_id, &xd->evtchn);
    if (!is_ok(s))
        goto out_dealloc;

    xen_register_evtchn_handler(xd->evtchn, closure(xd->h, xennet_event_handler, xd));

    xennet_debug("rx ring grantref %d, tx ring grantref %d, evtchn %d",
                 xd->rx_ring_gntref, xd->tx_ring_gntref, xd->evtchn);

    /* initialize rx buffers */
    xennet_populate_rx_ring(xd);

    s = xennet_inform_backend(xd);
    if (!is_ok(s))
        goto out_dealloc_rx_buffers;

    s = xenbus_set_state(0, xd->frontend, XenbusStateConnected);
    if (!is_ok(s))
        goto out_dealloc_rx_buffers;

    netif_add(xd->netif,
              0, 0, 0,
              xd,
              xennet_netif_init,
              ethernet_input);

    /* we're kind of always up ... start rx now */
    xd->rx_ring.sring->rsp_event = xd->rx_ring.rsp_cons + 1;
    write_barrier();
    int rv = xen_unmask_evtchn(xd->evtchn);
    if (rv < 0) {
        s = timm("result", "failed to unmask event channel %d: rv %d", xd->evtchn, rv);
        goto out_dealloc_rx_buffers;
    }
    rv = xen_notify_evtchn(xd->evtchn);
    if (rv < 0) {
        s = timm("result", "failed to notify event channel %d: rv %d", xd->evtchn, rv);
        goto out_dealloc_rx_buffers;
    }

    return s;
    /* XXX dealloc */
  out_dealloc_rx_buffers:
  out_dealloc:
    return s;
}

/* policy: meta becomes property of driver (unless failure status) */
static status xennet_attach(kernel_heaps kh, int id, buffer frontend, tuple meta)
{
    xennet_debug("%s: id %d, frontend %b, meta %v", __func__, id, frontend, meta);
    heap h = heap_general(kh);
    xennet_dev xd;
    value v;
    status s = STATUS_OK;

    xd = allocate(h, sizeof(struct xennet_dev));
    assert(xd != INVALID_ADDRESS);

    xd->h = heap_general(kh);
    xd->contiguous = heap_backed(kh);
    xd->if_id = id;
    xd->frontend = frontend;

    u64 val = infinity;
    v = table_find(meta, sym(backend-id));
    if (v)
        u64_from_value(v, &val);
    if (val == infinity) {
        s = timm("result", "unable to find backend-id");
        goto out_dealloc_xd;
    }
    xd->backend_id = val;
    xennet_debug("backend id is %d", xd->backend_id);

    v = table_find(meta, sym(backend));
    if (!v || tagof(v) == tag_tuple) {
        s = timm("result", "unable to find backend path");
        goto out_dealloc_xd;
    }
    xd->backend = (buffer)v;
    xennet_debug("backend path is %b", xd->backend);

    xd->netif = allocate(h, sizeof(struct netif));
    assert(xd->netif != INVALID_ADDRESS);

    /* get MAC address */
    v = table_find(meta, sym(mac));
    if (!v || tagof(v) == tag_tuple) {
        s = timm("result", "unable to find mac address");
        goto out_dealloc_xd;
    }

    /* destructive, but that's ok */
    for (int i = 0; i < ETHARP_HWADDR_LEN; i++) {
        u64 val;
        if (!parse_int((buffer)v, 16, &val)) {
            s = timm("result", "unable to parse mac address");
            goto out_dealloc_xd;
        }
        xd->mac[i] = val;
        if (i < ETHARP_HWADDR_LEN - 1)
            pop_u8((buffer)v);
    }

    xennet_debug("MAC address %2x:%2x:%2x:%2x:%2x:%2x",
                 xd->mac[0], xd->mac[1], xd->mac[2],
                 xd->mac[3], xd->mac[4], xd->mac[5]);

    /* use specified MTU, else default */
    xd->mtu = 1500;
    /* XXX t2 reports ~9k MTU which exceeds pagesize; sort out later */
#if 0
    v = table_find(meta, sym(mtu));
    if (v && tagof(v) != tag_tuple) {
        u64 val;
        if (u64_from_value(v, &val))
            xd->mtu = val;
    }
#endif
    xennet_debug("MTU %d", xd->mtu);

    /* figure rx buffer size */
    xd->rxbuflen = sizeof(struct eth_hdr) + sizeof(struct eth_vlan_hdr) + xd->mtu;

    list_init(&xd->rx_free);
    list_init(&xd->rx_inuse);
    list_init(&xd->tx_pending);
    list_init(&xd->tx_queued);
    list_init(&xd->tx_free);

    /* check if the backend is ready for us
       XXX This should poll or, better yet, set up an asynchronous xenstore watch...
     */
    XenbusState state;
    s = xenbus_get_state(xd->backend, &state);
    if (!is_ok(s))
        goto out_dealloc_xd;

    if (state != XenbusStateInitWait) {
        s = timm("result", "xennet %d backend not ready yet (state %d)", id, state);
        goto out_dealloc_xd;
    }

    s = xennet_enable(xd);
    if (!is_ok(s)) {
        s = timm("result", "xennet %d unable to start: %v", id, s);
        goto out_dealloc_xd;
    }
    return s;
  out_dealloc_xd:
    deallocate(h, xd, sizeof(struct xennet_dev));
    return s;
}
    
static CLOSURE_1_3(xennet_probe, boolean, kernel_heaps, int, buffer, tuple);
static boolean xennet_probe(kernel_heaps kh, int id, buffer frontend, tuple meta)
{
    xennet_debug("probe for id %d, meta: %v", id, meta);
    status s = xennet_attach(kh, id, frontend, meta);
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
