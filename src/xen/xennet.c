#include <kernel.h>
#include <page.h>

//#define XENNET_DEBUG
//#define XENNET_DEBUG_DATA
#ifdef XENNET_DEBUG
#define xennet_debug(x, ...) do {rprintf("XNET: " x "\n", ##__VA_ARGS__);} while(0)
#else
#define xennet_debug(x, ...)
#endif

/* for ring init in ring.h */
#include "lwip/opt.h"
#include "lwip/def.h"
#include "lwip/mem.h"
#include "lwip/pbuf.h"
#include "lwip/etharp.h"
#include "lwip/snmp.h"
#include "netif/ethernet.h"

#undef memset                   /* ugh, lwIP */
#include "xen_internal.h"
#include "io/netif.h"

#define GRANT_INVALID -1

#define XENNET_RX_RING_SIZE                                                \
  (__RD32(((PAGESIZE) - __builtin_offsetof(struct netif_rx_sring, ring)) / \
          sizeof(((struct netif_rx_sring *)0)->ring[0])))
#define XENNET_TX_RING_SIZE                                                \
  (__RD32(((PAGESIZE) - __builtin_offsetof(struct netif_tx_sring, ring)) / \
          sizeof(((struct netif_tx_sring *)0)->ring[0])))

/* A TX request ID is composed of a tx_buf ID and a page ID; the number of bits
 * reserved for the page ID is chosen so that it can accommodate the largest
 * number of pages needed for a pbuf length of 0xFFFF bytes. */
#define XENNET_TX_ID_SHIFT  5

struct xennet_dev;

typedef struct xennet_dev *xennet_dev;

typedef struct xennet_rx_buf {
    struct pbuf_custom p;       /* must be first field */
    struct list l;              /* rx_free or bh chain */
    xennet_dev xd;
    void * buf;                 /* virtual */
    u64 paddr;
    u32 idx;
    grant_ref_t gntref;
} *xennet_rx_buf;

typedef struct xennet_tx_buf {
    struct pbuf *p;
    struct list l;              /* tx_free, tx_pending or bh chain */
    u32 idx;
    u16 frags_queued;
    u16 start_idx;
    u16 npages;
    u16 nextpage;
    buffer pages;               /* array of xennet_txpages */
} *xennet_tx_buf;

typedef struct xennet_tx_page {
    u64 paddr;
    u16 offset;
    u16 len;
    boolean end;                /* of frame */
    grant_ref_t gntref;
} *xennet_tx_page;
    
struct xennet_dev {
    struct xen_dev dev;
    heap h;
    heap contiguous;                /* physically */

    u8 mac[ETHARP_HWADDR_LEN];
    u16 mtu;
    netif_rx_front_ring_t rx_ring;
    netif_tx_front_ring_t tx_ring;

    evtchn_port_t evtchn;
    grant_ref_t tx_ring_gntref;
    grant_ref_t rx_ring_gntref;

    /* lwIP */
    struct netif *netif;
    u16 rxbuflen;

    struct spinlock rx_fill_lock;
    vector rxbufs;
    struct list rx_free;

    thunk rx_service;           /* for bhqueue processing */
    queue rx_servicequeue;

    struct spinlock tx_fill_lock;
    vector txbufs;
    struct list tx_pending;     /* awaiting ring queueing (head may be partial) */
    struct list tx_free;

    thunk tx_service;           /* for bhqueue processing */
    queue tx_servicequeue;
};

#define XENNET_INFORM_BACKEND_RETRIES 1024

static status xennet_inform_backend(xennet_dev xnd)
{
    status s = STATUS_OK;
    xen_dev xd = &xnd->dev;
    xennet_debug("%s: dev id %d", __func__, xd->if_id);

    u32 tx_id;
    char *node;
    int retries = XENNET_INFORM_BACKEND_RETRIES;

  again:
    node = "transaction start";
    s = xenstore_transaction_start(&tx_id);
    if (!is_ok(s))
        return s;

    node = "vifname";
    s = xenstore_sync_printf(tx_id, xd->frontend, node, "vif%d", xd->if_id);
    if (!is_ok(s))
        goto abort;

    node = "rx-ring-ref";
    s = xenstore_sync_printf(tx_id, xd->frontend, node, "%d", xnd->rx_ring_gntref);
    if (!is_ok(s))
        goto abort;

    node = "tx-ring-ref";
    s = xenstore_sync_printf(tx_id, xd->frontend, node, "%d", xnd->tx_ring_gntref);
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
    s = xenstore_sync_printf(tx_id, xd->frontend, node, "%d", xnd->evtchn);
    if (!is_ok(s))
        goto abort;

    node = "transaction end";
    s = xenstore_transaction_end(tx_id, false);
    if (!is_ok(s)) {
        value v = table_find(s, sym(errno));
        if (v) {
            if (!runtime_strcmp("EAGAIN", buffer_ref((buffer)v, 0))) {
                deallocate_tuple(s);
                if (retries-- == 0) {
                    return timm("result", "%s failed: transaction end returned EAGAIN after %d tries",
                             __func__, XENNET_INFORM_BACKEND_RETRIES);
                }
                goto again;
            }
        }
        return timm_up(s, "result", "%s: transaction end failed", __func__);
    }
    return s;
  abort:
    xenstore_transaction_end(tx_id, true);
    return timm_up(s, "result", "%s: transaction aborted; step \"%s\" failed",
                   __func__, node);
}

static inline u16 xennet_form_tx_id(xennet_tx_buf txb, int pageidx)
{
    assert(pageidx < (1 << XENNET_TX_ID_SHIFT));
    return (txb->idx << XENNET_TX_ID_SHIFT) + pageidx;
}

static inline xennet_tx_buf xennet_tx_buf_from_id(xennet_dev xd, u16 id)
{
    return vector_get(xd->txbufs, id >> XENNET_TX_ID_SHIFT);
}

static inline int xennet_tx_page_idx_from_id(u16 id)
{
    return id & ((1 << XENNET_TX_ID_SHIFT) - 1);
}

static inline int xennet_get_n_tx_pages(xennet_tx_buf txb)
{
    return buffer_length(txb->pages) / sizeof(struct xennet_tx_page);
}

static inline xennet_tx_page xennet_get_tx_page(xennet_tx_buf txb, int idx)
{
    u64 offset = idx * sizeof(struct xennet_tx_page);
    assert(offset < buffer_length(txb->pages));
    return (xennet_tx_page)buffer_ref(txb->pages, offset);
}

static void xennet_return_txbuf(xennet_dev xd, xennet_tx_buf txb)
{
    txb->p = 0;
    txb->frags_queued = 0;
    txb->start_idx = -1;
    txb->npages = 0;
    txb->nextpage = 0;
    vector_clear(txb->pages);
    u64 flags = irq_disable_save();
    list_insert_before(&xd->tx_free, &txb->l);
    irq_restore(flags);
}

static xennet_tx_buf xennet_get_txbuf(xennet_dev xd)
{
    u64 flags = spin_lock_irq(&xd->tx_fill_lock);
    list l = list_get_next(&xd->tx_free);
    if (l) {
        list_delete(l);
        spin_unlock_irq(&xd->tx_fill_lock, flags);
        return struct_from_list(l, xennet_tx_buf, l);
    }
    spin_unlock_irq(&xd->tx_fill_lock, flags);

    if (vector_length(xd->txbufs) > (0xFFFF >> XENNET_TX_ID_SHIFT))
        return INVALID_ADDRESS;

    /* allocate new buffer */
    xennet_tx_buf txb = allocate(xd->h, sizeof(struct xennet_tx_buf));
    if (txb == INVALID_ADDRESS)
        return txb;
    txb->p = 0;
    list_init(&txb->l);
    txb->frags_queued = 0;
    txb->start_idx = -1;
    txb->npages = 0;
    txb->nextpage = 0;
    txb->pages = allocate_buffer(xd->h, sizeof(struct xennet_tx_page) * 4);

    flags = spin_lock_irq(&xd->tx_fill_lock);
    txb->idx = vector_length(xd->txbufs);
    vector_push(xd->txbufs, txb);
    spin_unlock_irq(&xd->tx_fill_lock, flags);

    return txb;
}

static void xennet_service_tx_ring(xennet_dev xd)
{
    int more;

    do {
        RING_IDX cons = xd->tx_ring.rsp_cons;
        RING_IDX prod = xd->tx_ring.sring->rsp_prod;
        memory_barrier();
        xennet_debug("%s: cons %d, prod %d", __func__, cons, prod);

        struct list q;
        list_init(&q);

        /* seems unfortunate to have to take the fill lock here...but
           we don't want to risk the tx buf vector changing underneath us */
        spin_lock(&xd->tx_fill_lock);
        while (cons < prod) {
            netif_tx_response_t *tx = RING_GET_RESPONSE(&xd->tx_ring, cons);
            xennet_tx_buf txb = xennet_tx_buf_from_id(xd, tx->id);
            assert(txb);

            if (tx->status != NETIF_RSP_OKAY) {
                /* XXX counters */
                msg_err("%s: cons %d, tx resp id %d, status %d\n",
                        __func__, cons, tx->id, tx->status);
            }

            xennet_tx_page txp = xennet_get_tx_page(txb, xennet_tx_page_idx_from_id(tx->id));
            if (txp->end) {
                list_insert_before(&q, &txb->l);
            }
            cons++;
        }
        spin_unlock(&xd->tx_fill_lock);
        write_barrier();
        xd->tx_ring.rsp_cons = cons;
        list l = list_get_next(&q);
        if (l) {
            /* trick: remove (local) head and queue first element */
            list_delete(&q);
            assert(enqueue(xd->tx_servicequeue, l));
            enqueue(bhqueue, xd->tx_service);
        }
        RING_FINAL_CHECK_FOR_RESPONSES(&xd->tx_ring, more);
    } while (more);
}

closure_function(1, 0, void, xennet_tx_service_bh,
                 xennet_dev, xd)
{
    xennet_dev xd = bound(xd);
    xennet_debug("%s: dev id %d", __func__, xd->dev.if_id);
    list l;
    while ((l = (list)dequeue(xd->tx_servicequeue)) != INVALID_ADDRESS) {
        struct list q;
        list_insert_before(l, &q); /* restore list head */
        list_foreach(&q, i) {
            xennet_tx_buf txb = struct_from_list(i, xennet_tx_buf, l);
            list_delete(i);
            for (int j = 0; j < xennet_get_n_tx_pages(txb); j++) {
                xennet_tx_page txp = xennet_get_tx_page(txb, j);
                xen_revoke_page_access(txp->gntref);
            }
            pbuf_free(txb->p);
            xennet_return_txbuf(xd, txb);
        }
    }
    xennet_debug("%s: exit", __func__);
}

/* called with tx_fill_lock taken / irqs disabled */
static xennet_tx_page xennet_fill_tx_request(xennet_dev xd, netif_tx_request_t *tx)
{
    list l = list_get_next(&xd->tx_pending);
    if (!l) {
        xennet_debug("tx pending empty");
        return 0;
    }
    xennet_tx_buf txb = struct_from_list(l, xennet_tx_buf, l);
    xennet_tx_page txp = xennet_get_tx_page(txb, txb->nextpage);
    tx->offset = txp->offset;
    tx->flags = txp->end ? 0 : NETTXF_more_data;
    tx->id = xennet_form_tx_id(txb, txb->nextpage);
    tx->size = txp->len;
    tx->gref = txp->gntref;

    if (txp->end) {
        list_delete(l);
    } else {
        txb->nextpage++;
        assert(txb->nextpage < txb->npages);
    }
    return txp;
}

static void xennet_populate_tx_ring(xennet_dev xd)
{
    u64 flags = spin_lock_irq(&xd->tx_fill_lock);

    RING_IDX prod = xd->tx_ring.req_prod_pvt;
    RING_IDX prod_end = xd->tx_ring.rsp_cons + XENNET_TX_RING_SIZE;
    xennet_debug("%s: prod %d, prod_end %d", __func__, prod, prod_end);

    while (prod < prod_end) {
        netif_tx_request_t *tx = RING_GET_REQUEST(&xd->tx_ring, prod);
        xennet_tx_page txp = xennet_fill_tx_request(xd, tx);
        if (!txp)
            break;
        xennet_debug("   prod %d: txp %p, offset %d, size %d, id %d, flags %x, gref %d",
                     prod, txp, tx->offset, tx->size, tx->id, tx->flags, tx->gref);
        prod++;
    }
    xd->tx_ring.req_prod_pvt = prod;
    write_barrier();

    int notify;
    RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&xd->tx_ring, notify);
    if (notify)
        xen_notify_evtchn(xd->evtchn);

    spin_unlock_irq(&xd->tx_fill_lock, flags);
    xennet_debug("queueing done");
}

/* We could just walk the pages using pointers in the txb, but we need
   somewhere to stash the phys addrs and grant references anyway, so
   just build an array of page descriptors.
*/
static void xennet_tx_buf_add_pages(xennet_dev xd, xennet_tx_buf txb, struct pbuf *p)
{
    for (struct pbuf *q = p; q != 0; q = q->next) {
        u64 va = u64_from_pointer(q->payload);
        u64 remain = q->len;
        u64 vpage = va & ~PAGEMASK;
        u64 offset = va & PAGEMASK;
        u64 len = MIN(PAGESIZE - offset, remain);

        xennet_tx_page txp;
        do {
            assert((vpage & (PAGESIZE - 1)) == 0); // XXX temp
            extend_total(txb->pages, sizeof(struct xennet_tx_page) * (txb->npages + 1));
            txp = xennet_get_tx_page(txb, txb->npages);
            txp->paddr = physical_from_virtual(pointer_from_u64(vpage));
            assert(txp->paddr != INVALID_PHYSICAL);
            txp->gntref = xen_grant_page_access(xd->dev.backend_id, txp->paddr, true);
            txp->offset = offset;
            txp->len = len;
            txp->end = false;
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
    xennet_debug("%s: id %d, pbuf %p", __func__, xd->dev.if_id, p);

    xennet_tx_buf txb = xennet_get_txbuf(xd);
    if (txb == INVALID_ADDRESS)
        return ERR_MEM;
    pbuf_ref(p);
    txb->p = p;
    xennet_tx_buf_add_pages(xd, txb, p);

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

    /* really should just be a mask of xen int or tx int if we ever split */
    u64 flags = spin_lock_irq(&xd->tx_fill_lock);
    list_insert_before(&xd->tx_pending, &txb->l);
    spin_unlock_irq(&xd->tx_fill_lock, flags);

    xennet_populate_tx_ring(xd);
    return ERR_OK;
}

void lwip_status_callback(struct netif *netif);

static err_t xennet_netif_init(struct netif *netif)
{
    xennet_dev xd = (xennet_dev)netif->state;
    netif->hostname = "uniboot"; // XXX fix in virtio too
    netif->name[0] = 'e';
    netif->name[1] = 'n';
    netif->output = etharp_output;
    netif->linkoutput = xennet_linkoutput;
    netif->hwaddr_len = ETHARP_HWADDR_LEN;
    netif->status_callback = lwip_status_callback;
    runtime_memcpy(netif->hwaddr, xd->mac, ETHARP_HWADDR_LEN);
    netif->mtu = xd->mtu;

    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP | NETIF_FLAG_UP;

    return ERR_OK;
}

/* Note: If we ever find ourselves short of grants, perhaps due to
   depth of queued packet data, number of interfaces or other
   variables, we can change this to confine their use to buffers that
   are actually on the ring - achievable by placing a lock around the
   grant allocator or drawing from preallocated ids for the ring. For
   our needs right now, it seems to suffice to just tie it to the
   buffer at alloc time. */

static void xennet_return_rxbuf(struct pbuf *p);

/* called from dev enable only at this point - but could also be called from bh service */
static xennet_rx_buf xennet_alloc_rxbuf(xennet_dev xd)
{
    xennet_rx_buf rxb = allocate(xd->h, sizeof(struct xennet_rx_buf));
    if (rxb == INVALID_ADDRESS)
        return rxb;
    rxb->xd = xd;
    rxb->buf = allocate(xd->contiguous, PAGESIZE); /* XXX multiple for large mtu */
    if (rxb->buf == INVALID_ADDRESS)
        goto out_dealloc_rxb;
    rxb->paddr = physical_from_virtual(rxb->buf);
    assert(rxb->paddr != INVALID_PHYSICAL);
    rxb->gntref = xen_grant_page_access(xd->dev.backend_id, rxb->paddr, false);
    if (!rxb->gntref)
        goto out_free_buf;

    rxb->p.custom_free_function = xennet_return_rxbuf;

    /* pbuf initialized on free list enqueue */

    /* locking not really necessary for init, but we're likely to add
       to the cache at some point */
    u64 flags = spin_lock_irq(&xd->rx_fill_lock);
    rxb->idx = vector_length(xd->rxbufs);
    vector_push(xd->rxbufs, rxb);
    spin_unlock_irq(&xd->rx_fill_lock, flags);
    return rxb;
  out_free_buf:
    deallocate(xd->contiguous, rxb->buf, PAGESIZE);
  out_dealloc_rxb:
    deallocate(xd->h, rxb, sizeof(struct xennet_rx_buf));
    return INVALID_ADDRESS;
}

/* called with lock taken */
static xennet_rx_buf xennet_get_rxbuf(xennet_dev xd)
{
    list l = list_get_next(&xd->rx_free);
    if (!l)
        return 0;
    xennet_rx_buf rxb = struct_from_list(l, xennet_rx_buf, l);
    list_delete(l);
    assert(rxb->gntref);
    return rxb;
}

/* called by attach, lwIP, or netif input drop / error */
static void xennet_return_rxbuf(struct pbuf *p)
{
    xennet_rx_buf rxb = (xennet_rx_buf)p;
    xennet_dev xd = rxb->xd;
    pbuf_alloced_custom(PBUF_RAW,
                        xd->rxbuflen,
                        PBUF_REF,
                        &rxb->p,
                        rxb->buf,
                        xd->rxbuflen);

    u64 flags = spin_lock_irq(&xd->rx_fill_lock);
    list_insert_before(&xd->rx_free, &rxb->l);
    spin_unlock_irq(&xd->rx_fill_lock, flags);
    assert(rxb->gntref);
 }

static void xennet_populate_rx_ring(xennet_dev xd)
{
    RING_IDX prod = xd->rx_ring.req_prod_pvt;
    RING_IDX prod_end = xd->rx_ring.rsp_cons + XENNET_RX_RING_SIZE;

    xennet_debug("%s: prod %d, prod_end %d", __func__, prod, prod_end);

    u64 flags = spin_lock_irq(&xd->rx_fill_lock);
    while (prod < prod_end) {
        xennet_rx_buf rxb = xennet_get_rxbuf(xd);
        if (!rxb) {
            /* not a ring underrun, but we still want to know if we're close */
            msg_err("xennet_get_rxbuf underrun\n");
            break;
        }

        netif_rx_request_t *rx = RING_GET_REQUEST(&xd->rx_ring, prod);
        rx->id = rxb->idx;
        rx->pad = 0;
        rx->gref = rxb->gntref;
        prod++;
    }
    spin_unlock_irq(&xd->rx_fill_lock, flags);
    xd->rx_ring.req_prod_pvt = prod;
    xennet_debug("fill done");
    write_barrier();

    int notify;
    RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&xd->rx_ring, notify);
    if (notify)
        xen_notify_evtchn(xd->evtchn);
}

static void xennet_service_rx_ring(xennet_dev xd)
{
    int more;

    do {
        RING_IDX cons = xd->rx_ring.rsp_cons;
        RING_IDX prod = xd->rx_ring.sring->rsp_prod;
        assert(prod - cons <= XENNET_RX_RING_SIZE);
        read_barrier();
        xennet_debug("%s: cons %d, prod %d", __func__, cons, prod);

        struct list q;
        list_init(&q);

        /* again, lock unfortunately needed for rxbufs - wouldn't be
           an issue if we could size the vector only once on init... */
        u64 flags = spin_lock_irq(&xd->rx_fill_lock);
        while (cons < prod) {
            netif_rx_response_t *rx = RING_GET_RESPONSE(&xd->rx_ring, cons);
            xennet_rx_buf rxb = vector_get(xd->rxbufs, rx->id);
            assert(rxb);
            assert(rxb->gntref != GRANT_INVALID);
            assert(rx->status >= 0);
            assert(rx->offset + rx->status <= PAGESIZE);

            xennet_debug("   RX flags %x, status %d, offset %d\n",
                         rx->flags, rx->status, rx->offset);
#ifdef XENNET_DEBUG_DATA
            xennet_debug("   buf:\n%X", alloca_wrap_buffer(rxb->p.pbuf.payload,
                                                           rx->status + rx->offset));
#endif
            rxb->p.pbuf.len = rx->status;
            rxb->p.pbuf.tot_len = rx->status;
            rxb->p.pbuf.payload += rx->offset;

            list_insert_before(&q, &rxb->l);
            cons++;
        }
        spin_unlock_irq(&xd->rx_fill_lock, flags);
        write_barrier();
        xd->rx_ring.rsp_cons = cons;
        list l = list_get_next(&q);
        if (l) {
            /* trick: remove (local) head and queue first element */
            list_delete(&q);
            assert(l->prev);
            assert(enqueue(xd->rx_servicequeue, l));
            enqueue(bhqueue, xd->rx_service);
        }
        RING_FINAL_CHECK_FOR_RESPONSES(&xd->rx_ring, more);
    } while (more);
}

closure_function(1, 0, void, xennet_rx_service_bh,
                 xennet_dev, xd)
{
    xennet_dev xd = bound(xd);
    xennet_debug("%s: dev id %d", __func__, xd->dev.if_id);
    list l;
    while ((l = (list)dequeue(xd->rx_servicequeue)) != INVALID_ADDRESS) {
        struct list q;
        assert(l);
        assert(l->prev);
        list_insert_before(l, &q); /* restore list head */
        list_foreach(&q, i) {
            assert(i);
            xennet_rx_buf rxb = struct_from_list(i, xennet_rx_buf, l);
            list_delete(i);
            err_enum_t err = xd->netif->input((struct pbuf *)&rxb->p, xd->netif);
            if (err != ERR_OK) {
                msg_err("xennet: rx drop by stack, err %d\n", err);
                xennet_return_rxbuf((struct pbuf *)&rxb->p);
            }
        }
    }
    xennet_debug("%s: exit", __func__);
}

closure_function(1, 0, void, xennet_event_handler,
                 xennet_dev, xd)
{
    xennet_dev xd = bound(xd);
    xennet_service_tx_ring(xd);
    xennet_populate_tx_ring(xd);
    xennet_service_rx_ring(xd);
    xennet_populate_rx_ring(xd);
    int rv = xen_unmask_evtchn(xd->evtchn);
    if (rv != 0)
        halt("%s: failed to unmask evtchn %d, rv %d\n", xd->evtchn, rv);
}

static status xennet_enable(xennet_dev xd)
{
    xen_dev xdev = &xd->dev;
    status s = STATUS_OK;
    xennet_debug("%s: dev id %d", __func__, xdev->if_id);

    u64 val;
    s = xenstore_read_u64(0, xdev->backend, "feature-rx-copy", &val);
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

    u64 phys = physical_from_virtual(rx_ring);
    xd->rx_ring_gntref = xen_grant_page_access(xdev->backend_id, phys, false);
    phys = physical_from_virtual(tx_ring);
    xd->tx_ring_gntref = xen_grant_page_access(xdev->backend_id, phys, false);
    if (xd->rx_ring_gntref == 0 || xd->tx_ring_gntref == 0) {
        s = timm("result", "failed to obtain grant references for rings");
        goto out_dealloc;
    }

    s = xen_allocate_evtchn(xdev->backend_id, &xd->evtchn);
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

    s = xenbus_set_state(0, xdev->frontend, XenbusStateConnected);
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
    xennet_debug("MTU %d, ring sizes: rx %d, tx %d\n", xd->mtu, XENNET_RX_RING_SIZE, XENNET_TX_RING_SIZE);
    xd->rxbufs = allocate_vector(h, 2 * XENNET_RX_RING_SIZE);
    xd->txbufs = allocate_vector(h, 2 * XENNET_TX_RING_SIZE);
    /* figure rx buffer size */
    xd->rxbuflen = sizeof(struct eth_hdr) + sizeof(struct eth_vlan_hdr) + xd->mtu;

    list_init(&xd->rx_free);
    xd->rx_servicequeue = allocate_queue(h, XENNET_RX_SERVICEQUEUE_DEPTH);
    assert(xd->rx_servicequeue != INVALID_ADDRESS);
    xd->rx_service = closure(h, xennet_rx_service_bh, xd);

    spin_lock_init(&xd->rx_fill_lock);
    spin_lock_init(&xd->tx_fill_lock);
    list_init(&xd->tx_pending);
    list_init(&xd->tx_free);
    xd->tx_servicequeue = allocate_queue(h, XENNET_TX_SERVICEQUEUE_DEPTH);
    assert(xd->tx_servicequeue != INVALID_ADDRESS);
    xd->tx_service = closure(h, xennet_tx_service_bh, xd);

    xen_dev xdev = &xd->dev;
    s = xendev_attach(xdev, id, frontend, meta);
    if (!is_ok(s))
        goto out_dealloc_xd;
    xennet_debug("backend id %d, backend path %b", xdev->backend_id, xdev->backend);

    /* allocate rx buffers up front */
    for (int i = 0; i < XENNET_INIT_RX_BUFFERS_FACTOR * XENNET_RX_RING_SIZE; i++) {
        xennet_rx_buf rxb = xennet_alloc_rxbuf(xd);
        if (rxb == INVALID_ADDRESS) {
            s = timm("result", "%s: unable to allocate rx buffers\n", __func__);
            goto out_dealloc_xd;
        }
        xennet_return_rxbuf((struct pbuf *)&rxb->p);
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
    
closure_function(1, 3, boolean, xennet_probe,
                 kernel_heaps, kh,
                 int, id, buffer, frontend, tuple, meta)
{
    xennet_debug("probe for id %d, meta: %v", id, meta);
    status s = xennet_attach(bound(kh), id, frontend, meta);
    if (!is_ok(s)) {
        msg_err("attach failed with status %v\n", s);
        return false;
    }
    return true;
}

void init_xennet(kernel_heaps kh)
{
    register_xen_driver("vif", closure(heap_general(kh), xennet_probe, kh));
}
