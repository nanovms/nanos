#include <kernel.h>
#include <page.h>
#include <pci.h>
#include "lwip/opt.h"
#include "lwip/def.h"
#include "lwip/mem.h"
#include "lwip/pbuf.h"
#include "vmxnet3_queue.h"
#include "vmxnet3_net.h"
#include "netif/ethernet.h"

#ifdef VMXNET3_NET_DEBUG
# define vmxnet3_net_debug rprintf
#else
# define vmxnet3_net_debug(...) do { } while(0)
#endif // defined(VMXNET3_NET_DEBUG)

static void
vmxnet3_init_txq(vmxnet3_pci dev, int q)
{
    struct vmxnet3_txqueue *txq;
    struct vmxnet3_comp_ring *txc;
    struct vmxnet3_txring *txr;

    txq = dev->vmx_txq[q];
    txc = &txq->vxtxq_comp_ring;
    txr = &txq->vxtxq_cmd_ring;

    buffer b = little_stack_buffer(16);
    bprintf(b, "%s-tx%d", DEVICE_NAME, q);
    memcpy(txq->vxtxq_name, b->contents, sizeof(txq->vxtxq_name));

    txq->vxtxq_sc = dev;
    txq->vxtxq_id = q;
    txc->vxcr_ndesc = VMXNET3_MAX_TX_NCOMPDESC;
    txr->vxtxr_ndesc = VMXNET3_MAX_TX_NDESC;
    txr->vxtxr_avail = VMXNET3_MAX_TX_NDESC;
    txr->vxtxr_head = 0;
}

static void
vmxnet3_init_rxq(vmxnet3_pci dev, int q)
{
    struct vmxnet3_rxqueue *rxq;
    struct vmxnet3_comp_ring *rxc;
    struct vmxnet3_rxring *rxr;

    rxq = dev->vmx_rxq[q];
    rxc = &rxq->vxrxq_comp_ring;

    buffer b = little_stack_buffer(16);
    bprintf(b, "%s-rx%d", DEVICE_NAME, q);
    memcpy(rxq->vxrxq_name, b->contents, sizeof(rxq->vxrxq_name));

    rxq->vxrxq_sc = dev;
    rxq->vxrxq_id = q;

    rxc->vxcr_ndesc = VMXNET3_MAX_RX_NCOMPDESC;
    for (int i = 0; i < VMXNET3_RXRINGS_PERQ; i++) {
        rxr = &rxq->vxrxq_cmd_ring[i];
        rxr->vxrxr_ndesc = VMXNET3_MAX_RX_NDESC;
    }
}

void
init_vmxnet3_tx_queue(vmxnet3_pci vp, struct vmxnet3_txqueue *txq)
{
    struct vmxnet3_txring *txr = &txq->vxtxq_cmd_ring;

    txq->vxtxq_last_flush = -1;

    txr = &txq->vxtxq_cmd_ring;
    txr->vxtxr_next = 0;
    txr->vxtxr_gen = VMXNET3_INIT_GEN;

    struct vmxnet3_comp_ring *txc = &txq->vxtxq_comp_ring;
    txc->vxcr_next = 0;
    txc->vxcr_gen = VMXNET3_INIT_GEN;
}

void init_vmxnet3_rx_queue(vmxnet3_pci vp, struct vmxnet3_rxqueue *rxq)
{
    for (int i=0; i < VMXNET3_RXRINGS_PERQ; i++) {
        struct vmxnet3_rxring *rxr = &rxq->vxrxq_cmd_ring[i];
        rxr->vxrxr_gen = VMXNET3_INIT_GEN;
        rxr->vxrxr_desc_skips = 0;
        rxr->vxrxr_refill_start = 0;
    }

    struct vmxnet3_comp_ring *rxc = &rxq->vxrxq_comp_ring;
    rxc->vxcr_next = 0;
    rxc->vxcr_gen = VMXNET3_INIT_GEN;
    rxc->vxcr_zero_length = 0;
    rxc->vxcr_pkt_errors = 0;
}

void vmxnet3_tx_queues_alloc(vmxnet3_pci dev)
{
    for (int i = 0; i < VMXNET3_DEF_TX_QUEUES; ++i) {
        dev->vmx_txq[i] = allocate_zero(dev->contiguous, sizeof(struct vmxnet3_txqueue));
        assert(dev->vmx_txq[i] != INVALID_ADDRESS);
        vmxnet3_init_txq(dev, i);
        init_vmxnet3_tx_queue(dev, dev->vmx_txq[i]);
    }

    // allocate tx descriptors memory
    u64 tx_desc_size = sizeof(struct vmxnet3_txdesc) * VMXNET3_MAX_TX_NDESC * VMXNET3_DEF_TX_QUEUES;
    dev->tx_desc_mem = allocate_zero(dev->contiguous, tx_desc_size);
    assert(dev->tx_desc_mem != INVALID_ADDRESS);
    // alignment
    assert((u64)dev->tx_desc_mem == pad((u64)dev->tx_desc_mem, VMXNET_ALIGN_QUEUES_DESC));

    u64 tx_compdesc_size = sizeof(struct vmxnet3_txcompdesc) * VMXNET3_MAX_TX_NDESC * VMXNET3_DEF_TX_QUEUES;
    dev->tx_compdesc_mem = allocate_zero(dev->contiguous, tx_compdesc_size);
    assert(dev->tx_compdesc_mem != INVALID_ADDRESS);
    // alignment
    assert((u64)dev->tx_compdesc_mem == pad((u64)dev->tx_compdesc_mem, VMXNET_ALIGN_QUEUES_DESC));

    memset(&dev->tx_pbuf, 0, sizeof(dev->tx_pbuf));
}

void vmxnet3_rx_queues_alloc(vmxnet3_pci dev)
{
    for (int i = 0; i < VMXNET3_DEF_RX_QUEUES; ++i) {
        dev->vmx_rxq[i] = allocate_zero(dev->contiguous, sizeof(struct vmxnet3_rxqueue));
        assert(dev->vmx_rxq[i] != INVALID_ADDRESS);
        vmxnet3_init_rxq(dev, i);
        init_vmxnet3_rx_queue(dev, dev->vmx_rxq[i]);
    }
    // allocate rx descriptors memory
    u64 rx_desc_size = sizeof(struct vmxnet3_rxdesc) * VMXNET3_MAX_RX_NDESC * VMXNET3_RXRINGS_PERQ * VMXNET3_DEF_RX_QUEUES;
    dev->rx_desc_mem = allocate_zero(dev->contiguous, rx_desc_size);
    assert(dev->rx_desc_mem != INVALID_ADDRESS);
    // alignment
    assert((u64)dev->rx_desc_mem == pad((u64)dev->rx_desc_mem, VMXNET_ALIGN_QUEUES_DESC));

    u64 rx_compdesc_size = sizeof(struct vmxnet3_rxcompdesc) * VMXNET3_MAX_RX_NDESC * VMXNET3_DEF_RX_QUEUES;
    dev->rx_compdesc_mem = allocate_zero(dev->contiguous, rx_compdesc_size);
    assert(dev->rx_compdesc_mem != INVALID_ADDRESS);
    // alignment
    assert((u64)dev->rx_compdesc_mem == pad((u64)dev->rx_compdesc_mem, VMXNET_ALIGN_QUEUES_DESC));
}

void vmxnet3_queues_shared_alloc(vmxnet3_pci dev)
{
    /*
     * The txq and rxq shared data areas must be allocated contiguously
     * as vmxnet3_driver_shared contains only a single address member
     * for the shared queue data area.
     */
    u64 size = VMXNET3_DEF_TX_QUEUES * sizeof(struct vmxnet3_txq_shared) +
        VMXNET3_DEF_RX_QUEUES * sizeof(struct vmxnet3_rxq_shared);
    dev->queues_shared_mem = allocate_zero(dev->contiguous, size);
    assert(dev->queues_shared_mem != INVALID_ADDRESS);
    // alignment
    assert((u64)dev->queues_shared_mem == pad((u64)dev->queues_shared_mem, VMXNET_ALIGN_QUEUES_SHARED));


    struct vmxnet3_driver_shared *vmx_ds = dev->vmx_ds;
    vmx_ds->queue_shared = physical_from_virtual(dev->queues_shared_mem);
    assert(vmx_ds->queue_shared != INVALID_PHYSICAL);
    vmx_ds->queue_shared_len = size;

    caddr_t addr = (caddr_t)dev->queues_shared_mem;
    for (int i = 0; i < VMXNET3_DEF_TX_QUEUES; ++i) {
        dev->vmx_txq[i]->vxtxq_ts = (struct vmxnet3_txq_shared *) addr;
        addr += sizeof(struct vmxnet3_txq_shared);
    }

    for (int i = 0; i < VMXNET3_DEF_RX_QUEUES; ++i) {
        dev->vmx_rxq[i]->vxrxq_rs = (struct vmxnet3_rxq_shared *) addr;
        addr += sizeof(struct vmxnet3_rxq_shared);
    }

    struct vmxnet3_txcompdesc* aligned_txcompdesc_mem = (struct vmxnet3_txcompdesc*)dev->tx_compdesc_mem;
    struct vmxnet3_txdesc* aligned_txdesc_mem = (struct vmxnet3_txdesc*)dev->tx_desc_mem;
    /* Record descriptor ring vaddrs and paddrs */
    for (int q = 0; q < VMXNET3_DEF_TX_QUEUES; q++) {

        struct vmxnet3_txqueue *txq = dev->vmx_txq[q];
        struct vmxnet3_comp_ring *txc = &txq->vxtxq_comp_ring;
        struct vmxnet3_txring *txr = &txq->vxtxq_cmd_ring;

        /* Completion ring */
        txc->vxcr_u.txcd = &aligned_txcompdesc_mem[q * VMXNET3_MAX_TX_NCOMPDESC];
        txc->vxcr_paddr = physical_from_virtual(txc->vxcr_u.txcd);
        assert(txc->vxcr_paddr != INVALID_PHYSICAL);

        /* Command ring */
        txr->vxtxr_txd = &aligned_txdesc_mem[q * VMXNET3_MAX_TX_NCOMPDESC];
        txr->vxtxr_paddr = physical_from_virtual(txr->vxtxr_txd);
        assert(txr->vxtxr_paddr != INVALID_PHYSICAL);
    }

    struct vmxnet3_rxcompdesc* aligned_rxcompdesc_mem = (struct vmxnet3_rxcompdesc*)dev->rx_compdesc_mem;
    struct vmxnet3_rxdesc* aligned_rxdesc_mem = (struct vmxnet3_rxdesc*)dev->rx_desc_mem;
    /* Record descriptor ring vaddrs and paddrs */
    for (int q = 0; q < VMXNET3_DEF_RX_QUEUES; q++) {
        struct vmxnet3_rxqueue *rxq = dev->vmx_rxq[q];
        struct vmxnet3_comp_ring *rxc = &rxq->vxrxq_comp_ring;

        /* Completion ring */
        rxc->vxcr_u.rxcd = &aligned_rxcompdesc_mem[q * VMXNET3_MAX_RX_NCOMPDESC];
        rxc->vxcr_paddr = physical_from_virtual(rxc->vxcr_u.rxcd);
        assert(rxc->vxcr_paddr != INVALID_PHYSICAL);

        /* Command ring(s) */
        for (int i = 0; i < VMXNET3_RXRINGS_PERQ; i++) {
            struct vmxnet3_rxring *rxr = &rxq->vxrxq_cmd_ring[i];

            rxr->vxrxr_rxd = &aligned_rxdesc_mem[(2*q  + i) * VMXNET3_MAX_RX_NDESC];
            rxr->vxrxr_paddr = physical_from_virtual(rxr->vxrxr_rxd);
            assert(rxr->vxrxr_paddr != INVALID_PHYSICAL);
        }
    }

}

void vmxnet3_init_shared_data(vmxnet3_pci dev)
{
    /* Tx queues */
    for (int i = 0; i < VMXNET3_DEF_TX_QUEUES; i++) {
        struct vmxnet3_txqueue *txq = dev->vmx_txq[i];
        struct vmxnet3_txq_shared *txs = txq->vxtxq_ts;

        txs->cmd_ring = txq->vxtxq_cmd_ring.vxtxr_paddr;
        txs->cmd_ring_len = txq->vxtxq_cmd_ring.vxtxr_ndesc;
        txs->comp_ring = txq->vxtxq_comp_ring.vxcr_paddr;
        txs->comp_ring_len = txq->vxtxq_comp_ring.vxcr_ndesc;
        txs->driver_data = physical_from_virtual(txq);
        assert(txs->driver_data != INVALID_PHYSICAL);
        txs->driver_data_len = sizeof(struct vmxnet3_txqueue);
    }

    /* Rx queues */
    for (int i = 0; i < VMXNET3_DEF_RX_QUEUES; i++) {
        struct vmxnet3_rxqueue *rxq = dev->vmx_rxq[i];
        struct vmxnet3_rxq_shared *rxs = rxq->vxrxq_rs;

        rxs->cmd_ring[0] = rxq->vxrxq_cmd_ring[0].vxrxr_paddr;
        rxs->cmd_ring_len[0] = rxq->vxrxq_cmd_ring[0].vxrxr_ndesc;
        rxs->cmd_ring[1] = rxq->vxrxq_cmd_ring[1].vxrxr_paddr;
        rxs->cmd_ring_len[1] = rxq->vxrxq_cmd_ring[1].vxrxr_ndesc;
        rxs->comp_ring = rxq->vxrxq_comp_ring.vxcr_paddr;
        rxs->comp_ring_len = rxq->vxrxq_comp_ring.vxcr_ndesc;
        rxs->driver_data = physical_from_virtual(rxq);
        assert(rxs->driver_data != INVALID_PHYSICAL);
        rxs->driver_data_len = sizeof(struct vmxnet3_rxqueue);
    }

}

int
vmxnet3_isc_txd_encap(vmxnet3_pci dev, struct pbuf *p)
{
    struct vmxnet3_txqueue *txq = dev->vmx_txq[0];
    struct vmxnet3_txring *txr = &txq->vxtxq_cmd_ring;

    //TODO: max segments?
    unsigned nsegs = 0;
    for (struct pbuf * q = p; q != NULL; q = q->next)
        nsegs += 1;

    if (txr->vxtxr_avail < nsegs + 1) {
        vmxnet3_isc_txd_credits_update(dev);
        if (txr->vxtxr_avail < nsegs + 1) {
            return ERR_BUF;
        }
    }

    unsigned pidx = txr->vxtxr_head;
    dev->tx_pbuf[txr->vxtxr_head] = p;
    pbuf_ref(p);

    assert(nsegs <= VMXNET3_TX_MAXSEGS);

    struct vmxnet3_txdesc *sop = &txr->vxtxr_txd[pidx];
    int gen = txr->vxtxr_gen ^ 1;    /* Owned by cpu (yet) */


    struct vmxnet3_txdesc *txd = NULL;
    for (struct pbuf * q = p; q != NULL; q = q->next) {

        txd = &txr->vxtxr_txd[pidx];
        txd->addr = physical_from_virtual(q->payload);
        assert(txd->addr != INVALID_PHYSICAL);
        txd->len = q->len;
        txd->gen = gen;
        txd->dtype = 0;
        txd->offload_mode = VMXNET3_OM_NONE;
        txd->offload_pos = 0;
        txd->hlen = 0;
        txd->eop = 0;
        txd->compreq = 0;
        txd->vtag_mode = 0;
        txd->vtag = 0;

        if (++pidx == txr->vxtxr_ndesc) {
            pidx = 0;
            txr->vxtxr_gen ^= 1;
        }
        gen = txr->vxtxr_gen;
    }
    assert(txd != NULL);
    txd->eop = 1;
    txd->compreq = 1;
    txr->vxtxr_head = pidx;
    txr->vxtxr_avail -= nsegs;

    /*
     * VLAN
     */
    //TODO: no vlan
//    if (pi->ipi_mflags & M_VLANTAG) {
//        sop->vtag_mode = 1;
//        sop->vtag = pi->ipi_vtag;
//    }

    /*
     * TSO and checksum offloads
     */
#if 0
    int hdrlen = pi->ipi_ehdrlen + pi->ipi_ip_hlen;
    if (pi->ipi_csum_flags & CSUM_TSO) {
        sop->offload_mode = VMXNET3_OM_TSO;
        sop->hlen = hdrlen + pi->ipi_tcp_hlen;
        sop->offload_pos = pi->ipi_tso_segsz;
    } else if (pi->ipi_csum_flags & (VMXNET3_CSUM_OFFLOAD |
        VMXNET3_CSUM_OFFLOAD_IPV6)) {
        sop->offload_mode = VMXNET3_OM_CSUM;
        sop->hlen = hdrlen;
        sop->offload_pos = hdrlen +
            ((pi->ipi_ipproto == IPPROTO_TCP) ?
            offsetof(struct tcphdr, th_sum) :
            offsetof(struct udphdr, uh_sum));
    }
#endif
    /* Finally, change the ownership. */
    write_barrier();
    sop->gen ^= 1;
    ++txq->vxtxq_ts->npending;

    return ERR_OK;
}

void
vmxnet3_isc_txd_credits_update(vmxnet3_pci dev)
{
    struct vmxnet3_txqueue *txq = dev->vmx_txq[0];
    struct vmxnet3_comp_ring *txc = &txq->vxtxq_comp_ring;
    struct vmxnet3_txring *txr = &txq->vxtxq_cmd_ring;

    int processed = 0;
    for (;;) {
        struct vmxnet3_txcompdesc *txcd = &txc->vxcr_u.txcd[txc->vxcr_next];
        if (txcd->gen != txc->vxcr_gen)
            break;
        read_barrier();

        if (++txc->vxcr_next == txc->vxcr_ndesc) {
            txc->vxcr_next = 0;
            txc->vxcr_gen ^= 1;
        }

        struct pbuf* p = dev->tx_pbuf[txcd->eop_idx];
        if (p != NULL) {
            dev->tx_pbuf[txcd->eop_idx] = NULL;
            pbuf_free(p);
        }

        if (txcd->eop_idx < txr->vxtxr_next)
            processed += txr->vxtxr_ndesc -
                (txr->vxtxr_next - txcd->eop_idx) + 1;
        else
            processed += txcd->eop_idx - txr->vxtxr_next + 1;
        txr->vxtxr_next = (txcd->eop_idx + 1) % txr->vxtxr_ndesc;
    }

    txr->vxtxr_avail += processed;
}

void
vmxnet3_set_interrupt_idx(vmxnet3_pci dev)
{
    // must be less than nintr
    int intr_idx = 1;
    for (int i = 0; i < VMXNET3_DEF_RX_QUEUES; i++, intr_idx++) {
        struct vmxnet3_rxqueue *rxq = dev->vmx_rxq[i];
        struct vmxnet3_rxq_shared *rxs = rxq->vxrxq_rs;
        rxq->vxrxq_intr_idx = intr_idx;
        rxs->intr_idx = rxq->vxrxq_intr_idx;
    }

    for (int i = 0; i < VMXNET3_DEF_TX_QUEUES; i++, intr_idx++) {
        struct vmxnet3_txqueue *txq = dev->vmx_txq[i];
        struct vmxnet3_txq_shared *txs = txq->vxtxq_ts;
        // Must be 0; must be less than nintr;
        txq->vxtxq_intr_idx = 0;
        txs->intr_idx = txq->vxtxq_intr_idx;
    }
}

boolean
vmxnet3_rxq_available(vmxnet3_pci dev)
{
    struct vmxnet3_rxqueue *rxq = dev->vmx_rxq[0];
    struct vmxnet3_comp_ring *rxc = &rxq->vxrxq_comp_ring;
    struct vmxnet3_rxcompdesc *rxcd = &rxc->vxcr_u.rxcd[rxc->vxcr_next];

    return (rxcd->gen == rxc->vxcr_gen);
}
