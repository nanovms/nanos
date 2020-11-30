/*-
 * BSD LICENSE
 *
 * Copyright (c) 2015-2019 Amazon.com, Inc. or its affiliates.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <kernel.h>
#include <page.h>
#include <pci.h>
#include <lwip/pbuf.h>
#include <lwip/netif.h>
#include "ena.h"
#include "ena_datapath.h"
#include "buf_ring.h"

#ifdef ENA_DATAPATH_DEBUG
#define ena_datapath_debug(x, ...) do { rprintf("ENA DATAPATH: " x "\n", ##__VA_ARGS__); } while(0)
#else
# define ena_datapath_debug(...)
#endif // defined(ENA_DEBUG)

/*********************************************************************
 *  Static functions prototypes
 *********************************************************************/

static int    ena_tx_cleanup(struct ena_ring *);
static int    ena_rx_cleanup(struct ena_ring *);
static inline int validate_tx_req_id(struct ena_ring *, uint16_t);
#if 0
static void    ena_rx_hash_mbuf(struct ena_ring *, struct ena_com_rx_ctx *,
    struct pbuf *);
#endif
static struct pbuf* ena_rx_mbuf(struct ena_ring *, struct ena_com_rx_buf_info *,
    struct ena_com_rx_ctx *, uint16_t *);
#if 0
static inline void ena_rx_checksum(struct ena_ring *, struct ena_com_rx_ctx *,
    struct pbuf *);
static void    ena_tx_csum(struct ena_com_tx_ctx *, struct pbuf *);
static int    ena_check_and_collapse_mbuf(struct ena_ring *tx_ring,
    struct pbuf **mbuf);
#endif
static int    ena_xmit_mbuf(struct ena_ring *, struct pbuf **);
static void    ena_start_xmit(struct ena_ring *);

static int
ena_m_append(struct ena_adapter *ena, xpbuf m0, int len, uint8_t *cp)
{
    xpbuf m;

    for (m = m0; m->p.pbuf.next != 0; m = (xpbuf)m->p.pbuf.next)
        ;
    int remainder = len;
    int space = ena->rxbuflen - m->p.pbuf.len;
    if (space > 0) {
        /*
         * Copy into available space.
         */
        if (space > remainder)
            space = remainder;
        runtime_memcpy(m->p.pbuf.payload + m->p.pbuf.len, cp, space);
        m->p.pbuf.len += space;
        m->p.pbuf.tot_len += space;
        m0->p.pbuf.tot_len += space;
        cp += space;
        remainder -= space;
    }
    while (remainder > 0) {
        /*
         * Allocate a new mbuf; could check space
         * and allocate a cluster instead.
         */
        xpbuf n = receive_buffer_alloc(ena);

        struct pbuf* np = &n->p.pbuf;
        np->len = MIN(sizeof(struct xpbuf) + ena->rxbuflen, remainder);
        np->tot_len = np->len;
        m0->p.pbuf.tot_len += np->len;
        runtime_memcpy(np->payload, cp, np->len);
        cp += np->len;
        remainder -= np->len;
        m->p.pbuf.next = np;
        m = n;
    }
    return (remainder == 0);
}

/*********************************************************************
 *  Global functions
 *********************************************************************/

void
ena_cleanup(void *arg, int pending)
{
    struct ena_que    *que = arg;
    struct ena_adapter *adapter = que->adapter;
//    if_t ifp = adapter->ifp;
    struct ena_ring *tx_ring;
    struct ena_ring *rx_ring;
    struct ena_com_io_cq* io_cq;
    struct ena_eth_io_intr_reg intr_reg;
    int qid, ena_qid;
    int txc, rxc, i;

    ena_trace(ENA_DBG, "MSI-X TX/RX routine\n");

    tx_ring = que->tx_ring;
    rx_ring = que->rx_ring;
    qid = que->id;
    ena_qid = ENA_IO_TXQ_IDX(qid);
    io_cq = &adapter->ena_dev->io_cq_queues[ena_qid];

    tx_ring->first_interrupt = true;
    rx_ring->first_interrupt = true;

    for (i = 0; i < CLEAN_BUDGET; ++i) {
        rxc = ena_rx_cleanup(rx_ring);
        txc = ena_tx_cleanup(tx_ring);

        if ((txc != TX_BUDGET) && (rxc != RX_BUDGET))
               break;
    }

    /* Signal that work is done and unmask interrupt */
    ena_com_update_intr_reg(&intr_reg,
        RX_IRQ_INTERVAL,
        TX_IRQ_INTERVAL,
        true);
    ena_com_unmask_intr(io_cq, &intr_reg);
}

void
ena_deferred_mq_start(void *arg, int pending)
{
    struct ena_ring *tx_ring = (struct ena_ring *)arg;

    while (!buf_ring_empty(tx_ring->br) &&
        tx_ring->running) {
        ena_datapath_debug("%s: not empty!, running: %d", __func__, tx_ring->running);
        ENA_RING_MTX_LOCK(tx_ring);
        ena_start_xmit(tx_ring);
        ENA_RING_MTX_UNLOCK(tx_ring);
    }
}

err_t
ena_mq_start(struct netif *netif, struct pbuf *m)
{
    struct ena_adapter *adapter = netif->state;
    struct ena_ring *tx_ring;
    int ret, is_drbr_empty;
    uint32_t i;

    /* Which queue to use */
    /*
     * If everything is setup correctly, it should be the
     * same bucket that the current CPU we're on is.
     * It should improve performance.
     */
    i = 0;
    tx_ring = &adapter->tx_ring[i];

    /* Check if drbr is empty before putting packet */
    is_drbr_empty = buf_ring_empty(tx_ring->br);
    ret = buf_ring_enqueue(tx_ring->br, m);
    if (unlikely(ret != 0)) {
        ena_datapath_debug("%s: enqueue enqueue_task: ERR_BUF", __func__);
        enqueue(runqueue, tx_ring->enqueue_task);
        return ERR_BUF;
    }

    pbuf_ref(m);

    if (is_drbr_empty && (ENA_RING_MTX_TRYLOCK(tx_ring) != 0)) {
        ena_start_xmit(tx_ring);
        ENA_RING_MTX_UNLOCK(tx_ring);
    } else {
        ena_datapath_debug("%s: enqueue enqueue_task", __func__);
        enqueue(runqueue, tx_ring->enqueue_task);
    }

    return ERR_OK;
}

void
ena_qflush(struct ena_adapter *adapter)
{
    struct ena_ring *tx_ring = adapter->tx_ring;
    for(int i = 0; i < adapter->num_queues; ++i, ++tx_ring)
        if (!buf_ring_empty(tx_ring->br)) {
            ENA_RING_MTX_LOCK(tx_ring);
            struct pbuf *m;
            while ((m = buf_ring_dequeue_sc(tx_ring->br)) != 0)
                pbuf_free(m);
            ENA_RING_MTX_UNLOCK(tx_ring);
        }
}

/*********************************************************************
 *  Static functions
 *********************************************************************/

static inline int
validate_tx_req_id(struct ena_ring *tx_ring, uint16_t req_id)
{
    struct ena_adapter *adapter = tx_ring->adapter;
    struct ena_tx_buffer *tx_info = 0;

    if (likely(req_id < tx_ring->ring_size)) {
        tx_info = &tx_ring->tx_buffer_info[req_id];
        if (tx_info->mbuf != 0)
            return (0);
        ena_datapath_debug("tx_info doesn't have valid mbuf");
    }

    ena_datapath_debug("Invalid req_id: %hu", req_id);
//    counter_u64_add(tx_ring->tx_stats.bad_req_id, 1);

    /* Trigger device reset */
    adapter->reset_reason = ENA_REGS_RESET_INV_TX_REQ_ID;
    ENA_FLAG_SET_ATOMIC(ENA_FLAG_TRIGGER_RESET, adapter);

    return (EFAULT);
}

/**
 * ena_tx_cleanup - clear sent packets and corresponding descriptors
 * @tx_ring: ring for which we want to clean packets
 *
 * Once packets are sent, we ask the device in a loop for no longer used
 * descriptors. We find the related mbuf chain in a map (index in an array)
 * and free it, then update ring state.
 * This is performed in "endless" loop, updating ring pointers every
 * TX_COMMIT. The first check of free descriptor is performed before the actual
 * loop, then repeated at the loop end.
 **/
static int
ena_tx_cleanup(struct ena_ring *tx_ring)
{
    struct ena_adapter *adapter;
    struct ena_com_io_cq* io_cq;
    uint16_t next_to_clean;
    uint16_t req_id;
    uint16_t ena_qid;
    unsigned int total_done = 0;
    int rc;
    int commit = TX_COMMIT;
    int budget = TX_BUDGET;
    int work_done;
    bool above_thresh;

    adapter = tx_ring->que->adapter;
    ena_qid = ENA_IO_TXQ_IDX(tx_ring->que->id);
    io_cq = &adapter->ena_dev->io_cq_queues[ena_qid];
    next_to_clean = tx_ring->next_to_clean;

#ifdef DEV_NETMAP
    if (netmap_tx_irq(adapter->ifp, tx_ring->qid) != NM_IRQ_PASS)
        return (0);
#endif /* DEV_NETMAP */

    do {
        struct ena_tx_buffer *tx_info;
        struct pbuf *mbuf;

        rc = ena_com_tx_comp_req_id_get(io_cq, &req_id);
        if (unlikely(rc != 0))
            break;

        rc = validate_tx_req_id(tx_ring, req_id);
        if (unlikely(rc != 0))
            break;

        tx_info = &tx_ring->tx_buffer_info[req_id];

        mbuf = tx_info->mbuf;

        tx_info->mbuf = 0;
//        bintime_clear(&tx_info->timestamp);
        tx_info->timestamp = 0;

#if 0
        bus_dmamap_sync(adapter->tx_buf_tag, tx_info->dmamap,
            BUS_DMASYNC_POSTWRITE);
        bus_dmamap_unload(adapter->tx_buf_tag,
            tx_info->dmamap);
#endif

        ena_trace(ENA_DBG | ENA_TXPTH, "tx: q %d mbuf %p completed\n",
            tx_ring->qid, mbuf);

        pbuf_free(mbuf);

        total_done += tx_info->tx_descs;

        tx_ring->free_tx_ids[next_to_clean] = req_id;
        next_to_clean = ENA_TX_RING_IDX_NEXT(next_to_clean,
            tx_ring->ring_size);

        if (unlikely(--commit == 0)) {
            commit = TX_COMMIT;
            /* update ring state every TX_COMMIT descriptor */
            tx_ring->next_to_clean = next_to_clean;
            ena_com_comp_ack(
                &adapter->ena_dev->io_sq_queues[ena_qid],
                total_done);
            ena_com_update_dev_comp_head(io_cq);
            total_done = 0;
        }
    } while (likely(--budget));

    work_done = TX_BUDGET - budget;

    ena_trace(ENA_DBG | ENA_TXPTH, "tx: q %d done. total pkts: %d\n",
    tx_ring->qid, work_done);

    /* If there is still something to commit update ring state */
    if (likely(commit != TX_COMMIT)) {
        tx_ring->next_to_clean = next_to_clean;
        ena_com_comp_ack(&adapter->ena_dev->io_sq_queues[ena_qid],
            total_done);
        ena_com_update_dev_comp_head(io_cq);
    }

    /*
     * Need to make the rings circular update visible to
     * ena_xmit_mbuf() before checking for tx_ring->running.
     */
    memory_barrier();

    above_thresh = ena_com_sq_have_enough_space(tx_ring->ena_com_io_sq,
        ENA_TX_RESUME_THRESH);
    if (unlikely(!tx_ring->running && above_thresh)) {
        ENA_RING_MTX_LOCK(tx_ring);
        above_thresh =
            ena_com_sq_have_enough_space(tx_ring->ena_com_io_sq,
            ENA_TX_RESUME_THRESH);
        if (!tx_ring->running && above_thresh) {
            tx_ring->running = true;
            //counter_u64_add(tx_ring->tx_stats.queue_wakeup, 1);
            ena_datapath_debug("%s: enqueue enqueue_task", __func__);
            enqueue(runqueue, tx_ring->enqueue_task);
        }
        ENA_RING_MTX_UNLOCK(tx_ring);
    }

    return (work_done);
}

#if 0
static void
ena_rx_hash_mbuf(struct ena_ring *rx_ring, struct ena_com_rx_ctx *ena_rx_ctx,
    struct pbuf *mbuf)
{
    struct ena_adapter *adapter = rx_ring->adapter;

    if (likely(ENA_FLAG_ISSET(ENA_FLAG_RSS_ACTIVE, adapter))) {
        mbuf->m_pkthdr.flowid = ena_rx_ctx->hash;

        if (ena_rx_ctx->frag &&
            (ena_rx_ctx->l3_proto != ENA_ETH_IO_L3_PROTO_UNKNOWN)) {
            M_HASHTYPE_SET(mbuf, M_HASHTYPE_OPAQUE_HASH);
            return;
        }

        switch (ena_rx_ctx->l3_proto) {
        case ENA_ETH_IO_L3_PROTO_IPV4:
            switch (ena_rx_ctx->l4_proto) {
            case ENA_ETH_IO_L4_PROTO_TCP:
                M_HASHTYPE_SET(mbuf, M_HASHTYPE_RSS_TCP_IPV4);
                break;
            case ENA_ETH_IO_L4_PROTO_UDP:
                M_HASHTYPE_SET(mbuf, M_HASHTYPE_RSS_UDP_IPV4);
                break;
            default:
                M_HASHTYPE_SET(mbuf, M_HASHTYPE_RSS_IPV4);
            }
            break;
        case ENA_ETH_IO_L3_PROTO_IPV6:
            switch (ena_rx_ctx->l4_proto) {
            case ENA_ETH_IO_L4_PROTO_TCP:
                M_HASHTYPE_SET(mbuf, M_HASHTYPE_RSS_TCP_IPV6);
                break;
            case ENA_ETH_IO_L4_PROTO_UDP:
                M_HASHTYPE_SET(mbuf, M_HASHTYPE_RSS_UDP_IPV6);
                break;
            default:
                M_HASHTYPE_SET(mbuf, M_HASHTYPE_RSS_IPV6);
            }
            break;
        case ENA_ETH_IO_L3_PROTO_UNKNOWN:
            M_HASHTYPE_SET(mbuf, M_HASHTYPE_NONE);
            break;
        default:
            M_HASHTYPE_SET(mbuf, M_HASHTYPE_OPAQUE_HASH);
        }
    } else {
        mbuf->m_pkthdr.flowid = rx_ring->qid;
        M_HASHTYPE_SET(mbuf, M_HASHTYPE_NONE);
    }
}
#endif

/**
 * ena_rx_mbuf - assemble mbuf from descriptors
 * @rx_ring: ring for which we want to clean packets
 * @ena_bufs: buffer info
 * @ena_rx_ctx: metadata for this packet(s)
 * @next_to_clean: ring pointer, will be updated only upon success
 *
 **/
static struct pbuf*
ena_rx_mbuf(struct ena_ring *rx_ring, struct ena_com_rx_buf_info *ena_bufs,
    struct ena_com_rx_ctx *ena_rx_ctx, uint16_t *next_to_clean)
{
    struct pbuf *mbuf;
    struct ena_rx_buffer *rx_info;
    struct ena_adapter *adapter;
    unsigned int descs = ena_rx_ctx->descs;
    int rc;
    uint16_t ntc, len, req_id, buf = 0;

    ntc = *next_to_clean;
    adapter = rx_ring->adapter;

    len = ena_bufs[buf].len;
    req_id = ena_bufs[buf].req_id;
    rc = validate_rx_req_id(rx_ring, req_id);
    if (unlikely(rc != 0))
        return (0);

    rx_info = &rx_ring->rx_buffer_info[req_id];
    if (unlikely(rx_info->mbuf == 0)) {
        ena_datapath_debug("NULL mbuf in rx_info");
        return (0);
    }

    ena_trace(ENA_DBG | ENA_RXPTH, "rx_info %p, mbuf %p, paddr %x\n",
        rx_info, rx_info->mbuf, (u64)rx_info->ena_buf.paddr);

#if 0
    bus_dmamap_sync(adapter->rx_buf_tag, rx_info->map,
        BUS_DMASYNC_POSTREAD);
#endif
    mbuf = rx_info->mbuf;
#if 0
    mbuf->m_flags |= M_PKTHDR;
    mbuf->m_pkthdr.len = len;
#endif
    mbuf->len = len;
//    mbuf->m_pkthdr.rcvif = rx_ring->que->adapter->ifp;

    /* Fill mbuf with hash key and it's interpretation for optimization */
//    ena_rx_hash_mbuf(rx_ring, ena_rx_ctx, mbuf);

    ena_trace(ENA_DBG | ENA_RXPTH, "rx mbuf 0x%p, flags=0x%x, len: %d\n",
        mbuf, mbuf->flags, mbuf->len);

    /* DMA address is not needed anymore, unmap it */
//    bus_dmamap_unload(rx_ring->adapter->rx_buf_tag, rx_info->map);

    rx_info->mbuf = 0;
    rx_ring->free_rx_ids[ntc] = req_id;
    ntc = ENA_RX_RING_IDX_NEXT(ntc, rx_ring->ring_size);

    /*
     * While we have more than 1 descriptors for one rcvd packet, append
     * other mbufs to the main one
     */
    while (--descs) {
        ++buf;
        len = ena_bufs[buf].len;
        req_id = ena_bufs[buf].req_id;
        rc = validate_rx_req_id(rx_ring, req_id);
        if (unlikely(rc != 0)) {
            /*
             * If the req_id is invalid, then the device will be
             * reset. In that case we must free all mbufs that
             * were already gathered.
             */
            pbuf_free(mbuf);
            return (0);
        }
        rx_info = &rx_ring->rx_buffer_info[req_id];

        if (unlikely(rx_info->mbuf == 0)) {
            ena_datapath_debug("NULL mbuf in rx_info");
            /*
             * If one of the required mbufs was not allocated yet,
             * we can break there.
             * All earlier used descriptors will be reallocated
             * later and not used mbufs can be reused.
             * The next_to_clean pointer will not be updated in case
             * of an error, so caller should advance it manually
             * in error handling routine to keep it up to date
             * with hw ring.
             */
            pbuf_free(mbuf);
            return (0);
        }

#if 0
        bus_dmamap_sync(adapter->rx_buf_tag, rx_info->map,
            BUS_DMASYNC_POSTREAD);
#endif
        if (unlikely(ena_m_append(adapter, (xpbuf)mbuf, len, rx_info->mbuf->payload) == 0)) {
            //counter_u64_add(rx_ring->rx_stats.mbuf_alloc_fail, 1);
            ena_trace(ENA_WARNING, "Failed to append Rx mbuf %p\n",
                mbuf);
        }

        ena_trace(ENA_DBG | ENA_RXPTH,
            "rx mbuf updated. len %d\n", mbuf->len);

        /* Free already appended mbuf, it won't be useful anymore */
//        bus_dmamap_unload(rx_ring->adapter->rx_buf_tag, rx_info->map);
        pbuf_free(rx_info->mbuf);
        rx_info->mbuf = 0;

        rx_ring->free_rx_ids[ntc] = req_id;
        ntc = ENA_RX_RING_IDX_NEXT(ntc, rx_ring->ring_size);
    }

    *next_to_clean = ntc;

    return (mbuf);
}

#if 0
/**
 * ena_rx_checksum - indicate in mbuf if hw indicated a good cksum
 **/
static inline void
ena_rx_checksum(struct ena_ring *rx_ring, struct ena_com_rx_ctx *ena_rx_ctx,
    struct pbuf *mbuf)
{

    /* if IP and error */
    if (unlikely((ena_rx_ctx->l3_proto == ENA_ETH_IO_L3_PROTO_IPV4) &&
        ena_rx_ctx->l3_csum_err)) {
        /* ipv4 checksum error */
        mbuf->m_pkthdr.csum_flags = 0;
        counter_u64_add(rx_ring->rx_stats.bad_csum, 1);
        ena_trace(ENA_DBG, "RX IPv4 header checksum error\n");
        return;
    }

    /* if TCP/UDP */
    if ((ena_rx_ctx->l4_proto == ENA_ETH_IO_L4_PROTO_TCP) ||
        (ena_rx_ctx->l4_proto == ENA_ETH_IO_L4_PROTO_UDP)) {
        if (ena_rx_ctx->l4_csum_err) {
            /* TCP/UDP checksum error */
            mbuf->m_pkthdr.csum_flags = 0;
            counter_u64_add(rx_ring->rx_stats.bad_csum, 1);
            ena_trace(ENA_DBG, "RX L4 checksum error\n");
        } else {
            mbuf->m_pkthdr.csum_flags = CSUM_IP_CHECKED;
            mbuf->m_pkthdr.csum_flags |= CSUM_IP_VALID;
        }
    }
}
#endif

/**
 * ena_rx_cleanup - handle rx irq
 * @arg: ring for which irq is being handled
 **/
static int
ena_rx_cleanup(struct ena_ring *rx_ring)
{
    struct ena_adapter *adapter;
    struct pbuf *mbuf;
    struct ena_com_rx_ctx ena_rx_ctx;
    struct ena_com_io_cq* io_cq;
    struct ena_com_io_sq* io_sq;
    uint16_t ena_qid;
    uint16_t next_to_clean;
    uint32_t refill_required;
    uint32_t refill_threshold;
    unsigned int qid;
    int rc, i;
    int budget = RX_BUDGET;
#ifdef DEV_NETMAP
    int done;
#endif /* DEV_NETMAP */

    adapter = rx_ring->que->adapter;
    qid = rx_ring->que->id;
    ena_qid = ENA_IO_RXQ_IDX(qid);
    io_cq = &adapter->ena_dev->io_cq_queues[ena_qid];
    io_sq = &adapter->ena_dev->io_sq_queues[ena_qid];
    next_to_clean = rx_ring->next_to_clean;

#ifdef DEV_NETMAP
    if (netmap_rx_irq(adapter->ifp, rx_ring->qid, &done) != NM_IRQ_PASS)
        return (0);
#endif /* DEV_NETMAP */

    ena_trace(ENA_DBG, "rx: qid %d\n", qid);

    do {
        ena_rx_ctx.ena_bufs = rx_ring->ena_bufs;
        ena_rx_ctx.max_bufs = adapter->max_rx_sgl_size;
        ena_rx_ctx.descs = 0;
//        bus_dmamap_sync(io_cq->cdesc_addr.mem_handle.tag,
//            io_cq->cdesc_addr.mem_handle.map, BUS_DMASYNC_POSTREAD);
        rc = ena_com_rx_pkt(io_cq, io_sq, &ena_rx_ctx);

        if (unlikely(rc != 0))
            goto error;

        if (unlikely(ena_rx_ctx.descs == 0))
            break;

        ena_trace(ENA_DBG | ENA_RXPTH, "rx: q %d got packet from ena. "
            "descs #: %d l3 proto %d l4 proto %d hash: %x\n",
            rx_ring->qid, ena_rx_ctx.descs, ena_rx_ctx.l3_proto,
            ena_rx_ctx.l4_proto, ena_rx_ctx.hash);

        /* Receive mbuf from the ring */
        mbuf = ena_rx_mbuf(rx_ring, rx_ring->ena_bufs,
            &ena_rx_ctx, &next_to_clean);
//        bus_dmamap_sync(io_cq->cdesc_addr.mem_handle.tag,
//            io_cq->cdesc_addr.mem_handle.map, BUS_DMASYNC_PREREAD);
        /* Exit if we failed to retrieve a buffer */
        if (unlikely(mbuf == 0)) {
            for (i = 0; i < ena_rx_ctx.descs; ++i) {
                rx_ring->free_rx_ids[next_to_clean] =
                    rx_ring->ena_bufs[i].req_id;
                next_to_clean =
                    ENA_RX_RING_IDX_NEXT(next_to_clean,
                    rx_ring->ring_size);

            }
            break;
        }
#if 0 // TODO
        if (((ifp->if_capenable & IFCAP_RXCSUM) != 0) ||
            ((ifp->if_capenable & IFCAP_RXCSUM_IPV6) != 0)) {
            ena_rx_checksum(rx_ring, &ena_rx_ctx, mbuf);
        }

        counter_enter();
        counter_u64_add_protected(rx_ring->rx_stats.bytes,
            mbuf->m_pkthdr.len);
        counter_u64_add_protected(adapter->hw_stats.rx_bytes,
            mbuf->m_pkthdr.len);
        counter_exit();
        /*
         * LRO is only for IP/TCP packets and TCP checksum of the packet
         * should be computed by hardware.
         */
        do_if_input = 1;
        if (((ifp->if_capenable & IFCAP_LRO) != 0)  &&
            ((mbuf->m_pkthdr.csum_flags & CSUM_IP_VALID) != 0) &&
            (ena_rx_ctx.l4_proto == ENA_ETH_IO_L4_PROTO_TCP)) {
            /*
             * Send to the stack if:
             *  - LRO not enabled, or
             *  - no LRO resources, or
             *  - lro enqueue fails
             */
            if ((rx_ring->lro.lro_cnt != 0) &&
                (tcp_lro_rx(&rx_ring->lro, mbuf, 0) == 0))
                    do_if_input = 0;
        }
        if (do_if_input != 0) {
            ena_trace(ENA_DBG | ENA_RXPTH,
                "calling if_input() with mbuf %p\n", mbuf);
            (*ifp->if_input)(ifp, mbuf);
        }

        counter_enter();
        counter_u64_add_protected(rx_ring->rx_stats.cnt, 1);
        counter_u64_add_protected(adapter->hw_stats.rx_packets, 1);
        counter_exit();
#endif
        err_enum_t err = adapter->netif->input(mbuf, adapter->netif);
        if (err != ERR_OK) {
            msg_err("netvsc: rx drop by stack, err %d\n", err);
            pbuf_free(mbuf);
        }
    } while (--budget);

    rx_ring->next_to_clean = next_to_clean;

    refill_required = ena_com_free_desc(io_sq);
    refill_threshold = min_t(int,
        rx_ring->ring_size / ENA_RX_REFILL_THRESH_DIVIDER,
        ENA_RX_REFILL_THRESH_PACKET);

    if (refill_required > refill_threshold) {
        ena_com_update_dev_comp_head(rx_ring->ena_com_io_cq);
        ena_refill_rx_bufs(rx_ring, refill_required);
    }

//    tcp_lro_flush_all(&rx_ring->lro);

    return (RX_BUDGET - budget);

error:
//    counter_u64_add(rx_ring->rx_stats.bad_desc_num, 1);

    /* Too many desc from the device. Trigger reset */
    if (likely(!ENA_FLAG_ISSET(ENA_FLAG_TRIGGER_RESET, adapter))) {
        adapter->reset_reason = ENA_REGS_RESET_TOO_MANY_RX_DESCS;
        ENA_FLAG_SET_ATOMIC(ENA_FLAG_TRIGGER_RESET, adapter);
    }

    return (0);
}

#if 0
static void
ena_tx_csum(struct ena_com_tx_ctx *ena_tx_ctx, struct pbuf *mbuf)
{
    struct ena_com_tx_meta *ena_meta;
    struct ether_vlan_header *eh;
    struct pbuf *mbuf_next;
    u32 mss;
    bool offload;
    uint16_t etype;
    int ehdrlen;
    struct ip *ip;
    int iphlen;
    struct tcphdr *th;
    int offset;

    offload = false;
    ena_meta = &ena_tx_ctx->ena_meta;
    mss = mbuf->m_pkthdr.tso_segsz;

    if (mss != 0)
        offload = true;

    if ((mbuf->m_pkthdr.csum_flags & CSUM_TSO) != 0)
        offload = true;

    if ((mbuf->m_pkthdr.csum_flags & CSUM_OFFLOAD) != 0)
        offload = true;

    if (!offload) {
        ena_tx_ctx->meta_valid = 0;
        return;
    }

    /* Determine where frame payload starts. */
    eh = mtod(mbuf, struct ether_vlan_header *);
    if (eh->evl_encap_proto == htons(ETHERTYPE_VLAN)) {
        etype = ntohs(eh->evl_proto);
        ehdrlen = ETHER_HDR_LEN + ETHER_VLAN_ENCAP_LEN;
    } else {
        etype = ntohs(eh->evl_encap_proto);
        ehdrlen = ETHER_HDR_LEN;
    }

    mbuf_next = m_getptr(mbuf, ehdrlen, &offset);
    ip = (struct ip *)(mtodo(mbuf_next, offset));
    iphlen = ip->ip_hl << 2;

    mbuf_next = m_getptr(mbuf, iphlen + ehdrlen, &offset);
    th = (struct tcphdr *)(mtodo(mbuf_next, offset));

    if ((mbuf->m_pkthdr.csum_flags & CSUM_IP) != 0) {
        ena_tx_ctx->l3_csum_enable = 1;
    }
    if ((mbuf->m_pkthdr.csum_flags & CSUM_TSO) != 0) {
        ena_tx_ctx->tso_enable = 1;
        ena_meta->l4_hdr_len = (th->th_off);
    }

    switch (etype) {
    case ETHERTYPE_IP:
        ena_tx_ctx->l3_proto = ENA_ETH_IO_L3_PROTO_IPV4;
        if ((ip->ip_off & htons(IP_DF)) != 0)
            ena_tx_ctx->df = 1;
        break;
    case ETHERTYPE_IPV6:
        ena_tx_ctx->l3_proto = ENA_ETH_IO_L3_PROTO_IPV6;

    default:
        break;
    }

    if (ip->ip_p == IPPROTO_TCP) {
        ena_tx_ctx->l4_proto = ENA_ETH_IO_L4_PROTO_TCP;
        if ((mbuf->m_pkthdr.csum_flags &
            (CSUM_IP_TCP | CSUM_IP6_TCP)) != 0)
            ena_tx_ctx->l4_csum_enable = 1;
        else
            ena_tx_ctx->l4_csum_enable = 0;
    } else if (ip->ip_p == IPPROTO_UDP) {
        ena_tx_ctx->l4_proto = ENA_ETH_IO_L4_PROTO_UDP;
        if ((mbuf->m_pkthdr.csum_flags &
            (CSUM_IP_UDP | CSUM_IP6_UDP)) != 0)
            ena_tx_ctx->l4_csum_enable = 1;
        else
            ena_tx_ctx->l4_csum_enable = 0;
    } else {
        ena_tx_ctx->l4_proto = ENA_ETH_IO_L4_PROTO_UNKNOWN;
        ena_tx_ctx->l4_csum_enable = 0;
    }

    ena_meta->mss = mss;
    ena_meta->l3_hdr_len = iphlen;
    ena_meta->l3_hdr_offset = ehdrlen;
    ena_tx_ctx->meta_valid = 1;
}

static int
ena_check_and_collapse_mbuf(struct ena_ring *tx_ring, struct pbuf **mbuf)
{
    struct ena_adapter *adapter;
    struct pbuf *collapsed_mbuf;
    int num_frags;

    adapter = tx_ring->adapter;
    num_frags = ena_mbuf_count(*mbuf);

    /* One segment must be reserved for configuration descriptor. */
    if (num_frags < adapter->max_tx_sgl_size)
        return (0);
    counter_u64_add(tx_ring->tx_stats.collapse, 1);

    collapsed_mbuf = m_collapse(*mbuf, M_NOWAIT,
        adapter->max_tx_sgl_size - 1);
    if (unlikely(collapsed_mbuf == NULL)) {
        counter_u64_add(tx_ring->tx_stats.collapse_err, 1);
        return (ENOMEM);
    }

    /* If mbuf was collapsed succesfully, original mbuf is released. */
    *mbuf = collapsed_mbuf;

    return (0);
}
#endif

typedef struct bus_dma_segment {
    u64  ds_addr;    /* DMA address */
    size_t  ds_len;  /* length of transfer */
} bus_dma_segment_t;

static int
ena_tx_map_mbuf(struct ena_ring *tx_ring, struct ena_tx_buffer *tx_info,
    struct pbuf *mbuf, void **push_hdr, u16 *header_len)
{
//    struct ena_adapter *adapter = tx_ring->adapter;
    struct ena_com_buf *ena_buf;
    bus_dma_segment_t segs[ENA_BUS_DMA_SEGS];
    size_t iseg = 0;
    uint32_t mbuf_head_len, frag_len;
    uint16_t push_len = 0;
    uint16_t delta = 0;

    mbuf_head_len = mbuf->len;
    tx_info->mbuf = mbuf;
    ena_buf = tx_info->bufs;

    int nsegs = 0;
    for (struct pbuf * q = mbuf; q != NULL; q = q->next) {
        if (q->len) {
            assert(nsegs < ENA_BUS_DMA_SEGS);
            segs[nsegs].ds_addr = physical_from_virtual(q->payload);
            assert(segs[nsegs].ds_addr != INVALID_PHYSICAL);
            segs[nsegs].ds_len = q->len;
            ++nsegs;
        }
    }
#if 0
    /*
     * For easier maintaining of the DMA map, map the whole mbuf even if
     * the LLQ is used. The descriptors will be filled using the segments.
     */
    rc = bus_dmamap_load_mbuf_sg(adapter->tx_buf_tag, tx_info->dmamap, mbuf,
        segs, &nsegs, BUS_DMA_NOWAIT);
    if (unlikely((rc != 0) || (nsegs == 0))) {
        ena_trace(ENA_WARNING,
            "dmamap load failed! err: %d nsegs: %d\n", rc, nsegs);
        goto dma_error;
    }
#endif

    if (tx_ring->tx_mem_queue_type == ENA_ADMIN_PLACEMENT_POLICY_DEV) {
        /*
         * When the device is LLQ mode, the driver will copy
         * the header into the device memory space.
         * the ena_com layer assumes the header is in a linear
         * memory space.
         * This assumption might be wrong since part of the header
         * can be in the fragmented buffers.
         * First check if header fits in the mbuf. If not, copy it to
         * separate buffer that will be holding linearized data.
         */
        push_len = min_t(uint32_t, mbuf->len,
            tx_ring->tx_max_header_size);
        *header_len = push_len;
        /* If header is in linear space, just point into mbuf's data. */
        if (likely(push_len <= mbuf_head_len)) {
            *push_hdr = mbuf->payload;
        /*
         * Otherwise, copy whole portion of header from multiple mbufs
         * to intermediate buffer.
         */
        } else {
//            m_copydata(mbuf, 0, push_len,
//                tx_ring->push_buf_intermediate_buf);
            runtime_memcpy(tx_ring->push_buf_intermediate_buf, mbuf->payload, push_len);
            *push_hdr = tx_ring->push_buf_intermediate_buf;

//            counter_u64_add(tx_ring->tx_stats.llq_buffer_copy, 1);
            delta = push_len - mbuf_head_len;
        }

        ena_trace(ENA_DBG | ENA_TXPTH,
            "mbuf: %p header_buf->vaddr: %p push_len: %d\n",
            mbuf, *push_hdr, push_len);

        /*
        * If header was in linear memory space, map for the dma rest of the data
        * in the first mbuf of the mbuf chain.
        */
        if (mbuf_head_len > push_len) {
            ena_buf->paddr = segs[iseg].ds_addr + push_len;
            ena_buf->len = segs[iseg].ds_len - push_len;
            ena_buf++;
            tx_info->num_of_bufs++;
        }
        /*
         * Advance the seg index as either the 1st mbuf was mapped or is
         * a part of push_hdr.
         */
        iseg++;
    } else {
        *push_hdr = NULL;
        /*
        * header_len is just a hint for the device. Because FreeBSD is not
        * giving us information about packet header length and it is not
        * guaranteed that all packet headers will be in the 1st mbuf, setting
        * header_len to 0 is making the device ignore this value and resolve
        * header on it's own.
        */
        *header_len = 0;
    }

    /*
     * If header is in non linear space (delta > 0), then skip mbufs
     * containing header and map the last one containing both header and the
     * packet data.
     * The first segment is already counted in.
     * If LLQ is not supported, the loop will be skipped.
     */
    while (delta > 0) {
        frag_len = segs[iseg].ds_len;

        /*
         * If whole segment contains header just move to the
         * next one and reduce delta.
         */
        if (unlikely(delta >= frag_len)) {
            delta -= frag_len;
        } else {
            /*
             * Map rest of the packet data that was contained in
             * the mbuf.
             */
            ena_buf->paddr = segs[iseg].ds_addr + delta;
            ena_buf->len = frag_len - delta;
            ena_buf++;
            tx_info->num_of_bufs++;

            delta = 0;
        }
        iseg++;
    }

    if (mbuf == NULL) {
        return (0);
    }

    /* Map rest of the mbuf */
    while (iseg < nsegs) {
        ena_buf->paddr = segs[iseg].ds_addr;
        ena_buf->len = segs[iseg].ds_len;
        ena_buf++;
        iseg++;
        tx_info->num_of_bufs++;
    }

    return (0);
}

static int
ena_xmit_mbuf(struct ena_ring *tx_ring, struct pbuf **mbuf)
{
    struct ena_adapter *adapter;
    struct ena_tx_buffer *tx_info;
    struct ena_com_tx_ctx ena_tx_ctx;
    struct ena_com_dev *ena_dev;
    struct ena_com_io_sq* io_sq;
    void *push_hdr;
    uint16_t next_to_use;
    uint16_t req_id;
    uint16_t ena_qid;
    uint16_t header_len;
    int rc;
    int nb_hw_desc;

    ena_qid = ENA_IO_TXQ_IDX(tx_ring->que->id);
    adapter = tx_ring->que->adapter;
    ena_dev = adapter->ena_dev;
    io_sq = &ena_dev->io_sq_queues[ena_qid];
#if 0
    rc = ena_check_and_collapse_mbuf(tx_ring, mbuf);
    if (unlikely(rc != 0)) {
        ena_trace(ENA_WARNING,
            "Failed to collapse mbuf! err: %d\n", rc);
        return (rc);
    }
#endif
    ena_trace(ENA_DBG | ENA_TXPTH, "Tx: %d bytes\n", (*mbuf)->len);

    next_to_use = tx_ring->next_to_use;
    req_id = tx_ring->free_tx_ids[next_to_use];
    tx_info = &tx_ring->tx_buffer_info[req_id];
    tx_info->num_of_bufs = 0;

    rc = ena_tx_map_mbuf(tx_ring, tx_info, *mbuf, &push_hdr, &header_len);
    if (unlikely(rc != 0)) {
        ena_trace(ENA_WARNING, "Failed to map TX mbuf\n");
        return (rc);
    }
    memset(&ena_tx_ctx, 0x0, sizeof(struct ena_com_tx_ctx));
    ena_tx_ctx.ena_bufs = tx_info->bufs;
    ena_tx_ctx.push_header = push_hdr;
    ena_tx_ctx.num_bufs = tx_info->num_of_bufs;
    ena_tx_ctx.req_id = req_id;
    ena_tx_ctx.header_len = header_len;

    /* Set flags and meta data */
//    ena_tx_csum(&ena_tx_ctx, *mbuf);

    if (tx_ring->acum_pkts == DB_THRESHOLD ||
        ena_com_is_doorbell_needed(tx_ring->ena_com_io_sq, &ena_tx_ctx)) {
        ena_trace(ENA_DBG | ENA_TXPTH,
            "llq tx max burst size of queue %d achieved, writing doorbell to send burst\n",
            tx_ring->que->id);
        write_barrier();
        ena_com_write_sq_doorbell(tx_ring->ena_com_io_sq);
//        counter_u64_add(tx_ring->tx_stats.doorbells, 1);
        tx_ring->acum_pkts = 0;
    }

    /* Prepare the packet's descriptors and send them to device */
    rc = ena_com_prepare_tx(io_sq, &ena_tx_ctx, &nb_hw_desc);
    if (unlikely(rc != 0)) {
        if (likely(rc == ENA_COM_NO_MEM)) {
            ena_trace(ENA_DBG | ENA_TXPTH,
                "tx ring[%d] if out of space\n", tx_ring->que->id);
        } else {
            ena_datapath_debug("failed to prepare tx bufs");
        }
        //counter_u64_add(tx_ring->tx_stats.prepare_ctx_err, 1);
        goto dma_error;
    }

#if 0
    counter_enter();
    counter_u64_add_protected(tx_ring->tx_stats.cnt, 1);
    counter_u64_add_protected(tx_ring->tx_stats.bytes,
        (*mbuf)->m_pkthdr.len);

    counter_u64_add_protected(adapter->hw_stats.tx_packets, 1);
    counter_u64_add_protected(adapter->hw_stats.tx_bytes,
        (*mbuf)->m_pkthdr.len);
    counter_exit();
#endif
    tx_info->tx_descs = nb_hw_desc;
    tx_info->timestamp = now(CLOCK_ID_MONOTONIC);
//    tx_info->print_once = true;

    tx_ring->next_to_use = ENA_TX_RING_IDX_NEXT(next_to_use,
        tx_ring->ring_size);

    /* stop the queue when no more space available, the packet can have up
     * to sgl_size + 2. one for the meta descriptor and one for header
     * (if the header is larger than tx_max_header_size).
     */
    if (unlikely(!ena_com_sq_have_enough_space(tx_ring->ena_com_io_sq,
        adapter->max_tx_sgl_size + 2))) {
        ena_trace(ENA_DBG | ENA_TXPTH, "Stop queue %d\n",
            tx_ring->que->id);

        tx_ring->running = false;
        //counter_u64_add(tx_ring->tx_stats.queue_stop, 1);

        /* There is a rare condition where this function decides to
         * stop the queue but meanwhile tx_cleanup() updates
         * next_to_completion and terminates.
         * The queue will remain stopped forever.
         * To solve this issue this function performs mb(), checks
         * the wakeup condition and wakes up the queue if needed.
         */
        memory_barrier();

        if (ena_com_sq_have_enough_space(tx_ring->ena_com_io_sq,
            ENA_TX_RESUME_THRESH)) {
            tx_ring->running = true;
            //counter_u64_add(tx_ring->tx_stats.queue_wakeup, 1);
        }
    }
#if 0
    bus_dmamap_sync(adapter->tx_buf_tag, tx_info->dmamap,
        BUS_DMASYNC_PREWRITE);
#endif

    return (0);

dma_error:
    tx_info->mbuf = 0;
    //bus_dmamap_unload(adapter->tx_buf_tag, tx_info->dmamap);

    return (rc);
}

static void
ena_start_xmit(struct ena_ring *tx_ring)
{
    struct pbuf *mbuf;
    struct ena_adapter *adapter = tx_ring->adapter;
    struct ena_com_io_sq* io_sq;
    int ena_qid;
    int ret = 0;

    if (unlikely(!ENA_FLAG_ISSET(ENA_FLAG_LINK_UP, adapter))) {
        ena_datapath_debug("LINK IS NOT UP");
        return;
    }

    ena_qid = ENA_IO_TXQ_IDX(tx_ring->que->id);
    io_sq = &adapter->ena_dev->io_sq_queues[ena_qid];

    while ((mbuf = buf_ring_peek_clear_sc(tx_ring->br)) != 0) {
        ena_trace(ENA_DBG | ENA_TXPTH, "\ndequeued mbuf %p with flags %x\n", mbuf, mbuf->flags);

        if (unlikely(!tx_ring->running)) {
            buf_ring_putback_sc(tx_ring->br, mbuf);
            break;
        }

        if (unlikely((ret = ena_xmit_mbuf(tx_ring, &mbuf)) != 0)) {
            if (ret == ENA_COM_NO_MEM) {
                buf_ring_putback_sc(tx_ring->br, mbuf);
            } else if (ret == ENA_COM_NO_SPACE) {
                buf_ring_putback_sc(tx_ring->br, mbuf);
            } else {
                pbuf_free(mbuf);
                buf_ring_advance_sc(tx_ring->br);
            }

            break;
        }

        buf_ring_advance_sc(tx_ring->br);

        tx_ring->acum_pkts++;

//        BPF_MTAP(adapter->ifp, mbuf);
    }

    if (likely(tx_ring->acum_pkts != 0)) {
        write_barrier();
        /* Trigger the dma engine */
        ena_com_write_sq_doorbell(io_sq);
//        counter_u64_add(tx_ring->tx_stats.doorbells, 1);
        tx_ring->acum_pkts = 0;
    }

    ena_datapath_debug("%s:%x, tx_ring->running %d", __func__, &tx_ring->que->cleanup_task,
            tx_ring->running);
    if (unlikely(!tx_ring->running)) {
        ena_datapath_debug("%s: enqueue cleanup_task", __func__);
        enqueue(runqueue, tx_ring->que->cleanup_task);
    }
}
