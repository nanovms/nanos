/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2015-2020 Amazon.com, Inc. or its affiliates.
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
#include <lwip.h>
#include <pci.h>

#include "ena.h"
#include "ena_datapath.h"

/*********************************************************************
 *  Static functions prototypes
 *********************************************************************/

static int ena_tx_cleanup(struct ena_ring *);
static int ena_rx_cleanup(struct ena_ring *);
static inline int validate_tx_req_id(struct ena_ring *, uint16_t);
static struct pbuf *ena_rx_mbuf(struct ena_ring *, struct ena_com_rx_buf_info *,
                                struct ena_com_rx_ctx *, uint16_t *);
static int ena_xmit_mbuf(struct ena_ring *, struct pbuf **);
static void ena_start_xmit(struct ena_ring *);

/*********************************************************************
 *  Global functions
 *********************************************************************/

void ena_cleanup(void *arg, int pending)
{
    struct ena_que *que = arg;
    struct ena_adapter *adapter = que->adapter;
    struct netif *netif = &adapter->ndev.n;
    struct ena_ring *tx_ring;
    struct ena_ring *rx_ring;
    struct ena_com_io_cq *io_cq;
    struct ena_eth_io_intr_reg intr_reg;
    int qid, ena_qid;
    int txc, rxc, i;

    if (unlikely(!netif_is_flag_set(netif, NETIF_FLAG_UP)))
        return;

    ena_trace(NULL, ENA_DBG, "MSI-X TX/RX routine\n");

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

        if (unlikely(!netif_is_flag_set(netif, NETIF_FLAG_UP)))
            return;

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

void ena_deferred_mq_start(void *arg, int pending)
{
    struct ena_ring *tx_ring = (struct ena_ring*) arg;
    struct netif *netif = &tx_ring->adapter->ndev.n;

    while (!queue_empty(tx_ring->br) && tx_ring->running && netif_is_flag_set(netif, NETIF_FLAG_UP)) {
        ENA_RING_MTX_LOCK(tx_ring);
        ena_start_xmit(tx_ring);
        ENA_RING_MTX_UNLOCK(tx_ring);
    }
}

err_t ena_linkoutput(struct netif *netif, struct pbuf *p)
{
    struct ena_adapter *adapter = netif->state;
    struct ena_ring *tx_ring;
    int is_drbr_empty;
    uint32_t i;

    if (unlikely(!netif_is_flag_set(netif, NETIF_FLAG_UP)))
        return ERR_IF;

    /* Which queue to use */
    i = current_cpu()->id % adapter->num_io_queues;
    tx_ring = &adapter->tx_ring[i];

    /* Check if drbr is empty before putting packet */
    is_drbr_empty = queue_empty(tx_ring->br);
    if (unlikely(!enqueue(tx_ring->br, p))) {
        async_apply((thunk)&tx_ring->enqueue_task);
        return ERR_MEM;
    }
    pbuf_ref(p);
    if (is_drbr_empty && (ENA_RING_MTX_TRYLOCK(tx_ring) != 0)) {
        ena_start_xmit(tx_ring);
        ENA_RING_MTX_UNLOCK(tx_ring);
    } else {
        async_apply((thunk)&tx_ring->enqueue_task);
    }

    return (0);
}

/*********************************************************************
 *  Static functions
 *********************************************************************/

static inline int validate_tx_req_id(struct ena_ring *tx_ring, uint16_t req_id)
{
    struct ena_adapter *adapter = tx_ring->adapter;
    struct ena_tx_buffer *tx_info = NULL;

    if (likely(req_id < tx_ring->ring_size)) {
        tx_info = &tx_ring->tx_buffer_info[req_id];
        if (tx_info->mbuf != NULL)
            return (0);
        device_printf(adapter->pdev, "tx_info doesn't have valid mbuf\n");
    }

    device_printf(adapter->pdev, "Invalid req_id: %hu\n", req_id);
    tx_ring->tx_stats.bad_req_id++;

    /* Trigger device reset */
    ena_trigger_reset(adapter, ENA_REGS_RESET_INV_TX_REQ_ID);

    return (ENA_COM_FAULT);
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
static int ena_tx_cleanup(struct ena_ring *tx_ring)
{
    struct ena_adapter *adapter;
    struct ena_com_io_cq *io_cq;
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

        tx_info->mbuf = NULL;
        tx_info->timestamp = 0;

        ena_trace(NULL, ENA_DBG | ENA_TXPTH, "tx: q %d mbuf %p completed\n", tx_ring->qid, mbuf);

        pbuf_free(mbuf);

        total_done += tx_info->tx_descs;

        tx_ring->free_tx_ids[next_to_clean] = req_id;
        next_to_clean = ENA_TX_RING_IDX_NEXT(next_to_clean, tx_ring->ring_size);

        if (unlikely(--commit == 0)) {
            commit = TX_COMMIT;
            /* update ring state every TX_COMMIT descriptor */
            tx_ring->next_to_clean = next_to_clean;
            ena_com_comp_ack(&adapter->ena_dev->io_sq_queues[ena_qid], total_done);
            ena_com_update_dev_comp_head(io_cq);
            total_done = 0;
        }
    } while (likely(--budget));

    work_done = TX_BUDGET - budget;

    ena_trace(NULL, ENA_DBG | ENA_TXPTH, "tx: q %d done. total pkts: %d\n",
              tx_ring->qid, work_done);

    /* If there is still something to commit update ring state */
    if (likely(commit != TX_COMMIT)) {
        tx_ring->next_to_clean = next_to_clean;
        ena_com_comp_ack(&adapter->ena_dev->io_sq_queues[ena_qid], total_done);
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
        above_thresh = ena_com_sq_have_enough_space(tx_ring->ena_com_io_sq,
        ENA_TX_RESUME_THRESH);
        if (!tx_ring->running && above_thresh) {
            tx_ring->running = true;
            tx_ring->tx_stats.queue_wakeup++;
            async_apply((thunk)&tx_ring->enqueue_task);
        }
        ENA_RING_MTX_UNLOCK(tx_ring);
    }

    return (work_done);
}

/**
 * ena_rx_mbuf - assemble mbuf from descriptors
 * @rx_ring: ring for which we want to clean packets
 * @ena_bufs: buffer info
 * @ena_rx_ctx: metadata for this packet(s)
 * @next_to_clean: ring pointer, will be updated only upon success
 *
 * called with lwIP lock held
 **/
static struct pbuf *ena_rx_mbuf(struct ena_ring *rx_ring, struct ena_com_rx_buf_info *ena_bufs,
                                struct ena_com_rx_ctx *ena_rx_ctx, uint16_t *next_to_clean)
{
    struct pbuf *mbuf;
    struct ena_rx_buffer *rx_info;
    unsigned int descs = ena_rx_ctx->descs;
    uint16_t ntc, len, req_id, buf = 0;

    ntc = *next_to_clean;

    len = ena_bufs[buf].len;
    req_id = ena_bufs[buf].req_id;
    rx_info = &rx_ring->rx_buffer_info[req_id];
    if (unlikely(rx_info->mbuf == NULL)) {
        device_printf(rx_ring->adapter->pdev, "NULL mbuf in rx_info");
        return (NULL);
    }

    ena_trace(NULL, ENA_DBG | ENA_RXPTH, "rx_info %p, mbuf %p, paddr %p\n",
              rx_info, rx_info->mbuf, rx_info->ena_buf.paddr);

    mbuf = rx_info->mbuf;
    mbuf->len = mbuf->tot_len = len;
    // Only for the first segment the data starts at specific offset
    mbuf->payload += ena_rx_ctx->pkt_offset;
    ena_trace(NULL, ENA_DBG | ENA_RXPTH, "Mbuf data offset=%d\n", ena_rx_ctx->pkt_offset);

    ena_trace(NULL, ENA_DBG | ENA_RXPTH, "rx mbuf 0x%p, len: %d\n", mbuf, mbuf->len);

    rx_info->mbuf = NULL;
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
        rx_info = &rx_ring->rx_buffer_info[req_id];

        if (unlikely(rx_info->mbuf == NULL)) {
            device_printf(rx_ring->adapter->pdev, "NULL mbuf in rx_info");
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
            return (NULL);
        }

        rx_info->mbuf->len = rx_info->mbuf->tot_len = len;
        pbuf_cat(mbuf, rx_info->mbuf);

        ena_trace(NULL, ENA_DBG | ENA_RXPTH, "rx mbuf updated. len %d\n", mbuf->tot_len);

        rx_ring->free_rx_ids[ntc] = req_id;
        ntc = ENA_RX_RING_IDX_NEXT(ntc, rx_ring->ring_size);
    }

    *next_to_clean = ntc;

    return (mbuf);
}

/**
 * ena_rx_cleanup - handle rx irq
 * @arg: ring for which irq is being handled
 **/
static int ena_rx_cleanup(struct ena_ring *rx_ring)
{
    struct ena_adapter *adapter;
    struct pbuf *mbuf;
    struct ena_com_rx_ctx ena_rx_ctx;
    struct ena_com_io_cq *io_cq;
    struct ena_com_io_sq *io_sq;
    enum ena_regs_reset_reason_types reset_reason;
    struct netif *ifp;
    uint16_t ena_qid;
    uint16_t next_to_clean;
    uint32_t refill_required;
    uint32_t refill_threshold;
    unsigned int qid;
    int rc, i;
    int budget = RX_BUDGET;

    adapter = rx_ring->que->adapter;
    ifp = &adapter->ndev.n;
    qid = rx_ring->que->id;
    ena_qid = ENA_IO_RXQ_IDX(qid);
    io_cq = &adapter->ena_dev->io_cq_queues[ena_qid];
    io_sq = &adapter->ena_dev->io_sq_queues[ena_qid];
    next_to_clean = rx_ring->next_to_clean;

    ena_trace(NULL, ENA_DBG, "rx: qid %d\n", qid);

    do {
        ena_rx_ctx.ena_bufs = rx_ring->ena_bufs;
        ena_rx_ctx.max_bufs = adapter->max_rx_sgl_size;
        ena_rx_ctx.descs = 0;
        ena_rx_ctx.pkt_offset = 0;

        rc = ena_com_rx_pkt(io_cq, io_sq, &ena_rx_ctx);
        if (unlikely(rc != 0)) {
            if (rc == ENA_COM_NO_SPACE) {
                rx_ring->rx_stats.bad_desc_num++;
                reset_reason = ENA_REGS_RESET_TOO_MANY_RX_DESCS;
            } else {
                rx_ring->rx_stats.bad_req_id++;
                reset_reason = ENA_REGS_RESET_INV_RX_REQ_ID;
            }
            ena_trigger_reset(adapter, reset_reason);
            return (0);
        }

        if (unlikely(ena_rx_ctx.descs == 0))
            break;

        ena_trace(NULL, ENA_DBG | ENA_RXPTH, "rx: q %d got packet from ena. "
                  "descs #: %d l3 proto %d l4 proto %d hash: %x\n",
                  rx_ring->qid, ena_rx_ctx.descs, ena_rx_ctx.l3_proto,
                  ena_rx_ctx.l4_proto, ena_rx_ctx.hash);

        /* Receive mbuf from the ring */
        mbuf = ena_rx_mbuf(rx_ring, rx_ring->ena_bufs, &ena_rx_ctx, &next_to_clean);
        /* Exit if we failed to retrieve a buffer */
        if (unlikely(mbuf == NULL)) {
            for (i = 0; i < ena_rx_ctx.descs; ++i) {
                rx_ring->free_rx_ids[next_to_clean] = rx_ring->ena_bufs[i].req_id;
                next_to_clean = ENA_RX_RING_IDX_NEXT(next_to_clean, rx_ring->ring_size);
            }
            break;
        }

        rx_ring->rx_stats.bytes += mbuf->tot_len;
        adapter->hw_stats.rx_bytes += mbuf->tot_len;

        ena_trace(NULL, ENA_DBG | ENA_RXPTH, "calling if_input() with mbuf %p\n", mbuf);
        (*ifp->input)(mbuf, ifp);

        rx_ring->rx_stats.cnt++;
        adapter->hw_stats.rx_packets++;
    } while (--budget);

    rx_ring->next_to_clean = next_to_clean;

    refill_required = ena_com_free_q_entries(io_sq);
    refill_threshold = min_t(int, rx_ring->ring_size / ENA_RX_REFILL_THRESH_DIVIDER,
        ENA_RX_REFILL_THRESH_PACKET);

    if (refill_required > refill_threshold) {
        ena_com_update_dev_comp_head(rx_ring->ena_com_io_cq);
        ena_refill_rx_bufs(rx_ring, refill_required);
    }

    return (RX_BUDGET - budget);
}

static void ena_tx_csum(struct ena_com_tx_ctx *ena_tx_ctx, struct pbuf *mbuf,
                        bool disable_meta_caching)
{
    struct ena_com_tx_meta *ena_meta;

    ena_meta = &ena_tx_ctx->ena_meta;
    if (disable_meta_caching) {
        zero(ena_meta, sizeof(*ena_meta));
        ena_tx_ctx->meta_valid = 1;
    } else {
        ena_tx_ctx->meta_valid = 0;
    }
}

static int ena_tx_map_mbuf(struct ena_ring *tx_ring, struct ena_tx_buffer *tx_info,
                           struct pbuf *mbuf, void **push_hdr, uint16_t *header_len)
{
    struct ena_com_buf *ena_buf;
    uint16_t offset;
    int nsegs = 0;

    tx_info->mbuf = mbuf;
    if (tx_ring->tx_mem_queue_type == ENA_ADMIN_PLACEMENT_POLICY_DEV) {
        *header_len = min_t(uint16_t, mbuf->tot_len, tx_ring->tx_max_header_size);
        *push_hdr = pbuf_get_contiguous(mbuf, tx_ring->push_buf_intermediate_buf,
                                        tx_ring->tx_max_header_size, *header_len, 0);
        offset = *header_len;
        while ((offset > 0) && (offset >= mbuf->len)) {
            offset -= mbuf->len;
            mbuf = mbuf->next;
        }
    } else {
        *push_hdr = NULL;
        *header_len = 0;
        offset = 0;
    }

    for (struct pbuf *q = mbuf; q != NULL; q = q->next) {
        if (q->len) {
            ena_buf = &tx_info->bufs[nsegs];
            ena_buf->paddr = physical_from_virtual(q->payload + offset);
            ena_buf->len = q->len - offset;
            tx_info->num_of_bufs++;
            if (++nsegs >= ENA_PKT_MAX_BUFS)
                break;
            offset = 0;
        }
    }

    return (0);
}

static int ena_xmit_mbuf(struct ena_ring *tx_ring, struct pbuf **mbuf)
{
    struct ena_adapter *adapter;
    struct ena_tx_buffer *tx_info;
    struct ena_com_tx_ctx ena_tx_ctx;
    struct ena_com_dev *ena_dev;
    struct ena_com_io_sq *io_sq;
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

    ena_trace(NULL, ENA_DBG | ENA_TXPTH, "Tx: %d bytes\n", (*mbuf)->tot_len);

    next_to_use = tx_ring->next_to_use;
    req_id = tx_ring->free_tx_ids[next_to_use];
    tx_info = &tx_ring->tx_buffer_info[req_id];
    tx_info->num_of_bufs = 0;

    rc = ena_tx_map_mbuf(tx_ring, tx_info, *mbuf, &push_hdr, &header_len);
    if (unlikely(rc != 0)) {
        ena_trace(NULL, ENA_WARNING, "Failed to map TX mbuf\n");
        return (rc);
    }
    zero(&ena_tx_ctx, sizeof(struct ena_com_tx_ctx));
    ena_tx_ctx.ena_bufs = tx_info->bufs;
    ena_tx_ctx.push_header = push_hdr;
    ena_tx_ctx.num_bufs = tx_info->num_of_bufs;
    ena_tx_ctx.req_id = req_id;
    ena_tx_ctx.header_len = header_len;
    ena_tx_csum(&ena_tx_ctx, *mbuf, io_sq->disable_meta_caching);

    if (tx_ring->acum_pkts == DB_THRESHOLD ||
            ena_com_is_doorbell_needed(tx_ring->ena_com_io_sq, &ena_tx_ctx)) {
        ena_trace(NULL, ENA_DBG | ENA_TXPTH,
            "llq tx max burst size of queue %d achieved, writing doorbell to send burst\n",
            tx_ring->que->id);
        ena_com_write_sq_doorbell(tx_ring->ena_com_io_sq);
        tx_ring->tx_stats.doorbells++;
        tx_ring->acum_pkts = 0;
    }

    /* Prepare the packet's descriptors and send them to device */
    rc = ena_com_prepare_tx(io_sq, &ena_tx_ctx, &nb_hw_desc);
    if (unlikely(rc != 0)) {
        if (likely(rc == ENA_COM_NO_MEM)) {
            ena_trace(NULL, ENA_DBG | ENA_TXPTH, "tx ring[%d] if out of space\n", tx_ring->que->id);
        } else {
            device_printf(adapter->pdev, "failed to prepare tx bufs\n");
        }
        tx_ring->tx_stats.prepare_ctx_err++;
        goto dma_error;
    }

    tx_ring->tx_stats.cnt++;
    tx_ring->tx_stats.bytes += (*mbuf)->tot_len;

    adapter->hw_stats.tx_packets++;
    adapter->hw_stats.tx_bytes += (*mbuf)->tot_len;

    tx_info->tx_descs = nb_hw_desc;
    tx_info->timestamp = uptime();
    tx_info->print_once = true;

    tx_ring->next_to_use = ENA_TX_RING_IDX_NEXT(next_to_use, tx_ring->ring_size);

    /* stop the queue when no more space available, the packet can have up
     * to sgl_size + 2. one for the meta descriptor and one for header
     * (if the header is larger than tx_max_header_size).
     */
    if (unlikely(!ena_com_sq_have_enough_space(tx_ring->ena_com_io_sq,
            adapter->max_tx_sgl_size + 2))) {
        ena_trace(NULL, ENA_DBG | ENA_TXPTH, "Stop queue %d\n", tx_ring->que->id);

        tx_ring->running = false;
        tx_ring->tx_stats.queue_stop++;

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
            tx_ring->tx_stats.queue_wakeup++;
        }
    }

    return (0);

dma_error:
    tx_info->mbuf = NULL;

    return (rc);
}

/* called with lwIP lock held */
static void ena_start_xmit(struct ena_ring *tx_ring)
{
    struct pbuf *mbuf;
    struct ena_adapter *adapter = tx_ring->adapter;
    struct netif *netif = &adapter->ndev.n;
    struct ena_com_io_sq *io_sq;
    int ena_qid;
    int ret = 0;

    if (unlikely(!netif_is_flag_set(netif, NETIF_FLAG_UP)))
        return;

    if (unlikely(!ENA_FLAG_ISSET(ENA_FLAG_LINK_UP, adapter)))
        return;

    ena_qid = ENA_IO_TXQ_IDX(tx_ring->que->id);
    io_sq = &adapter->ena_dev->io_sq_queues[ena_qid];

    while (tx_ring->running && ((mbuf = dequeue(tx_ring->br)) != INVALID_ADDRESS)) {
        ena_trace(NULL, ENA_DBG | ENA_TXPTH, "\ndequeued mbuf %p\n", mbuf);

        if (unlikely((ret = ena_xmit_mbuf(tx_ring, &mbuf)) != 0)) {
            if (ret == ENA_COM_NO_MEM) {
                assert(enqueue(tx_ring->br, mbuf));
            } else if (ret == ENA_COM_NO_SPACE) {
                assert(enqueue(tx_ring->br, mbuf));
            } else {
                pbuf_free(mbuf);
            }

            break;
        }

        if (unlikely(!netif_is_flag_set(netif, NETIF_FLAG_UP)))
            return;

        tx_ring->acum_pkts++;
    }

    if (likely(tx_ring->acum_pkts != 0)) {
        /* Trigger the dma engine */
        ena_com_write_sq_doorbell(io_sq);
        tx_ring->tx_stats.doorbells++;
        tx_ring->acum_pkts = 0;
    }

    if (unlikely(!tx_ring->running))
        async_apply((thunk)&tx_ring->que->cleanup_task);
}
