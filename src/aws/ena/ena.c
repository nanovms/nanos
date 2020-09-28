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
#include <lwip/opt.h>
#include <lwip/def.h>
#include <lwip/mem.h>
#include <lwip/pbuf.h>
#include <lwip/stats.h>
#include <lwip/snmp.h>
#include <lwip/etharp.h>
#include <netif/ethernet.h>
#include "ena.h"
#include "ena_datapath.h"
#include "buf_ring.h"
#include "aws_platform.h"

#ifdef ENA_DEBUG
#define ena_debug(x, ...) do { rprintf("ENA: " x "\n", ##__VA_ARGS__); } while(0)
#else
# define ena_debug(...)
#endif // defined(ENA_DEBUG)

static ena_vendor_info_t ena_vendor_info_array[] = {
    { PCI_VENDOR_ID_AMAZON, PCI_DEV_ID_ENA_PF, 0},
    { PCI_VENDOR_ID_AMAZON, PCI_DEV_ID_ENA_LLQ_PF, 0},
    { PCI_VENDOR_ID_AMAZON, PCI_DEV_ID_ENA_VF, 0},
    { PCI_VENDOR_ID_AMAZON, PCI_DEV_ID_ENA_LLQ_VF, 0},
    /* Last entry */
    { 0, 0, 0 }
};

/*
 * Contains pointers to event handlers, e.g. link state chage.
 */
static struct ena_aenq_handlers aenq_handlers;

// TODO
int ena_log_level = 0xFF & ~ENA_RSC;

/* Check for keep alive expiration */
static void check_for_missing_keep_alive(struct ena_adapter *adapter)
{
    if (adapter->wd_active == 0)
        return;

    if (adapter->keep_alive_timeout == ENA_HW_HINTS_NO_TIMEOUT)
        return;

    timestamp keep_alive_timestamp = atomic_load_acq64(&adapter->keep_alive_timestamp);
    timestamp time = uptime() - keep_alive_timestamp;
    if (time > adapter->keep_alive_timeout) {
        ena_debug("Keep alive watchdog timeout.");
//        counter_u64_add(adapter->dev_stats.wd_expired, 1);
        if (likely(!ENA_FLAG_ISSET(ENA_FLAG_TRIGGER_RESET, adapter))) {
            adapter->reset_reason = ENA_REGS_RESET_KEEP_ALIVE_TO;
            ENA_FLAG_SET_ATOMIC(ENA_FLAG_TRIGGER_RESET, adapter);
        }
    }
}

/* Check if admin queue is enabled */
static void check_for_admin_com_state(struct ena_adapter *adapter)
{
    if (ena_com_get_admin_running_state(adapter->ena_dev) == false) {
        ena_debug("ENA admin queue is not in running state!");
        //counter_u64_add(adapter->dev_stats.admin_q_pause, 1);
        if (!ENA_FLAG_ISSET(ENA_FLAG_TRIGGER_RESET, adapter)) {
            adapter->reset_reason = ENA_REGS_RESET_ADMIN_TO;
            ENA_FLAG_SET_ATOMIC(ENA_FLAG_TRIGGER_RESET, adapter);
        }
    }
}

static int check_missing_comp_in_tx_queue(struct ena_adapter *adapter,
    struct ena_ring *tx_ring)
{
    uint32_t missed_tx = 0;
    timestamp curtime = uptime();
    int rc = 0;

    for (int i = 0; i < tx_ring->ring_size; i++) {
        struct ena_tx_buffer *tx_buf = &tx_ring->tx_buffer_info[i];

        if (tx_buf->timestamp == 0)
            continue;

        timestamp time_offset = curtime - tx_buf->timestamp;

        if (!tx_ring->first_interrupt &&
            time_offset > 2 * adapter->missing_tx_timeout) {
            /*
             * If after graceful period interrupt is still not
             * received, we schedule a reset.
             */
            ena_debug("Potential MSIX issue on Tx side Queue = %d. "
                "Reset the device\n", tx_ring->qid);
            if (!ENA_FLAG_ISSET(ENA_FLAG_TRIGGER_RESET, adapter)) {
                adapter->reset_reason =
                    ENA_REGS_RESET_MISS_INTERRUPT;
                ENA_FLAG_SET_ATOMIC(ENA_FLAG_TRIGGER_RESET, adapter);
            }
            return (EIO);
        }

        /* Check again if packet is still waiting */
        if (time_offset > adapter->missing_tx_timeout) {

            ena_trace(ENA_WARNING, "Found a Tx that wasn't "
                    "completed on time, qid %d, index %d.\n",
                    tx_ring->qid, i);
            missed_tx++;
        }
    }

    if (missed_tx > adapter->missing_tx_threshold) {
        ena_debug("The number of lost tx completion is above the threshold "
            "(%d > %d). Reset the device\n", missed_tx, adapter->missing_tx_threshold);
        if (!ENA_FLAG_ISSET(ENA_FLAG_TRIGGER_RESET, adapter)) {
            adapter->reset_reason = ENA_REGS_RESET_MISS_TX_CMPL;
            ENA_FLAG_SET_ATOMIC(ENA_FLAG_TRIGGER_RESET, adapter);
        }
        rc = EIO;
    }

//    counter_u64_add(tx_ring->tx_stats.missing_tx_comp, missed_tx);
    return (rc);
}

static int check_for_rx_interrupt_queue(struct ena_adapter *adapter,
    struct ena_ring *rx_ring)
{
    if (rx_ring->first_interrupt)
        return (0);

    if (ena_com_cq_empty(rx_ring->ena_com_io_cq))
        return (0);

    rx_ring->no_interrupt_event_cnt++;

    if (rx_ring->no_interrupt_event_cnt == ENA_MAX_NO_INTERRUPT_ITERATIONS) {
        ena_debug("Potential MSIX issue on Rx side "
            "Queue = %d. Reset the device", rx_ring->qid);
        if (!ENA_FLAG_ISSET(ENA_FLAG_TRIGGER_RESET, adapter)) {
            adapter->reset_reason = ENA_REGS_RESET_MISS_INTERRUPT;
            ENA_FLAG_SET_ATOMIC(ENA_FLAG_TRIGGER_RESET, adapter);
        }
        return (EIO);
    }

    return (0);
}

/*
 * Check for TX which were not completed on time.
 * Timeout is defined by "missing_tx_timeout".
 * Reset will be performed if number of incompleted
 * transactions exceeds "missing_tx_threshold".
 */
static void check_for_missing_completions(struct ena_adapter *adapter)
{
    /* Make sure the driver doesn't turn the device in other process */
    read_barrier();

    if (!ENA_FLAG_ISSET(ENA_FLAG_DEV_UP, adapter))
        return;

    if (ENA_FLAG_ISSET(ENA_FLAG_TRIGGER_RESET, adapter))
        return;

    if (adapter->missing_tx_timeout == ENA_HW_HINTS_NO_TIMEOUT)
        return;


    int budget = adapter->missing_tx_max_queues;

    int i = adapter->next_monitored_tx_qid;
    for (/* above */; i < adapter->num_queues; i++) {
        struct ena_ring *tx_ring = &adapter->tx_ring[i];
        struct ena_ring *rx_ring = &adapter->rx_ring[i];

        int rc = check_missing_comp_in_tx_queue(adapter, tx_ring);
        if (unlikely(rc != 0))
            return;

        rc = check_for_rx_interrupt_queue(adapter, rx_ring);
        if (unlikely(rc != 0))
            return;

        budget--;
        if (budget == 0) {
            i++;
            break;
        }
    }

    adapter->next_monitored_tx_qid = i % adapter->num_queues;
}

/* trigger rx cleanup after 2 consecutive detections */
#define EMPTY_RX_REFILL 2
/* For the rare case where the device runs out of Rx descriptors and the
 * msix handler failed to refill new Rx descriptors (due to a lack of memory
 * for example).
 * This case will lead to a deadlock:
 * The device won't send interrupts since all the new Rx packets will be dropped
 * The msix handler won't allocate new Rx descriptors so the device won't be
 * able to send new packets.
 *
 * When such a situation is detected - execute rx cleanup task in another thread
 */
static void check_for_empty_rx_ring(struct ena_adapter *adapter)
{
    if (!ENA_FLAG_ISSET(ENA_FLAG_DEV_UP, adapter))
        return;

    if (ENA_FLAG_ISSET(ENA_FLAG_TRIGGER_RESET, adapter))
        return;

    for (int i = 0; i < adapter->num_queues; i++) {
        struct ena_ring *rx_ring = &adapter->rx_ring[i];

        int refill_required = ena_com_free_desc(rx_ring->ena_com_io_sq);
        if (refill_required == (rx_ring->ring_size - 1)) {
            rx_ring->empty_rx_queue++;

            if (rx_ring->empty_rx_queue >= EMPTY_RX_REFILL) {
                //counter_u64_add(rx_ring->rx_stats.empty_rx_ring, 1);

                ena_debug("trigger refill for ring %d\n", i);

//                taskqueue_enqueue(rx_ring->que->cleanup_tq,
//                    &rx_ring->que->cleanup_task);
                enqueue(runqueue, rx_ring->que->cleanup_task);
                rx_ring->empty_rx_queue = 0;
            }
        } else {
            rx_ring->empty_rx_queue = 0;
        }
    }
}

closure_function(1, 1, void, ena_timer_service, struct ena_adapter *, adapter,
                 u64, overruns /* ignored */)
{
    struct ena_adapter *adapter = bound(adapter);

#if 1
    // TODO: FIX INTERRUPTS AND REMOVE
    ena_debug("emulating mgmt intr");
    ena_com_admin_q_comp_intr_handler(adapter->ena_dev);
    if (likely(ENA_FLAG_ISSET(ENA_FLAG_DEVICE_RUNNING, adapter)))
        ena_com_aenq_intr_handler(adapter->ena_dev, adapter);

    ena_debug("emulating io intr");
    for (int i = 0; i < adapter->num_queues; i++) {
        enqueue(bhqueue, adapter->que[i].cleanup_task);
    }
#endif

    check_for_missing_keep_alive(adapter);

    check_for_admin_com_state(adapter);

    check_for_missing_completions(adapter);

    check_for_empty_rx_ring(adapter);

    // TODO
#if 0
    struct ena_admin_host_info *host_info =
        adapter->ena_dev->host_attr.host_info;
    if (host_info != NULL)
        ena_update_host_info(host_info, adapter->ifp);
#endif

    if (ENA_FLAG_ISSET(ENA_FLAG_TRIGGER_RESET, adapter)) {
        ena_debug("Trigger reset is on");
        enqueue(runqueue, adapter->reset_task);
        return;
    }

    /*
     * Schedule another timeout one second from now.
     */
    adapter->timer_service = register_timer(runloop_timers, CLOCK_ID_MONOTONIC,
                                            seconds(1), false, 0, adapter->timer_task);
}

static void receive_buffer_release(struct pbuf *p)
{
    xpbuf x  = (void *)p;
    u64 flags = spin_lock_irq(&x->ena->rx_buflock);
    deallocate(x->ena->rxbuffers, x, x->ena->rxbuflen + sizeof(struct xpbuf));
    spin_unlock_irq(&x->ena->rx_buflock, flags);
}

xpbuf
receive_buffer_alloc(struct ena_adapter *ena)
{
    u64 flags = spin_lock_irq(&ena->rx_buflock);
    xpbuf x = allocate(ena->rxbuffers, sizeof(struct xpbuf) + ena->rxbuflen);
    assert(x != INVALID_ADDRESS);
    x->ena = ena;
    x->p.custom_free_function = receive_buffer_release;
    pbuf_alloced_custom(PBUF_RAW,
                        ena->rxbuflen,
                        PBUF_REF,
                        &x->p,
                        x+1,
                        ena->rxbuflen);
    spin_unlock_irq(&ena->rx_buflock, flags);
    return x;
}

int
ena_dma_alloc(struct ena_adapter_pci* adapter, u64 size,
    ena_mem_handle_t *dma , int mapflags)
{
    u32 maxsize = ((size - 1) / PAGESIZE + 1) * PAGESIZE;

    /* TODO
    u64 dma_space_addr = ENA_DMA_BIT_MASK(adapter->dma_width);
    if (unlikely(dma_space_addr == 0))
        dma_space_addr = BUS_SPACE_MAXADDR;
        */

    dma->vaddr = allocate_zero(adapter->contiguous, maxsize);
    assert(dma->vaddr != INVALID_ADDRESS);
    assert((u64)dma->vaddr == pad((u64)dma->vaddr, 8));

    dma->paddr = physical_from_virtual(dma->vaddr);
    assert(dma->paddr != INVALID_PHYSICAL);

    return (0);
}

void ena_dma_free(struct ena_adapter_pci* adapter, void *virt, u64 size)
{
    deallocate(adapter->contiguous, virt, size);
}

/**
 * ena_intr_msix_mgmnt - MSIX Interrupt Handler for admin/async queue
 * @arg: interrupt number
 **/
closure_function(1, 0, void, ena_intr_msix_mgmnt,
                 struct ena_adapter *, adapter)
{
    ena_debug("MGMNT INTR!");
    struct ena_adapter *adapter = bound(adapter);

    ena_com_admin_q_comp_intr_handler(adapter->ena_dev);
    if (likely(ENA_FLAG_ISSET(ENA_FLAG_DEVICE_RUNNING, adapter)))
        ena_com_aenq_intr_handler(adapter->ena_dev, adapter);
#if 1
    ena_debug("emulating io intr");
    for (int i = 0; i < adapter->num_queues; i++) {
        enqueue(bhqueue, adapter->que[i].cleanup_task);
    }
#endif
}

/**
 * ena_handle_msix - MSIX Interrupt Handler for Tx/Rx
 * @arg: queue
 **/
closure_function(1, 0, void, ena_handle_msix,
                 struct ena_que *, queue)
{
    ena_debug("ena_handle_msix\n");
    struct ena_que *queue = bound(queue);

    enqueue(bhqueue, queue->cleanup_task);
}

static void ena_enable_msix(struct ena_adapter *adapter)
{
    if (ENA_FLAG_ISSET(ENA_FLAG_MSIX_ENABLED, adapter)) {
        halt("Error, MSI-X is already enabled\n");
    }

    /* Reserved the max msix vectors we might need */
    int msix_vecs = ENA_MAX_MSIX_VEC(adapter->num_queues);

    adapter->msix_entries = allocate_zero(adapter->ena_pci.general, msix_vecs * sizeof(struct msix_entry));

    ena_trace(ENA_DBG, "trying to enable MSI-X, vectors: %d\n", msix_vecs);

    for (int i = 0; i < msix_vecs; i++) {
        adapter->msix_entries[i].entry = i;
        /* Vectors must start from 1 */
        adapter->msix_entries[i].vector = i + 1;
    }

    int num_entries = pci_enable_msix(adapter->ena_pci.dev);

    if (num_entries < msix_vecs) {
        if (msix_vecs == ENA_ADMIN_MSIX_VEC) {
            halt("Not enough number of MSI-x allocated: %d\n", msix_vecs);
        }
        ena_debug("Enable only %d MSI-x (out of %d), reduce the number of queues",
                  num_entries, msix_vecs);
        adapter->num_queues = num_entries - ENA_ADMIN_MSIX_VEC;
    }
    adapter->msix_vecs = msix_vecs;
    ENA_FLAG_SET_ATOMIC(ENA_FLAG_MSIX_ENABLED, adapter);
}

static void ena_disable_msix(struct ena_adapter *adapter)
{
    if (ENA_FLAG_ISSET(ENA_FLAG_MSIX_ENABLED, adapter)) {
        ENA_FLAG_CLEAR_ATOMIC(ENA_FLAG_MSIX_ENABLED, adapter);
        pci_disable_msix(adapter->ena_pci.dev);
    }

    adapter->msix_vecs = 0;
    if (adapter->msix_entries != NULL)
        deallocate(adapter->ena_pci.general, adapter->msix_entries,
                   ENA_MAX_MSIX_VEC(adapter->num_queues) * sizeof(struct msix_entry));
    adapter->msix_entries = NULL;
}

/* Configure the Rx forwarding */
static void ena_rss_configure(struct ena_adapter *adapter)
{
    struct ena_com_dev *ena_dev = adapter->ena_dev;

    /* Set indirect table */
    int rc = ena_com_indirect_table_set(ena_dev);
    assert(rc == 0 || rc == EOPNOTSUPP);

    /* Configure hash function (if supported) */
    rc = ena_com_set_hash_function(ena_dev);
    assert(rc == 0 || rc == EOPNOTSUPP);

    /* Configure hash inputs (if supported) */
    rc = ena_com_set_hash_ctrl(ena_dev);
    assert(rc == 0 || rc == EOPNOTSUPP);
}

static void ena_change_mtu(struct ena_adapter *adapter)
{
    // TODO
    assert(ENA_MIN_MTU < ENA_ADAPTER_MTU);
#if 0
    if ((new_mtu > adapter->max_mtu) || (new_mtu < ENA_MIN_MTU)) {
        ena_debug(adapter->pdev, "Invalid MTU setting. "
            "new_mtu: %d max mtu: %d min mtu: %d",
            new_mtu, adapter->max_mtu, ENA_MIN_MTU);
        return (EINVAL);
    }
#endif
    int rc = ena_com_set_dev_mtu(adapter->ena_dev, ENA_ADAPTER_MTU);
    assert(rc == 0);
    ena_trace(ENA_DBG, "set MTU to %d\n", ENA_ADAPTER_MTU);
}

static inline void ena_alloc_rx_mbuf(struct ena_adapter *adapter,
    struct ena_ring *rx_ring, struct ena_rx_buffer *rx_info)
{
    /* if previous allocated frag is not used */
    if (rx_info->mbuf != 0)
        return;

    xpbuf x = receive_buffer_alloc(adapter);
    rx_info->mbuf = (struct pbuf *)x;
    //TODO!
#if 0
    /* Get mbuf using UMA allocator */
    rx_info->mbuf = m_getjcl(M_NOWAIT, MT_DATA, M_PKTHDR,
        rx_ring->rx_mbuf_sz);

    if (unlikely(rx_info->mbuf == NULL)) {
        counter_u64_add(rx_ring->rx_stats.mjum_alloc_fail, 1);
        rx_info->mbuf = m_getcl(M_NOWAIT, MT_DATA, M_PKTHDR);
        if (unlikely(rx_info->mbuf == NULL)) {
            counter_u64_add(rx_ring->rx_stats.mbuf_alloc_fail, 1);
            return (ENOMEM);
        }
       mlen = MCLBYTES;
    } else {
        mlen = rx_ring->rx_mbuf_sz;
    }
    /* Set mbuf length*/
    rx_info->mbuf->m_pkthdr.len = rx_info->mbuf->m_len = adapter->rxbuflen;

    /* Map packets for DMA */
    ena_trace(ENA_DBG | ENA_RSC | ENA_RXPTH,
        "Using tag %p for buffers' DMA mapping, mbuf %p len: %d\n",
        adapter->rx_buf_tag,rx_info->mbuf, rx_info->mbuf->m_len);
    error = bus_dmamap_load_mbuf_sg(adapter->rx_buf_tag, rx_info->map,
        rx_info->mbuf, segs, &nsegs, BUS_DMA_NOWAIT);
    if (unlikely((error != 0) || (nsegs != 1))) {
        ena_trace(ENA_WARNING, "failed to map mbuf, error: %d, "
            "nsegs: %d\n", error, nsegs);
        counter_u64_add(rx_ring->rx_stats.dma_mapping_err, 1);
        goto exit;

    }

    bus_dmamap_sync(adapter->rx_buf_tag, rx_info->map, BUS_DMASYNC_PREREAD);
#endif
    struct ena_com_buf *ena_buf = &rx_info->ena_buf;
    ena_buf->paddr = physical_from_virtual(x + 1);
    ena_buf->len = adapter->rxbuflen;

    ena_trace(ENA_DBG | ENA_RSC | ENA_RXPTH,
        "ALLOC RX BUF: mbuf %p, rx_info %p, len %d, paddr %x",
        rx_info->mbuf, rx_info, ena_buf->len, ena_buf->paddr);
}

static void ena_free_rx_mbuf(struct ena_adapter *adapter, struct ena_ring *rx_ring,
    struct ena_rx_buffer *rx_info)
{

    if (rx_info->mbuf == NULL) {
        ena_trace(ENA_WARNING, "Trying to free unallocated buffer\n");
        return;
    }

#if 0
    bus_dmamap_sync(adapter->rx_buf_tag, rx_info->map,
        BUS_DMASYNC_POSTREAD);
    bus_dmamap_unload(adapter->rx_buf_tag, rx_info->map);
#endif
    pbuf_free(rx_info->mbuf);
    rx_info->mbuf = NULL;
}

/**
 * ena_refill_rx_bufs - Refills ring with descriptors
 * @rx_ring: the ring which we want to feed with free descriptors
 * @num: number of descriptors to refill
 * Refills the ring with newly allocated DMA-mapped mbufs for receiving
 **/
int
ena_refill_rx_bufs(struct ena_ring *rx_ring, uint32_t num)
{
    struct ena_adapter *adapter = rx_ring->adapter;

    ena_trace(ENA_DBG | ENA_RXPTH | ENA_RSC, "refill qid: %d\n",
        rx_ring->qid);

    uint16_t next_to_use = rx_ring->next_to_use;

    int i = 0;
    for (/* above */; i < num; i++) {
        struct ena_rx_buffer *rx_info;

        ena_trace(ENA_DBG | ENA_RXPTH | ENA_RSC,
            "RX buffer - next to use: %d\n", next_to_use);

        int req_id = rx_ring->free_rx_ids[next_to_use];
        rx_info = &rx_ring->rx_buffer_info[req_id];
        ena_alloc_rx_mbuf(adapter, rx_ring, rx_info);
        int rc = ena_com_add_single_rx_desc(rx_ring->ena_com_io_sq,
            &rx_info->ena_buf, req_id);
        if (rc != 0) {
            ena_trace(ENA_WARNING,
                "failed to add buffer for rx queue %d\n",
                rx_ring->qid);
            break;
        }
        next_to_use = ENA_RX_RING_IDX_NEXT(next_to_use,
            rx_ring->ring_size);

    }
#if 0
    if (unlikely(i < num)) {
        counter_u64_add(rx_ring->rx_stats.refil_partial, 1);
        ena_trace(ENA_WARNING,
             "refilled rx qid %d with only %d mbufs (from %d)\n",
             rx_ring->qid, i, num);
    }
#endif
    if (i != 0) {
        write_barrier();
        ena_com_write_sq_doorbell(rx_ring->ena_com_io_sq);
    }
    rx_ring->next_to_use = next_to_use;
    return (i);
}

/**
 * ena_refill_all_rx_bufs - allocate all queues Rx buffers
 * @adapter: network interface device structure
 *
 */
static void
ena_refill_all_rx_bufs(struct ena_adapter *adapter)
{
    for (int i = 0; i < adapter->num_queues; i++) {
         struct ena_ring *rx_ring = &adapter->rx_ring[i];
        int bufs_num = rx_ring->ring_size - 1;
        int rc = ena_refill_rx_bufs(rx_ring, bufs_num);
        if (rc != bufs_num)
            ena_trace(ENA_WARNING, "refilling Queue %d failed. "
                "Allocated %d buffers from: %d\n", i, rc, bufs_num);
#ifdef DEV_NETMAP
        rx_ring->initialized = true;
#endif /* DEV_NETMAP */
    }
}

static void ena_up_complete(struct ena_adapter *adapter)
{
    if (ENA_FLAG_ISSET(ENA_FLAG_RSS_ACTIVE, adapter)) {
        ena_rss_configure(adapter);
    }

    ena_change_mtu(adapter);

    ena_refill_all_rx_bufs(adapter);
#if 0
    ena_reset_counters((counter_u64_t *)&adapter->hw_stats,
        sizeof(adapter->hw_stats));
#endif
}

static void ena_setup_mgmnt_intr(struct ena_adapter *adapter)
{
    buffer b = alloca_wrap_buffer(adapter->irq_tbl[ENA_MGMNT_IRQ_IDX].name,
                       sizeof(adapter->irq_tbl[ENA_MGMNT_IRQ_IDX].name));
    b->end = 0;
    bprintf(b, "ena-mgmnt@pci:%s", DRV_MODULE_NAME);

    /*
     * Handler is NULL on purpose, it will be set
     * when mgmnt interrupt is acquired
     */
    adapter->irq_tbl[ENA_MGMNT_IRQ_IDX].handler = NULL;
    adapter->irq_tbl[ENA_MGMNT_IRQ_IDX].data = adapter;
    adapter->irq_tbl[ENA_MGMNT_IRQ_IDX].vector =
        adapter->msix_entries[ENA_MGMNT_IRQ_IDX].vector;
}

static void ena_setup_io_intr(struct ena_adapter *adapter)
{
    assert(adapter->msix_entries != NULL);

    for (int i = 0; i < adapter->num_queues; i++) {
        int irq_idx = ENA_IO_IRQ_IDX(i);

        buffer b = alloca_wrap_buffer(adapter->irq_tbl[irq_idx].name,
                                      sizeof(adapter->irq_tbl[irq_idx].name));
        b->end = 0;
        bprintf(b, "%s-TxRx-%d", DRV_MODULE_NAME, i);
#if 0
        snprintf(adapter->irq_tbl[irq_idx].name, ENA_IRQNAME_SIZE,
            "%s-TxRx-%d", device_get_nameunit(adapter->pdev), i);
#endif
        adapter->irq_tbl[irq_idx].handler = closure(adapter->ena_pci.general, ena_handle_msix,
                                                    &adapter->que[i]);
        // TODO: remove .data!
        adapter->irq_tbl[irq_idx].data = &adapter->que[i];
        adapter->irq_tbl[irq_idx].vector =
            adapter->msix_entries[irq_idx].vector;
        ena_trace(ENA_INFO | ENA_IOQ, "ena_setup_io_intr vector: %d\n",
            adapter->msix_entries[irq_idx].vector);

        /*
         * We want to bind rings to the corresponding cpu
         * using something similar to the RSS round-robin technique.
         */
        adapter->que[i].cpu = adapter->irq_tbl[irq_idx].cpu = 0;
    }
}

closure_function(1, 0, void, ena_deferred_mq_start_closure,
                 struct ena_ring *, tx_ring)
{
    ena_debug("%s: enter", __func__);
    struct ena_ring *tx_ring = bound(tx_ring);

    ena_deferred_mq_start(tx_ring, 0);
    ena_debug("%s: end", __func__);
}

/**
 * ena_setup_tx_resources - allocate Tx resources (Descriptors)
 * @adapter: network interface device structure
 * @qid: queue index
 *
 * Returns 0 on success, otherwise on failure.
 **/
static void ena_setup_tx_resources(struct ena_adapter *adapter, int qid)
{
    struct ena_que *que = &adapter->que[qid];
    struct ena_ring *tx_ring = que->tx_ring;

    int size = sizeof(struct ena_tx_buffer) * tx_ring->ring_size;

    tx_ring->tx_buffer_info = allocate_zero(adapter->ena_pci.general, size);

    assert(tx_ring->tx_buffer_info != INVALID_ADDRESS);

    size = sizeof(uint16_t) * tx_ring->ring_size;
    tx_ring->free_tx_ids = allocate_zero(adapter->ena_pci.general, size);
    assert(tx_ring->free_tx_ids != INVALID_ADDRESS);

    size = tx_ring->tx_max_header_size;
    tx_ring->push_buf_intermediate_buf = allocate_zero(adapter->ena_pci.general, size);
    assert(tx_ring->push_buf_intermediate_buf != INVALID_ADDRESS);

    /* Req id stack for TX OOO completions */
    for (int i = 0; i < tx_ring->ring_size; i++)
        tx_ring->free_tx_ids[i] = i;

    /* Reset TX statistics. */
//    ena_reset_counters((counter_u64_t *)&tx_ring->tx_stats,
//        sizeof(tx_ring->tx_stats));

    tx_ring->next_to_use = 0;
    tx_ring->next_to_clean = 0;
    tx_ring->acum_pkts = 0;

    /* Make sure that drbr is empty */
    ENA_RING_MTX_LOCK(tx_ring);
    struct pbuf *m;
    while ((m = buf_ring_dequeue_sc(tx_ring->br)) != NULL)
        pbuf_free(m);
    ENA_RING_MTX_UNLOCK(tx_ring);

    // TODO
#if 0
    /* ... and create the buffer DMA maps */
    for (i = 0; i < tx_ring->ring_size; i++) {
        err = bus_dmamap_create(adapter->tx_buf_tag, 0,
            &tx_ring->tx_buffer_info[i].dmamap);
        if (unlikely(err != 0)) {
            ena_trace(ENA_ALERT,
                "Unable to create Tx DMA map for buffer %d\n",
                i);
            goto err_map_release;
        }
    }
    /* Allocate taskqueues */
    TASK_INIT(&tx_ring->enqueue_task, 0, ena_deferred_mq_start, tx_ring);
    tx_ring->enqueue_tq = taskqueue_create_fast("ena_tx_enque", M_NOWAIT,
        taskqueue_thread_enqueue, &tx_ring->enqueue_tq);
    if (unlikely(tx_ring->enqueue_tq == NULL)) {
        ena_trace(ENA_ALERT,
            "Unable to create taskqueue for enqueue task\n");
        i = tx_ring->ring_size;
        goto err_map_release;
    }
#endif
    tx_ring->enqueue_task = closure(adapter->ena_pci.general, ena_deferred_mq_start_closure, tx_ring);

    tx_ring->running = true;

    // TODO
//    taskqueue_start_threads(&tx_ring->enqueue_tq, 1, PI_NET,
//        "%s txeq %d", device_get_nameunit(adapter->pdev), que->cpu);

}

/**
 * ena_free_tx_resources - Free Tx Resources per Queue
 * @adapter: network interface device structure
 * @qid: queue index
 *
 * Free all transmit software resources
 **/
static void ena_free_tx_resources(struct ena_adapter *adapter, int qid)
{
    struct ena_ring *tx_ring = &adapter->tx_ring[qid];

    // TODO
#if 0
    while (taskqueue_cancel(tx_ring->enqueue_tq, &tx_ring->enqueue_task,
        NULL))
        taskqueue_drain(tx_ring->enqueue_tq, &tx_ring->enqueue_task);

    taskqueue_free(tx_ring->enqueue_tq);
#endif

    ENA_RING_MTX_LOCK(tx_ring);
    /* Flush buffer ring, */
    struct pbuf *m;
    while ((m = buf_ring_dequeue_sc(tx_ring->br)) != NULL)
        pbuf_free(m);

    /* Free buffer DMA maps, */
    for (int i = 0; i < tx_ring->ring_size; i++) {
        // TODO
#if 0
        bus_dmamap_sync(adapter->tx_buf_tag,
            tx_ring->tx_buffer_info[i].dmamap, BUS_DMASYNC_POSTWRITE);
        bus_dmamap_unload(adapter->tx_buf_tag,
            tx_ring->tx_buffer_info[i].dmamap);
        bus_dmamap_destroy(adapter->tx_buf_tag,
            tx_ring->tx_buffer_info[i].dmamap);

#endif
        pbuf_free(tx_ring->tx_buffer_info[i].mbuf);
        tx_ring->tx_buffer_info[i].mbuf = NULL;
    }
    ENA_RING_MTX_UNLOCK(tx_ring);

    /* And free allocated memory. */
    deallocate(adapter->ena_pci.general, tx_ring->tx_buffer_info,
               sizeof(struct ena_tx_buffer) * tx_ring->ring_size);
    tx_ring->tx_buffer_info = NULL;

    deallocate(adapter->ena_pci.general, tx_ring->free_tx_ids, sizeof(uint16_t) * tx_ring->ring_size);
    tx_ring->free_tx_ids = NULL;

    ENA_MEM_FREE(adapter->ena_dev->dmadev,
        tx_ring->push_buf_intermediate_buf, tx_ring->tx_max_header_size);
    tx_ring->push_buf_intermediate_buf = NULL;
}

/**
 * ena_free_all_tx_resources - Free Tx Resources for All Queues
 * @adapter: network interface device structure
 **/
static void ena_free_all_tx_resources(struct ena_adapter *adapter)
{
    for (int i = 0; i < adapter->num_queues; i++)
        ena_free_tx_resources(adapter, i);
}

/**
 * ena_setup_all_tx_resources - allocate all queues Tx resources
 * @adapter: network interface device structure
 **/
static void ena_setup_all_tx_resources(struct ena_adapter *adapter)
{
    for (int i = 0; i < adapter->num_queues; i++) {
        ena_setup_tx_resources(adapter, i);
    }
}

/**
 * ena_setup_rx_resources - allocate Rx resources (Descriptors)
 * @adapter: network interface device structure
 * @qid: queue index
 **/
static void ena_setup_rx_resources(struct ena_adapter *adapter, unsigned int qid)
{
    struct ena_que *que = &adapter->que[qid];
    struct ena_ring *rx_ring = que->rx_ring;

    /*
     * Alloc extra element so in rx path
     * we can always prefetch rx_info + 1
     */
    int size = sizeof(struct ena_rx_buffer) * (rx_ring->ring_size + 1);

    rx_ring->rx_buffer_info = allocate_zero(adapter->ena_pci.general, size);
    assert(rx_ring->rx_buffer_info != INVALID_ADDRESS);

    size = sizeof(uint16_t) * rx_ring->ring_size;
    rx_ring->free_rx_ids = allocate(adapter->ena_pci.general, size);
    assert(rx_ring->free_rx_ids != INVALID_ADDRESS);

    for (int i = 0; i < rx_ring->ring_size; i++)
        rx_ring->free_rx_ids[i] = i;

    /* Reset RX statistics. */
//    ena_reset_counters((counter_u64_t *)&rx_ring->rx_stats,
//        sizeof(rx_ring->rx_stats));

    rx_ring->next_to_clean = 0;
    rx_ring->next_to_use = 0;

    /* ... and create the buffer DMA maps */
#if 0
    for (int i = 0; i < rx_ring->ring_size; i++) {
        err = bus_dmamap_create(adapter->rx_buf_tag, 0,
            &(rx_ring->rx_buffer_info[i].map));
        if (err != 0) {
            ena_trace(ENA_ALERT,
                "Unable to create Rx DMA map for buffer %d\n", i);
            goto err_buf_info_unmap;
        }
    }

    /* Create LRO for the ring */
    if ((adapter->ifp->if_capenable & IFCAP_LRO) != 0) {
        int err = tcp_lro_init(&rx_ring->lro);
        if (err != 0) {
            device_printf(adapter->pdev,
                "LRO[%d] Initialization failed!\n", qid);
        } else {
            ena_trace(ENA_INFO,
                "RX Soft LRO[%d] Initialized\n", qid);
            rx_ring->lro.ifp = adapter->ifp;
        }
    }
#endif
}

/**
 * ena_free_rx_resources - Free Rx Resources
 * @adapter: network interface device structure
 * @qid: queue index
 *
 * Free all receive software resources
 **/
static void ena_free_rx_resources(struct ena_adapter *adapter, unsigned int qid)
{
    struct ena_ring *rx_ring = &adapter->rx_ring[qid];

    /* Free buffer DMA maps, */
    for (int i = 0; i < rx_ring->ring_size; i++) {
//        bus_dmamap_sync(adapter->rx_buf_tag,
//            rx_ring->rx_buffer_info[i].map, BUS_DMASYNC_POSTREAD);
        pbuf_free(rx_ring->rx_buffer_info[i].mbuf);
        rx_ring->rx_buffer_info[i].mbuf = NULL;
#if 0
        bus_dmamap_unload(adapter->rx_buf_tag,
            rx_ring->rx_buffer_info[i].map);
        bus_dmamap_destroy(adapter->rx_buf_tag,
            rx_ring->rx_buffer_info[i].map);
#endif
    }
    /* free LRO resources, */
//    tcp_lro_free(&rx_ring->lro);

    /* free allocated memory */
    deallocate(adapter->ena_pci.general, rx_ring->rx_buffer_info,
               sizeof(struct ena_rx_buffer) * (rx_ring->ring_size + 1));
    rx_ring->rx_buffer_info = NULL;

    deallocate(adapter->ena_pci.general, rx_ring->free_rx_ids, sizeof(uint16_t) * rx_ring->ring_size);
    rx_ring->free_rx_ids = NULL;
}

/**
 * ena_free_all_rx_resources - Free Rx resources for all queues
 * @adapter: network interface device structure
 *
 * Free all receive software resources
 **/
static void ena_free_all_rx_resources(struct ena_adapter *adapter)
{
    for (int i = 0; i < adapter->num_queues; i++)
        ena_free_rx_resources(adapter, i);
}

/**
 * ena_setup_all_rx_resources - allocate all queues Rx resources
 * @adapter: network interface device structure
 **/
static void ena_setup_all_rx_resources(struct ena_adapter *adapter)
{
    for (int i = 0; i < adapter->num_queues; i++) {
        ena_setup_rx_resources(adapter, i);
    }
}

static void ena_request_mgmnt_irq(struct ena_adapter *adapter)
{
    struct ena_irq *irq = &adapter->irq_tbl[ENA_MGMNT_IRQ_IDX];

    irq->handler = closure(adapter->ena_pci.general, ena_intr_msix_mgmnt, adapter);

    irq->int_vector = pci_setup_msix(adapter->ena_pci.dev, irq->vector, irq->handler, "ena mgnmt handler");

    irq->requested = true;
}

static void ena_request_io_irq(struct ena_adapter *adapter)
{
    if (!ENA_FLAG_ISSET(ENA_FLAG_MSIX_ENABLED, adapter))
        halt("failed to request I/O IRQ: MSI-X is not enabled\n");

    for (int i = ENA_IO_IRQ_FIRST_IDX; i < adapter->msix_vecs; i++) {
        struct ena_irq *irq = &adapter->irq_tbl[i];

        if (irq->requested)
            continue;

        irq->int_vector = pci_setup_msix(adapter->ena_pci.dev, irq->vector, irq->handler, "ena io handler");
#if 0
        irq->res = bus_alloc_resource_any(adapter->pdev, SYS_RES_IRQ,
            &irq->vector, flags);
        if (unlikely(irq->res == NULL)) {
            rc = ENOMEM;
            device_printf(adapter->pdev, "could not allocate "
                "irq vector: %d\n", irq->vector);
            goto err;
        }

        rc = bus_setup_intr(adapter->pdev, irq->res,
            INTR_TYPE_NET | INTR_MPSAFE, irq->handler, NULL,
            irq->data, &irq->cookie);
         if (unlikely(rc != 0)) {
            device_printf(adapter->pdev, "failed to register "
                "interrupt handler for irq %ju: %d\n",
                rman_get_start(irq->res), rc);
            goto err;
        }
#endif
        irq->requested = true;

        ena_trace(ENA_INFO, "queue %d - cpu %d\n",
            i - ENA_IO_IRQ_FIRST_IDX, irq->cpu);
    }
}

static void ena_free_mgmnt_irq(struct ena_adapter *adapter)
{
    struct ena_irq *irq = &adapter->irq_tbl[ENA_MGMNT_IRQ_IDX];

    if (irq->requested) {
        ena_trace(ENA_INFO | ENA_ADMQ, "tear down irq: %d\n",
            irq->vector);
        pci_deallocate_msix(adapter->ena_pci.dev, irq->vector, irq->int_vector);
#if 0
        rc = bus_teardown_intr(adapter->pdev, irq->res, irq->cookie);
        if (unlikely(rc != 0))
            device_printf(adapter->pdev, "failed to tear "
                "down irq: %d\n", irq->vector);
#endif
        irq->requested = 0;
    }
#if 0
    if (irq->res != NULL) {
        ena_trace(ENA_INFO | ENA_ADMQ, "release resource irq: %d\n",
            irq->vector);
        rc = bus_release_resource(adapter->pdev, SYS_RES_IRQ,
            irq->vector, irq->res);
        irq->res = NULL;
        if (unlikely(rc != 0))
            device_printf(adapter->pdev, "dev has no parent while "
                "releasing res for irq: %d\n", irq->vector);
    }
#endif
}

static void ena_free_io_irq(struct ena_adapter *adapter)
{
    struct ena_irq *irq;

    for (int i = ENA_IO_IRQ_FIRST_IDX; i < adapter->msix_vecs; i++) {
        irq = &adapter->irq_tbl[i];
        if (irq->requested) {
            ena_trace(ENA_INFO | ENA_IOQ, "tear down irq: %d\n",
                irq->vector);
            pci_deallocate_msix(adapter->ena_pci.dev, irq->vector, irq->int_vector);
#if 0
            int rc = bus_teardown_intr(adapter->pdev, irq->res,
                irq->cookie);
            if (unlikely(rc != 0)) {
                device_printf(adapter->pdev, "failed to tear "
                    "down irq: %d\n", irq->vector);
            }
#endif
            irq->requested = 0;
        }

        if (irq->res != NULL) {
            ena_trace(ENA_INFO | ENA_IOQ, "release resource irq: %d\n",
                irq->vector);
#if 0
            rc = bus_release_resource(adapter->pdev, SYS_RES_IRQ,
                irq->vector, irq->res);
            irq->res = NULL;
            if (unlikely(rc != 0)) {
                device_printf(adapter->pdev, "dev has no parent"
                    " while releasing res for irq: %d\n",
                    irq->vector);
            }
#endif
        }
    }
}

closure_function(1, 0, void, ena_cleanup_closure,
                 struct ena_que *, queue)
{
    struct ena_que *queue = bound(queue);

    ena_debug("ena_cleanup_closure\n");
    ena_cleanup(queue, 0);
}

static void ena_create_io_queues(struct ena_adapter *adapter)
{
    struct ena_com_dev *ena_dev = adapter->ena_dev;
    struct ena_com_create_io_ctx ctx;
    struct ena_ring *ring;
    struct ena_que *queue;
    uint16_t ena_qid;
    uint32_t msix_vector;

    /* Create TX queues */
    for (int i = 0; i < adapter->num_queues; i++) {
        msix_vector = ENA_IO_IRQ_IDX(i);
        ena_qid = ENA_IO_TXQ_IDX(i);
        ctx.mem_queue_type = ena_dev->tx_mem_queue_type;
        ctx.direction = ENA_COM_IO_QUEUE_DIRECTION_TX;
        ctx.queue_size = adapter->tx_ring_size;
        ctx.msix_vector = msix_vector;
        ctx.qid = ena_qid;
        int rc = ena_com_create_io_queue(ena_dev, &ctx);
        assert(rc == 0); //Failed to create io TX queue
        ring = &adapter->tx_ring[i];
        rc = ena_com_get_io_handlers(ena_dev, ena_qid,
            &ring->ena_com_io_sq,
            &ring->ena_com_io_cq);
        assert(rc == 0); //Failed to get TX queue handlers
    }

    /* Create RX queues */
    for (int i = 0; i < adapter->num_queues; i++) {
        msix_vector = ENA_IO_IRQ_IDX(i);
        ena_qid = ENA_IO_RXQ_IDX(i);
        ctx.mem_queue_type = ENA_ADMIN_PLACEMENT_POLICY_HOST;
        ctx.direction = ENA_COM_IO_QUEUE_DIRECTION_RX;
        ctx.queue_size = adapter->rx_ring_size;
        ctx.msix_vector = msix_vector;
        ctx.qid = ena_qid;
        int rc = ena_com_create_io_queue(ena_dev, &ctx);
        assert(rc == 0); //Failed to create io RX queue
        ring = &adapter->rx_ring[i];
        rc = ena_com_get_io_handlers(ena_dev, ena_qid,
            &ring->ena_com_io_sq,
            &ring->ena_com_io_cq);
        assert(rc == 0); //Failed to get RX queue handlers
    }

    for (int i = 0; i < adapter->num_queues; i++) {
        queue = &adapter->que[i];

        queue->cleanup_task = closure(adapter->ena_pci.general, ena_cleanup_closure, queue);
    }
}

static void ena_unmask_all_io_irqs(struct ena_adapter *adapter)
{
    struct ena_com_io_cq* io_cq;
    struct ena_eth_io_intr_reg intr_reg;
    uint16_t ena_qid;
    int i;

    /* Unmask interrupts for all queues */
    for (i = 0; i < adapter->num_queues; i++) {
        ena_qid = ENA_IO_TXQ_IDX(i);
        io_cq = &adapter->ena_dev->io_cq_queues[ena_qid];
        ena_com_update_intr_reg(&intr_reg, 0, 0, true);
        ena_com_unmask_intr(io_cq, &intr_reg);
    }
}

void ena_up(struct ena_adapter *adapter)
{
    if (!ENA_FLAG_ISSET(ENA_FLAG_DEV_UP, adapter)) {
        ena_debug("device is going UP");

        /* setup interrupts for IO queues */
        ena_setup_io_intr(adapter);

        ena_request_io_irq(adapter);

        /* allocate transmit descriptors */
        ena_setup_all_tx_resources(adapter);

        /* allocate receive descriptors */
        ena_setup_all_rx_resources(adapter);


        /* create IO queues for Rx & Tx */
        ena_create_io_queues(adapter);
#if 0
        if (ENA_FLAG_ISSET(ENA_FLAG_LINK_UP, adapter))
            if_link_state_change(adapter->ifp, LINK_STATE_UP);
#endif
        ena_up_complete(adapter);
#if 0
        counter_u64_add(adapter->dev_stats.interface_up, 1);

        ena_update_hwassist(adapter);

        if_setdrvflagbits(adapter->ifp, IFF_DRV_RUNNING,
            IFF_DRV_OACTIVE);
#endif

        /* Activate timer service only if the device is running.
         * If this flag is not set, it means that the driver is being
         * reset and timer service will be activated afterwards.
         */
        if (ENA_FLAG_ISSET(ENA_FLAG_DEVICE_RUNNING, adapter)) {
            adapter->timer_service = register_timer(runloop_timers, CLOCK_ID_MONOTONIC,
                                                    seconds(1), false, 0, adapter->timer_task);
        }

        ENA_FLAG_SET_ATOMIC(ENA_FLAG_DEV_UP, adapter);

        ena_unmask_all_io_irqs(adapter);
    }
}

#define OSRELVER 11
#define STR(x) #x
static const char osrelver[] = STR(OSRELVER);
static const char osdist[] = "nanos";

static void ena_config_host_info(struct ena_com_dev *ena_dev,
                                 struct ena_adapter *adapter)
{
    /* Allocate only the host info */
    int rc = ena_com_allocate_host_info(ena_dev);
    assert(rc == 0);

    struct ena_admin_host_info *host_info = ena_dev->host_attr.host_info;

    host_info->bdf = PCI_GET_RID(adapter->ena_pci.dev);
    host_info->os_type = ENA_ADMIN_OS_FREEBSD;
    host_info->kernel_ver = OSRELVER;

    runtime_memcpy(host_info->kernel_ver_str, osrelver, sizeof(osrelver));
    host_info->os_dist = 0;
    runtime_memcpy(host_info->os_dist_str, osdist, sizeof(osdist));

    host_info->driver_version =
        (DRV_MODULE_VER_MAJOR) |
        (DRV_MODULE_VER_MINOR << ENA_ADMIN_HOST_INFO_MINOR_SHIFT) |
        (DRV_MODULE_VER_SUBMINOR << ENA_ADMIN_HOST_INFO_SUB_MINOR_SHIFT);
    host_info->num_cpus = 1;
}

static void ena_device_init(struct ena_adapter *adapter,
    struct ena_com_dev_get_features_ctx *get_feat_ctx, int *wd_active)
{
    struct ena_com_dev* ena_dev = adapter->ena_dev;
    uint32_t aenq_groups;

    int rc = ena_com_mmio_reg_read_request_init(ena_dev);
    assert(rc == 0);

    /*
     * The PCIe configuration space revision id indicate if mmio reg
     * read is disabled
     */
    bool readless_supported = !(pci_get_revid(adapter->ena_pci.dev) & ENA_MMIO_DISABLE_REG_READ);
    ena_com_set_mmio_read_mode(ena_dev, readless_supported);

    rc = ena_com_dev_reset(ena_dev, ENA_REGS_RESET_NORMAL);
    assert(rc == 0);

    rc = ena_com_validate_version(ena_dev);
    if (rc != 0) {
        halt("device version is too low\n");
    }

    int dma_width = ena_com_get_dma_width(ena_dev);
    if (dma_width < 0) {
        halt("Invalid dma width value %d", dma_width);
    }
    //TODO
    //adapter->dma_width = dma_width;

    /* ENA admin level init */
    rc = ena_com_admin_init(ena_dev, &aenq_handlers);
    assert(rc == 0);

    /*
     * To enable the msix interrupts the driver needs to know the number
     * of queues. So the driver uses polling mode to retrieve this
     * information
     */
    ena_com_set_admin_polling_mode(ena_dev, true);

    ena_config_host_info(ena_dev, adapter);

    /* Get Device Attributes */
    rc = ena_com_get_dev_attr_feat(ena_dev, get_feat_ctx);
    assert(rc == 0);

    aenq_groups = BIT(ENA_ADMIN_LINK_CHANGE) |
        BIT(ENA_ADMIN_FATAL_ERROR) |
        BIT(ENA_ADMIN_WARNING) |
        BIT(ENA_ADMIN_NOTIFICATION) |
        BIT(ENA_ADMIN_KEEP_ALIVE);

    aenq_groups &= get_feat_ctx->aenq.supported_groups;
    rc = ena_com_set_aenq_config(ena_dev, aenq_groups);
    assert(rc == 0);

    *wd_active = !!(aenq_groups & BIT(ENA_ADMIN_KEEP_ALIVE));

    if (get_feat_ctx->dev_attr.max_mtu < ENA_ADAPTER_MTU) {
        halt("Error, device max mtu is smaller than ifp MTU\n");
    }
}

static void ena_enable_msix_and_set_admin_interrupts(struct ena_adapter *adapter,
    int io_vectors, boolean disable_polling_mode)
{
    struct ena_com_dev *ena_dev = adapter->ena_dev;

    ena_enable_msix(adapter);

    ena_setup_mgmnt_intr(adapter);
    ena_request_mgmnt_irq(adapter);

    if (disable_polling_mode)
        ena_com_set_admin_polling_mode(ena_dev, false);

    ena_com_admin_aenq_enable(ena_dev);
}


static void ena_calc_queue_size(struct ena_adapter *adapter,
                                struct ena_calc_queue_size_ctx *ctx)
{
    struct ena_admin_feature_llq_desc *llq = &ctx->get_feat_ctx->llq;
    struct ena_com_dev *ena_dev = ctx->ena_dev;
    uint32_t tx_queue_size = ENA_DEFAULT_RING_SIZE;
    uint32_t rx_queue_size = adapter->rx_ring_size;

    if (ena_dev->supported_features & BIT(ENA_ADMIN_MAX_QUEUES_EXT)) {
        struct ena_admin_queue_ext_feature_fields *max_queue_ext =
            &ctx->get_feat_ctx->max_queue_ext.max_queue_ext;
        rx_queue_size = min_t(uint32_t, rx_queue_size,
            max_queue_ext->max_rx_cq_depth);
        rx_queue_size = min_t(uint32_t, rx_queue_size,
            max_queue_ext->max_rx_sq_depth);
        tx_queue_size = min_t(uint32_t, tx_queue_size,
            max_queue_ext->max_tx_cq_depth);

        if (ena_dev->tx_mem_queue_type ==
            ENA_ADMIN_PLACEMENT_POLICY_DEV)
            tx_queue_size = min_t(uint32_t, tx_queue_size,
                llq->max_llq_depth);
        else
            tx_queue_size = min_t(uint32_t, tx_queue_size,
                max_queue_ext->max_tx_sq_depth);

        ctx->max_rx_sgl_size = min_t(uint16_t, ENA_PKT_MAX_BUFS,
            max_queue_ext->max_per_packet_rx_descs);
        ctx->max_tx_sgl_size = min_t(uint16_t, ENA_PKT_MAX_BUFS,
            max_queue_ext->max_per_packet_tx_descs);
    } else {
        struct ena_admin_queue_feature_desc *max_queues =
            &ctx->get_feat_ctx->max_queues;
        rx_queue_size = min_t(uint32_t, rx_queue_size,
            max_queues->max_cq_depth);
        rx_queue_size = min_t(uint32_t, rx_queue_size,
            max_queues->max_sq_depth);
        tx_queue_size = min_t(uint32_t, tx_queue_size,
            max_queues->max_cq_depth);

        if (ena_dev->tx_mem_queue_type ==
            ENA_ADMIN_PLACEMENT_POLICY_DEV)
            tx_queue_size = min_t(uint32_t, tx_queue_size,
                llq->max_llq_depth);
        else
            tx_queue_size = min_t(uint32_t, tx_queue_size,
                max_queues->max_sq_depth);

        ctx->max_rx_sgl_size = min_t(uint16_t, ENA_PKT_MAX_BUFS,
            max_queues->max_packet_tx_descs);
        ctx->max_tx_sgl_size = min_t(uint16_t, ENA_PKT_MAX_BUFS,
            max_queues->max_packet_rx_descs);
    }

    /* round down to the nearest power of 2 */
    rx_queue_size = 1 << (fls(rx_queue_size) - 1);
    tx_queue_size = 1 << (fls(tx_queue_size) - 1);

    if (rx_queue_size == 0 || tx_queue_size == 0) {
        halt("Invalid queue size\n");
    }

    ctx->rx_queue_size = rx_queue_size;
    ctx->tx_queue_size = tx_queue_size;
}

static void ena_rss_init_default(struct ena_adapter *adapter)
{
    struct ena_com_dev *ena_dev = adapter->ena_dev;

    int rc = ena_com_rss_init(ena_dev, ENA_RX_RSS_TABLE_LOG_SIZE);
    assert(rc == 0);// Cannot init indirect table

    for (int i = 0; i < ENA_RX_RSS_TABLE_SIZE; i++) {
        int qid = i % adapter->num_queues;
        rc = ena_com_indirect_table_fill_entry(ena_dev, i,
            ENA_IO_RXQ_IDX(qid));
        assert(rc == 0); // Cannot fill indirect table
    }

    rc = ena_com_fill_hash_function(ena_dev, ENA_ADMIN_CRC32, 0,
        ENA_HASH_KEY_SIZE, 0xFFFFFFFF);
    assert(rc == 0 || rc == EOPNOTSUPP); // Cannot fill hash function

    rc = ena_com_set_default_hash_ctrl(ena_dev);
    assert(rc == 0 || rc == EOPNOTSUPP); // Cannot fill hash control
}

#define ena_mbuf_sz PAGESIZE

static void ena_init_io_rings_common(struct ena_adapter *adapter, struct ena_ring *ring,
    uint16_t qid)
{
    ring->qid = qid;
    ring->adapter = adapter;
    ring->ena_dev = adapter->ena_dev;
    ring->first_interrupt = false;
    ring->no_interrupt_event_cnt = 0;
    ring->rx_mbuf_sz = ena_mbuf_sz;
}

static void ena_init_io_rings(struct ena_adapter *adapter)
{
    struct ena_com_dev *ena_dev;
    struct ena_ring *txr, *rxr;
    struct ena_que *que;
    int i;

    ena_dev = adapter->ena_dev;

    for (i = 0; i < adapter->num_queues; i++) {
        txr = &adapter->tx_ring[i];
        rxr = &adapter->rx_ring[i];

        /* TX/RX common ring state */
        ena_init_io_rings_common(adapter, txr, i);
        ena_init_io_rings_common(adapter, rxr, i);

        /* TX specific ring state */
        txr->ring_size = adapter->tx_ring_size;
        txr->tx_max_header_size = ena_dev->tx_max_header_size;
        txr->tx_mem_queue_type = ena_dev->tx_mem_queue_type;
        txr->smoothed_interval =
            ena_com_get_nonadaptive_moderation_interval_tx(ena_dev);

        /* Allocate a buf ring */
        txr->buf_ring_size = adapter->buf_ring_size;
        txr->br = buf_ring_alloc(txr->buf_ring_size, adapter->ena_pci.general);

        //TODO
#if 0
        /* Alloc TX statistics. */
        ena_alloc_counters((counter_u64_t *)&txr->tx_stats,
            sizeof(txr->tx_stats));
#endif
        /* RX specific ring state */
        rxr->ring_size = adapter->rx_ring_size;
        rxr->smoothed_interval =
            ena_com_get_nonadaptive_moderation_interval_rx(ena_dev);

#if 0
        /* Alloc RX statistics. */
        ena_alloc_counters((counter_u64_t *)&rxr->rx_stats,
            sizeof(rxr->rx_stats));
#endif

        /* Initialize locks */
        spin_lock_init(&txr->ring_lock);

        que = &adapter->que[i];
        que->adapter = adapter;
        que->id = i;
        que->tx_ring = txr;
        que->rx_ring = rxr;

        txr->que = que;
        rxr->que = que;

        rxr->empty_rx_queue = 0;
    }
}

static void ena_free_io_ring_resources(struct ena_adapter *adapter, unsigned int qid)
{
    // TODO
    struct ena_ring *txr = &adapter->tx_ring[qid];
#if 0
    struct ena_ring *rxr = &adapter->rx_ring[qid];

    ena_free_counters((counter_u64_t *)&txr->tx_stats,
        sizeof(txr->tx_stats));
    ena_free_counters((counter_u64_t *)&rxr->rx_stats,
        sizeof(rxr->rx_stats));
#endif

    ENA_RING_MTX_LOCK(txr);
    struct pbuf *m;
    while ((m = buf_ring_dequeue_sc(txr->br)) != NULL)
        pbuf_free(m);
    buf_ring_free(txr->br, adapter->ena_pci.general);
    ENA_RING_MTX_UNLOCK(txr);
}

static void ena_free_all_io_rings_resources(struct ena_adapter *adapter)
{
    for (int i = 0; i < adapter->num_queues; i++)
        ena_free_io_ring_resources(adapter, i);
}

static void ena_device_validate_params(struct ena_adapter *adapter,
    struct ena_com_dev_get_features_ctx *get_feat_ctx)
{

    if (memcmp(get_feat_ctx->dev_attr.mac_addr, adapter->netif->hwaddr, ETHARP_HWADDR_LEN) != 0) {
        halt("Error, mac address are different\n");
    }

    if (get_feat_ctx->dev_attr.max_mtu < adapter->netif->mtu) {
        halt("Error, device max mtu is smaller than ifp MTU\n");
    }
}

static void ena_handle_updated_queues(struct ena_adapter *adapter,
    struct ena_com_dev_get_features_ctx *get_feat_ctx)
{
    struct ena_com_dev *ena_dev = adapter->ena_dev;
    struct ena_calc_queue_size_ctx calc_queue_ctx = { 0 };
    bool are_queues_changed = false;

    calc_queue_ctx.ena_dev = ena_dev;
    calc_queue_ctx.get_feat_ctx = get_feat_ctx;

    // TODO!
    int io_queue_num = 1;
    ena_calc_queue_size(adapter, &calc_queue_ctx);

    if (adapter->tx_ring->buf_ring_size != adapter->buf_ring_size)
        are_queues_changed = true;

    if (unlikely(adapter->tx_ring_size > calc_queue_ctx.tx_queue_size ||
        adapter->rx_ring_size > calc_queue_ctx.rx_queue_size)) {
        ena_debug("Not enough resources to allocate requested queue sizes "
            "(TX,RX)=(%d,%d), falling back to queue sizes "
            "(TX,RX)=(%d,%d)",
            adapter->tx_ring_size,
            adapter->rx_ring_size,
            calc_queue_ctx.tx_queue_size,
            calc_queue_ctx.rx_queue_size);
        adapter->tx_ring_size = calc_queue_ctx.tx_queue_size;
        adapter->rx_ring_size = calc_queue_ctx.rx_queue_size;
        adapter->max_tx_sgl_size = calc_queue_ctx.max_tx_sgl_size;
        adapter->max_rx_sgl_size = calc_queue_ctx.max_rx_sgl_size;
        are_queues_changed = true;
    }

    if (unlikely(adapter->num_queues > io_queue_num)) {
        ena_debug("Not enough resources to allocate %d queues, "
            "falling back to %d queues",
            adapter->num_queues, io_queue_num);
        adapter->num_queues = io_queue_num;
        if (ENA_FLAG_ISSET(ENA_FLAG_RSS_ACTIVE, adapter)) {
            ena_com_rss_destroy(ena_dev);
            ena_rss_init_default(adapter);
        }
        are_queues_changed = true;
    }

    if (unlikely(are_queues_changed)) {
        ena_free_all_io_rings_resources(adapter);
        ena_init_io_rings(adapter);
    }
}

static void ena_restore_device(struct ena_adapter *adapter)
{
    struct ena_com_dev_get_features_ctx get_feat_ctx;
    int wd_active;

    ENA_FLAG_SET_ATOMIC(ENA_FLAG_ONGOING_RESET, adapter);

    ena_device_init(adapter, &get_feat_ctx, &wd_active);

    /*
     * Only enable WD if it was enabled before reset, so it won't override
     * value set by the user by the sysctl.
     */
    if (adapter->wd_active != 0)
        adapter->wd_active = wd_active;

    ena_device_validate_params(adapter, &get_feat_ctx);

    ena_handle_updated_queues(adapter, &get_feat_ctx);

    ENA_FLAG_CLEAR_ATOMIC(ENA_FLAG_ONGOING_RESET, adapter);
    /* Make sure we don't have a race with AENQ Links state handler */
#if 0
    if (ENA_FLAG_ISSET(ENA_FLAG_LINK_UP, adapter))
        if_link_state_change(ifp, LINK_STATE_UP);
#endif

    ena_enable_msix_and_set_admin_interrupts(adapter, adapter->num_queues, true);

    /* If the interface was up before the reset bring it up */
    if (ENA_FLAG_ISSET(ENA_FLAG_DEV_UP_BEFORE_RESET, adapter)) {
        ena_up(adapter);
    }

    /* Indicate that device is running again and ready to work */
    ENA_FLAG_SET_ATOMIC(ENA_FLAG_DEVICE_RUNNING, adapter);

    if (ENA_FLAG_ISSET(ENA_FLAG_DEV_UP_BEFORE_RESET, adapter)) {
        /*
         * As the AENQ handlers weren't executed during reset because
         * the flag ENA_FLAG_DEVICE_RUNNING was turned off, the
         * timestamp must be updated again That will prevent next reset
         * caused by missing keep alive.
         */
        adapter->keep_alive_timestamp = uptime();
        adapter->timer_service = register_timer(runloop_timers, CLOCK_ID_MONOTONIC,
                                                seconds(1), false, 0, adapter->timer_task);
    }
    ena_debug("Device reset completed successfully");
}

static inline void set_default_llq_configurations(struct ena_llq_configurations *llq_config)
{
    llq_config->llq_header_location = ENA_ADMIN_INLINE_HEADER;
    llq_config->llq_ring_entry_size = ENA_ADMIN_LIST_ENTRY_SIZE_128B;
    llq_config->llq_stride_ctrl = ENA_ADMIN_MULTIPLE_DESCS_PER_ENTRY;
    llq_config->llq_num_decs_before_header =
        ENA_ADMIN_LLQ_NUM_DESCS_BEFORE_HEADER_2;
    llq_config->llq_ring_entry_size_value = 128;
}

static void ena_set_queues_placement_policy(struct ena_adapter *adapter, struct ena_com_dev *ena_dev,
    struct ena_admin_feature_llq_desc *llq, struct ena_llq_configurations *llq_default_configurations)
{
    uint32_t llq_feature_mask = 1 << ENA_ADMIN_LLQ;
    if (!(ena_dev->supported_features & llq_feature_mask)) {
        ena_debug("LLQ is not supported. Fallback to host mode policy.");
        ena_dev->tx_mem_queue_type = ENA_ADMIN_PLACEMENT_POLICY_HOST;
        return;
    }

    int rc = ena_com_config_dev_mode(ena_dev, llq, llq_default_configurations);
    if (rc != 0) {
        ena_debug("Failed to configure the device mode. "
            "Fallback to host mode policy.");
        ena_dev->tx_mem_queue_type = ENA_ADMIN_PLACEMENT_POLICY_HOST;
        return;
    }

    /* Nothing to config, exit */
    if (ena_dev->tx_mem_queue_type == ENA_ADMIN_PLACEMENT_POLICY_HOST)
        return;

    /* Try to allocate resources for LLQ bar */
    pci_bar_init(adapter->ena_pci.dev, &adapter->ena_pci.memory, ENA_MEM_BAR, 0, -1);

#if 0
    /* Enable write combining for better LLQ performance */
    rc = ena_enable_wc(adapter->memory);
    if (unlikely(rc != 0)) {
        device_printf(pdev, "failed to enable write combining.\n");
        return (rc);
    }
#endif

    /*
     * Save virtual address of the device's memory region
     * for the ena_com layer.
     */
    ena_dev->mem_bar = (void *)adapter->ena_pci.memory.vaddr;
}

void lwip_status_callback(struct netif *netif);

static err_t enaif_init(struct netif *netif)
{
    netif->hostname = "uniboot"; // from config

    netif->name[0] = DEVICE_NAME[0];
    netif->name[1] = DEVICE_NAME[1];

    netif->output = etharp_output;
    netif->linkoutput = ena_mq_start;
    netif->hwaddr_len = ETHARP_HWADDR_LEN;
    netif->status_callback = lwip_status_callback;
    ena_debug("%s: hwaddr %02x:%02x:%02x:%02x:%02x:%02x\n",
        __func__,
        netif->hwaddr[0], netif->hwaddr[1], netif->hwaddr[2],
        netif->hwaddr[3], netif->hwaddr[4], netif->hwaddr[5]);
    netif->mtu = ENA_ADAPTER_MTU;

    /* device capabilities */
    /* don't set NETIF_FLAG_ETHARP if this device is not an ethernet one */
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP | NETIF_FLAG_UP;

    return ERR_OK;
}

static void ena_setup_ifnet(struct ena_adapter *dev, struct ena_com_dev_get_features_ctx *feat)
{
    memcpy(dev->netif->hwaddr, feat->dev_attr.mac_addr,
        ETHARP_HWADDR_LEN);

    ena_up(dev);

    netif_add(dev->netif,
              0, 0, 0,
              dev,
              enaif_init,
              ethernet_input);
}

static void
ena_destroy_all_tx_queues(struct ena_adapter *adapter)
{
    uint16_t ena_qid;
    int i;

    for (i = 0; i < adapter->num_queues; i++) {
        ena_qid = ENA_IO_TXQ_IDX(i);
        ena_com_destroy_io_queue(adapter->ena_dev, ena_qid);
    }
}

static void
ena_destroy_all_rx_queues(struct ena_adapter *adapter)
{
    uint16_t ena_qid;
    int i;

    for (i = 0; i < adapter->num_queues; i++) {
        ena_qid = ENA_IO_RXQ_IDX(i);
        ena_com_destroy_io_queue(adapter->ena_dev, ena_qid);
    }
}

static void ena_destroy_all_io_queues(struct ena_adapter *adapter)
{
    for (int i = 0; i < adapter->num_queues; i++) {
        // TODO
#if 0
        struct ena_que *queue = &adapter->que[i];
        while (taskqueue_cancel(queue->cleanup_tq,
            &queue->cleanup_task, NULL))
            taskqueue_drain(queue->cleanup_tq,
                &queue->cleanup_task);
        taskqueue_free(queue->cleanup_tq);
#endif
    }

    ena_destroy_all_tx_queues(adapter);
    ena_destroy_all_rx_queues(adapter);
}

static void ena_free_rx_bufs(struct ena_adapter *adapter, unsigned int qid)
{
    struct ena_ring *rx_ring = &adapter->rx_ring[qid];

    for (unsigned int i = 0; i < rx_ring->ring_size; i++) {
        struct ena_rx_buffer *rx_info = &rx_ring->rx_buffer_info[i];

        if (rx_info->mbuf != NULL)
            ena_free_rx_mbuf(adapter, rx_ring, rx_info);
    }
}

static void ena_free_all_rx_bufs(struct ena_adapter *adapter)
{
    for (int i = 0; i < adapter->num_queues; i++)
        ena_free_rx_bufs(adapter, i);
}

/**
 * ena_free_tx_bufs - Free Tx Buffers per Queue
 * @adapter: network interface device structure
 * @qid: queue index
 **/
static void ena_free_tx_bufs(struct ena_adapter *adapter, unsigned int qid)
{
    struct ena_ring *tx_ring = &adapter->tx_ring[qid];

    ENA_RING_MTX_LOCK(tx_ring);
    for (int i = 0; i < tx_ring->ring_size; i++) {
        struct ena_tx_buffer *tx_info = &tx_ring->tx_buffer_info[i];

        if (tx_info->mbuf == NULL)
            continue;

        ena_trace(ENA_DBG, "free uncompleted tx mbuf qid %d idx 0x%x\n", qid, i);

        // TODO
/*
        bus_dmamap_sync(adapter->tx_buf_tag, tx_info->dmamap,
            BUS_DMASYNC_POSTWRITE);
        bus_dmamap_unload(adapter->tx_buf_tag, tx_info->dmamap);
*/

        pbuf_free(tx_info->mbuf);
        tx_info->mbuf = NULL;
    }
    ENA_RING_MTX_UNLOCK(tx_ring);
}

static void
ena_free_all_tx_bufs(struct ena_adapter *adapter)
{

    for (int i = 0; i < adapter->num_queues; i++)
        ena_free_tx_bufs(adapter, i);
}

void ena_down(struct ena_adapter *adapter)
{
    if (ENA_FLAG_ISSET(ENA_FLAG_DEV_UP, adapter)) {
        ena_debug("device is going DOWN");

        remove_timer(adapter->timer_service, 0);

        ENA_FLAG_CLEAR_ATOMIC(ENA_FLAG_DEV_UP, adapter);
//        if_setdrvflagbits(adapter->ifp, IFF_DRV_OACTIVE,
//            IFF_DRV_RUNNING);

        ena_free_io_irq(adapter);

        if (ENA_FLAG_ISSET(ENA_FLAG_TRIGGER_RESET, adapter)) {
            int rc = ena_com_dev_reset(adapter->ena_dev,
                adapter->reset_reason);
            if (rc != 0)
                ena_debug("Device reset failed");
        }

        ena_destroy_all_io_queues(adapter);

        ena_free_all_tx_bufs(adapter);
        ena_free_all_rx_bufs(adapter);
        ena_free_all_tx_resources(adapter);
        ena_free_all_rx_resources(adapter);

//        counter_u64_add(adapter->dev_stats.interface_down, 1);
    }
}

void ena_destroy_device(struct ena_adapter *adapter, bool graceful)
{
    struct ena_com_dev *ena_dev = adapter->ena_dev;

    if (!ENA_FLAG_ISSET(ENA_FLAG_DEVICE_RUNNING, adapter))
        return;

//    if_link_state_change(ifp, LINK_STATE_DOWN);

    bool dev_up = ENA_FLAG_ISSET(ENA_FLAG_DEV_UP, adapter);
    if (dev_up)
        ENA_FLAG_SET_ATOMIC(ENA_FLAG_DEV_UP_BEFORE_RESET, adapter);
    else
        ENA_FLAG_CLEAR_ATOMIC(ENA_FLAG_DEV_UP_BEFORE_RESET, adapter);

    if (!graceful)
        ena_com_set_admin_running_state(ena_dev, false);

    if (ENA_FLAG_ISSET(ENA_FLAG_DEV_UP, adapter))
        ena_down(adapter);

    /*
     * Stop the device from sending AENQ events (if the device was up, and
     * the trigger reset was on, ena_down already performs device reset)
     */
    if (!(ENA_FLAG_ISSET(ENA_FLAG_TRIGGER_RESET, adapter) && dev_up))
        ena_com_dev_reset(adapter->ena_dev, adapter->reset_reason);

    ena_free_mgmnt_irq(adapter);

    ena_disable_msix(adapter);

    ena_com_abort_admin_commands(ena_dev);

    ena_com_wait_for_abort_completion(ena_dev);

    ena_com_admin_destroy(ena_dev);

    ena_com_mmio_reg_read_request_destroy(ena_dev);

    adapter->reset_reason = ENA_REGS_RESET_NORMAL;

    ENA_FLAG_CLEAR_ATOMIC(ENA_FLAG_TRIGGER_RESET, adapter);
    ENA_FLAG_CLEAR_ATOMIC(ENA_FLAG_DEVICE_RUNNING, adapter);
}

closure_function(1, 0, void, ena_reset_task,
                 struct ena_adapter *, adapter)
{
    struct ena_adapter *adapter = bound(adapter);

    if (!ENA_FLAG_ISSET(ENA_FLAG_TRIGGER_RESET, adapter)) {
        ena_debug("device reset scheduled but trigger_reset is off");
        return;
    }

    ena_debug("ena_reset_task:  resetting!");

    //TODO!
//    sx_xlock(&adapter->ioctl_sx);
    ena_destroy_device(adapter, false);
    ena_restore_device(adapter);
//    sx_unlock(&adapter->ioctl_sx);
}

static void ena_attach(heap general, heap page_allocator, pci_dev d)
{
    struct ena_adapter *dev = allocate(general, sizeof(struct ena_adapter));
    dev->ena_pci._dev = *d;
    dev->ena_pci.dev = &dev->ena_pci._dev;

    // TODO!
    /* Set up the timer service */
    dev->keep_alive_timeout = DEFAULT_KEEP_ALIVE_TO;
    dev->missing_tx_timeout = DEFAULT_TX_CMP_TO;
    dev->missing_tx_max_queues = DEFAULT_TX_MONITORED_QUEUES;
    dev->missing_tx_threshold = DEFAULT_TX_CMP_THRESHOLD;

    dev->ena_pci.general = general;
    dev->ena_pci.contiguous = page_allocator;

    /* Allocate memory for ena_dev structure */
    struct ena_com_dev *ena_dev = allocate_zero(dev->ena_pci.general, sizeof(struct ena_com_dev));
    assert(ena_dev != INVALID_ADDRESS);

    ena_dev->dmadev = &dev->ena_pci;
    dev->ena_dev = ena_dev;

    pci_bar_init(dev->ena_pci.dev, &dev->ena_pci.registers, ENA_REG_BAR, 0, -1);

    ena_dev->bus = allocate_zero(dev->ena_pci.general, sizeof(struct ena_bus));
    assert(ena_dev->bus != INVALID_ADDRESS);

    /* Store register resources */
    ((struct ena_bus*)(ena_dev->bus))->reg_bar_p = &dev->ena_pci.registers;

    ena_dev->tx_mem_queue_type = ENA_ADMIN_PLACEMENT_POLICY_HOST;

    /* Initially clear all the flags */
    ENA_FLAG_ZERO(dev);

    struct ena_com_dev_get_features_ctx get_feat_ctx;
    ena_device_init(dev, &get_feat_ctx, &dev->wd_active);

    dev->max_mtu = get_feat_ctx.dev_attr.max_mtu;

    dev->rxbuflen = dev->max_mtu;
    dev->rxbuffers = allocate_objcache(dev->ena_pci.general, dev->ena_pci.contiguous,
                                       dev->rxbuflen + sizeof(struct xpbuf), PAGESIZE_2M);
    spin_lock_init(&dev->rx_buflock);

    struct netif *netif = allocate(dev->ena_pci.general, sizeof(struct netif));
    assert(netif != INVALID_ADDRESS);
    dev->netif = netif;

    struct ena_llq_configurations llq_config;
    set_default_llq_configurations(&llq_config);
    ena_set_queues_placement_policy(dev, ena_dev, &get_feat_ctx.llq, &llq_config);

    if (ena_dev->tx_mem_queue_type == ENA_ADMIN_PLACEMENT_POLICY_HOST)
        ena_debug("Placement policy: regular");
    else
        ena_debug("Placement policy: low latency");

    dev->keep_alive_timestamp = uptime();

    // TODO!!
    dev->num_queues = 1;

    // Set the requested Rx ring size
    dev->rx_ring_size = ENA_DEFAULT_RING_SIZE;

    struct ena_calc_queue_size_ctx calc_queue_ctx = { 0 };
    calc_queue_ctx.ena_dev = ena_dev;
    calc_queue_ctx.get_feat_ctx = &get_feat_ctx;
    ena_calc_queue_size(dev, &calc_queue_ctx);

    dev->reset_reason = ENA_REGS_RESET_NORMAL;

    dev->tx_ring_size = calc_queue_ctx.tx_queue_size;
    dev->rx_ring_size = calc_queue_ctx.rx_queue_size;

    dev->max_tx_sgl_size = calc_queue_ctx.max_tx_sgl_size;
    dev->max_rx_sgl_size = calc_queue_ctx.max_rx_sgl_size;

    dev->buf_ring_size = ENA_DEFAULT_BUF_RING_SIZE;

    /* initialize rings basic information */
    ena_debug("Creating %d io queues. Rx queue size: %d, Tx queue size: %d",
              dev->num_queues, calc_queue_ctx.rx_queue_size, calc_queue_ctx.tx_queue_size);
    ena_init_io_rings(dev);

    ena_enable_msix_and_set_admin_interrupts(dev, dev->num_queues, false);

    /* Initialize reset task */
    dev->reset_task = closure(dev->ena_pci.general, ena_reset_task, dev);

    dev->timer_task = closure(dev->ena_pci.general, ena_timer_service, dev);

    ENA_FLAG_SET_ATOMIC(ENA_FLAG_DEVICE_RUNNING, dev);

    ena_setup_ifnet(dev, &get_feat_ctx);

    ena_com_set_admin_polling_mode(ena_dev, true);
}

boolean ena_dev_probe(pci_dev d)
{
    u16 pci_vendor_id = pci_get_vendor(d);
    u16 pci_device_id = pci_get_device(d);
    ena_vendor_info_t *ent = ena_vendor_info_array;
    while (ent->vendor_id != 0) {
        if ((pci_vendor_id == ent->vendor_id) &&
            (pci_device_id == ent->device_id)) {
            ena_debug("vendor=%x device=%x", pci_vendor_id, pci_device_id);
            return true;
        }
        ent++;
    }

    return false;
}

closure_function(2, 1, boolean, ena_probe,
                 heap, general, heap, page_allocator, pci_dev, d)
{
    if (!ena_dev_probe(d))
        return false;

    ena_attach(bound(general), bound(page_allocator), d);
    return true;
}

void init_aws_ena(kernel_heaps kh)
{
    heap h = heap_general(kh);
    register_pci_driver(closure(h, ena_probe, h, heap_backed(kh)));
}

/******************************************************************************
 ******************************** AENQ Handlers *******************************
 *****************************************************************************/
static void ena_update_hints(struct ena_adapter *adapter,
                 struct ena_admin_ena_hw_hints *hints)
{
    struct ena_com_dev *ena_dev = adapter->ena_dev;

    if (hints->admin_completion_tx_timeout)
        ena_dev->admin_queue.completion_timeout =
            hints->admin_completion_tx_timeout * 1000;

    if (hints->mmio_read_timeout)
        /* convert to usec */
        ena_dev->mmio_read.reg_read_to =
            hints->mmio_read_timeout * 1000;

    if (hints->missed_tx_completion_count_threshold_to_reset)
        adapter->missing_tx_threshold =
            hints->missed_tx_completion_count_threshold_to_reset;

    if (hints->missing_tx_completion_timeout) {
        if (hints->missing_tx_completion_timeout ==
             ENA_HW_HINTS_NO_TIMEOUT)
            adapter->missing_tx_timeout = ENA_HW_HINTS_NO_TIMEOUT;
        else
            adapter->missing_tx_timeout =
                milliseconds(hints->missing_tx_completion_timeout);
    }

    if (hints->driver_watchdog_timeout) {
        if (hints->driver_watchdog_timeout == ENA_HW_HINTS_NO_TIMEOUT)
            adapter->keep_alive_timeout = ENA_HW_HINTS_NO_TIMEOUT;
        else
            adapter->keep_alive_timeout =
                milliseconds(hints->driver_watchdog_timeout);
    }
}

/**
 * ena_update_on_link_change:
 * Notify the network interface about the change in link status
 **/
static void
ena_update_on_link_change(void *adapter_data,
    struct ena_admin_aenq_entry *aenq_e)
{
    ena_debug("%s", __func__);
    struct ena_adapter *adapter = (struct ena_adapter *)adapter_data;
    struct ena_admin_aenq_link_change_desc *aenq_desc;
    int status;

    aenq_desc = (struct ena_admin_aenq_link_change_desc *)aenq_e;
    status = aenq_desc->flags &
        ENA_ADMIN_AENQ_LINK_CHANGE_DESC_LINK_STATUS_MASK;

    if (status != 0) {
        ena_debug("link is UP");
        ENA_FLAG_SET_ATOMIC(ENA_FLAG_LINK_UP, adapter);
        // TODO: we can already have enqueued packets. Can poll in ena_attach till status became UP
        if (!ENA_FLAG_ISSET(ENA_FLAG_ONGOING_RESET, adapter)) {
            for (int i = 0; i < adapter->num_queues; i++) {
                struct ena_ring *tx_ring = &adapter->tx_ring[i];
                enqueue(runqueue, tx_ring->enqueue_task);
            }
        }
        // TODO
//        if (!ENA_FLAG_ISSET(ENA_FLAG_ONGOING_RESET, adapter))
//            if_link_state_change(ifp, LINK_STATE_UP);
    } else {
        ena_debug("link is DOWN");
//        if_link_state_change(ifp, LINK_STATE_DOWN);
        ENA_FLAG_CLEAR_ATOMIC(ENA_FLAG_LINK_UP, adapter);
    }
}

static void ena_notification(void *adapter_data,
    struct ena_admin_aenq_entry *aenq_e)
{
    ena_debug("%s", __func__);
    struct ena_adapter *adapter = (struct ena_adapter *)adapter_data;
    struct ena_admin_ena_hw_hints *hints;

    ENA_WARN(aenq_e->aenq_common_desc.group != ENA_ADMIN_NOTIFICATION,
        "Invalid group(%x) expected %x\n",  aenq_e->aenq_common_desc.group,
        ENA_ADMIN_NOTIFICATION);

    switch (aenq_e->aenq_common_desc.syndrom) {
    case ENA_ADMIN_UPDATE_HINTS:
        hints =
            (struct ena_admin_ena_hw_hints *)(&aenq_e->inline_data_w4);
        ena_update_hints(adapter, hints);
        break;
    default:
        ena_debug(
            "Invalid aenq notification link state %d",
            aenq_e->aenq_common_desc.syndrom);
    }
}

/* Function called on ENA_ADMIN_KEEP_ALIVE event */
static void ena_keep_alive_wd(void *adapter_data,
    struct ena_admin_aenq_entry *aenq_e)
{
    struct ena_adapter *adapter = (struct ena_adapter *)adapter_data;

#ifdef ENA_DEBUG
    struct ena_admin_aenq_keep_alive_desc *desc = (struct ena_admin_aenq_keep_alive_desc *)aenq_e;

    uint64_t rx_drops = ((uint64_t)desc->rx_drops_high << 32) | desc->rx_drops_low;

    ena_debug("%s rx_drops %ld", __func__, rx_drops);
#endif

#if 0
    counter_u64_zero(adapter->hw_stats.rx_drops);
    counter_u64_add(adapter->hw_stats.rx_drops, rx_drops);
#endif

    timestamp stime = uptime();
    atomic_store_rel64(&adapter->keep_alive_timestamp, stime);
}

/**
 * This handler will called for unknown event group or unimplemented handlers
 **/
static void
unimplemented_aenq_handler(void *adapter_data,
    struct ena_admin_aenq_entry *aenq_e)
{
    ena_debug("Unknown event was received or event with unimplemented handler");
}

static struct ena_aenq_handlers aenq_handlers = {
    .handlers = {
        [ENA_ADMIN_LINK_CHANGE] = ena_update_on_link_change,
        [ENA_ADMIN_NOTIFICATION] = ena_notification,
        [ENA_ADMIN_KEEP_ALIVE] = ena_keep_alive_wd,
    },
    .unimplemented_handler = unimplemented_aenq_handler
};
