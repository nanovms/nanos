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
#include <lwip/prot/tcp.h>
#include <netif/ethernet.h>
#include <pci.h>

#include "../aws.h"

#include "ena_datapath.h"
#include "ena.h"

/*********************************************************
 *  Function prototypes
 *********************************************************/
static void ena_intr_msix_mgmnt(void *);
static int ena_change_mtu(struct ena_adapter *, int);
static inline void ena_reset_counters(void *, int);
static void ena_init_io_rings_common(struct ena_adapter *, struct ena_ring *, uint16_t);
static void ena_init_io_rings_basic(struct ena_adapter *);
static void ena_init_io_rings_advanced(struct ena_adapter *);
static void ena_init_io_rings(struct ena_adapter *);
static void ena_free_io_ring_resources(struct ena_adapter *, unsigned int);
static void ena_free_all_io_rings_resources(struct ena_adapter *);
static int ena_setup_tx_resources(struct ena_adapter *, int);
static void ena_free_tx_resources(struct ena_adapter *, int);
static int ena_setup_all_tx_resources(struct ena_adapter *);
static void ena_free_all_tx_resources(struct ena_adapter *);
static int ena_setup_rx_resources(struct ena_adapter *, unsigned int);
static void ena_free_rx_resources(struct ena_adapter *, unsigned int);
static int ena_setup_all_rx_resources(struct ena_adapter *);
static void ena_free_all_rx_resources(struct ena_adapter *);
static inline int ena_alloc_rx_mbuf(struct ena_adapter *, struct ena_ring *,
                                    struct ena_rx_buffer *);
static void ena_free_rx_mbuf(struct ena_adapter *, struct ena_ring *, struct ena_rx_buffer *);
static void ena_free_rx_bufs(struct ena_adapter *, unsigned int);
static void ena_refill_all_rx_bufs(struct ena_adapter *);
static void ena_free_all_rx_bufs(struct ena_adapter *);
static void ena_free_tx_bufs(struct ena_adapter *, unsigned int);
static void ena_free_all_tx_bufs(struct ena_adapter *);
static void ena_destroy_all_tx_queues(struct ena_adapter *);
static void ena_destroy_all_rx_queues(struct ena_adapter *);
static void ena_destroy_all_io_queues(struct ena_adapter *);
static int ena_create_io_queues(struct ena_adapter *);
static void ena_handle_msix(void *);
static int ena_enable_msix(struct ena_adapter *);
static void ena_setup_mgmnt_intr(struct ena_adapter *);
static int ena_setup_io_intr(struct ena_adapter *);
static int ena_request_mgmnt_irq(struct ena_adapter *);
static int ena_request_io_irq(struct ena_adapter *);
static void ena_free_mgmnt_irq(struct ena_adapter *);
static void ena_free_io_irq(struct ena_adapter *);
static void ena_disable_msix(struct ena_adapter *);
static void ena_unmask_all_io_irqs(struct ena_adapter *);
static int ena_up_complete(struct ena_adapter *);
static err_t ena_init(struct netif *);
static int ena_setup_ifnet(struct ena_adapter *, struct ena_com_dev_get_features_ctx *);
static int ena_set_queues_placement_policy(struct ena_adapter *,
                                           struct ena_admin_feature_llq_desc *,
                                           struct ena_llq_configurations *);
static uint32_t ena_calc_max_io_queue_num(struct ena_adapter *,
                                          struct ena_com_dev_get_features_ctx *);
static int ena_calc_io_queue_size(struct ena_calc_queue_size_ctx *);
static void ena_config_host_info(struct ena_adapter *);
static boolean ena_attach(heap general, heap page_allocator, pci_dev d);
static int ena_device_init(struct ena_adapter *,
                           struct ena_com_dev_get_features_ctx *, int *);
static int ena_enable_msix_and_set_admin_interrupts(struct ena_adapter *);
static void ena_update_on_link_change(void *, struct ena_admin_aenq_entry *);
static void unimplemented_aenq_handler(void *, struct ena_admin_aenq_entry *);

static char ena_version[] = DEVICE_NAME " " DRV_MODULE_NAME " v" DRV_MODULE_VERSION;

static ena_vendor_info_t ena_vendor_info_array[] = {
        { PCI_VENDOR_ID_AMAZON, PCI_DEV_ID_ENA_PF, 0 },
        { PCI_VENDOR_ID_AMAZON, PCI_DEV_ID_ENA_PF_RSERV0, 0 },
        { PCI_VENDOR_ID_AMAZON, PCI_DEV_ID_ENA_VF, 0 },
        { PCI_VENDOR_ID_AMAZON, PCI_DEV_ID_ENA_VF_RSERV0, 0 },
    /* Last entry */
        { 0, 0, 0 }
};

/*
 * Contains pointers to event handlers, e.g. link state chage.
 */
static struct ena_aenq_handlers aenq_handlers;

int ena_dma_alloc(struct ena_adapter *adapter, u64 size, ena_mem_handle_t *dma,
                  int mapflags, u64 alignment)
{
    if (size < alignment)
        /* Enforce alignment by exploiting the bitmap (and thus id heap) allocation policy. */
        size = alignment;

    dma->vaddr = allocate_zero(adapter->contiguous, size);
    if (dma->vaddr == INVALID_ADDRESS) {
        ena_trace(NULL, ENA_ALERT, "allocate_zero(%ld) failed\n", size);
        dma->vaddr = 0;
        dma->paddr = 0;
        return ENA_COM_NO_MEM;
    }

    dma->paddr = physical_from_virtual(dma->vaddr);
    dma->size = size;
    return 0;
}

closure_function(2, 1, boolean, ena_probe,
        heap, general, heap, page_allocator,
        pci_dev, d)
{
    ena_vendor_info_t *ent;
    uint16_t pci_vendor_id = 0;
    uint16_t pci_device_id = 0;

    pci_vendor_id = pci_get_vendor(d);
    pci_device_id = pci_get_device(d);

    ent = ena_vendor_info_array;
    while (ent->vendor_id != 0) {
        if ((pci_vendor_id == ent->vendor_id) && (pci_device_id == ent->device_id)) {
            ena_trace(NULL, ENA_DBG, "vendor=%x device=%x\n", pci_vendor_id, pci_device_id);
            return ena_attach(bound(general), bound(page_allocator), d);
        }
        ent++;
    }
    return false;
}

static int ena_change_mtu(struct ena_adapter *adapter, int new_mtu)
{
    int rc;

    if ((new_mtu > adapter->max_mtu) || (new_mtu < ENA_MIN_MTU)) {
        device_printf(adapter->pdev, "Invalid MTU setting. "
            "new_mtu: %d max mtu: %d min mtu: %d\n", new_mtu,
            adapter->max_mtu, ENA_MIN_MTU);
        return ENA_COM_INVAL;
    }

    rc = ena_com_set_dev_mtu(adapter->ena_dev, new_mtu);
    if (likely (rc == 0)) {
        ena_trace (NULL, ENA_DBG, "set MTU to %d\n", new_mtu);
    }
    else {
        device_printf(adapter->pdev, "Failed to set MTU to %d\n", new_mtu);
    }

    return rc;
}

static inline void ena_reset_counters(void *begin, int size)
{
    zero(begin, size);
}

static void ena_init_io_rings_common(struct ena_adapter *adapter, struct ena_ring *ring,
                          uint16_t qid)
{

    ring->qid = qid;
    ring->adapter = adapter;
    ring->ena_dev = adapter->ena_dev;
    ring->first_interrupt = false;
    ring->no_interrupt_event_cnt = 0;
}

static void ena_init_io_rings_basic(struct ena_adapter *adapter)
{
    struct ena_com_dev *ena_dev;
    struct ena_ring *txr, *rxr;
    struct ena_que *que;
    int i;

    ena_dev = adapter->ena_dev;

    for (i = 0; i < adapter->num_io_queues; i++) {
        txr = &adapter->tx_ring[i];
        rxr = &adapter->rx_ring[i];

        /* TX/RX common ring state */
        ena_init_io_rings_common (adapter, txr, i);
        ena_init_io_rings_common (adapter, rxr, i);

        /* TX specific ring state */
        txr->tx_max_header_size = ena_dev->tx_max_header_size;
        txr->tx_mem_queue_type = ena_dev->tx_mem_queue_type;

        que = &adapter->que[i];
        que->adapter = adapter;
        que->id = i;
        que->tx_ring = txr;
        que->rx_ring = rxr;

        txr->que = que;
        rxr->que = que;

        rxr->empty_rx_queue = 0;
        rxr->rx_mbuf_sz = PBUF_POOL_BUFSIZE;
    }
}

static void ena_init_io_rings_advanced(struct ena_adapter *adapter)
{
    struct ena_ring *txr;
    int i;

    for (i = 0; i < adapter->num_io_queues; i++) {
        txr = &adapter->tx_ring[i];

        /* Allocate a buf ring */
        txr->buf_ring_size = adapter->buf_ring_size;
        txr->br = allocate_queue(adapter->general, txr->buf_ring_size);
        assert(txr->br != INVALID_ADDRESS);

        /* Initialize locks */
        ENA_SPINLOCK_INIT(txr->ring_mtx);
    }
}

static void ena_init_io_rings(struct ena_adapter *adapter)
{
    /*
     * IO rings initialization can be divided into the 2 steps:
     *   1. Initialize variables and fields with initial values and copy
     *      them from adapter/ena_dev (basic)
     *   2. Allocate mutex, counters and buf_ring (advanced)
     */
    ena_init_io_rings_basic(adapter);
    ena_init_io_rings_advanced(adapter);
}

static void ena_txring_flush(struct ena_ring *tx_ring)
{
    struct pbuf *p;
    while ((p = dequeue(tx_ring->br)) != INVALID_ADDRESS) {
        pbuf_free(p);
    }
}

static void ena_free_io_ring_resources(struct ena_adapter *adapter, unsigned int qid)
{
    struct ena_ring *txr = &adapter->tx_ring[qid];

    ENA_RING_MTX_LOCK(txr);
    ena_txring_flush(txr);
    deallocate_queue(txr->br);
    ENA_RING_MTX_UNLOCK(txr);

    ENA_SPINLOCK_DESTROY(txr->ring_mtx);
}

static void ena_free_all_io_rings_resources(struct ena_adapter *adapter)
{
    int i;

    for (i = 0; i < adapter->num_io_queues; i++)
        ena_free_io_ring_resources(adapter, i);

}

define_closure_function(1, 0, void, ena_enqueue_task,
                        struct ena_ring *, ring)
{
    ena_deferred_mq_start(bound(ring), 1);
}

/**
 * ena_setup_tx_resources - allocate Tx resources (Descriptors)
 * @adapter: network interface device structure
 * @qid: queue index
 *
 * Returns 0 on success, otherwise on failure.
 **/
static int ena_setup_tx_resources(struct ena_adapter *adapter, int qid)
{
    struct ena_que *que = &adapter->que[qid];
    struct ena_ring *tx_ring = que->tx_ring;
    int size, i;

    size = sizeof(struct ena_tx_buffer) * tx_ring->ring_size;

    tx_ring->tx_buffer_info = allocate_zero(adapter->general, size);
    if (unlikely(tx_ring->tx_buffer_info == INVALID_ADDRESS))
        return ENA_COM_NO_MEM;

    size = sizeof(uint16_t) * tx_ring->ring_size;
    tx_ring->free_tx_ids = allocate_zero(adapter->general, size);
    if (unlikely(tx_ring->free_tx_ids == INVALID_ADDRESS))
        goto err_buf_info_free;

    size = tx_ring->tx_max_header_size;
    tx_ring->push_buf_intermediate_buf = allocate_zero(adapter->general, size);
    if (unlikely(tx_ring->push_buf_intermediate_buf == INVALID_ADDRESS))
        goto err_tx_ids_free;

    /* Req id stack for TX OOO completions */
    for (i = 0; i < tx_ring->ring_size; i++)
        tx_ring->free_tx_ids[i] = i;

    /* Reset TX statistics. */
    ena_reset_counters(&tx_ring->tx_stats, sizeof(tx_ring->tx_stats));

    tx_ring->next_to_use = 0;
    tx_ring->next_to_clean = 0;
    tx_ring->acum_pkts = 0;

    ENA_RING_MTX_LOCK(tx_ring);
    ena_txring_flush(tx_ring);
    ENA_RING_MTX_UNLOCK(tx_ring);

    init_closure(&tx_ring->enqueue_task, ena_enqueue_task, tx_ring);
    tx_ring->running = true;

    return 0;

err_tx_ids_free:
    deallocate(adapter->general, tx_ring->free_tx_ids, sizeof(uint16_t) * tx_ring->ring_size);
    tx_ring->free_tx_ids = NULL;
err_buf_info_free:
    deallocate(adapter->general, tx_ring->tx_buffer_info,
        sizeof(struct ena_tx_buffer) * tx_ring->ring_size);
    tx_ring->tx_buffer_info = NULL;

    return ENA_COM_NO_MEM;
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

    ENA_RING_MTX_LOCK(tx_ring);
    /* Flush buffer ring */
    ena_txring_flush(tx_ring);

    for (int i = 0; i < tx_ring->ring_size; i++) {
        pbuf_free(tx_ring->tx_buffer_info[i].mbuf);
        tx_ring->tx_buffer_info[i].mbuf = NULL;
    }
    ENA_RING_MTX_UNLOCK(tx_ring);

    /* And free allocated memory. */
    deallocate(adapter->general, tx_ring->tx_buffer_info,
            sizeof(struct ena_tx_buffer) * tx_ring->ring_size);
    tx_ring->tx_buffer_info = NULL;

    deallocate(adapter->general, tx_ring->free_tx_ids, sizeof(uint16_t) * tx_ring->ring_size);
    tx_ring->free_tx_ids = NULL;

    deallocate(adapter->general, tx_ring->push_buf_intermediate_buf, tx_ring->tx_max_header_size);
    tx_ring->push_buf_intermediate_buf = NULL;
}

/**
 * ena_setup_all_tx_resources - allocate all queues Tx resources
 * @adapter: network interface device structure
 *
 * Returns 0 on success, otherwise on failure.
 **/
static int ena_setup_all_tx_resources(struct ena_adapter *adapter)
{
    int i, rc;

    for (i = 0; i < adapter->num_io_queues; i++) {
        rc = ena_setup_tx_resources(adapter, i);
        if (rc != 0) {
            device_printf(adapter->pdev, "Allocation for Tx Queue %d failed\n", i);
            goto err_setup_tx;
        }
    }

    return 0;

err_setup_tx:
    /* Rewind the index freeing the rings as we go */
    while (i--)
        ena_free_tx_resources(adapter, i);
    return rc;
}

/**
 * ena_free_all_tx_resources - Free Tx Resources for All Queues
 * @adapter: network interface device structure
 *
 * Free all transmit software resources
 **/
static void ena_free_all_tx_resources(struct ena_adapter *adapter)
{
    int i;

    for (i = 0; i < adapter->num_io_queues; i++)
        ena_free_tx_resources(adapter, i);
}

/**
 * ena_setup_rx_resources - allocate Rx resources (Descriptors)
 * @adapter: network interface device structure
 * @qid: queue index
 *
 * Returns 0 on success, otherwise on failure.
 **/
static int ena_setup_rx_resources(struct ena_adapter *adapter, unsigned int qid)
{
    struct ena_que *que = &adapter->que[qid];
    struct ena_ring *rx_ring = que->rx_ring;
    int size, i;

    size = sizeof(struct ena_rx_buffer) * rx_ring->ring_size;

    /*
     * Alloc extra element so in rx path
     * we can always prefetch rx_info + 1
     */
    size += sizeof(struct ena_rx_buffer);

    rx_ring->rx_buffer_info = allocate_zero(adapter->general, size);
    if (rx_ring->rx_buffer_info == INVALID_ADDRESS)
        return ENA_COM_NO_MEM;

    rx_ring->free_rx_ids = allocate_zero(adapter->general, sizeof(uint16_t) * rx_ring->ring_size);
    if (rx_ring->free_rx_ids == INVALID_ADDRESS)
        goto err_free_binfo;

    for (i = 0; i < rx_ring->ring_size; i++)
        rx_ring->free_rx_ids[i] = i;

    /* Reset RX statistics. */
    ena_reset_counters(&rx_ring->rx_stats, sizeof(rx_ring->rx_stats));

    rx_ring->next_to_clean = 0;
    rx_ring->next_to_use = 0;

    return 0;

err_free_binfo:
    deallocate(adapter->general, rx_ring->rx_buffer_info, size);
    rx_ring->rx_buffer_info = NULL;
    return ENA_COM_NO_MEM;
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

    for (int i = 0; i < rx_ring->ring_size; i++) {
        pbuf_free(rx_ring->rx_buffer_info[i].mbuf);
        rx_ring->rx_buffer_info[i].mbuf = NULL;
    }

    /* free allocated memory */
    deallocate(adapter->general, rx_ring->rx_buffer_info,
               sizeof(struct ena_rx_buffer) * (rx_ring->ring_size + 1));
    rx_ring->rx_buffer_info = NULL;

    deallocate(adapter->general, rx_ring->free_rx_ids, sizeof(uint16_t) * rx_ring->ring_size);
    rx_ring->free_rx_ids = NULL;
}

/**
 * ena_setup_all_rx_resources - allocate all queues Rx resources
 * @adapter: network interface device structure
 *
 * Returns 0 on success, otherwise on failure.
 **/
static int ena_setup_all_rx_resources(struct ena_adapter *adapter)
{
    int i, rc = 0;

    for (i = 0; i < adapter->num_io_queues; i++) {
        rc = ena_setup_rx_resources (adapter, i);
        if (rc != 0) {
            device_printf(adapter->pdev, "Allocation for Rx Queue %d failed\n", i);
            goto err_setup_rx;
        }
    }
    return 0;

err_setup_rx:
    /* rewind the index freeing the rings as we go */
    while (i--)
        ena_free_rx_resources (adapter, i);
    return rc;
}

/**
 * ena_free_all_rx_resources - Free Rx resources for all queues
 * @adapter: network interface device structure
 *
 * Free all receive software resources
 **/
static void ena_free_all_rx_resources(struct ena_adapter *adapter)
{
    int i;

    for (i = 0; i < adapter->num_io_queues; i++)
        ena_free_rx_resources(adapter, i);
}

static inline int ena_alloc_rx_mbuf(struct ena_adapter *adapter, struct ena_ring *rx_ring,
                                    struct ena_rx_buffer *rx_info)
{
    struct ena_com_buf *ena_buf;
    int len = rx_ring->rx_mbuf_sz;

    /* if previous allocated frag is not used */
    if (unlikely(rx_info->mbuf != NULL))
        return 0;

    rx_info->mbuf = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
    if (unlikely(rx_info->mbuf == 0)) {
        rx_ring->rx_stats.mjum_alloc_fail++;
        return ENA_COM_NO_MEM;
    }
    ena_buf = &rx_info->ena_buf;
    ena_buf->paddr = physical_from_virtual(rx_info->mbuf->payload);
    ena_buf->len = len;

    ena_trace(NULL, ENA_DBG | ENA_RSC | ENA_RXPTH,
        "ALLOC RX BUF: mbuf %p, rx_info %p, len %d, paddr %p\n",
        rx_info->mbuf, rx_info, ena_buf->len, ena_buf->paddr);

    return 0;
}

static void ena_free_rx_mbuf(struct ena_adapter *adapter, struct ena_ring *rx_ring,
                  struct ena_rx_buffer *rx_info)
{

    if (rx_info->mbuf == NULL) {
        ena_trace (NULL, ENA_WARNING, "Trying to free unallocated buffer\n");
        return;
    }

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
    uint16_t next_to_use, req_id;
    uint32_t i;
    int rc;

    ena_trace(NULL, ENA_DBG | ENA_RXPTH | ENA_RSC, "refill qid: %d\n", rx_ring->qid);

    next_to_use = rx_ring->next_to_use;

    for (i = 0; i < num; i++) {
        struct ena_rx_buffer *rx_info;

        ena_trace(NULL, ENA_DBG | ENA_RXPTH | ENA_RSC,
            "RX buffer - next to use: %d\n", next_to_use);

        req_id = rx_ring->free_rx_ids[next_to_use];
        rx_info = &rx_ring->rx_buffer_info[req_id];
        rc = ena_alloc_rx_mbuf(adapter, rx_ring, rx_info);
        if (unlikely(rc != 0)) {
            ena_trace(NULL, ENA_WARNING, "failed to alloc buffer for rx queue %d\n", rx_ring->qid);
            break;
        }
        rc = ena_com_add_single_rx_desc(rx_ring->ena_com_io_sq, &rx_info->ena_buf, req_id);
        if (unlikely(rc != 0)) {
            ena_trace(NULL, ENA_WARNING, "failed to add buffer for rx queue %d\n", rx_ring->qid);
            break;
        }
        next_to_use = ENA_RX_RING_IDX_NEXT(next_to_use, rx_ring->ring_size);
    }

    if (unlikely(i < num)) {
        rx_ring->rx_stats.refil_partial++;
        ena_trace(NULL, ENA_WARNING,
            "refilled rx qid %d with only %d mbufs (from %d)\n", rx_ring->qid,
            i, num);
    }

    if (likely(i != 0))
        ena_com_write_sq_doorbell(rx_ring->ena_com_io_sq);

    rx_ring->next_to_use = next_to_use;
    return i;
}

static void ena_free_rx_bufs(struct ena_adapter *adapter, unsigned int qid)
{
    struct ena_ring *rx_ring = &adapter->rx_ring[qid];
    unsigned int i;

    for (i = 0; i < rx_ring->ring_size; i++) {
        struct ena_rx_buffer *rx_info = &rx_ring->rx_buffer_info[i];

        if (rx_info->mbuf != NULL)
            ena_free_rx_mbuf(adapter, rx_ring, rx_info);
    }
}

/**
 * ena_refill_all_rx_bufs - allocate all queues Rx buffers
 * @adapter: network interface device structure
 *
 */
static void ena_refill_all_rx_bufs(struct ena_adapter *adapter)
{
    struct ena_ring *rx_ring;
    int i, rc, bufs_num;

    for (i = 0; i < adapter->num_io_queues; i++) {
        rx_ring = &adapter->rx_ring[i];
        bufs_num = rx_ring->ring_size - 1;
        rc = ena_refill_rx_bufs (rx_ring, bufs_num);
        if (unlikely(rc != bufs_num))
            ena_trace(NULL, ENA_WARNING, "refilling Queue %d failed. "
                "Allocated %d buffers from: %d\n", i, rc, bufs_num);
    }
}

static void ena_free_all_rx_bufs(struct ena_adapter *adapter)
{
    int i;

    for (i = 0; i < adapter->num_io_queues; i++)
        ena_free_rx_bufs(adapter, i);
}

/**
 * ena_free_tx_bufs - Free Tx Buffers per Queue
 * @adapter: network interface device structure
 * @qid: queue index
 **/
static void ena_free_tx_bufs(struct ena_adapter *adapter, unsigned int qid)
{
    bool print_once = true;
    struct ena_ring *tx_ring = &adapter->tx_ring[qid];

    ENA_RING_MTX_LOCK(tx_ring);
    for (int i = 0; i < tx_ring->ring_size; i++) {
        struct ena_tx_buffer *tx_info = &tx_ring->tx_buffer_info[i];

        if (tx_info->mbuf == NULL)
            continue;

        if (print_once) {
            device_printf(adapter->pdev, "free uncompleted tx mbuf qid %d idx 0x%x\n",
                qid, i);
            print_once = false;
        } else {
            ena_trace(NULL, ENA_DBG, "free uncompleted tx mbuf qid %d idx 0x%x\n",
                qid, i);
        }

        pbuf_free(tx_info->mbuf);
        tx_info->mbuf = NULL;
    }
    ENA_RING_MTX_UNLOCK(tx_ring);
}

static void ena_free_all_tx_bufs(struct ena_adapter *adapter)
{

    for (int i = 0; i < adapter->num_io_queues; i++)
        ena_free_tx_bufs(adapter, i);
}

static void
ena_destroy_all_tx_queues (struct ena_adapter *adapter)
{
    uint16_t ena_qid;
    int i;

    for (i = 0; i < adapter->num_io_queues; i++) {
        ena_qid = ENA_IO_TXQ_IDX (i);
        ena_com_destroy_io_queue(adapter->ena_dev, ena_qid);
    }
}

static void ena_destroy_all_rx_queues(struct ena_adapter *adapter)
{
    uint16_t ena_qid;
    int i;

    for (i = 0; i < adapter->num_io_queues; i++) {
        ena_qid = ENA_IO_RXQ_IDX(i);
        ena_com_destroy_io_queue(adapter->ena_dev, ena_qid);
    }
}

static void ena_destroy_all_io_queues(struct ena_adapter *adapter)
{
    ena_destroy_all_tx_queues(adapter);
    ena_destroy_all_rx_queues(adapter);
}

define_closure_function(1, 0, void, ena_cleanup_task,
                        struct ena_que *, que)
{
    ena_cleanup(bound(que), 1);
}

static int ena_create_io_queues(struct ena_adapter *adapter)
{
    struct ena_com_dev *ena_dev = adapter->ena_dev;
    struct ena_com_create_io_ctx ctx;
    struct ena_ring *ring;
    struct ena_que *queue;
    uint16_t ena_qid;
    uint32_t msix_vector;
    int rc, i;

    /* Create TX queues */
    for (i = 0; i < adapter->num_io_queues; i++) {
        msix_vector = ENA_IO_IRQ_IDX(i);
        ena_qid = ENA_IO_TXQ_IDX(i);
        ctx.mem_queue_type = ena_dev->tx_mem_queue_type;
        ctx.direction = ENA_COM_IO_QUEUE_DIRECTION_TX;
        ctx.queue_size = adapter->requested_tx_ring_size;
        ctx.msix_vector = msix_vector;
        ctx.qid = ena_qid;
        rc = ena_com_create_io_queue(ena_dev, &ctx);
        if (rc != 0) {
            device_printf(adapter->pdev, "Failed to create io TX queue #%d rc: %d\n", i, rc);
            goto err_tx;
        }
        ring = &adapter->tx_ring[i];
        rc = ena_com_get_io_handlers(ena_dev, ena_qid, &ring->ena_com_io_sq, &ring->ena_com_io_cq);
        if (rc != 0) {
            device_printf(adapter->pdev, "Failed to get TX queue handlers. TX queue num"
                    " %d rc: %d\n", i, rc);
            ena_com_destroy_io_queue(ena_dev, ena_qid);
            goto err_tx;
        }
    }

    /* Create RX queues */
    for (i = 0; i < adapter->num_io_queues; i++) {
        msix_vector = ENA_IO_IRQ_IDX(i);
        ena_qid = ENA_IO_RXQ_IDX(i);
        ctx.mem_queue_type = ENA_ADMIN_PLACEMENT_POLICY_HOST;
        ctx.direction = ENA_COM_IO_QUEUE_DIRECTION_RX;
        ctx.queue_size = adapter->requested_rx_ring_size;
        ctx.msix_vector = msix_vector;
        ctx.qid = ena_qid;
        rc = ena_com_create_io_queue(ena_dev, &ctx);
        if (unlikely(rc != 0)) {
            device_printf(adapter->pdev, "Failed to create io RX queue[%d] rc: %d\n", i, rc);
            goto err_rx;
        }

        ring = &adapter->rx_ring[i];
        rc = ena_com_get_io_handlers(ena_dev, ena_qid, &ring->ena_com_io_sq, &ring->ena_com_io_cq);
        if (unlikely (rc != 0)) {
            device_printf(adapter->pdev, "Failed to get RX queue handlers. RX queue num"
                    " %d rc: %d\n", i, rc);
            ena_com_destroy_io_queue(ena_dev, ena_qid);
            goto err_rx;
        }
    }

    for (i = 0; i < adapter->num_io_queues; i++) {
        queue = &adapter->que[i];
        init_closure(&queue->cleanup_task, ena_cleanup_task, queue);
    }

    return 0;

err_rx:
    while (i--)
        ena_com_destroy_io_queue(ena_dev, ENA_IO_RXQ_IDX (i));
    i = adapter->num_io_queues;
err_tx:
    while (i--)
        ena_com_destroy_io_queue(ena_dev, ENA_IO_TXQ_IDX (i));

    return ENA_COM_EIO;
}

/*********************************************************************
 *
 *  MSIX & Interrupt Service routine
 *
 **********************************************************************/

define_closure_function(1, 0, void, ena_irq_handler,
                        struct ena_irq *, irq)
{
    struct ena_irq *irq = bound(irq);
    irq->handler(irq->data);
}

/**
 * ena_intr_msix_mgmnt - MSIX Interrupt Handler for admin/async queue
 * @arg: network adapter
 **/
static void ena_intr_msix_mgmnt(void *arg)
{
    struct ena_adapter *adapter = (struct ena_adapter *)arg;

    ena_com_admin_q_comp_intr_handler(adapter->ena_dev);
    if (likely(ENA_FLAG_ISSET(ENA_FLAG_DEVICE_RUNNING, adapter)))
        ena_com_aenq_intr_handler(adapter->ena_dev, arg);
}

/**
 * ena_handle_msix - MSIX Interrupt Handler for Tx/Rx
 * @arg: queue
 **/
static void ena_handle_msix(void *arg)
{
    struct ena_que *queue = arg;
    struct ena_adapter *adapter = queue->adapter;
    struct netif *netif = &adapter->ifp;

    if (likely(netif_is_flag_set(netif, NETIF_FLAG_UP)))
        enqueue(runqueue, &queue->cleanup_task);
}

static int ena_enable_msix(struct ena_adapter *adapter)
{
    pci_dev dev = adapter->pdev;
    int msix_vecs, msix_avail;

    if (ENA_FLAG_ISSET(ENA_FLAG_MSIX_ENABLED, adapter)) {
        device_printf(dev, "Error, MSI-X is already enabled\n");
        return ENA_COM_INVAL;
    }

    /* Reserved the max msix vectors we might need */
    msix_vecs = ENA_MAX_MSIX_VEC(adapter->max_num_io_queues);

    ena_trace(NULL, ENA_DBG, "trying to enable MSI-X, vectors: %d\n", msix_vecs);

    msix_avail = pci_enable_msix(dev);
    if (msix_avail < msix_vecs) {
        if (msix_avail == ENA_ADMIN_MSIX_VEC) {
            device_printf(dev, "Not enough number of MSI-x allocated: %d\n", msix_avail);
            return ENA_COM_NO_SPACE;
        }
        device_printf(dev, "Enable only %d MSI-x (out of %d), reduce the number of queues\n",
                      msix_avail, msix_vecs);
        msix_vecs = msix_avail;
    }

    adapter->msix_vecs = msix_vecs;
    ENA_FLAG_SET_ATOMIC(ENA_FLAG_MSIX_ENABLED, adapter);

    return 0;
}

static void ena_setup_mgmnt_intr(struct ena_adapter *adapter)
{
    struct ena_irq *irq = &adapter->irq_tbl[ENA_MGMNT_IRQ_IDX];

    irq->handler = ena_intr_msix_mgmnt;
    irq->data = adapter;
    irq->vector = ENA_MGMNT_IRQ_IDX;
}

static int ena_setup_io_intr(struct ena_adapter *adapter)
{
    int irq_idx;
    struct ena_irq *irq;

    for (int i = 0; i < adapter->num_io_queues; i++) {
        irq_idx = ENA_IO_IRQ_IDX(i);
        irq = &adapter->irq_tbl[irq_idx];

        irq->handler = ena_handle_msix;
        irq->data = &adapter->que[i];
        irq->vector = irq_idx;
        ena_trace(NULL, ENA_INFO | ENA_IOQ, "ena_setup_io_intr vector: %d\n", irq_idx);
    }

    return 0;
}

static int ena_request_mgmnt_irq(struct ena_adapter *adapter)
{
    struct ena_irq *irq;

    irq = &adapter->irq_tbl[ENA_MGMNT_IRQ_IDX];

    if (pci_setup_msix(adapter->pdev, irq->vector, init_closure(&irq->th, ena_irq_handler, irq),
                       "ena_mgmnt") == INVALID_PHYSICAL)
        return ENA_COM_FAULT;
    return 0;
}

static int ena_request_io_irq(struct ena_adapter *adapter)
{
    struct ena_irq *irq;
    int i;

    if (unlikely(!ENA_FLAG_ISSET (ENA_FLAG_MSIX_ENABLED, adapter))) {
        device_printf(adapter->pdev, "failed to request I/O IRQ: MSI-X is not enabled\n");
        return ENA_COM_INVAL;
    }

    for (i = ENA_IO_IRQ_FIRST_IDX; i < adapter->msix_vecs; i++) {
        irq = &adapter->irq_tbl[i];
        if (pci_setup_msix(adapter->pdev, irq->vector, init_closure(&irq->th, ena_irq_handler, irq),
                           "ena_io") == INVALID_PHYSICAL)
            return ENA_COM_FAULT;
        ena_trace(NULL, ENA_INFO, "queue %d\n", i - ENA_IO_IRQ_FIRST_IDX);
    }

    return 0;
}

static void ena_free_mgmnt_irq(struct ena_adapter *adapter)
{
    struct ena_irq *irq;

    irq = &adapter->irq_tbl[ENA_MGMNT_IRQ_IDX];
    ena_trace(NULL, ENA_INFO | ENA_ADMQ, "tear down irq: %d\n", irq->vector);
    pci_teardown_msix(adapter->pdev, irq->vector);
}

static void ena_free_io_irq(struct ena_adapter *adapter)
{
    struct ena_irq *irq;

    for (int i = ENA_IO_IRQ_FIRST_IDX; i < adapter->msix_vecs; i++) {
        irq = &adapter->irq_tbl[i];
        ena_trace(NULL, ENA_INFO | ENA_IOQ, "tear down irq: %d\n", irq->vector);
        pci_teardown_msix(adapter->pdev, irq->vector);
    }
}

static void ena_disable_msix(struct ena_adapter *adapter)
{
    if (ENA_FLAG_ISSET(ENA_FLAG_MSIX_ENABLED, adapter)) {
        ENA_FLAG_CLEAR_ATOMIC(ENA_FLAG_MSIX_ENABLED, adapter);
        pci_disable_msix(adapter->pdev);
    }

    adapter->msix_vecs = 0;
}

static void ena_unmask_all_io_irqs(struct ena_adapter *adapter)
{
    struct ena_com_io_cq *io_cq;
    struct ena_eth_io_intr_reg intr_reg;
    uint16_t ena_qid;
    int i;

    /* Unmask interrupts for all queues */
    for (i = 0; i < adapter->num_io_queues; i++) {
        ena_qid = ENA_IO_TXQ_IDX(i);
        io_cq = &adapter->ena_dev->io_cq_queues[ena_qid];
        ena_com_update_intr_reg(&intr_reg, 0, 0, true);
        ena_com_unmask_intr(io_cq, &intr_reg);
    }
}

static int ena_up_complete(struct ena_adapter *adapter)
{
    int rc;

    rc = ena_change_mtu(adapter, adapter->ifp.mtu);
    if (unlikely(rc != 0))
        return rc;

    ena_refill_all_rx_bufs(adapter);
    ena_reset_counters(&adapter->hw_stats, sizeof(adapter->hw_stats));

    return 0;
}

static void set_io_rings_size(struct ena_adapter *adapter, int new_tx_size,
                              int new_rx_size)
{
    int i;

    for (i = 0; i < adapter->num_io_queues; i++) {
        adapter->tx_ring[i].ring_size = new_tx_size;
        adapter->rx_ring[i].ring_size = new_rx_size;
    }
}

static int create_queues_with_size_backoff(struct ena_adapter *adapter)
{
    int rc;
    uint32_t cur_rx_ring_size, cur_tx_ring_size;
    uint32_t new_rx_ring_size, new_tx_ring_size;

    /*
     * Current queue sizes might be set to smaller than the requested
     * ones due to past queue allocation failures.
     */
    set_io_rings_size(adapter, adapter->requested_tx_ring_size,
        adapter->requested_rx_ring_size);

    while (1) {
        /* Allocate transmit descriptors */
        rc = ena_setup_all_tx_resources(adapter);
        if (unlikely(rc != 0)) {
            ena_trace(NULL, ENA_ALERT, "err_setup_tx\n");
            goto err_setup_tx;
        }

        /* Allocate receive descriptors */
        rc = ena_setup_all_rx_resources(adapter);
        if (unlikely(rc != 0)) {
            ena_trace(NULL, ENA_ALERT, "err_setup_rx\n");
            goto err_setup_rx;
        }

        /* Create IO queues for Rx & Tx */
        rc = ena_create_io_queues(adapter);
        if (unlikely(rc != 0)) {
            ena_trace(NULL, ENA_ALERT, "create IO queues failed\n");
            goto err_io_que;
        }

        return 0;

err_io_que:
    ena_free_all_rx_resources(adapter);
err_setup_rx:
    ena_free_all_tx_resources(adapter);
err_setup_tx:
        /*
         * Lower the ring size if ENOMEM. Otherwise, return the
         * error straightaway.
         */
        if (unlikely(rc != ENA_COM_NO_MEM)) {
            ena_trace(NULL, ENA_ALERT, "Queue creation failed with error code: %d\n", rc);
            return rc;
        }

        cur_tx_ring_size = adapter->tx_ring[0].ring_size;
        cur_rx_ring_size = adapter->rx_ring[0].ring_size;

        device_printf(adapter->pdev,
            "Not enough memory to create queues with sizes TX=%d, RX=%d\n",
            cur_tx_ring_size, cur_rx_ring_size);

        new_tx_ring_size = cur_tx_ring_size;
        new_rx_ring_size = cur_rx_ring_size;

        /*
         * Decrease the size of a larger queue, or decrease both if they are
         * the same size.
         */
        if (cur_rx_ring_size <= cur_tx_ring_size)
            new_tx_ring_size = cur_tx_ring_size / 2;
        if (cur_rx_ring_size >= cur_tx_ring_size)
            new_rx_ring_size = cur_rx_ring_size / 2;

        if (new_tx_ring_size < ENA_MIN_RING_SIZE || new_rx_ring_size < ENA_MIN_RING_SIZE) {
            device_printf(adapter->pdev,
                "Queue creation failed with the smallest possible queue size"
                "of %d for both queues. Not retrying with smaller queues\n",
                ENA_MIN_RING_SIZE);
            return rc;
        }

        set_io_rings_size(adapter, new_tx_ring_size, new_rx_ring_size);
    }
}

/* Check for keep alive expiration */
static void check_for_missing_keep_alive(struct ena_adapter *adapter)
{
    timestamp time;

    if (adapter->wd_active == 0)
        return;

    if (adapter->keep_alive_timeout == ENA_HW_HINTS_NO_TIMEOUT)
        return;

    time = uptime() - adapter->keep_alive_timestamp;
    if (unlikely(time > adapter->keep_alive_timeout)) {
        device_printf(adapter->pdev, "Keep alive watchdog timeout.\n");
        adapter->dev_stats.wd_expired++;
        ena_trigger_reset(adapter, ENA_REGS_RESET_KEEP_ALIVE_TO);
    }
}

/* Check if admin queue is enabled */
static void check_for_admin_com_state(struct ena_adapter *adapter)
{
    if (unlikely(ena_com_get_admin_running_state(adapter->ena_dev) == false)) {
        device_printf(adapter->pdev, "ENA admin queue is not in running state!\n");
        adapter->dev_stats.admin_q_pause++;
        ena_trigger_reset(adapter, ENA_REGS_RESET_ADMIN_TO);
    }
}

static int check_for_rx_interrupt_queue(struct ena_adapter *adapter,
                              struct ena_ring *rx_ring)
{
    if (likely(rx_ring->first_interrupt))
        return 0;

    if (ena_com_cq_empty(rx_ring->ena_com_io_cq))
        return 0;

    rx_ring->no_interrupt_event_cnt++;

    if (rx_ring->no_interrupt_event_cnt == ENA_MAX_NO_INTERRUPT_ITERATIONS) {
        device_printf(adapter->pdev, "Potential MSIX issue on Rx side "
            "Queue = %d. Reset the device\n", rx_ring->qid);
        ena_trigger_reset(adapter, ENA_REGS_RESET_MISS_INTERRUPT);
        return ENA_COM_EIO;
    }

    return 0;
}

static int check_missing_comp_in_tx_queue(struct ena_adapter *adapter,
                                struct ena_ring *tx_ring)
{
    timestamp curtime;
    struct ena_tx_buffer *tx_buf;
    timestamp time_offset;
    uint32_t missed_tx = 0;
    int i, rc = 0;

    curtime = uptime();

    for (i = 0; i < tx_ring->ring_size; i++) {
        tx_buf = &tx_ring->tx_buffer_info[i];

        if (tx_buf->timestamp == 0)
            continue;

        time_offset = curtime - tx_buf->timestamp;

        if (unlikely(!tx_ring->first_interrupt && time_offset > 2 * adapter->missing_tx_timeout)) {
            /*
             * If after graceful period interrupt is still not
             * received, we schedule a reset.
             */
            device_printf(adapter->pdev, "Potential MSIX issue on Tx side Queue = %d. "
                    "Reset the device\n", tx_ring->qid);
            ena_trigger_reset(adapter, ENA_REGS_RESET_MISS_INTERRUPT);
            return ENA_COM_EIO;
        }

        /* Check again if packet is still waiting */
        if (unlikely(time_offset > adapter->missing_tx_timeout)) {

            if (!tx_buf->print_once)
                ena_trace(NULL, ENA_WARNING, "Found a Tx that wasn't "
                    "completed on time, qid %d, index %d.\n", tx_ring->qid, i);

            tx_buf->print_once = true;
            missed_tx++;
        }
    }

    if (unlikely(missed_tx > adapter->missing_tx_threshold)) {
        device_printf(adapter->pdev,
            "The number of lost tx completion is above the threshold "
                "(%d > %d). Reset the device\n", missed_tx,
            adapter->missing_tx_threshold);
        ena_trigger_reset(adapter, ENA_REGS_RESET_MISS_TX_CMPL);
        rc = ENA_COM_EIO;
    }

    tx_ring->tx_stats.missing_tx_comp += missed_tx;

    return rc;
}

/*
 * Check for TX which were not completed on time.
 * Timeout is defined by "missing_tx_timeout".
 * Reset will be performed if number of incompleted
 * transactions exceeds "missing_tx_threshold".
 */
static void check_for_missing_completions(struct ena_adapter *adapter)
{
    struct ena_ring *tx_ring;
    struct ena_ring *rx_ring;
    int i, budget, rc;

    /* Make sure the driver doesn't turn the device in other process */
    read_barrier();

    if (!ENA_FLAG_ISSET(ENA_FLAG_DEV_UP, adapter))
        return;

    if (ENA_FLAG_ISSET(ENA_FLAG_TRIGGER_RESET, adapter))
        return;

    if (adapter->missing_tx_timeout == ENA_HW_HINTS_NO_TIMEOUT)
        return;

    budget = adapter->missing_tx_max_queues;

    for (i = adapter->next_monitored_tx_qid; i < adapter->num_io_queues; i++) {
        tx_ring = &adapter->tx_ring[i];
        rx_ring = &adapter->rx_ring[i];

        rc = check_missing_comp_in_tx_queue(adapter, tx_ring);
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

    adapter->next_monitored_tx_qid = i % adapter->num_io_queues;
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
    struct ena_ring *rx_ring;
    int i, refill_required;

    if (!ENA_FLAG_ISSET(ENA_FLAG_DEV_UP, adapter))
        return;

    if (ENA_FLAG_ISSET(ENA_FLAG_TRIGGER_RESET, adapter))
        return;

    for (i = 0; i < adapter->num_io_queues; i++) {
        rx_ring = &adapter->rx_ring[i];

        refill_required = ena_com_free_q_entries(rx_ring->ena_com_io_sq);
        if (unlikely(refill_required == (rx_ring->ring_size - 1))) {
            rx_ring->empty_rx_queue++;

            if (rx_ring->empty_rx_queue >= EMPTY_RX_REFILL) {
                rx_ring->rx_stats.empty_rx_ring++;

                device_printf(adapter->pdev, "trigger refill for ring %d\n", i);

                enqueue_irqsafe(runqueue, &rx_ring->que->cleanup_task);
                rx_ring->empty_rx_queue = 0;
            }
        }
        else {
            rx_ring->empty_rx_queue = 0;
        }
    }
}

define_closure_function(1, 1, void, ena_timer_task,
                       struct ena_adapter *, adapter,
                       u64, overruns)
{
    struct ena_adapter *adapter = bound(adapter);

    check_for_missing_keep_alive(adapter);

    check_for_admin_com_state(adapter);

    check_for_missing_completions(adapter);

    check_for_empty_rx_ring(adapter);

    if (unlikely(ENA_FLAG_ISSET (ENA_FLAG_TRIGGER_RESET, adapter))) {
        device_printf(adapter->pdev, "Trigger reset is on\n");
        enqueue_irqsafe(runqueue, &adapter->reset_task);
    }
}

int ena_up(struct ena_adapter *adapter)
{
    int rc = 0;

    if (ENA_FLAG_ISSET(ENA_FLAG_DEV_UP, adapter))
        return 0;

    ena_trace(NULL, ENA_INFO, "device is going UP\n");

    /* setup interrupts for IO queues */
    rc = ena_setup_io_intr(adapter);
    if (unlikely(rc != 0)) {
        ena_trace(NULL, ENA_ALERT, "error setting up IO interrupt\n");
        goto error;
    }
    rc = ena_request_io_irq(adapter);
    if (unlikely(rc != 0)) {
        ena_trace(NULL, ENA_ALERT, "err_req_irq\n");
        goto error;
    }

    ena_trace(NULL, ENA_INFO,
        "Creating %d IO queues. Rx queue size: %d, Tx queue size: %d, LLQ is %s\n",
        adapter->num_io_queues,
        adapter->requested_rx_ring_size,
        adapter->requested_tx_ring_size,
        (adapter->ena_dev->tx_mem_queue_type == ENA_ADMIN_PLACEMENT_POLICY_DEV) ?
                "ENABLED" : "DISABLED");

    rc = create_queues_with_size_backoff(adapter);
    if (unlikely(rc != 0)) {
        ena_trace(NULL, ENA_ALERT, "error creating queues with size backoff\n");
        goto err_create_queues_with_backoff;
    }

    if (ENA_FLAG_ISSET(ENA_FLAG_LINK_UP, adapter))
        netif_set_link_up(&adapter->ifp);

    rc = ena_up_complete(adapter);
    if (unlikely(rc != 0))
        goto err_up_complete;

    adapter->dev_stats.interface_up++;

    netif_set_flags(&adapter->ifp, NETIF_FLAG_UP);

    /* Activate timer service only if the device is running.
     * If this flag is not set, it means that the driver is being
     * reset and timer service will be activated afterwards.
     */
    if (ENA_FLAG_ISSET (ENA_FLAG_DEVICE_RUNNING, adapter))
        adapter->timer_service = register_timer(runloop_timers,
            CLOCK_ID_MONOTONIC, seconds(1), false, seconds(1),
            init_closure(&adapter->timer_task, ena_timer_task, adapter));

    ENA_FLAG_SET_ATOMIC(ENA_FLAG_DEV_UP, adapter);

    ena_unmask_all_io_irqs(adapter);

    return 0;

err_up_complete:
    ena_destroy_all_io_queues(adapter);
    ena_free_all_rx_resources(adapter);
    ena_free_all_tx_resources(adapter);
err_create_queues_with_backoff:
    ena_free_io_irq(adapter);
error:
    return rc;
}

static err_t ena_init(struct netif *netif)
{
    struct ena_adapter *adapter = netif->state;

    netif = &adapter->ifp;
    netif->hostname = "uniboot";
    netif->name[0] = 'e';
    netif->name[1] = 'n';
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP;
    netif->output = etharp_output;
    netif->linkoutput = ena_linkoutput;
    netif->hwaddr_len = ETHARP_HWADDR_LEN;
    netif->mtu = sizeof(struct ip_hdr) + sizeof(struct tcp_hdr) + TCP_MSS;
    return ERR_OK;
}

static int ena_setup_ifnet(struct ena_adapter *adapter,
                           struct ena_com_dev_get_features_ctx *feat)
{
    runtime_memcpy(adapter->ifp.hwaddr, feat->dev_attr.mac_addr, ETHARP_HWADDR_LEN);
    netif_add(&adapter->ifp, 0, 0, 0, adapter, ena_init, ethernet_input);

    return 0;
}

void ena_down(struct ena_adapter *adapter)
{
    int rc;

    if (!ENA_FLAG_ISSET(ENA_FLAG_DEV_UP, adapter))
        return;

    ena_trace(NULL, ENA_INFO, "device is going DOWN\n");

    remove_timer(adapter->timer_service, 0);

    ENA_FLAG_CLEAR_ATOMIC(ENA_FLAG_DEV_UP, adapter);
    netif_clear_flags(&adapter->ifp, NETIF_FLAG_UP);

    ena_free_io_irq(adapter);

    if (ENA_FLAG_ISSET(ENA_FLAG_TRIGGER_RESET, adapter)) {
        rc = ena_com_dev_reset(adapter->ena_dev, adapter->reset_reason);
        if (unlikely(rc != 0))
            device_printf(adapter->pdev, "Device reset failed\n");
    }

    ena_destroy_all_io_queues(adapter);

    ena_free_all_tx_bufs(adapter);
    ena_free_all_rx_bufs(adapter);
    ena_free_all_tx_resources(adapter);
    ena_free_all_rx_resources(adapter);

    adapter->dev_stats.interface_down++;
}

static uint32_t ena_calc_max_io_queue_num(struct ena_adapter *adapter,
    struct ena_com_dev_get_features_ctx *get_feat_ctx)
{
    struct ena_com_dev *ena_dev = adapter->ena_dev;
    uint32_t io_tx_sq_num, io_tx_cq_num, io_rx_num, max_num_io_queues;

    /* Regular queues capabilities */
    if (ena_dev->supported_features & BIT (ENA_ADMIN_MAX_QUEUES_EXT)) {
        struct ena_admin_queue_ext_feature_fields *max_queue_ext =
                &get_feat_ctx->max_queue_ext.max_queue_ext;
        io_rx_num = MIN(max_queue_ext->max_rx_sq_num,
                max_queue_ext->max_rx_cq_num);

        io_tx_sq_num = max_queue_ext->max_tx_sq_num;
        io_tx_cq_num = max_queue_ext->max_tx_cq_num;
    } else {
        struct ena_admin_queue_feature_desc *max_queues = &get_feat_ctx->max_queues;
        io_tx_sq_num = max_queues->max_sq_num;
        io_tx_cq_num = max_queues->max_cq_num;
        io_rx_num = MIN(io_tx_sq_num, io_tx_cq_num);
    }

    /* In case of LLQ use the llq fields for the tx SQ/CQ */
    if (ena_dev->tx_mem_queue_type == ENA_ADMIN_PLACEMENT_POLICY_DEV)
        io_tx_sq_num = get_feat_ctx->llq.max_llq_num;

    max_num_io_queues = min_t(uint32_t, total_processors, ENA_MAX_NUM_IO_QUEUES);
    max_num_io_queues = min_t(uint32_t, max_num_io_queues, io_rx_num);
    max_num_io_queues = min_t(uint32_t, max_num_io_queues, io_tx_sq_num);
    max_num_io_queues = min_t(uint32_t, max_num_io_queues, io_tx_cq_num);
    /* 1 IRQ for for mgmnt and 1 IRQ for each TX/RX pair */
    max_num_io_queues = min_t(uint32_t, max_num_io_queues, pci_get_msix_count(adapter->pdev) - 1);

    return max_num_io_queues;
}

static int ena_set_queues_placement_policy(struct ena_adapter *adapter,
    struct ena_admin_feature_llq_desc *llq,
    struct ena_llq_configurations *llq_default_configurations)
{
    struct ena_com_dev *ena_dev = adapter->ena_dev;

    /* LLQ not supported */
    ena_dev->tx_mem_queue_type = ENA_ADMIN_PLACEMENT_POLICY_HOST;
    return 0;
}

static inline void set_default_llq_configurations(struct ena_llq_configurations *llq_config)
{
    llq_config->llq_header_location = ENA_ADMIN_INLINE_HEADER;
    llq_config->llq_ring_entry_size = ENA_ADMIN_LIST_ENTRY_SIZE_128B;
    llq_config->llq_stride_ctrl = ENA_ADMIN_MULTIPLE_DESCS_PER_ENTRY;
    llq_config->llq_num_decs_before_header = ENA_ADMIN_LLQ_NUM_DESCS_BEFORE_HEADER_2;
    llq_config->llq_ring_entry_size_value = 128;
}

static int ena_calc_io_queue_size(struct ena_calc_queue_size_ctx *ctx)
{
    struct ena_admin_feature_llq_desc *llq = &ctx->get_feat_ctx->llq;
    struct ena_com_dev *ena_dev = ctx->ena_dev;
    uint32_t tx_queue_size = ENA_DEFAULT_RING_SIZE;
    uint32_t rx_queue_size = ENA_DEFAULT_RING_SIZE;
    uint32_t max_tx_queue_size;
    uint32_t max_rx_queue_size;

    if (ena_dev->supported_features & BIT (ENA_ADMIN_MAX_QUEUES_EXT)) {
        struct ena_admin_queue_ext_feature_fields *max_queue_ext =
                &ctx->get_feat_ctx->max_queue_ext.max_queue_ext;
        max_rx_queue_size = min_t(uint32_t, max_queue_ext->max_rx_cq_depth,
            max_queue_ext->max_rx_sq_depth);
        max_tx_queue_size = max_queue_ext->max_tx_cq_depth;

        if (ena_dev->tx_mem_queue_type == ENA_ADMIN_PLACEMENT_POLICY_DEV)
            max_tx_queue_size = min_t(uint32_t, max_tx_queue_size, llq->max_llq_depth);
        else
            max_tx_queue_size = min_t(uint32_t, max_tx_queue_size, max_queue_ext->max_tx_sq_depth);

        ctx->max_tx_sgl_size = min_t(uint16_t, ENA_PKT_MAX_BUFS,
            max_queue_ext->max_per_packet_tx_descs);
        ctx->max_rx_sgl_size = min_t(uint16_t, ENA_PKT_MAX_BUFS,
            max_queue_ext->max_per_packet_rx_descs);
    } else {
        struct ena_admin_queue_feature_desc *max_queues = &ctx->get_feat_ctx->max_queues;
        max_rx_queue_size = min_t(uint32_t, max_queues->max_cq_depth, max_queues->max_sq_depth);
        max_tx_queue_size = max_queues->max_cq_depth;

        if (ena_dev->tx_mem_queue_type == ENA_ADMIN_PLACEMENT_POLICY_DEV)
            max_tx_queue_size = min_t(uint32_t, max_tx_queue_size, llq->max_llq_depth);
        else
            max_tx_queue_size = min_t(uint32_t, max_tx_queue_size, max_queues->max_sq_depth);

        ctx->max_tx_sgl_size = min_t(uint16_t, ENA_PKT_MAX_BUFS, max_queues->max_packet_tx_descs);
        ctx->max_rx_sgl_size = min_t(uint16_t, ENA_PKT_MAX_BUFS, max_queues->max_packet_rx_descs);
    }

    /* round down to the nearest power of 2 */
    max_tx_queue_size = 1 << msb(max_tx_queue_size);
    max_rx_queue_size = 1 << msb(max_rx_queue_size);

    tx_queue_size = clamp_val(tx_queue_size, ENA_MIN_RING_SIZE, max_tx_queue_size);
    rx_queue_size = clamp_val(rx_queue_size, ENA_MIN_RING_SIZE, max_rx_queue_size);

    tx_queue_size = 1 << msb(tx_queue_size);
    rx_queue_size = 1 << msb(rx_queue_size);

    ctx->max_tx_queue_size = max_tx_queue_size;
    ctx->max_rx_queue_size = max_rx_queue_size;
    ctx->tx_queue_size = tx_queue_size;
    ctx->rx_queue_size = rx_queue_size;

    return 0;
}

static void ena_config_host_info(struct ena_adapter *adapter)
{
    struct ena_com_dev *ena_dev = adapter->ena_dev;
    struct ena_admin_host_info *host_info;
    int rc;

    /* Allocate only the host info */
    rc = ena_com_allocate_host_info(ena_dev);
    if (unlikely(rc != 0)) {
        ena_trace(NULL, ENA_ALERT, "Cannot allocate host info\n");
        return;
    }

    host_info = ena_dev->host_attr.host_info;

    host_info->bdf = (adapter->pdev->bus << 8) | (adapter->pdev->slot << 3) |
            adapter->pdev->function;
    host_info->os_type = ENA_ADMIN_OS_LINUX;
    host_info->kernel_ver = 0;

    host_info->kernel_ver_str[0] = '\0';
    host_info->os_dist = 0;
    host_info->os_dist_str[0] = '\0';

    host_info->driver_version = (DRV_MODULE_VER_MAJOR) |
            (DRV_MODULE_VER_MINOR << ENA_ADMIN_HOST_INFO_MINOR_SHIFT) |
            (DRV_MODULE_VER_SUBMINOR << ENA_ADMIN_HOST_INFO_SUB_MINOR_SHIFT);
    host_info->num_cpus = total_processors;
    host_info->driver_supported_features = ENA_ADMIN_HOST_INFO_RX_OFFSET_MASK;

    rc = ena_com_set_host_attributes(ena_dev);
    if (unlikely(rc != 0)) {
        if (rc == ENA_COM_UNSUPPORTED)
            ena_trace(NULL, ENA_WARNING, "Cannot set host attributes\n");
        else
            ena_trace(NULL, ENA_ALERT, "Cannot set host attributes\n");

        goto err;
    }

    return;

err:
    ena_com_delete_host_info(ena_dev);
}

static int ena_device_init(struct ena_adapter *adapter,
                           struct ena_com_dev_get_features_ctx *get_feat_ctx,
                           int *wd_active)
{
    struct ena_com_dev *ena_dev = adapter->ena_dev;
    pci_dev pdev = adapter->pdev;
    bool readless_supported;
    uint32_t aenq_groups;
    int rc;

    rc = ena_com_mmio_reg_read_request_init(ena_dev);
    if (unlikely(rc != 0)) {
        device_printf(pdev, "failed to init mmio read less\n");
        return rc;
    }

    /*
     * The PCIe configuration space revision id indicate if mmio reg
     * read is disabled
     */
    readless_supported = !(pci_get_revid(adapter->pdev) & ENA_MMIO_DISABLE_REG_READ);
    ena_com_set_mmio_read_mode(ena_dev, readless_supported);

    rc = ena_com_dev_reset(ena_dev, ENA_REGS_RESET_NORMAL);
    if (unlikely(rc != 0)) {
        device_printf(pdev, "Can not reset device\n");
        goto err_mmio_read_less;
    }

    rc = ena_com_validate_version(ena_dev);
    if (unlikely(rc != 0)) {
        device_printf(pdev, "device version is too low\n");
        goto err_mmio_read_less;
    }

    int dma_width = ena_com_get_dma_width(ena_dev);
    if (dma_width < 0) {
        device_printf(pdev, "Invalid dma width value %d", dma_width);
        rc = dma_width;
        goto err_mmio_read_less;
    }

    /* ENA admin level init */
    rc = ena_com_admin_init(ena_dev, &aenq_handlers);
    if (unlikely(rc != 0)) {
        device_printf(pdev, "Can not initialize ena admin queue with device\n");
        goto err_mmio_read_less;
    }

    /*
     * To enable the msix interrupts the driver needs to know the number
     * of queues. So the driver uses polling mode to retrieve this
     * information
     */
    ena_com_set_admin_polling_mode(ena_dev, true);

    ena_config_host_info(adapter);

    /* Get Device Attributes */
    rc = ena_com_get_dev_attr_feat(ena_dev, get_feat_ctx);
    if (unlikely(rc != 0)) {
        device_printf(pdev, "Cannot get attribute for ena device rc: %d\n", rc);
        goto err_admin_init;
    }

    aenq_groups = BIT (ENA_ADMIN_LINK_CHANGE) | BIT (ENA_ADMIN_FATAL_ERROR) |
            BIT (ENA_ADMIN_WARNING) | BIT (ENA_ADMIN_NOTIFICATION) | BIT (ENA_ADMIN_KEEP_ALIVE);

    aenq_groups &= get_feat_ctx->aenq.supported_groups;
    rc = ena_com_set_aenq_config(ena_dev, aenq_groups);
    if (unlikely(rc != 0)) {
        device_printf(pdev, "Cannot configure aenq groups rc: %d\n", rc);
        goto err_admin_init;
    }

    *wd_active = !!(aenq_groups & BIT (ENA_ADMIN_KEEP_ALIVE));

    return 0;

err_admin_init:
    ena_com_delete_host_info(ena_dev);
    ena_com_admin_destroy(ena_dev);
err_mmio_read_less:
    ena_com_mmio_reg_read_request_destroy(ena_dev);

    return rc;
}

static int ena_enable_msix_and_set_admin_interrupts(struct ena_adapter *adapter)
{
    struct ena_com_dev *ena_dev = adapter->ena_dev;
    int rc;

    rc = ena_enable_msix(adapter);
    if (unlikely(rc != 0)) {
        device_printf(adapter->pdev, "Error with MSI-X enablement\n");
        return rc;
    }

    ena_setup_mgmnt_intr(adapter);

    rc = ena_request_mgmnt_irq(adapter);
    if (unlikely(rc != 0)) {
        device_printf(adapter->pdev, "Cannot setup mgmnt queue intr\n");
        goto err_disable_msix;
    }

    ena_com_set_admin_polling_mode(ena_dev, false);

    ena_com_admin_aenq_enable(ena_dev);

    return 0;

err_disable_msix:
    ena_disable_msix(adapter);

    return rc;
}

/* Function called on ENA_ADMIN_KEEP_ALIVE event */
static void ena_keep_alive_wd(void *adapter_data, struct ena_admin_aenq_entry *aenq_e)
{
    struct ena_adapter *adapter = (struct ena_adapter *)adapter_data;
    struct ena_admin_aenq_keep_alive_desc *desc;

    desc = (struct ena_admin_aenq_keep_alive_desc *)aenq_e;

    adapter->hw_stats.rx_drops = ((uint64_t) desc->rx_drops_high << 32) | desc->rx_drops_low;
    adapter->hw_stats.tx_drops = ((uint64_t) desc->tx_drops_high << 32) | desc->tx_drops_low;

    adapter->keep_alive_timestamp = uptime();
}

static void ena_update_hints(struct ena_adapter *adapter,
                             struct ena_admin_ena_hw_hints *hints)
{
    struct ena_com_dev *ena_dev = adapter->ena_dev;

    if (hints->admin_completion_tx_timeout)
        ena_dev->admin_queue.completion_timeout = hints->admin_completion_tx_timeout * 1000;

    if (hints->mmio_read_timeout)
        /* convert to usec */
        ena_dev->mmio_read.reg_read_to = hints->mmio_read_timeout * 1000;

    if (hints->missed_tx_completion_count_threshold_to_reset)
        adapter->missing_tx_threshold = hints->missed_tx_completion_count_threshold_to_reset;

    if (hints->missing_tx_completion_timeout) {
        if (hints->missing_tx_completion_timeout == ENA_HW_HINTS_NO_TIMEOUT)
            adapter->missing_tx_timeout = ENA_HW_HINTS_NO_TIMEOUT;
        else
            adapter->missing_tx_timeout = milliseconds(1) * hints->missing_tx_completion_timeout;
    }

    if (hints->driver_watchdog_timeout) {
        if (hints->driver_watchdog_timeout == ENA_HW_HINTS_NO_TIMEOUT)
            adapter->keep_alive_timeout = ENA_HW_HINTS_NO_TIMEOUT;
        else
            adapter->keep_alive_timeout = milliseconds(1) * hints->driver_watchdog_timeout;
    }
}

void ena_destroy_device(struct ena_adapter *adapter, bool graceful)
{
    struct netif *ifp = &adapter->ifp;
    struct ena_com_dev *ena_dev = adapter->ena_dev;
    bool dev_up;

    if (!ENA_FLAG_ISSET(ENA_FLAG_DEVICE_RUNNING, adapter))
        return;

    netif_set_link_down(ifp);

    dev_up = ENA_FLAG_ISSET(ENA_FLAG_DEV_UP, adapter);
    if (dev_up)
        ENA_FLAG_SET_ATOMIC(ENA_FLAG_DEV_UP_BEFORE_RESET, adapter);

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

    /*
     * IO rings resources should be freed because `ena_restore_device()`
     * calls (not directly) `ena_enable_msix()`, which re-allocates MSIX
     * vectors. The amount of MSIX vectors after destroy-restore may be
     * different than before. Therefore, IO rings resources should be
     * established from scratch each time.
     */
    ena_free_all_io_rings_resources(adapter);

    ena_com_abort_admin_commands(ena_dev);

    ena_com_wait_for_abort_completion(ena_dev);

    ena_com_admin_destroy(ena_dev);

    ena_com_mmio_reg_read_request_destroy(ena_dev);

    adapter->reset_reason = ENA_REGS_RESET_NORMAL;

    ENA_FLAG_CLEAR_ATOMIC(ENA_FLAG_TRIGGER_RESET, adapter);
    ENA_FLAG_CLEAR_ATOMIC(ENA_FLAG_DEVICE_RUNNING, adapter);
}

static int ena_device_validate_params(struct ena_adapter *adapter,
                                      struct ena_com_dev_get_features_ctx *get_feat_ctx)
{
    if (get_feat_ctx->dev_attr.max_mtu < adapter->ifp.mtu) {
        device_printf(adapter->pdev, "Error, device max mtu is smaller than ifp MTU\n");
        return ENA_COM_INVAL;
    }

    return 0;
}

int ena_restore_device(struct ena_adapter *adapter)
{
    struct ena_com_dev_get_features_ctx get_feat_ctx;
    struct ena_com_dev *ena_dev = adapter->ena_dev;
    struct netif *ifp = &adapter->ifp;
    int wd_active;
    int rc;

    ENA_FLAG_SET_ATOMIC(ENA_FLAG_ONGOING_RESET, adapter);

    rc = ena_device_init(adapter, &get_feat_ctx, &wd_active);
    if (rc != 0) {
        device_printf(adapter->pdev, "Cannot initialize device\n");
        goto err;
    }
    /*
     * Only enable WD if it was enabled before reset, so it won't override
     * value set by the user by the sysctl.
     */
    if (adapter->wd_active != 0)
        adapter->wd_active = wd_active;

    rc = ena_device_validate_params(adapter, &get_feat_ctx);
    if (rc != 0) {
        device_printf(adapter->pdev, "Validation of device parameters failed\n");
        goto err_device_destroy;
    }

    ENA_FLAG_CLEAR_ATOMIC(ENA_FLAG_ONGOING_RESET, adapter);
    /* Make sure we don't have a race with AENQ Links state handler */
    if (ENA_FLAG_ISSET(ENA_FLAG_LINK_UP, adapter))
        netif_set_link_up(ifp);

    rc = ena_enable_msix_and_set_admin_interrupts(adapter);
    if (rc != 0) {
        device_printf(adapter->pdev, "Enable MSI-X failed\n");
        goto err_device_destroy;
    }

    /*
     * Effective value of used MSIX vectors should be the same as before
     * `ena_destroy_device()`, if possible, or closest to it if less vectors
     * are available.
     */
    if ((adapter->msix_vecs - ENA_ADMIN_MSIX_VEC) < adapter->num_io_queues)
        adapter->num_io_queues = adapter->msix_vecs - ENA_ADMIN_MSIX_VEC;

    /* Re-initialize rings basic information */
    ena_init_io_rings(adapter);

    /* If the interface was up before the reset bring it up */
    if (ENA_FLAG_ISSET(ENA_FLAG_DEV_UP_BEFORE_RESET, adapter)) {
        rc = ena_up(adapter);
        if (rc != 0) {
            device_printf(adapter->pdev, "Failed to create I/O queues\n");
            goto err_disable_msix;
        }
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
            seconds(1), false, seconds(1), (timer_handler)&adapter->timer_task);
    }
    ENA_FLAG_CLEAR_ATOMIC(ENA_FLAG_DEV_UP_BEFORE_RESET, adapter);

    device_printf(adapter->pdev, "Device reset completed successfully, Driver info: %s\n",
        ena_version);

    return rc;

err_disable_msix:
    ena_free_mgmnt_irq(adapter);
    ena_disable_msix(adapter);
err_device_destroy:
    ena_com_abort_admin_commands(ena_dev);
    ena_com_wait_for_abort_completion(ena_dev);
    ena_com_admin_destroy(ena_dev);
    ena_com_dev_reset(ena_dev, ENA_REGS_RESET_DRIVER_INVALID_STATE);
    ena_com_mmio_reg_read_request_destroy(ena_dev);
err:
    ENA_FLAG_CLEAR_ATOMIC(ENA_FLAG_DEVICE_RUNNING, adapter);
    ENA_FLAG_CLEAR_ATOMIC(ENA_FLAG_ONGOING_RESET, adapter);
    device_printf(adapter->pdev, "Reset attempt failed. Can not reset the device\n");

    return rc;
}

define_closure_function(1, 0, void, ena_reset_task,
                        struct ena_adapter *, adapter)
{
    struct ena_adapter *adapter = bound(adapter);

    if (unlikely(!ENA_FLAG_ISSET(ENA_FLAG_TRIGGER_RESET, adapter))) {
        device_printf(adapter->pdev, "device reset scheduled but trigger_reset is off\n");
        return;
    }

    ENA_LOCK_LOCK(adapter);
    ena_destroy_device(adapter, false);
    ena_restore_device(adapter);
    ENA_LOCK_UNLOCK(adapter);
}

/**
 * ena_attach - Device Initialization Routine
 *
 * ena_attach initializes an adapter identified by a device structure.
 * The OS initialization, configuring of the adapter private structure,
 * and a hardware reset occur.
 **/
static boolean ena_attach(heap general, heap page_allocator, pci_dev d)
{
    struct ena_com_dev_get_features_ctx get_feat_ctx;
    struct ena_llq_configurations llq_config;
    struct ena_calc_queue_size_ctx calc_queue_ctx = { 0 };
    static int version_printed;
    struct ena_adapter *adapter;
    struct ena_com_dev *ena_dev = NULL;
    uint32_t max_num_io_queues;
    int rc;

    adapter = allocate(general, sizeof(struct ena_adapter));
    if (adapter == INVALID_ADDRESS)
        return false;
    adapter->general = general;
    adapter->contiguous = page_allocator;
    adapter->pdev = d;

    ENA_LOCK_INIT(adapter);

    /*
     * Set up the timer service - driver is responsible for avoiding
     * concurrency, as the callout won't be using any locking inside.
     */
    adapter->keep_alive_timeout = DEFAULT_KEEP_ALIVE_TO;
    adapter->missing_tx_timeout = DEFAULT_TX_CMP_TO;
    adapter->missing_tx_max_queues = DEFAULT_TX_MONITORED_QUEUES;
    adapter->missing_tx_threshold = DEFAULT_TX_CMP_THRESHOLD;

    if (version_printed++ == 0)
        ena_trace(NULL, ENA_INFO, "%s\n", ena_version);

    /* Allocate memory for ena_dev structure */
    ena_dev = allocate_zero(general, sizeof(struct ena_com_dev));
    if (ena_dev == INVALID_ADDRESS)
        goto err_adapter_free;

    adapter->ena_dev = ena_dev;
    ena_dev->dmadev = adapter;

    pci_bar_init(adapter->pdev, &adapter->registers, ENA_REG_BAR, 0, -1);

    ena_dev->bus = allocate(general, sizeof(struct ena_bus));
    if (ena_dev->bus == INVALID_ADDRESS)
        goto err_dev_free;

    /* Store register resources */
    ((struct ena_bus *)(ena_dev->bus))->reg_bar = &adapter->registers;

    ena_dev->tx_mem_queue_type = ENA_ADMIN_PLACEMENT_POLICY_HOST;

    /* Initially clear all the flags */
    ENA_FLAG_ZERO(adapter);

    /* Device initialization */
    rc = ena_device_init(adapter, &get_feat_ctx, &adapter->wd_active);
    if (unlikely(rc != 0)) {
        device_printf(d, "ENA device init failed! (err: %d)\n", rc);
        rc = ENA_COM_EIO;
        goto err_bus_free;
    }

    set_default_llq_configurations(&llq_config);

    rc = ena_set_queues_placement_policy(adapter, &get_feat_ctx.llq, &llq_config);
    if (unlikely (rc != 0)) {
        device_printf (d, "failed to set placement policy\n");
        goto err_com_free;
    }

    adapter->keep_alive_timestamp = uptime();

    calc_queue_ctx.ena_dev = ena_dev;
    calc_queue_ctx.get_feat_ctx = &get_feat_ctx;

    /* Calculate initial and maximum IO queue number and size */
    max_num_io_queues = ena_calc_max_io_queue_num(adapter, &get_feat_ctx);
    rc = ena_calc_io_queue_size(&calc_queue_ctx);
    if (unlikely((rc != 0) || (max_num_io_queues <= 0))) {
        rc = ENA_COM_FAULT;
        goto err_com_free;
    }

    adapter->requested_tx_ring_size = calc_queue_ctx.tx_queue_size;
    adapter->requested_rx_ring_size = calc_queue_ctx.rx_queue_size;
    adapter->max_tx_sgl_size = calc_queue_ctx.max_tx_sgl_size;
    adapter->max_rx_sgl_size = calc_queue_ctx.max_rx_sgl_size;

    adapter->max_num_io_queues = max_num_io_queues;

    adapter->buf_ring_size = ENA_DEFAULT_BUF_RING_SIZE;

    adapter->max_mtu = get_feat_ctx.dev_attr.max_mtu;

    adapter->reset_reason = ENA_REGS_RESET_NORMAL;

    /*
     * The amount of requested MSIX vectors is equal to
     * adapter::max_num_io_queues (see `ena_enable_msix()`), plus a constant
     * number of admin queue interrupts. The former is initially determined
     * by HW capabilities (see `ena_calc_max_io_queue_num())` but may not be
     * achieved if there are not enough system resources. By default, the
     * number of effectively used IO queues is the same but later on it can
     * be limited by the user using sysctl interface.
     */
    rc = ena_enable_msix_and_set_admin_interrupts(adapter);
    if (unlikely(rc != 0)) {
        device_printf(d, "Failed to enable and set the admin interrupts\n");
        goto err_io_free;
    }
    /* By default all of allocated MSIX vectors are actively used */
    adapter->num_io_queues = adapter->msix_vecs - ENA_ADMIN_MSIX_VEC;

    /* initialize rings basic information */
    ena_init_io_rings(adapter);

    /* setup network interface */
    rc = ena_setup_ifnet(adapter, &get_feat_ctx);
    if (unlikely(rc != 0)) {
        device_printf(d, "Error with network interface setup\n");
        goto err_msix_free;
    }

    init_closure(&adapter->reset_task, ena_reset_task, adapter);

    /* Initialize statistics */
    zero(&adapter->dev_stats, sizeof(struct ena_stats_dev));
    zero(&adapter->hw_stats, sizeof(struct ena_hw_stats));

    ENA_FLAG_SET_ATOMIC(ENA_FLAG_DEVICE_RUNNING, adapter);
    ena_up(adapter);

    return true;

err_msix_free:
    ena_com_dev_reset(adapter->ena_dev, ENA_REGS_RESET_INIT_ERR);
    ena_free_mgmnt_irq(adapter);
    ena_disable_msix(adapter);
err_io_free:
    ena_free_all_io_rings_resources(adapter);
err_com_free:
    ena_com_admin_destroy(ena_dev);
    ena_com_delete_host_info(ena_dev);
    ena_com_mmio_reg_read_request_destroy(ena_dev);
err_bus_free:
    deallocate(general, ena_dev->bus, sizeof(struct ena_bus));
err_dev_free:
    deallocate(general, ena_dev, sizeof(struct ena_com_dev));
err_adapter_free:
    deallocate(general, adapter, sizeof(*adapter));
    return false;
}

/******************************************************************************
 ******************************** AENQ Handlers *******************************
 *****************************************************************************/
/**
 * ena_update_on_link_change:
 * Notify the network interface about the change in link status
 **/
static void ena_update_on_link_change(void *adapter_data, struct ena_admin_aenq_entry *aenq_e)
{
    struct ena_adapter *adapter = (struct ena_adapter *)adapter_data;
    struct ena_admin_aenq_link_change_desc *aenq_desc;
    int status;
    struct netif *ifp;

    aenq_desc = (struct ena_admin_aenq_link_change_desc *)aenq_e;
    ifp = &adapter->ifp;
    status = aenq_desc->flags & ENA_ADMIN_AENQ_LINK_CHANGE_DESC_LINK_STATUS_MASK;

    if (status != 0) {
        ena_trace(NULL, ENA_INFO, "link is UP\n");
        ENA_FLAG_SET_ATOMIC(ENA_FLAG_LINK_UP, adapter);
        if (!ENA_FLAG_ISSET(ENA_FLAG_ONGOING_RESET, adapter))
            netif_set_link_up(ifp);
    } else {
        ena_trace(NULL, ENA_INFO, "link is DOWN\n");
        netif_set_link_down(ifp);
        ENA_FLAG_CLEAR_ATOMIC(ENA_FLAG_LINK_UP, adapter);
    }
}

static void ena_notification(void *adapter_data, struct ena_admin_aenq_entry *aenq_e)
{
    struct ena_adapter *adapter = (struct ena_adapter *)adapter_data;
    struct ena_admin_ena_hw_hints *hints;

    ENA_WARN(NULL, aenq_e->aenq_common_desc.group != ENA_ADMIN_NOTIFICATION,
        "Invalid group(%x) expected %x\n", aenq_e->aenq_common_desc.group,
        ENA_ADMIN_NOTIFICATION);

    switch (aenq_e->aenq_common_desc.syndrome) {
    case ENA_ADMIN_UPDATE_HINTS:
        hints = (struct ena_admin_ena_hw_hints *)(&aenq_e->inline_data_w4);
        ena_update_hints(adapter, hints);
        break;
    default:
        device_printf(adapter->pdev, "Invalid aenq notification link state %d\n",
            aenq_e->aenq_common_desc.syndrome);
        }
}

/**
 * This handler will called for unknown event group or unimplemented handlers
 **/
static void unimplemented_aenq_handler(void *adapter_data, struct ena_admin_aenq_entry *aenq_e)
{
    device_printf(((struct ena_adapter *)adapter_data)->pdev,
        "Unknown event was received or event with unimplemented handler\n");
}

static struct ena_aenq_handlers aenq_handlers = {
        .handlers = {
                [ENA_ADMIN_LINK_CHANGE] = ena_update_on_link_change,
                [ENA_ADMIN_NOTIFICATION] = ena_notification,
                [ENA_ADMIN_KEEP_ALIVE ] = ena_keep_alive_wd,
        },
        .unimplemented_handler = unimplemented_aenq_handler
};

void init_aws_ena(kernel_heaps kh)
{
    heap h = heap_general(kh);
    register_pci_driver(closure(h, ena_probe, h, heap_backed (kh)));
}
