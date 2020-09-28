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
 *
 * $FreeBSD$
 *
 */

#ifndef ENA_H
#define ENA_H

#include "ena-com/ena_internal.h"
#include "ena-com/ena_com.h"
#include "ena-com/ena_eth_com.h"

#define DRV_MODULE_VER_MAJOR	2
#define DRV_MODULE_VER_MINOR	1
#define DRV_MODULE_VER_SUBMINOR 2

#define DRV_MODULE_NAME		"ena"

#define DEVICE_NAME         "en"

#if 0
#ifndef DRV_MODULE_VERSION
#define DRV_MODULE_VERSION				\
	__XSTRING(DRV_MODULE_VER_MAJOR) "."		\
	__XSTRING(DRV_MODULE_VER_MINOR) "."		\
	__XSTRING(DRV_MODULE_VER_SUBMINOR)
#endif
#define DEVICE_NAME	"Elastic Network Adapter (ENA)"
#define DEVICE_DESC	"ENA adapter"
#endif

/* Calculate DMA mask - width for ena cannot exceed 48, so it is safe */
#define ENA_DMA_BIT_MASK(x)     ((1ULL << (x)) - 1ULL)

/* 1 for AENQ + ADMIN */
#define ENA_ADMIN_MSIX_VEC      1
#define ENA_MAX_MSIX_VEC(io_queues) (ENA_ADMIN_MSIX_VEC + (io_queues))

#define ENA_REG_BAR         0
#define ENA_MEM_BAR         2

#define ENA_BUS_DMA_SEGS        32

#define ENA_DEFAULT_BUF_RING_SIZE   4096

#define ENA_DEFAULT_RING_SIZE       1024

/*
 * Refill Rx queue when number of required descriptors is above
 * QUEUE_SIZE / ENA_RX_REFILL_THRESH_DIVIDER or ENA_RX_REFILL_THRESH_PACKET
 */
#define ENA_RX_REFILL_THRESH_DIVIDER    8
#define ENA_RX_REFILL_THRESH_PACKET 256

#define ENA_IRQNAME_SIZE        40

#define ENA_PKT_MAX_BUFS        19

#define ENA_RX_RSS_TABLE_LOG_SIZE   7
#define ENA_RX_RSS_TABLE_SIZE       (1 << ENA_RX_RSS_TABLE_LOG_SIZE)

#define ENA_HASH_KEY_SIZE       40

#define ENA_TX_RESUME_THRESH        (ENA_PKT_MAX_BUFS + 2)

#define DB_THRESHOLD    64

#define TX_COMMIT   32
 /*
 * TX budget for cleaning. It should be half of the RX budget to reduce amount
 *  of TCP retransmissions.
 */
#define TX_BUDGET   128
/* RX cleanup budget. -1 stands for infinity. */
#define RX_BUDGET   256
/*
 * How many times we can repeat cleanup in the io irq handling routine if the
 * RX or TX budget was depleted.
 */
#define CLEAN_BUDGET    8

#define RX_IRQ_INTERVAL 20
#define TX_IRQ_INTERVAL 50

#define ENA_MIN_MTU     128

#define ENA_MMIO_DISABLE_REG_READ   BIT(0)

#define ENA_TX_RING_IDX_NEXT(idx, ring_size) (((idx) + 1) & ((ring_size) - 1))

#define ENA_RX_RING_IDX_NEXT(idx, ring_size) (((idx) + 1) & ((ring_size) - 1))

#define ENA_IO_TXQ_IDX(q)       (2 * (q))
#define ENA_IO_RXQ_IDX(q)       (2 * (q) + 1)

#define ENA_MGMNT_IRQ_IDX       0
#define ENA_IO_IRQ_FIRST_IDX        1
#define ENA_IO_IRQ_IDX(q)       (ENA_IO_IRQ_FIRST_IDX + (q))

#define ENA_MAX_NO_INTERRUPT_ITERATIONS 3

/*
 * ENA device should send keep alive msg every 1 sec.
 * We wait for 6 sec just to be on the safe side.
 */
#define DEFAULT_KEEP_ALIVE_TO       (TIMESTAMP_SECOND * 6)

/* Time in jiffies before concluding the transmitter is hung. */
#define DEFAULT_TX_CMP_TO       (TIMESTAMP_SECOND * 5)

/* Number of queues to check for missing queues per timer tick */
#define DEFAULT_TX_MONITORED_QUEUES (4)

/* Max number of timeouted packets before device reset */
#define DEFAULT_TX_CMP_THRESHOLD    (128)

/*
 * Supported PCI vendor and devices IDs
 */
#define PCI_VENDOR_ID_AMAZON    0x1d0f

#define PCI_DEV_ID_ENA_PF   0x0ec2
#define PCI_DEV_ID_ENA_LLQ_PF   0x1ec2
#define PCI_DEV_ID_ENA_VF   0xec20
#define PCI_DEV_ID_ENA_LLQ_VF   0xec21

/*
 * Flags indicating current ENA driver state
 */
enum ena_flags_t {
    ENA_FLAG_DEVICE_RUNNING,
    ENA_FLAG_DEV_UP,
    ENA_FLAG_LINK_UP,
    ENA_FLAG_MSIX_ENABLED,
    ENA_FLAG_TRIGGER_RESET,
    ENA_FLAG_ONGOING_RESET,
    ENA_FLAG_DEV_UP_BEFORE_RESET,
    ENA_FLAG_RSS_ACTIVE,
    ENA_FLAGS_NUMBER = ENA_FLAG_RSS_ACTIVE
};

struct ena_calc_queue_size_ctx {
    struct ena_com_dev_get_features_ctx *get_feat_ctx;
    struct ena_com_dev *ena_dev;
    //device_t pdev;
    uint16_t rx_queue_size;
    uint16_t tx_queue_size;
    uint16_t max_tx_sgl_size;
    uint16_t max_rx_sgl_size;
};

struct ena_tx_buffer {
    struct pbuf *mbuf;
    /* # of ena desc for this specific mbuf
     * (includes data desc and metadata desc) */
    unsigned int tx_descs;
    /* # of buffers used by this mbuf */
    unsigned int num_of_bufs;

//    bus_dmamap_t dmamap;

    /* Used to detect missing tx packets */
    timestamp timestamp;
//    bool print_once;

#ifdef DEV_NETMAP
    struct ena_netmap_tx_info nm_info;
#endif /* DEV_NETMAP */

    struct ena_com_buf bufs[ENA_PKT_MAX_BUFS];
} __aligned(CACHE_LINE_SIZE);

struct ena_rx_buffer {
    struct pbuf *mbuf;
//    bus_dmamap_t map;
    struct ena_com_buf ena_buf;
#ifdef DEV_NETMAP
    uint32_t netmap_buf_idx;
#endif /* DEV_NETMAP */
} __aligned(CACHE_LINE_SIZE);

BITSET_DEFINE(_ena_state, ENA_FLAGS_NUMBER);
typedef struct _ena_state ena_state_t;

#define ENA_FLAG_ZERO(adapter)      \
    BIT_ZERO(ENA_FLAGS_NUMBER, &(adapter)->flags)
#define ENA_FLAG_ISSET(bit, adapter)    \
    BIT_ISSET(ENA_FLAGS_NUMBER, (bit), &(adapter)->flags)
#define ENA_FLAG_SET_ATOMIC(bit, adapter)   \
    BIT_SET_ATOMIC(ENA_FLAGS_NUMBER, (bit), &(adapter)->flags)
#define ENA_FLAG_CLEAR_ATOMIC(bit, adapter) \
        BIT_CLR_ATOMIC(ENA_FLAGS_NUMBER, (bit), &(adapter)->flags)

struct msix_entry {
    int entry;
    int vector;
};

typedef struct _ena_vendor_info_t {
    u16 vendor_id;
    u16 device_id;
    unsigned int index;
} ena_vendor_info_t;

//typedef int (driver_filter_t)(void *arg);
//typedef thunk driver_filter_t;

struct ena_irq {
    /* Interrupt resources */
    struct resource *res;
    thunk handler;
    void *data;
    void *cookie;
    unsigned int vector;
    int int_vector;
    bool requested;
    int cpu;
    char name[ENA_IRQNAME_SIZE];
};

struct ena_que {
    struct ena_adapter *adapter;
    struct ena_ring *tx_ring;
    struct ena_ring *rx_ring;

    thunk cleanup_task;

    uint32_t id;
    int cpu;
};

struct ena_ring {
    /* Holds the empty requests for TX/RX out of order completions */
    union {
        uint16_t *free_tx_ids;
        uint16_t *free_rx_ids;
    };
    struct ena_com_dev *ena_dev;
    struct ena_adapter *adapter;
    struct ena_com_io_cq *ena_com_io_cq;
    struct ena_com_io_sq *ena_com_io_sq;

    uint16_t qid;

    /* Determines if device will use LLQ or normal mode for TX */
    enum ena_admin_placement_policy_type tx_mem_queue_type;
    union {
        /* The maximum length the driver can push to the device (For LLQ) */
        uint8_t tx_max_header_size;
        /* The maximum (and default) mbuf size for the Rx descriptor. */
        uint16_t rx_mbuf_sz;

    };

    bool first_interrupt;
    uint16_t no_interrupt_event_cnt;

    struct ena_com_rx_buf_info ena_bufs[ENA_PKT_MAX_BUFS];

    /*
     * Fields used for Adaptive Interrupt Modulation - to be implemented in
     * the future releases
     */
    uint32_t  smoothed_interval;
    enum ena_intr_moder_level moder_tbl_idx;

    struct ena_que *que;
//    struct lro_ctrl lro;

    uint16_t next_to_use;
    uint16_t next_to_clean;

    union {
        struct ena_tx_buffer *tx_buffer_info; /* contex of tx packet */
        struct ena_rx_buffer *rx_buffer_info; /* contex of rx packet */
    };
    int ring_size; /* number of tx/rx_buffer_info's entries */

    struct buf_ring *br; /* only for TX */
    uint32_t buf_ring_size;

    struct spinlock ring_lock;

    thunk enqueue_task;
// TODO
#if 0
    struct {
        struct task enqueue_task;
        struct taskqueue *enqueue_tq;
    };

    union {
        struct ena_stats_tx tx_stats;
        struct ena_stats_rx rx_stats;
    };
#endif

    union {
        int empty_rx_queue;
        /* For Tx ring to indicate if it's running or not */
        bool running;
    };

    /* How many packets are sent in one Tx loop, used for doorbells */
    uint32_t acum_pkts;

    /* Used for LLQ */
    uint8_t *push_buf_intermediate_buf;
} __aligned(CACHE_LINE_SIZE);

struct ena_adapter {
    struct ena_adapter_pci ena_pci;

    /* lwIP */
    struct netif *netif;
    u16 rxbuflen;
    heap rxbuffers;
    struct spinlock rx_buflock;

    struct ena_com_dev *ena_dev;

    /* MSI-X */
    struct msix_entry *msix_entries;
    int msix_vecs;

    int dma_width;

    uint32_t max_mtu;

    uint16_t max_tx_sgl_size;
    uint16_t max_rx_sgl_size;

    /* Tx fast path data */
    int num_queues;

    unsigned int tx_ring_size;
    unsigned int rx_ring_size;

    uint16_t buf_ring_size;

    ena_state_t flags;

    /* Queue will represent one TX and one RX ring */
    struct ena_que que[ENA_MAX_NUM_IO_QUEUES]
        __aligned(CACHE_LINE_SIZE);

    /* TX */
    struct ena_ring tx_ring[ENA_MAX_NUM_IO_QUEUES]
        __aligned(CACHE_LINE_SIZE);

    /* RX */
    struct ena_ring rx_ring[ENA_MAX_NUM_IO_QUEUES]
        __aligned(CACHE_LINE_SIZE);

    struct ena_irq irq_tbl[ENA_MAX_MSIX_VEC(ENA_MAX_NUM_IO_QUEUES)];

    int wd_active;

    /* Timer service */
    timer timer_service;
    timer_handler timer_task;
    thunk reset_task;
    timestamp keep_alive_timestamp;
    uint32_t next_monitored_tx_qid;
    timestamp keep_alive_timeout;
    timestamp missing_tx_timeout;
    uint32_t missing_tx_max_queues;
    uint32_t missing_tx_threshold;

    enum ena_regs_reset_reason_types reset_reason;
};

typedef struct xpbuf
{
    struct pbuf_custom p;
    struct ena_adapter* ena;
} *xpbuf;

xpbuf receive_buffer_alloc(struct ena_adapter *ena);
int ena_refill_rx_bufs(struct ena_ring *, uint32_t);

#define ENA_RING_MTX_LOCK(_ring)        spin_lock(&(_ring)->ring_lock)
#define ENA_RING_MTX_TRYLOCK(_ring)     spin_try(&(_ring)->ring_lock)
#define ENA_RING_MTX_UNLOCK(_ring)      spin_unlock(&(_ring)->ring_lock)

#define ENA_ADAPTER_MTU 1500

static inline int
validate_rx_req_id(struct ena_ring *rx_ring, uint16_t req_id)
{
    if (likely(req_id < rx_ring->ring_size))
        return (0);

#if 0
    device_printf(rx_ring->adapter->pdev, "Invalid rx req_id: %hu\n",
        req_id);
    counter_u64_add(rx_ring->rx_stats.bad_req_id, 1);
#endif
    /* Trigger device reset */
    if (likely(!ENA_FLAG_ISSET(ENA_FLAG_TRIGGER_RESET, rx_ring->adapter))) {
        rx_ring->adapter->reset_reason = ENA_REGS_RESET_INV_RX_REQ_ID;
        ENA_FLAG_SET_ATOMIC(ENA_FLAG_TRIGGER_RESET, rx_ring->adapter);
    }

    return (EFAULT);
}


#endif /* !(ENA_H) */

