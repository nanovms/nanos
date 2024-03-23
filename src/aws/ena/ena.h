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

#ifndef ENA_H
#define ENA_H

#include "ena_com/ena_com.h"
#include "ena_com/ena_eth_com.h"

#define DRV_MODULE_VER_MAJOR    2
#define DRV_MODULE_VER_MINOR    3
#define DRV_MODULE_VER_SUBMINOR 0

#define DRV_MODULE_NAME "ena"

#ifndef DRV_MODULE_VERSION
#define DRV_MODULE_VERSION              \
    __XSTRING(DRV_MODULE_VER_MAJOR) "." \
    __XSTRING(DRV_MODULE_VER_MINOR) "." \
    __XSTRING(DRV_MODULE_VER_SUBMINOR)
#endif
#define DEVICE_NAME "Elastic Network Adapter (ENA)"
#define DEVICE_DESC "ENA adapter"

/* 1 for AENQ + ADMIN */
#define	ENA_ADMIN_MSIX_VEC          1
#define	ENA_MAX_MSIX_VEC(io_queues) (ENA_ADMIN_MSIX_VEC + (io_queues))

#define	ENA_REG_BAR 0
#define	ENA_MEM_BAR 2

#define	ENA_BUS_DMA_SEGS    32

#define	ENA_DEFAULT_BUF_RING_SIZE   4096

#define	ENA_DEFAULT_RING_SIZE   1024
#define	ENA_MIN_RING_SIZE       256

/*
 * Refill Rx queue when number of required descriptors is above
 * QUEUE_SIZE / ENA_RX_REFILL_THRESH_DIVIDER or ENA_RX_REFILL_THRESH_PACKET
 */
#define	ENA_RX_REFILL_THRESH_DIVIDER    8
#define	ENA_RX_REFILL_THRESH_PACKET     256

#define	ENA_PKT_MAX_BUFS    19

#define	ENA_RX_RSS_TABLE_LOG_SIZE   7
#define	ENA_RX_RSS_TABLE_SIZE       (1 << ENA_RX_RSS_TABLE_LOG_SIZE)

#define	ENA_HASH_KEY_SIZE   40

#define	ENA_MAX_FRAME_LEN   10000
#define	ENA_MIN_FRAME_LEN   60

#define ENA_TX_RESUME_THRESH    (ENA_PKT_MAX_BUFS + 2)

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

#define	ENA_MIN_MTU     128

#define	ENA_TSO_MAXSIZE 65536

#define	ENA_MMIO_DISABLE_REG_READ   BIT(0)

#define	ENA_TX_RING_IDX_NEXT(idx, ring_size)    (((idx) + 1) & ((ring_size) - 1))

#define	ENA_RX_RING_IDX_NEXT(idx, ring_size)    (((idx) + 1) & ((ring_size) - 1))

#define	ENA_IO_TXQ_IDX(q)   (2 * (q))
#define	ENA_IO_RXQ_IDX(q)   (2 * (q) + 1)

#define	ENA_MGMNT_IRQ_IDX       0
#define	ENA_IO_IRQ_FIRST_IDX    1
#define	ENA_IO_IRQ_IDX(q)       (ENA_IO_IRQ_FIRST_IDX + (q))

#define	ENA_MAX_NO_INTERRUPT_ITERATIONS 3

/*
 * ENA device should send keep alive msg every 1 sec.
 * We wait for 6 sec just to be on the safe side.
 */
#define DEFAULT_KEEP_ALIVE_TO   seconds(6)

/* Time in jiffies before concluding the transmitter is hung. */
#define DEFAULT_TX_CMP_TO       seconds(5)

/* Number of queues to check for missing queues per timer tick */
#define DEFAULT_TX_MONITORED_QUEUES 4

/* Max number of timeouted packets before device reset */
#define DEFAULT_TX_CMP_THRESHOLD    128

/*
 * Supported PCI vendor and devices IDs
 */
#define	PCI_VENDOR_ID_AMAZON    0x1d0f

#define	PCI_DEV_ID_ENA_PF           0x0ec2
#define	PCI_DEV_ID_ENA_PF_RSERV0    0x1ec2
#define	PCI_DEV_ID_ENA_VF           0xec20
#define	PCI_DEV_ID_ENA_VF_RSERV0    0xec21

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

BITSET_DEFINE(_ena_state, ENA_FLAGS_NUMBER);
typedef struct _ena_state ena_state_t;

#define ENA_FLAG_ZERO(adapter)                      \
    BIT_ZERO(ENA_FLAGS_NUMBER, &(adapter)->flags)
#define ENA_FLAG_ISSET(bit, adapter)                        \
    BIT_ISSET(ENA_FLAGS_NUMBER, (bit), &(adapter)->flags)
#define ENA_FLAG_SET_ATOMIC(bit, adapter)                       \
    BIT_SET_ATOMIC(ENA_FLAGS_NUMBER, (bit), &(adapter)->flags)
#define ENA_FLAG_CLEAR_ATOMIC(bit, adapter)                     \
    BIT_CLR_ATOMIC(ENA_FLAGS_NUMBER, (bit), &(adapter)->flags)

typedef struct _ena_vendor_info_t {
    uint16_t vendor_id;
    uint16_t device_id;
    unsigned int index;
} ena_vendor_info_t;

struct ena_irq {
    closure_struct(thunk, th);
    void (*handler)(void*);
    void *data;
    unsigned int vector;
};

struct ena_que {
    struct ena_adapter *adapter;
    struct ena_ring *tx_ring;
    struct ena_ring *rx_ring;
    closure_struct(thunk, cleanup_task);
    uint32_t id;
};

struct ena_calc_queue_size_ctx {
    struct ena_com_dev_get_features_ctx *get_feat_ctx;
    struct ena_com_dev *ena_dev;
    uint32_t tx_queue_size;
    uint32_t rx_queue_size;
    uint32_t max_tx_queue_size;
    uint32_t max_rx_queue_size;
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

    /* Used to detect missing tx packets */
    timestamp timestamp;
    bool print_once;

    struct ena_com_buf bufs[ENA_PKT_MAX_BUFS];
} ____cacheline_aligned;

struct ena_rx_buffer {
    struct pbuf *mbuf;
    struct ena_com_buf ena_buf;
} ____cacheline_aligned;

struct ena_stats_tx {
    uint64_t cnt;
    uint64_t bytes;
    uint64_t prepare_ctx_err;
    uint64_t doorbells;
    uint64_t missing_tx_comp;
    uint64_t bad_req_id;
    uint64_t queue_wakeup;
    uint64_t queue_stop;
};

struct ena_stats_rx {
    uint64_t cnt;
    uint64_t bytes;
    uint64_t refil_partial;
    uint64_t mjum_alloc_fail;
    uint64_t bad_desc_num;
    uint64_t bad_req_id;
    uint64_t empty_rx_ring;
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

    struct ena_que *que;

    uint16_t next_to_use;
    uint16_t next_to_clean;

    union {
        struct ena_tx_buffer *tx_buffer_info; /* contex of tx packet */
        struct ena_rx_buffer *rx_buffer_info; /* contex of rx packet */
    };
    int ring_size; /* number of tx/rx_buffer_info's entries */

    queue br; /* only for TX */
    uint32_t buf_ring_size;

    ena_spinlock_t ring_mtx;

    closure_struct(thunk, enqueue_task);

    union {
        struct ena_stats_tx tx_stats;
        struct ena_stats_rx rx_stats;
    };

    union {
        int empty_rx_queue;
        /* For Tx ring to indicate if it's running or not */
        bool running;
    };

    /* How many packets are sent in one Tx loop, used for doorbells */
    uint32_t acum_pkts;

    /* Used for LLQ */
    uint8_t *push_buf_intermediate_buf;
} ____cacheline_aligned;

struct ena_stats_dev {
    uint64_t wd_expired;
    uint64_t interface_up;
    uint64_t interface_down;
    uint64_t admin_q_pause;
};

struct ena_hw_stats {
    uint64_t rx_packets;
    uint64_t tx_packets;

    uint64_t rx_bytes;
    uint64_t tx_bytes;

    uint64_t rx_drops;
    uint64_t tx_drops;
};

/* Board specific private data structure */
struct ena_adapter {
    struct netif_dev ndev;
    heap general, contiguous;
    pci_dev pdev;
    struct ena_com_dev *ena_dev;

    /* OS resources */
    struct pci_bar memory;
    struct pci_bar registers;

    ena_spinlock_t global_lock;

    /* MSI-X */
    int msix_vecs;

    uint32_t max_mtu;

    uint32_t num_io_queues;
    uint32_t max_num_io_queues;

    uint32_t requested_tx_ring_size;
    uint32_t requested_rx_ring_size;

    uint16_t max_tx_sgl_size;
    uint16_t max_rx_sgl_size;

    uint32_t buf_ring_size;

    ena_state_t flags;

    /* Queue will represent one TX and one RX ring */
    struct ena_que que[ENA_MAX_NUM_IO_QUEUES] ____cacheline_aligned;

    /* TX */
    struct ena_ring tx_ring[ENA_MAX_NUM_IO_QUEUES] ____cacheline_aligned;

    /* RX */
    struct ena_ring rx_ring[ENA_MAX_NUM_IO_QUEUES] ____cacheline_aligned;

    struct ena_irq irq_tbl[ENA_MAX_MSIX_VEC(ENA_MAX_NUM_IO_QUEUES)];

    /* Timer service */
    struct timer timer_service;
    closure_struct(timer_handler, timer_task);
    timestamp keep_alive_timestamp;
    uint32_t next_monitored_tx_qid;
    closure_struct(thunk, reset_task);
    int wd_active;
    timestamp keep_alive_timeout;
    timestamp missing_tx_timeout;
    uint32_t missing_tx_max_queues;
    uint32_t missing_tx_threshold;

    /* Statistics */
    struct ena_stats_dev dev_stats;
    struct ena_hw_stats hw_stats;

    enum ena_regs_reset_reason_types reset_reason;

    /* Deferred link change tasks: Note that these are not folded into one
       closure, as doing so (with a closed-over link status variable common to
       all task enqueues) could lead to missed transient state transitions. */
    closure_struct(thunk, link_up_task);
    closure_struct(thunk, link_down_task);
};

#define	ENA_RING_MTX_LOCK(_ring)    spin_lock(&(_ring)->ring_mtx)
#define	ENA_RING_MTX_TRYLOCK(_ring) spin_try(&(_ring)->ring_mtx)
#define	ENA_RING_MTX_UNLOCK(_ring)  spin_unlock(&(_ring)->ring_mtx)

#define ENA_LOCK_INIT(adapter)      spin_lock_init(&(adapter)->global_lock)
#define ENA_LOCK_DESTROY(adapter)
#define ENA_LOCK_LOCK(adapter)      spin_lock(&(adapter)->global_lock)
#define ENA_LOCK_UNLOCK(adapter)    spin_unlock(&(adapter)->global_lock)

#define clamp_t(type, _x, min, max) min_t(type, max_t(type, _x, min), max)
#define clamp_val(val, lo, hi)      clamp_t(__typeof(val), val, lo, hi)

int ena_up(struct ena_adapter *adapter);
void ena_down(struct ena_adapter *adapter);
int ena_restore_device(struct ena_adapter *adapter);
void ena_destroy_device(struct ena_adapter *adapter, bool graceful);
int ena_refill_rx_bufs(struct ena_ring *rx_ring, uint32_t num);

static inline void ena_trigger_reset(struct ena_adapter *adapter,
                                     enum ena_regs_reset_reason_types reset_reason)
{
    if (likely(!ENA_FLAG_ISSET(ENA_FLAG_TRIGGER_RESET, adapter))) {
        adapter->reset_reason = reset_reason;
        ENA_FLAG_SET_ATOMIC(ENA_FLAG_TRIGGER_RESET, adapter);
    }
}

#endif /* !(ENA_H) */
