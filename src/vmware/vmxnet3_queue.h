/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * This header is BSD licensed so anyone can use the definitions to implement
 * compatible drivers/servers.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of IBM nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL IBM OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#ifndef _VMXNET3_QUEUE_H
#define _VMXNET3_QUEUE_H

#define VMXNET3_REVISION	1
#define VMXNET3_UPT_VERSION	1

#define VMXNET3_REV1_MAGIC	0XBABEFEE1

#define VMXNET3_GOS_UNKNOWN	0x00
#define VMXNET3_GOS_LINUX	0x04
#define VMXNET3_GOS_WINDOWS	0x08
#define VMXNET3_GOS_SOLARIS	0x0C
#define VMXNET3_GOS_FREEBSD	0x10
#define VMXNET3_GOS_PXE		0x14

#define VMXNET3_GOS_32BIT	0x01
#define VMXNET3_GOS_64BIT	0x02

//Mimic FreeBSD driver behavior
#define VMXNET3_DRIVER_VERSION  0x01020000
#define VMXNET3_TX_MAXSEGS		32

#define VMXNET3_MAX_TX_QUEUES	8
#define VMXNET3_MAX_RX_QUEUES	16
#define VMXNET3_RXRINGS_PERQ	2

#define VMXNET3_MAX_INTRS \
    (VMXNET3_MAX_TX_QUEUES + VMXNET3_MAX_RX_QUEUES + 1)

#define VMXNET3_MAX_TX_NDESC	512
#define VMXNET3_MAX_RX_NDESC	256
#define VMXNET3_MAX_TX_NCOMPDESC	VMXNET3_MAX_TX_NDESC
#define VMXNET3_MAX_RX_NCOMPDESC	VMXNET3_MAX_RX_NDESC * VMXNET3_RXRINGS_PERQ

#define VMXNET3_RX_SERVICEQUEUE_DEPTH	VMXNET3_MAX_RX_NDESC * VMXNET3_RXRINGS_PERQ

#define VMXNET3_MAX_DESC_LEN = (1 << 14) - 1

#define VMXNET3_RXMODE_UCAST	0x01
#define VMXNET3_RXMODE_MCAST	0x02
#define VMXNET3_RXMODE_BCAST	0x04
#define VMXNET3_RXMODE_ALLMULTI	0x08
#define VMXNET3_RXMODE_PROMISC	0x10

//TODO  where we can get it?
#define VMXNET3_MAX_RX_SEGS     17
struct vmxnet3_driver_shared {
    u32	magic;
    u32 pad1;

    /* Misc. control */
    u32 version;        /* Driver version */
    u32 guest;            /* Guest OS */
    u32 vmxnet3_revision;    /* Supported VMXNET3 revision */
    u32 upt_version;        /* Supported UPT version */
    u64 upt_features;
    u64 driver_data;
    u64 queue_shared;
    u32 driver_data_len;
    u32 queue_shared_len;
    u32 mtu;
    u16 nrxsg_max;
    u8 ntxqueue;
    u8 nrxqueue;
    u32 reserved1[4];

    /* Interrupt control */
    u8 automask;
    u8 nintr;
    u8 evintr;
    u8 modlevel[VMXNET3_MAX_INTRS];
    u32 ictrl;
    u32 reserved2[2];

    /* Receive filter parameters */
    u32 rxmode;
    u16 mcast_tablelen;
    u16 pad2;
    u64 mcast_table;
    u32 vlan_filter[4096 / 32];

    struct {
        u32 version;
        u32 len;
        u64 paddr;
    } rss, pm, plugin;

    u32 event;
    u32 reserved3[5];
} __attribute__((packed));

struct UPT1_TxStats {
    u64 TSO_packets;
    u64 TSO_bytes;
    u64 ucast_packets;
    u64 ucast_bytes;
    u64 mcast_packets;
    u64 mcast_bytes;
    u64 bcast_packets;
    u64 bcast_bytes;
    u64 error;
    u64 discard;
} __attribute__((packed));

struct UPT1_RxStats {
    u64 LRO_packets;
    u64 LRO_bytes;
    u64 ucast_packets;
    u64 ucast_bytes;
    u64 mcast_packets;
    u64 mcast_bytes;
    u64 bcast_packets;
    u64 bcast_bytes;
    u64 nobuffer;
    u64 error;
} __attribute__((packed));

#define VMXNET3_INIT_GEN	1

/* Hardware features */
#define UPT1_F_CSUM	0x0001		/* Rx checksum verification */
#define UPT1_F_RSS	0x0002		/* Receive side scaling */
#define UPT1_F_VLAN	0x0004		/* VLAN tag stripping */
#define UPT1_F_LRO	0x0008		/* Large receive offloading */

struct vmxnet3_txdesc {
    u64 addr;

    u32 len:14;
    u32 gen:1;        /* Generation */
    u32 pad1:1;
    u32 dtype:1;    /* Descriptor type */
    u32 pad2:1;
    u32 offload_pos:14;    /* Offloading position */

    u32 hlen:10;    /* Header len */
    u32 offload_mode:2;    /* Offloading mode */
    u32 eop:1;        /* End of packet */
    u32 compreq:1;    /* Completion request */
    u32 pad3:1;
    u32 vtag_mode:1;    /* VLAN tag insertion mode */
    u32 vtag:16;    /* VLAN tag */
} __attribute__((packed));

/* Offloading modes */
#define VMXNET3_OM_NONE 0
#define VMXNET3_OM_CSUM 2
#define VMXNET3_OM_TSO  3

struct vmxnet3_txcompdesc {
    u32 eop_idx:12;    /* EOP index in Tx ring */
    u32 pad1:20;

    u32 pad2:32;
    u32 pad3:32;

    u32 rsvd:24;
    u32 type:7;
    u32 gen:1;
} __attribute__((packed));

/* Buffer types */
#define VMXNET3_BTYPE_HEAD	0	/* Head only */
#define VMXNET3_BTYPE_BODY	1	/* Body only */

struct vmxnet3_rxdesc {
    u64 addr;

    u32 len:14;
    u32 btype:1;    /* Buffer type */
    u32 dtype:1;    /* Descriptor type */
    u32 rsvd:15;
    u32 gen:1;

    u32 pad1:32;
} __attribute__((packed));

struct vmxnet3_rxcompdesc {
    u32 rxd_idx:12;    /* Rx descriptor index */
    u32 pad1:2;
    u32 eop:1;        /* End of packet */
    u32 sop:1;        /* Start of packet */
    u32 qid:10;
    u32 rss_type:4;
    u32 no_csum:1;    /* No checksum calculated */
    u32 pad2:1;

    u32 rss_hash:32;    /* RSS hash value */

    u32 len:14;
    u32 error:1;
    u32 vlan:1;        /* 802.1Q VLAN frame */
    u32 vtag:16;    /* VLAN tag */

    u32 csum:16;
    u32 csum_ok:1;    /* TCP/UDP checksum ok */
    u32 udp:1;
    u32 tcp:1;
    u32 ipcsum_ok:1;    /* IP checksum OK */
    u32 ipv6:1;
    u32 ipv4:1;
    u32 fragment:1;    /* IP fragment */
    u32 fcs:1;        /* Frame CRC correct */
    u32 type:7;
    u32 gen:1;
} __attribute__((packed));


struct vmxnet3_txq_shared {
    /* Control */
    u32 npending;
    u32 intr_threshold;
    u64 reserved1;

    /* Config */
    u64 cmd_ring;
    u64 data_ring;
    u64 comp_ring;
    u64 driver_data;
    u64 reserved2;
    u32 cmd_ring_len;
    u32 data_ring_len;
    u32 comp_ring_len;
    u32 driver_data_len;
    u8 intr_idx;
    u8 pad1[7];

    /* Queue status */
    u8 stopped;
    u8 pad2[3];
    u32 error;

    struct UPT1_TxStats stats;

    u8 pad3[88];
} __attribute__((packed));

struct vmxnet3_rxq_shared {
    u8 update_rxhead;
    u8 pad1[7];
    u64 reserved1;

    u64 cmd_ring[2];
    u64 comp_ring;
    u64 driver_data;
    u64 reserved2;
    u32 cmd_ring_len[2];
    u32 comp_ring_len;
    u32 driver_data_len;
    u8  intr_idx;
    u8  pad2[7];

    u8  stopped;
    u8  pad3[3];
    u32 error;

    struct UPT1_RxStats stats;

    u8 pad4[88];
} __attribute__((packed));

struct vmxnet3_txring {
    u16 vxtxr_next;
    u16 vxtxr_ndesc;
    int vxtxr_gen;
    struct vmxnet3_txdesc *vxtxr_txd;
    u64 vxtxr_paddr;
    //extra field for  nanos
    u16 vxtxr_avail;
    u16 vxtxr_head;
};

struct vmxnet3_rxring {
    struct vmxnet3_rxdesc *vxrxr_rxd;
    u16 vxrxr_ndesc;
    int vxrxr_gen;
    u64 vxrxr_paddr;
    u64 vxrxr_desc_skips;
    u16 vxrxr_refill_start;
};

struct vmxnet3_comp_ring {
    union {
        struct vmxnet3_txcompdesc *txcd;
        struct vmxnet3_rxcompdesc *rxcd;
    } vxcr_u;
    /*
     * vxcr_next is used on the transmit side to track the next index to
     * begin cleaning at.  It is not used on the receive side.
     */
    u16 vxcr_next;
    u16 vxcr_ndesc;
    int vxcr_gen;
    u64 vxcr_paddr;
    u64 vxcr_zero_length;
    u64 vxcr_pkt_errors;
};

typedef struct vmxnet3 *vmxnet3;
typedef struct vmxnet3_pci *vmxnet3_pci;

struct vmxnet3_txqueue {
    vmxnet3_pci vxtxq_sc;
    int vxtxq_id;
    int vxtxq_last_flush;
    int vxtxq_intr_idx;
    struct vmxnet3_txring vxtxq_cmd_ring;
    struct vmxnet3_comp_ring vxtxq_comp_ring;
    struct vmxnet3_txq_shared *vxtxq_ts;
    char vxtxq_name[16];
};

struct vmxnet3_rxqueue {
    vmxnet3_pci vxrxq_sc;
    int vxrxq_id;
    int vxrxq_intr_idx;
    struct vmxnet3_rxring vxrxq_cmd_ring[VMXNET3_RXRINGS_PERQ];
    struct vmxnet3_comp_ring vxrxq_comp_ring;
    struct vmxnet3_rxq_shared *vxrxq_rs;
    char vxrxq_name[16];
};

/*
 * The number of Rx/Tx queues this driver prefers.
 */
#define VMXNET3_DEF_RX_QUEUES   1 /* 8 on FreeBSD */
#define VMXNET3_DEF_TX_QUEUES   1 /* 8 on FreeBSD */

//aligment
#define VMXNET_ALIGN_MULTICAST 32
#define VMXNET_ALIGN_QUEUES_SHARED 128
#define VMXNET_ALIGN_QUEUES_DESC 512

typedef char *caddr_t;

#define DEVICE_NAME "en"

void vmxnet3_tx_queues_alloc(vmxnet3_pci vp);
void vmxnet3_rx_queues_alloc(vmxnet3_pci vp);

void vmxnet3_queues_shared_alloc(vmxnet3_pci vp);
void vmxnet3_init_shared_data(vmxnet3_pci vp);

int vmxnet3_isc_txd_encap(vmxnet3_pci vp, struct pbuf *p);
void vmxnet3_isc_txd_credits_update(vmxnet3_pci vp);

void vmxnet3_set_interrupt_idx(vmxnet3_pci vp);
boolean vmxnet3_rxq_available(vmxnet3_pci vp);

#endif /* _VMXNET3_QUEUE_H */
