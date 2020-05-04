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

#ifndef _VMXNET3_NET_H
#define _VMXNET3_NET_H

#include "vmxnet3_queue.h"

typedef struct vmxnet3_pci *vmxnet3_pci;

#define VMXNET3_VMWARE_VENDOR_ID	0x15AD
#define VMXNET3_VMWARE_DEVICE_ID	0x07B0

#define VMXNET3_BAR0_IMASK(irq)	(0x000 + (irq) * 8)	/* Interrupt mask */
#define VMXNET3_BAR0_TXH(q)	(0x600 + (q) * 8)	/* Tx head */
#define VMXNET3_BAR0_RXH1(q)	(0x800 + (q) * 8)	/* Ring1 Rx head */
#define VMXNET3_BAR0_RXH2(q)	(0xA00 + (q) * 8)	/* Ring2 Rx head */
#define VMXNET3_BAR1_VRRS	0x000	/* VMXNET3 revision report selection */
#define VMXNET3_BAR1_UVRS	0x008	/* UPT version report selection */
#define VMXNET3_BAR1_DSL	0x010	/* Driver shared address low */
#define VMXNET3_BAR1_DSH	0x018	/* Driver shared address high */
#define VMXNET3_BAR1_CMD	0x020	/* Command */
#define VMXNET3_BAR1_MACL	0x028	/* MAC address low */
#define VMXNET3_BAR1_MACH	0x030	/* MAC address high */
#define VMXNET3_BAR1_INTR	0x038	/* Interrupt status */
#define VMXNET3_BAR1_EVENT	0x040	/* Event status */


#define VMXNET3_CMD_ENABLE	0xCAFE0000	/* Enable VMXNET3 */
#define VMXNET3_CMD_DISABLE	0xCAFE0001	/* Disable VMXNET3 */
#define VMXNET3_CMD_RESET	0xCAFE0002	/* Reset device */
#define VMXNET3_CMD_SET_RXMODE	0xCAFE0003	/* Set interface flags */
#define VMXNET3_CMD_SET_FILTER	0xCAFE0004	/* Set address filter */
#define VMXNET3_CMD_VLAN_FILTER	0xCAFE0005	/* Set VLAN filter */
#define VMXNET3_CMD_GET_STATUS	0xF00D0000	/* Get queue errors */
#define VMXNET3_CMD_GET_STATS	0xF00D0001	/* Get queue statistics */
#define VMXNET3_CMD_GET_LINK	0xF00D0002	/* Get link status */
#define VMXNET3_CMD_GET_MACL	0xF00D0003	/* Get MAC address low */
#define VMXNET3_CMD_GET_MACH	0xF00D0004	/* Get MAC address high */
#define VMXNET3_CMD_GET_INTRCFG	0xF00D0008	/* Get interrupt config */

typedef struct vmxnet3_pci {
    struct pci_dev _dev;
    pci_dev dev;

    struct pci_bar bar0;
    struct pci_bar bar1;  // notify config

    heap contiguous;
    heap general;

    struct vmxnet3_driver_shared* vmx_ds;
    void *vmxnet3_mcast_table_mem;
    struct vmxnet3_txqueue *vmx_txq[VMXNET3_DEF_TX_QUEUES];
    struct vmxnet3_rxqueue *vmx_rxq[VMXNET3_DEF_RX_QUEUES];
    void *queues_shared_mem;
    struct vmxnet3_txdesc *tx_desc_mem;
    struct pbuf *tx_pbuf[VMXNET3_MAX_TX_NDESC];
    struct vmxnet3_txcompdesc *tx_compdesc_mem;
    struct vmxnet3_rxdesc *rx_desc_mem;
    struct pbuf *rx_pbuf[VMXNET3_RXRINGS_PERQ][VMXNET3_MAX_RX_NDESC];
    struct vmxnet3_rxcompdesc *rx_compdesc_mem;
    struct pbuf *currpkt_head, *currpkt_tail;
} *vmxnet3_pci;

#define VMXNET3_RX_MAXSEGSIZE		((1 << 14) - 1)

/*
 * Predetermined size of the multicast MACs filter table. If the
 * number of multicast addresses exceeds this size, then the
 * ALL_MULTI mode is use instead.
 */
#define VMXNET3_MULTICAST_MAX		32

#define ETHER_ADDR_LEN 6

#endif /* _VMXNET3_NET_H */
