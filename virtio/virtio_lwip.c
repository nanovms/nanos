/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Adam Dunkels <adam@sics.se>
 *
 */

/*
 * This file is a skeleton for developing Ethernet network interface
 * drivers for lwIP. Add code to the low_level functions and do a
 * search-and-replace for the word "ethernetif" to replace it with
 * something that better describes your network interface.
 */

#include "lwip/opt.h"

#include "lwip/def.h"
#include "lwip/mem.h"
#include "lwip/pbuf.h"
#include "lwip/stats.h"
#include "lwip/snmp.h"
#include "lwip/ethip6.h"
#include "lwip/etharp.h"
#include "lwip/dhcp.h"
#include "lwip/timeouts.h"
#include "netif/ethernet.h"

/* Define those to better describe your network interface. */
#define IFNAME0 'e'
#define IFNAME1 'n'

#include <virtio_internal.h>
#include <virtio_net.h>

typedef struct vnet {
    vtpci dev;
    u16 port;
    struct virtqueue *txq;
    struct virtqueue *rxq;
    struct virtqueue *ctl;
    void *empty;
} *vnet;

// fix, this per-device offset is variable - 24 with msi
#define DEVICE_CONFIG_OFFSET 24

static err_t low_level_output(struct netif *netif, struct pbuf *p)
{
    vnet vn = netif->state;
    struct pbuf *q;

    console("output frame ");
    print_u64(p->tot_len);
    console("\n");

    void *address[3];
    boolean writables[3];
    bytes lengths[3];
    int index = 0;

    address[index] = vn->empty;
    writables[index] = false;
    lengths[index] = NET_HEADER_LENGTH;


    for (q = p; index++, q != NULL; q = q->next) {
        address[index] = q->payload;
        writables[index] = false;
        lengths[index] = q->len;
    }

    // second argument correlator
    virtqueue_enqueue(vn->txq, 0, address, lengths, writables, index);
    virtqueue_notify(vn->txq);

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

    return ERR_OK;
}

static void tx_complete(void *z)
{
    console("tx complete\n");
    vnet vn = z;
}


static void post_recv(vnet vn)
{
    struct pbuf *p = pbuf_alloc(PBUF_RAW, 1500, PBUF_RAM);
    void *x = p->payload;
    void *address[] = {x};
    u64 lengths[] = {contiguous->pagesize};
    boolean writables[] = {true};
    virtqueue_enqueue(vn->rxq, p, address, lengths, writables, 1);    
}

static void input(void *z)
{
    struct netif *netif = z;
    struct eth_hdr *ethhdr;
    /* move received packet into a new pbuf */
    vnet vn= netif->state;
    u32 len;
    struct pbuf *p = virtqueue_dequeue(vn->rxq, &len);
    console("rx packet: ");
    print_u64(len);
    console("\n");
    post_recv(vn);
    if (p != NULL) {
        p->len = len;
        if (netif->input(p, netif) != ERR_OK) {
            LWIP_DEBUGF(NETIF_DEBUG, ("ethernetif_input: IP input error\n"));
            pbuf_free(p);
            p = NULL;
        }
    }
}

static err_t virtioif_init(struct netif *netif)
{

    vnet vn = netif->state;
    /* Initialize interface hostname */
    //    netif->hostname = "virtiosomethingsomething";

    netif->name[0] = IFNAME0;
    netif->name[1] = IFNAME1;
    netif->output = etharp_output;
    netif->linkoutput = low_level_output;
    netif->hwaddr_len = ETHARP_HWADDR_LEN;
    for (int i = 0; i < ETHER_ADDR_LEN; i++) 
        netif->hwaddr[i] =  in8(vn->dev->base+DEVICE_CONFIG_OFFSET+i);
    netif->mtu = 1500;

    /* device capabilities */
    /* don't set NETIF_FLAG_ETHARP if this device is not an ethernet one */
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP | NETIF_FLAG_UP;
    return ERR_OK;
}


void init_vnet(vtpci dev)
{
    vnet vn = allocate(dev->general, sizeof(struct vnet));
    struct netif *n = allocate(dev->general, sizeof(struct netif));
    /* rx = 0, tx = 1, ctl = 2 by page 53 of http://docs.oasis-open.org/virtio/virtio/v1.0/cs01/virtio-v1.0-cs01.pdf */
    vn->dev = dev;
    // causes qemu to handle on exit?
    //     vtpci_alloc_virtqueue(dev, "ctrl", 0, 0, &vn->txq);
    
    vtpci_alloc_virtqueue(dev, intern(tx)->s, 1, allocate_handler(general, tx_complete, vn), &vn->txq);
    vtpci_alloc_virtqueue(dev, intern(rx)->s, 0, allocate_handler(general, input, n), &vn->rxq);
    // just need 10 contig bytes really
    vn->empty = allocate(contiguous, contiguous->pagesize);
    for (int i = 0; i < NET_HEADER_LENGTH ; i++)  ((u8 *)vn->empty)[i] = 0;
    n->state = vn;
    netif_add(n,
              0, 0, 0, //&x, &x, &x,
              vn, // i dont understand why this is getting passed
              virtioif_init,
              ethernet_input);

    post_recv(vn);
    dhcp_start(n);
    // setup sys_check_timeouts() timer
}

