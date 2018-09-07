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

#include <virtio_internal.h>
#include <virtio_net.h>


typedef struct vnet {
    vtpci dev;
    u16 port;
    heap rxbuffers;
    int rxbuflen;
    struct netif *n;
    struct virtqueue *txq;
    struct virtqueue *rxq;
    struct virtqueue *ctl;
    void *empty; // just a mac..fix, from pre-heap days
} *vnet;

typedef struct xpbuf
{
    struct pbuf_custom p;
    buffer b;
    vnet vn;
} *xpbuf;


// fix, this per-device offset is variable - 24 with msi
#define DEVICE_CONFIG_OFFSET 24


static CLOSURE_1_1(tx_complete, void, struct pbuf *, u64);
static void tx_complete(struct pbuf *p, u64 len)
{
    // unfortunately we dont have control over the allocation
    // path (?)
    // free me!
    pbuf_free(p);
}


static err_t low_level_output(struct netif *netif, struct pbuf *p)
{
    vnet vn = netif->state;
    struct pbuf *q;

    void *address[3];
    boolean writables[3];
    bytes lengths[3];
    int index = 0;

    address[index] = vn->empty;
    writables[index] = false;
    lengths[index] = NET_HEADER_LENGTH;

    pbuf_ref(p);

    for (q = p; index++, q != NULL; q = q->next) {
        address[index] = q->payload;
        writables[index] = false;
        lengths[index] = q->len;
    }

    virtqueue_enqueue(vn->txq, address, lengths, writables, index, closure(vn->dev->general, tx_complete, p));

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

static void receive_buffer_release(struct pbuf *p)
{
    xpbuf x  = (void *)p;
    deallocate(x->vn->rxbuffers, x, x->vn->rxbuflen + sizeof(struct xpbuf));
}

static void post_receive(vnet vn);

static CLOSURE_1_1(input, void, xpbuf, u64);
static void input(xpbuf x, u64 len)
{
    struct eth_hdr *ethhdr;
    vnet vn= x->vn;
    // under what conditions does a virtio queue give us zero?
    if (x != NULL) {
        x->p.pbuf.len = len;
        x->p.pbuf.payload += 10;
        if (vn->n->input(&x->p.pbuf, vn->n) != ERR_OK) {
            receive_buffer_release(&x->p.pbuf);
        }
    } else {
        rprintf ("virtio null\n");
    }
    // we need to get a signal from the device side that there was
    // an underrun here to open up the window
    post_receive(vn);
}


static void post_receive(vnet vn)
{
    u64 len = 1500;
    // use aligned half pages just because
    xpbuf x = allocate(vn->rxbuffers, sizeof(struct xpbuf) + vn->rxbuflen);
    x->vn = vn;
    x->p.custom_free_function = receive_buffer_release;
    struct pbuf* p = pbuf_alloced_custom(PBUF_RAW,
                                         vn->rxbuflen,
                                         PBUF_REF,
                                         &x->p,
                                         x+1,
                                         // this is fucked
                                         vn->rxbuflen);
    void *address[] = {x+1};
    u64 lengths[] = {vn->rxbuflen};
    boolean writables[] = {true};
    virtqueue_enqueue(vn->rxq, address, lengths, writables, 1, closure(vn->dev->general, input, x));    
}

static void status_callback(struct netif *netif)
{
    u8 *n = (u8 *)&netif->ip_addr;
    rprintf("assigned: %d.%d.%d.%d\n", n[0], n[1], n[2], n[3]);
}

static CLOSURE_0_0(timeout, void);
static void timeout()
{
    static int c;
    sys_check_timeouts();
}

static err_t virtioif_init(struct netif *netif)
{
    vnet vn = netif->state;
    netif->hostname = "uniboot"; // from config

    netif->name[0] = 'e';
    netif->name[1] = 'n';
    netif->output = etharp_output;
    netif->linkoutput = low_level_output;
    netif->hwaddr_len = ETHARP_HWADDR_LEN;
    netif->status_callback = status_callback;
    for (int i = 0; i < ETHER_ADDR_LEN; i++) 
        netif->hwaddr[i] =  in8(vn->dev->base+DEVICE_CONFIG_OFFSET+i);
    netif->mtu = 1500;

    /* device capabilities */
    /* don't set NETIF_FLAG_ETHARP if this device is not an ethernet one */
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP | NETIF_FLAG_UP;

    // fix
    post_receive(vn);
    post_receive(vn);
    post_receive(vn);
    register_periodic_timer(milliseconds(500), closure(vn->dev->general, timeout));
    dhcp_start(vn->n); 
    
    return ERR_OK;
}


static heap lwip_heap;

void *lwip_allocate(u64 size)
{
    return allocate_zero(lwip_heap, size);
}

void lwip_deallocate(void *x)
{
    /* no size info; mcache won't care */
    deallocate(lwip_heap, x, -1ull);
}

extern void lwip_init();

static CLOSURE_3_3(init_vnet, void, heap, heap, heap, int, int, int);
static void init_vnet(heap general, heap page_allocator, heap page_allocator_2M,
		      int bus, int slot, int function)
{
    u32 badness = VIRTIO_F_BAD_FEATURE | VIRTIO_NET_F_CSUM | VIRTIO_NET_F_GUEST_CSUM |
        VIRTIO_NET_F_GUEST_TSO4 | VIRTIO_NET_F_GUEST_TSO6 |  VIRTIO_NET_F_GUEST_ECN|
        VIRTIO_NET_F_GUEST_UFO | VIRTIO_NET_F_CTRL_VLAN | VIRTIO_NET_F_MQ;

    vtpci dev = attach_vtpci(general, page_allocator, bus, slot, function, VIRTIO_NET_F_MAC);
    vnet vn = allocate(dev->general, sizeof(struct vnet));
    vn->n = allocate(dev->general, sizeof(struct netif));
    bytes mcache_sizes[] = {8, 16, 32, 64, 128, 256, 512, 1024, -1};
    lwip_heap = allocate_mcache(dev->general, page_allocator, mcache_sizes);
    vn->rxbuflen = 1500;
    vn->rxbuffers = wrap_freelist(dev->general, dev->general, vn->rxbuflen + sizeof(struct xpbuf));
    vn->rxbuffers = allocate_objcache(dev->general, page_allocator_2M,
				      vn->rxbuflen + sizeof(struct xpbuf));
    /* rx = 0, tx = 1, ctl = 2 by 
       page 53 of http://docs.oasis-open.org/virtio/virtio/v1.0/cs01/virtio-v1.0-cs01.pdf */
    vn->dev = dev;
    lwip_init();
    vtpci_alloc_virtqueue(dev, 1, &vn->txq);
    vtpci_alloc_virtqueue(dev, 0, &vn->rxq);
    // just need 10 contig bytes really
    vn->empty = allocate(dev->contiguous, dev->contiguous->pagesize);
    for (int i = 0; i < NET_HEADER_LENGTH ; i++)  ((u8 *)vn->empty)[i] = 0;
    vn->n->state = vn;
    netif_add(vn->n,
              0, 0, 0, 
              vn,
              virtioif_init,
              ethernet_input);
}


void init_virtio_network(heap h, heap page_allocator, heap page_allocator_2M, heap pages)
{
    register_pci_driver(VIRTIO_PCI_VENDORID, VIRTIO_PCI_DEVICEID_NETWORK,
			closure(h, init_vnet, h, page_allocator, page_allocator_2M));
}
