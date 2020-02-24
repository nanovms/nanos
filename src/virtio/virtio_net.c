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

#include <kernel.h>
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
#include "virtio_internal.h"
#include "virtio_net.h"

#include <io.h>

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
    vnet vn;
} *xpbuf;


closure_function(1, 1, void, tx_complete,
                 struct pbuf *, p,
                 u64, len)
{
    // unfortunately we dont have control over the allocation
    // path (?)
    // free me!
    pbuf_free(bound(p));
    closure_finish();
}


static err_t low_level_output(struct netif *netif, struct pbuf *p)
{
    vnet vn = netif->state;

    vqmsg m = allocate_vqmsg(vn->txq);
    assert(m != INVALID_ADDRESS);
    vqmsg_push(vn->txq, m, vn->empty, NET_HEADER_LENGTH, false);

    pbuf_ref(p);

    for (struct pbuf * q = p; q != NULL; q = q->next)
        vqmsg_push(vn->txq, m, q->payload, q->len, false);

    vqmsg_commit(vn->txq, m, closure(vn->dev->general, tx_complete, p));
    
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

closure_function(1, 1, void, input,
                 xpbuf, x,
                 u64, len)
{
    xpbuf x = bound(x);
    vnet vn= x->vn;
    // under what conditions does a virtio queue give us zero?
    if (x != NULL) {
        len -= NET_HEADER_LENGTH;
        assert(len <= x->p.pbuf.len);
        x->p.pbuf.tot_len = x->p.pbuf.len = len;
        x->p.pbuf.payload += NET_HEADER_LENGTH;
        if (vn->n->input(&x->p.pbuf, vn->n) != ERR_OK) {
            receive_buffer_release(&x->p.pbuf);
        }
    } else {
        rprintf ("virtio null\n");
    }
    // we need to get a signal from the device side that there was
    // an underrun here to open up the window
    post_receive(vn);
    closure_finish();
}


static void post_receive(vnet vn)
{
    xpbuf x = allocate(vn->rxbuffers, sizeof(struct xpbuf) + vn->rxbuflen);
    x->vn = vn;
    x->p.custom_free_function = receive_buffer_release;
    pbuf_alloced_custom(PBUF_RAW,
                        vn->rxbuflen,
                        PBUF_REF,
                        &x->p,
                        x+1,
                        vn->rxbuflen);

    vqmsg m = allocate_vqmsg(vn->rxq);
    assert(m != INVALID_ADDRESS);
    vqmsg_push(vn->rxq, m, x+1, vn->rxbuflen, true);
    vqmsg_commit(vn->rxq, m, closure(vn->dev->general, input, x));
}

void lwip_status_callback(struct netif *netif);

static err_t virtioif_init(struct netif *netif)
{
    vnet vn = netif->state;
    netif->hostname = "uniboot"; // from config

    netif->name[0] = 'e';
    netif->name[1] = 'n';
    netif->output = etharp_output;
    netif->linkoutput = low_level_output;
    netif->hwaddr_len = ETHARP_HWADDR_LEN;
    netif->status_callback = lwip_status_callback;
    for (int i = 0; i < ETHER_ADDR_LEN; i++) 
        netif->hwaddr[i] =  in8(vn->dev->base + VIRTIO_MSI_DEVICE_CONFIG + i);
    netif->mtu = 1500;

    /* device capabilities */
    /* don't set NETIF_FLAG_ETHARP if this device is not an ethernet one */
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP | NETIF_FLAG_UP;

    for (int i = 0; i < virtqueue_entries(vn->rxq); i++)
        post_receive(vn);
    
    return ERR_OK;
}

static void virtio_net_attach(heap general, heap page_allocator, pci_dev d)
{
    //u32 badness = VIRTIO_F_BAD_FEATURE | VIRTIO_NET_F_CSUM | VIRTIO_NET_F_GUEST_CSUM |
    //    VIRTIO_NET_F_GUEST_TSO4 | VIRTIO_NET_F_GUEST_TSO6 |  VIRTIO_NET_F_GUEST_ECN|
    //    VIRTIO_NET_F_GUEST_UFO | VIRTIO_NET_F_CTRL_VLAN | VIRTIO_NET_F_MQ;

    vtpci dev = attach_vtpci(general, page_allocator, d, VIRTIO_NET_F_MAC);
    vnet vn = allocate(dev->general, sizeof(struct vnet));
    vn->n = allocate(dev->general, sizeof(struct netif));
    vn->rxbuflen = NET_HEADER_LENGTH + sizeof(struct eth_hdr) + sizeof(struct eth_vlan_hdr) + 1500;
    vn->rxbuffers = allocate_objcache(dev->general, page_allocator,
				      vn->rxbuflen + sizeof(struct xpbuf), PAGESIZE_2M);
    /* rx = 0, tx = 1, ctl = 2 by 
       page 53 of http://docs.oasis-open.org/virtio/virtio/v1.0/cs01/virtio-v1.0-cs01.pdf */
    vn->dev = dev;
    vtpci_alloc_virtqueue(dev, "virtio net tx", 1, &vn->txq);
    vtpci_alloc_virtqueue(dev, "virtio net rx", 0, &vn->rxq);
    // just need 10 contig bytes really
    vn->empty = allocate(dev->contiguous, dev->contiguous->pagesize);
    for (int i = 0; i < NET_HEADER_LENGTH ; i++)  ((u8 *)vn->empty)[i] = 0;
    vn->n->state = vn;
    // initialization complete
    vtpci_set_status(dev, VIRTIO_CONFIG_STATUS_DRIVER_OK);

    netif_add(vn->n,
              0, 0, 0, 
              vn,
              virtioif_init,
              ethernet_input);
}

closure_function(2, 1, boolean, virtio_net_probe,
                 heap, general, heap, page_allocator,
                 pci_dev, d)
{
    if (pci_get_vendor(d) != VIRTIO_PCI_VENDORID || pci_get_device(d) != VIRTIO_PCI_DEVICEID_NETWORK)
        return false;

    virtio_net_attach(bound(general), bound(page_allocator), d);
    return true;
}

void init_virtio_network(kernel_heaps kh)
{
    heap h = heap_general(kh);
    register_pci_driver(closure(h, virtio_net_probe, h, heap_backed(kh)));
}

/* XXX move these to a general net area */
err_t init_static_config(tuple root, struct netif *n) {
    ip4_addr_t ip;
    ip4_addr_t netmask;
    ip4_addr_t gw;
    value v;

    if(!(v = table_find(root, sym(ipaddr)))) return ERR_ARG;
    ip4addr_aton((char *)v, &ip);

    if(!(v= table_find(root, sym(gateway)))) return ERR_ARG;
    ip4addr_aton((char *)v, &gw);

    if(!(v= table_find(root, sym(netmask)))) return ERR_ARG;
    ip4addr_aton((char *)v, &netmask);
    
    netif_set_addr(n, &ip, &netmask, &gw);
    netif_set_up(n); 
    return ERR_OK;       
}

void init_network_iface(tuple root) {
    struct netif *n = netif_find("en0");
    if (!n) {
        rprintf("no network interface found\n");
        return;
    }
    netif_set_default(n);
    if (ERR_OK != init_static_config(root, n)) {
         dhcp_start(n);
    } 
}
