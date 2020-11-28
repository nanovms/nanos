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
#include "virtio_mmio.h"
#include "virtio_net.h"
#include "virtio_pci.h"

#include <io.h>

#ifdef VIRTIO_NET_DEBUG
# define virtio_net_debug rprintf
#else
# define virtio_net_debug(...) do { } while(0)
#endif // defined(VIRTIO_NET_DEBUG)

typedef struct vnet {
    vtdev dev;
    u16 port;
    heap rxbuffers;
    bytes net_header_len;
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
    vqmsg_push(vn->txq, m, vn->empty, vn->net_header_len, false);

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

static u16 vnet_csum(u8 *buf, u64 len)
{
    u64 sum = 0;
    while (len >= sizeof(u64)) {
        u64 s = *(u64 *)buf;
        sum += s;
        if (sum < s)
            sum++;
        buf += sizeof(u64);
        len -= sizeof(u64);
    }
    if (len >= sizeof(u32)) {
        u32 s = *(u32 *)buf;
        sum += s;
        if (sum < s)
            sum++;
        buf += sizeof(u32);
        len -= sizeof(u32);
    }
    if (len >= sizeof(u16)) {
        u16 s = *(u16 *)buf;
        sum += s;
        if (sum < s)
            sum++;
        buf += sizeof(u16);
        len -= sizeof(u16);
    }
    if (len) {
        u8 s = *buf;
        sum += s;
        if (sum < s)
            sum++;
    }

    /* Fold down to 16 bits */
    u32 s1 = sum;
    u32 s2 = sum >> 32;
    s1 += s2;
    if (s1 < s2)
        s1++;
    u16 s3 = s1;
    u16 s4 = s1 >> 16;
    s3 += s4;
    if (s3 < s4)
        s3++;
    return ~s3;
}

closure_function(1, 1, void, input,
                 xpbuf, x,
                 u64, len)
{
    virtio_net_debug("%s: len %ld\n", __func__, len);

    xpbuf x = bound(x);
    vnet vn= x->vn;
    // under what conditions does a virtio queue give us zero?
    if (x != NULL) {
        struct virtio_net_hdr *hdr = (struct virtio_net_hdr *)x->p.pbuf.payload;
        boolean err = false;
        len -= vn->net_header_len;
        assert(len <= x->p.pbuf.len);
        x->p.pbuf.tot_len = x->p.pbuf.len = len;
        x->p.pbuf.payload += vn->net_header_len;
        if (hdr->flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) {
            if (hdr->csum_start + hdr->csum_offset <= len - sizeof(u16)) {
                u16 csum = vnet_csum(x->p.pbuf.payload + hdr->csum_start,
                    len - hdr->csum_start);
                *(u16 *)(x->p.pbuf.payload + hdr->csum_start +
                        hdr->csum_offset) = csum;
            } else
                err = true;
        }
        if (!err)
            err = (vn->n->input(&x->p.pbuf, vn->n) != ERR_OK);
        if (err) {
            receive_buffer_release(&x->p.pbuf);
        }
    } else {
        rprintf("virtio null\n");
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
    vtdev_cfg_read_mem(vn->dev, netif->hwaddr, ETHER_ADDR_LEN);
    virtio_net_debug("%s: hwaddr %02x:%02x:%02x:%02x:%02x:%02x\n",
        __func__,
        netif->hwaddr[0], netif->hwaddr[1], netif->hwaddr[2],
        netif->hwaddr[3], netif->hwaddr[4], netif->hwaddr[5]);

    /* We're defaulting to Google Cloud's maximum MTU so as to
       minimize issues for new users. If you require an MTU of 1500
       (or some other value) for your system, you may override it by
       setting 'mtu' in the root tuple (see init_network_iface).

       See https://cloud.google.com/compute/docs/troubleshooting/general-tips
    */
    netif->mtu = 1460;

    /* device capabilities */
    /* don't set NETIF_FLAG_ETHARP if this device is not an ethernet one */
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP | NETIF_FLAG_UP;

    for (int i = 0; i < virtqueue_entries(vn->rxq); i++)
        post_receive(vn);
    
    return ERR_OK;
}

static void virtio_net_attach(vtdev dev)
{
    //u32 badness = VIRTIO_F_BAD_FEATURE | VIRTIO_NET_F_CSUM | VIRTIO_NET_F_GUEST_CSUM |
    //    VIRTIO_NET_F_GUEST_TSO4 | VIRTIO_NET_F_GUEST_TSO6 |  VIRTIO_NET_F_GUEST_ECN|
    //    VIRTIO_NET_F_GUEST_UFO | VIRTIO_NET_F_CTRL_VLAN | VIRTIO_NET_F_MQ;

    heap h = dev->general;
    heap contiguous = dev->contiguous;
    vnet vn = allocate(h, sizeof(struct vnet));
    vn->n = allocate(h, sizeof(struct netif));
    vn->net_header_len = (dev->features & VIRTIO_F_VERSION_1) ||
        (dev->features & VIRTIO_NET_F_MRG_RXBUF) != 0 ?
        sizeof(struct virtio_net_hdr_mrg_rxbuf) : sizeof(struct virtio_net_hdr);
    vn->rxbuflen = vn->net_header_len + sizeof(struct eth_hdr) + sizeof(struct eth_vlan_hdr) + 1500;
    virtio_net_debug("%s: net_header_len %d, rxbuflen %d\n", __func__, vn->net_header_len, vn->rxbuflen);
    vn->rxbuffers = allocate_objcache(h, contiguous,
				      vn->rxbuflen + sizeof(struct xpbuf), PAGESIZE_2M);
    /* rx = 0, tx = 1, ctl = 2 by 
       page 53 of http://docs.oasis-open.org/virtio/virtio/v1.0/cs01/virtio-v1.0-cs01.pdf */
    vn->dev = dev;
    virtio_alloc_virtqueue(dev, "virtio net tx", 1, runqueue, &vn->txq);
    virtio_alloc_virtqueue(dev, "virtio net rx", 0, runqueue, &vn->rxq);
    // just need vn->net_header_len contig bytes really
    vn->empty = allocate(contiguous, contiguous->pagesize);
    for (int i = 0; i < vn->net_header_len; i++)  ((u8 *)vn->empty)[i] = 0;
    vn->n->state = vn;
    // initialization complete
    vtdev_set_status(dev, VIRTIO_CONFIG_STATUS_DRIVER_OK);

    netif_add(vn->n,
              0, 0, 0, 
              vn,
              virtioif_init,
              ethernet_input);
}

closure_function(2, 1, boolean, vtpci_net_probe,
                 heap, general, heap, page_allocator,
                 pci_dev, d)
{
    if (!vtpci_probe(d, VIRTIO_ID_NETWORK))
        return false;
    vtpci dev = attach_vtpci(bound(general), bound(page_allocator), d,
        VIRTIO_NET_F_MAC);
    virtio_net_attach(&dev->virtio_dev);
    return true;
}

closure_function(2, 1, void, vtmmio_net_probe,
                 heap, general, heap, page_allocator,
                 vtmmio, d)
{
    if ((vtmmio_get_u32(d, VTMMIO_OFFSET_DEVID) != VIRTIO_ID_NETWORK) ||
            (d->memsize < VTMMIO_OFFSET_CONFIG +
            sizeof(struct virtio_net_config)))
        return;
    if (attach_vtmmio(bound(general), bound(page_allocator), d,
            VIRTIO_NET_F_MAC))
        virtio_net_attach(&d->virtio_dev);
}

void init_virtio_network(kernel_heaps kh)
{
    heap h = heap_locked(kh);
    heap page_allocator = heap_backed(kh);
    register_pci_driver(closure(h, vtpci_net_probe, h, page_allocator));
    vtmmio_probe_devs(stack_closure(vtmmio_net_probe, h, page_allocator));
}
