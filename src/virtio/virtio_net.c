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
#include "lwip.h"
#include "lwip/opt.h"
#include "lwip/def.h"
#include "lwip/mem.h"
#include "lwip/pbuf.h"
#include "lwip/stats.h"
#include "lwip/snmp.h"
#include "lwip/ethip6.h"
#include "lwip/etharp.h"
#include "lwip/dhcp.h"
#include "lwip/inet_chksum.h"
#include "lwip/timeouts.h"
#include "netif/ethernet.h"
#include "virtio_internal.h"
#include "virtio_mmio.h"
#include "virtio_net.h"
#include "virtio_pci.h"

#ifdef VIRTIO_NET_DEBUG
# define virtio_net_debug(x, ...) do {tprintf(sym(virtio_net), 0, ss(x), __VA_ARGS__);} while (0)
#else
# define virtio_net_debug(...) do { } while(0)
#endif // defined(VIRTIO_NET_DEBUG)

#define VIRTIO_NET_DRV_FEATURES \
    (VIRTIO_NET_F_GUEST_CSUM | VIRTIO_NET_F_MAC | VIRTIO_NET_F_GUEST_TSO4 |         \
     VIRTIO_NET_F_GUEST_TSO6 | VIRTIO_NET_F_GUEST_ECN | VIRTIO_NET_F_GUEST_UFO |    \
     VIRTIO_NET_F_MRG_RXBUF | VIRTIO_F_ANY_LAYOUT | VIRTIO_F_RING_EVENT_IDX)

typedef struct vnet {
    vtdev dev;
    u16 port;
    caching_heap rxbuffers;
    caching_heap txhandlers;
    closure_struct(mem_cleaner, mem_cleaner);
    bytes net_header_len;
    int rxbuflen;
    u32 rx_seqno;
    struct virtio_net_hdr_mrg_rxbuf *rx_hdr;
    struct netif *n;
    struct virtqueue *txq;
    struct virtqueue *rxq;
    struct virtqueue *ctl;
    u64 empty_phys;
    void *empty; // just a mac..fix, from pre-heap days
} *vnet;

typedef struct xpbuf
{
    struct pbuf_custom p;
    vnet vn;
    closure_struct(vqfinish, input);
    u32 seqno;
} __attribute__((aligned(8))) *xpbuf;


closure_function(1, 1, void, tx_complete,
                 struct pbuf *, p,
                 u64 len)
{
    pbuf_free(bound(p));
    closure_finish();
}


static err_t low_level_output(struct netif *netif, struct pbuf *p)
{
    vnet vn = netif->state;

    vqmsg m = allocate_vqmsg(vn->txq);
    assert(m != INVALID_ADDRESS);
    vqmsg_push(vn->txq, m, vn->empty_phys, vn->net_header_len, false);

    pbuf_ref(p);

    for (struct pbuf * q = p; q != NULL; q = q->next)
        vqmsg_push(vn->txq, m, physical_from_virtual(q->payload), q->len, false);

    vqmsg_commit(vn->txq, m, closure((heap)vn->txhandlers, tx_complete, p));
    
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

static vqmsg vnet_rxq_push(vnet vn, xpbuf x, int *desc_count)
{
    virtqueue rxq = vn->rxq;
    vqmsg m = allocate_vqmsg(rxq);
    if (m == INVALID_ADDRESS)
        return m;
    int rxbuflen = vn->rxbuflen;
    pbuf_alloced_custom(PBUF_RAW, rxbuflen, PBUF_REF, &x->p, x + 1, rxbuflen);
    u64 phys = physical_from_virtual(x + 1);
    if (vtdev_is_modern(vn->dev) || (vn->dev->features & VIRTIO_F_ANY_LAYOUT)) {
        vqmsg_push(rxq, m, phys, rxbuflen, true);
        *desc_count = 1;
    } else {
        int header_len = vn->net_header_len;
        vqmsg_push(rxq, m, phys, header_len, true);
        vqmsg_push(rxq, m, phys + header_len, rxbuflen - header_len, true);
        *desc_count = 2;
    }
    return m;
}

static void receive_buffer_release(struct pbuf *p)
{
    xpbuf x  = (void *)p;
    vnet vn = x->vn;
    virtqueue rxq = vn->rxq;
    if (virtqueue_free_entries(rxq) > 0) {
        int desc_count;
        vqmsg m = vnet_rxq_push(vn, x, &desc_count);
        if (m != INVALID_ADDRESS) {
            vqmsg_commit_seqno(rxq, m, (vqfinish)&x->input, &x->seqno, true);
            return;
        }
    }
    deallocate((heap)vn->rxbuffers, x, vn->rxbuflen + sizeof(struct xpbuf));
}

static int post_receive(vnet vn);

closure_func_basic(vqfinish, void, vnet_input,
                   u64 len)
{
    virtio_net_debug("%s: len %ld\n", func_ss, len);

    xpbuf x = struct_from_field(closure_self(), xpbuf, input);
    vnet vn= x->vn;
    boolean err = false;
    struct virtio_net_hdr *hdr;
    boolean pkt_complete;
    if (vn->dev->features & VIRTIO_NET_F_MRG_RXBUF) {
        /* Ensure received messages are processed in the same order as they are received.
         * This is necessary in order to correctly process packets spread in multiple rx buffers. */
        u32 attempts = 0;
        while ((volatile u32)vn->rx_seqno != x->seqno) {
            if (++attempts == 0) {
                err = true;
                goto out;
            }
            kern_pause();
        }

        struct virtio_net_hdr_mrg_rxbuf *saved_hdr = vn->rx_hdr;
        boolean first_msg = (saved_hdr == 0);
        if (first_msg) {
            saved_hdr = (struct virtio_net_hdr_mrg_rxbuf *)x->p.pbuf.payload;
            if (saved_hdr->num_buffers == 1) {
                pkt_complete = true;
            } else {
                saved_hdr->num_buffers--;
                vn->rx_hdr = saved_hdr;
                pkt_complete = false;
            }
        } else {
            xpbuf head_pbuf = ((xpbuf)saved_hdr) - 1;
            x->p.pbuf.tot_len = x->p.pbuf.len = len;
            pbuf_cat(&head_pbuf->p.pbuf, &x->p.pbuf);
            if (--saved_hdr->num_buffers > 0) {
                pkt_complete = false;
            } else {
                hdr = &saved_hdr->hdr;
                x = head_pbuf;
                len = head_pbuf->p.pbuf.tot_len;
                vn->rx_hdr = 0;
                pkt_complete = true;
            }
        }
        vn->rx_seqno++;
        if (!first_msg)
            goto msg_processed;
    } else {
        pkt_complete = true;
    }
    hdr = (struct virtio_net_hdr *)x->p.pbuf.payload;
    len -= vn->net_header_len;
    assert(len <= x->p.pbuf.len);
    x->p.pbuf.tot_len = x->p.pbuf.len = len;
    x->p.pbuf.payload += vn->net_header_len;
  msg_processed:
    if (!pkt_complete) {
        post_receive(vn);
        return;
    }
    if (hdr->flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) {
        if (hdr->csum_start + hdr->csum_offset <= len - sizeof(u16)) {
            u16 offset = hdr->csum_start;
            struct pbuf *q = &x->p.pbuf;
            while (q->len <= offset) {
                offset -= q->len;
                q = q->next;
            }
            q->payload += offset;
            q->len -= offset;
            u16 csum = inet_chksum_pbuf(q);
            q->payload -= offset;
            q->len += offset;
            offset = hdr->csum_start + hdr->csum_offset;
            q = &x->p.pbuf;
            while (q->len <= offset) {
                offset -= q->len;
                q = q->next;
            }
            if (offset + sizeof(csum) <= q->len) {
                *(u16 *)(q->payload + offset) = csum;
            } else {
                *(u8 *)(q->payload + offset) = csum;
                *(u8 *)q->next->payload = csum >> 8;
            }
        } else {
            err = true;
        }
    }
    if (!err)
        err = (vn->n->input(&x->p.pbuf, vn->n) != ERR_OK);
  out:
    if (err)
        receive_buffer_release(&x->p.pbuf);
    // we need to get a signal from the device side that there was
    // an underrun here to open up the window
    post_receive(vn);
}


static int post_receive(vnet vn)
{
    virtqueue rxq = vn->rxq;
    u16 free_entries = virtqueue_free_entries(rxq);
    int new_entries = 0;
    int rxbuflen = vn->rxbuflen;
    while (new_entries < free_entries) {
        xpbuf x = allocate((heap)vn->rxbuffers, sizeof(struct xpbuf) + rxbuflen);
        if (x == INVALID_ADDRESS)
            break;
        x->vn = vn;
        x->p.custom_free_function = receive_buffer_release;
        int desc_count;
        vqmsg m = vnet_rxq_push(vn, x, &desc_count);
        if (m == INVALID_ADDRESS)
            break;
        new_entries += desc_count;
        vqmsg_commit_seqno(rxq, m, init_closure_func(&x->input, vqfinish, vnet_input), &x->seqno,
                           new_entries >= free_entries);
    }
    if ((new_entries > 0) && (new_entries < free_entries))
        virtqueue_kick(rxq);
    return new_entries;
}

closure_func_basic(mem_cleaner, u64, vnet_mem_cleaner,
                   u64 clean_bytes)
{
    vnet vn = struct_from_field(closure_self(), vnet, mem_cleaner);
    return cache_drain(vn->rxbuffers, clean_bytes,
                       NET_RX_BUFFERS_RETAIN * (sizeof(struct xpbuf) + vn->rxbuflen));
}

static err_t virtioif_init(struct netif *netif)
{
    vnet vn = netif->state;
    netif->hostname = sstring_empty();

    netif->name[0] = 'e';
    netif->name[1] = 'n';
    netif->output = etharp_output;
    netif->linkoutput = low_level_output;
    netif->hwaddr_len = ETHARP_HWADDR_LEN;
    vtdev_cfg_read_mem(vn->dev, 0, netif->hwaddr, ETHER_ADDR_LEN);
    virtio_net_debug("%s: hwaddr %02x:%02x:%02x:%02x:%02x:%02x\n",
        func_ss,
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
    return ERR_OK;
}

static inline u64 find_page_size(bytes each, int n)
{
    /* extra element to cover objcache meta */
    return MIN(1ul << find_order(each * (n + 1)), PAGESIZE_2M);
}

static void virtio_net_attach(vtdev dev)
{
    //u32 badness = VIRTIO_F_BAD_FEATURE | VIRTIO_NET_F_CSUM | VIRTIO_NET_F_GUEST_CSUM |
    //    VIRTIO_NET_F_GUEST_TSO4 | VIRTIO_NET_F_GUEST_TSO6 |  VIRTIO_NET_F_GUEST_ECN|
    //    VIRTIO_NET_F_GUEST_UFO | VIRTIO_NET_F_CTRL_VLAN | VIRTIO_NET_F_MQ;

    heap h = dev->general;
    backed_heap contiguous = dev->contiguous;
    vnet vn = allocate(h, sizeof(struct vnet));
    assert(vn != INVALID_ADDRESS);
    vn->n = allocate(h, sizeof(struct netif));
    assert(vn->n != INVALID_ADDRESS);
    vn->net_header_len = (dev->features & VIRTIO_F_VERSION_1) ||
        (dev->features & VIRTIO_NET_F_MRG_RXBUF) != 0 ?
        sizeof(struct virtio_net_hdr_mrg_rxbuf) : sizeof(struct virtio_net_hdr);

    /* RX buffer length should be a multiple of 8 bytes to make xpbuf structures aligned to 8 bytes
     */
    if (!(dev->features & (VIRTIO_NET_F_GUEST_TSO4 | VIRTIO_NET_F_GUEST_TSO6 |
                           VIRTIO_NET_F_GUEST_UFO)) ||
        (dev->features & VIRTIO_NET_F_MRG_RXBUF))
        vn->rxbuflen = pad(vn->net_header_len + sizeof(struct eth_hdr) +
                           sizeof(struct eth_vlan_hdr) + 1500, 8);
    else
        vn->rxbuflen = U16_MAX & ~0x7;  /* lwIP maximum packet length is U16_MAX */

    mm_register_mem_cleaner(init_closure_func(&vn->mem_cleaner, mem_cleaner, vnet_mem_cleaner));
    /* rx = 0, tx = 1, ctl = 2 by 
       page 53 of http://docs.oasis-open.org/virtio/virtio/v1.0/cs01/virtio-v1.0-cs01.pdf */
    vn->dev = dev;
    virtio_alloc_virtqueue(dev, ss("virtio net tx"), 1, &vn->txq);
    virtqueue_set_polling(vn->txq, true);
    virtio_alloc_virtqueue(dev, ss("virtio net rx"), 0, &vn->rxq);
    virtio_net_debug("%s: rx q entries %d, tx q entries %d\n", func_ss,
                     virtqueue_entries(vn->rxq), virtqueue_entries(vn->txq));
    bytes rx_allocsize = vn->rxbuflen + sizeof(struct xpbuf);
    bytes rxbuffers_pagesize = find_page_size(rx_allocsize, virtqueue_entries(vn->rxq));
    bytes tx_handler_size = sizeof(closure_struct_type(tx_complete));
    bytes tx_handler_pagesize = find_page_size(tx_handler_size, virtqueue_entries(vn->txq));
    virtio_net_debug("%s: net_header_len %d, rx_allocsize %d, rxbuffers_pagesize %d "
                     "tx_handler_size %d tx_handler_pagesize %d\n", func_ss, vn->net_header_len,
                     rx_allocsize, rxbuffers_pagesize, tx_handler_size, tx_handler_pagesize);
    vn->rxbuffers = allocate_objcache(h, (heap)contiguous, rx_allocsize, rxbuffers_pagesize, true);
    assert(vn->rxbuffers != INVALID_ADDRESS);
    vn->rx_seqno = 0;
    vn->rx_hdr = 0;
    vn->txhandlers = allocate_objcache(h, (heap)contiguous, tx_handler_size, tx_handler_pagesize, true);
    assert(vn->txhandlers != INVALID_ADDRESS);
    vn->empty = alloc_map(contiguous, contiguous->h.pagesize, &vn->empty_phys);
    assert(vn->empty != INVALID_ADDRESS);
    for (int i = 0; i < vn->net_header_len; i++)
        ((u8 *)vn->empty)[i] = 0;
    vn->n->state = vn;
    vtdev_set_status(dev, VIRTIO_CONFIG_STATUS_DRIVER_OK);
    netif_add(vn->n,
              0, 0, 0, 
              vn,
              virtioif_init,
              ethernet_input);
    assert(post_receive(vn) > 0);
}

closure_function(2, 1, boolean, vtpci_net_probe,
                 heap, general, backed_heap, page_allocator,
                 pci_dev d)
{
    if (!vtpci_probe(d, VIRTIO_ID_NETWORK))
        return false;
    vtpci dev = attach_vtpci(bound(general), bound(page_allocator), d,
        VIRTIO_NET_DRV_FEATURES);
    virtio_net_attach(&dev->virtio_dev);
    return true;
}

closure_function(2, 1, void, vtmmio_net_probe,
                 heap, general, backed_heap, page_allocator,
                 vtmmio d)
{
    if ((vtmmio_get_u32(d, VTMMIO_OFFSET_DEVID) != VIRTIO_ID_NETWORK) ||
            (d->memsize < VTMMIO_OFFSET_CONFIG +
            sizeof(struct virtio_net_config)))
        return;
    if (attach_vtmmio(bound(general), bound(page_allocator), d,
        VIRTIO_NET_DRV_FEATURES))
        virtio_net_attach(&d->virtio_dev);
}

void init_virtio_network(kernel_heaps kh)
{
    heap h = heap_locked(kh);
    backed_heap page_allocator = heap_linear_backed(kh);
    register_pci_driver(closure(h, vtpci_net_probe, h, page_allocator), 0);
    vtmmio_probe_devs(stack_closure(vtmmio_net_probe, h, page_allocator));
}
