#include <kernel.h>
#include <page.h>
#include <hyperv_internal.h>
#include <hyperv.h>
#include <lwip/opt.h>
#include <lwip/def.h>
#include <lwip/mem.h>
#include <lwip/pbuf.h>
#include <lwip/stats.h>
#include <lwip/snmp.h>
#include <lwip/etharp.h>
#include <netif/ethernet.h>
#include "hv_net_vsc.h"
#include "hv_rndis.h"
#include "hv_rndis_filter.h"

//#define NETVSC_DEBUG
#ifdef NETVSC_DEBUG
#define netvsc_debug(x, ...) do {rprintf(" NETVSC: " x "\n", ##__VA_ARGS__);} while(0)
#else
#define netvsc_debug(x, ...)
#endif

#define DEVICE_NAME "en"

/*
 * It looks like offset 0 of buf is reserved to hold the softc pointer.
 * The sc pointer evidently not needed, and is not presently populated.
 * The packet offset is where the netvsc_packet starts in the buffer.
 */
#define NETVSC_NV_SC_PTR_OFFSET_IN_BUF         0
#define NETVSC_NV_PACKET_OFFSET_IN_BUF         16

#define NETVSC_NV_BUF_SIZE_NO_VLAN             (NETVSC_NV_PACKET_OFFSET_IN_BUF + sizeof(netvsc_packet) \
                                            + sizeof(rndis_filter_packet))

/*
 * Maximum MTU we permit to be configured for a netvsc interface.
 * When the code was developed, a max MTU of 12232 was tested and
 * proven to work.  9K is a reasonable maximum for an Ethernet.
 */
#define NETVSC_MAX_CONFIGURABLE_MTU     (9 * 1024)

#define NETVSC_RX_MAXSEGSIZE       NETVSC_MAX_CONFIGURABLE_MTU

int hv_promisc_mode = 0;

typedef struct xpbuf
{
    struct pbuf_custom p;
    hn_softc_t *hn;
} *xpbuf;

static void
receive_buffer_release(struct pbuf *p)
{
    xpbuf x  = (void *)p;
    u64 flags = spin_lock_irq(&x->hn->rx_buflock);
    deallocate(x->hn->rxbuffers, x, x->hn->rxbuflen + sizeof(struct xpbuf));
    spin_unlock_irq(&x->hn->rx_buflock, flags);
}

static xpbuf
receive_buffer_alloc(hn_softc_t *hn)
{
    u64 flags = spin_lock_irq(&hn->rx_buflock);
    xpbuf x = allocate(hn->rxbuffers, sizeof(struct xpbuf) + hn->rxbuflen);
    assert(x != INVALID_ADDRESS);
    x->hn = hn;
    x->p.custom_free_function = receive_buffer_release;
    pbuf_alloced_custom(PBUF_RAW,
                        hn->rxbuflen,
                        PBUF_REF,
                        &x->p,
                        x+1,
                        hn->rxbuflen);
    spin_unlock_irq(&hn->rx_buflock, flags);
    return x;
}

/*
 * Send completion processing
 *
 * Note:  It looks like offset 0 of buf is reserved to hold the softc
 * pointer.  The sc pointer is not currently needed in this function, and
 * it is not presently populated by the TX function.
 */
void
netvsc_xmit_completion(void *context)
{
    netvsc_packet *packet = (netvsc_packet *)context;

    uint8_t *buf = ((uint8_t *)packet) - NETVSC_NV_PACKET_OFFSET_IN_BUF;

    deallocate(packet->device->device->general, buf, NETVSC_NV_BUF_SIZE_NO_VLAN);
}

static err_t
low_level_output(struct netif *netif, struct pbuf *p)
{
    hn_softc_t *hn = netif->state;

    /* Walk the mbuf list computing total length and num frags */
    int num_frags = 0;
    int len = 0;
    for (struct pbuf * q = p; q != NULL; q = q->next) {
        if (q->len != 0) {
            num_frags++;
            len += q->len;
        }
    }

    /*
     * Reserve the number of pages requested.  Currently,
     * one page is reserved for the message in the RNDIS
     * filter packet
     */
    num_frags += HV_RF_NUM_TX_RESERVED_PAGE_BUFS;

    /* If exceeds # page_buffers in netvsc_packet */
    if (num_frags > NETVSC_PACKET_MAXPAGE) {
        return ERR_BUF;
    }

    /*
     * Allocate a buffer with space for a netvsc packet plus a
     * number of reserved areas.  First comes a (currently 16
     * bytes, currently unused) reserved data area.  Second is
     * the netvsc_packet, which includes (currently 4) page
     * buffers.  Third (optional) is a rndis_per_packet_info
     * struct, but only if a VLAN tag should be inserted into the
     * Ethernet frame by the Hyper-V infrastructure.  Fourth is
     * an area reserved for an rndis_filter_packet struct.
     * Changed malloc to M_NOWAIT to avoid sleep under spin lock.
     * No longer reserving extra space for page buffers, as they
     * are already part of the netvsc_packet.
     */
    uint8_t *buf = allocate_zero(hn->general, NETVSC_NV_BUF_SIZE_NO_VLAN);
    assert(buf != INVALID_ADDRESS);

    netvsc_packet *packet = (netvsc_packet *)(buf + NETVSC_NV_PACKET_OFFSET_IN_BUF);
    *(vm_offset_t *)buf = NETVSC_NV_SC_PTR_OFFSET_IN_BUF;

    /*
     * extension points to the area reserved for the
     * rndis_filter_packet, which is placed just after
     * the netvsc_packet (and rppi struct, if present;
     * length is updated later).
     */
    packet->extension = packet + 1;
    /* Set up the rndis header */
    packet->page_buf_count = num_frags;

    /* Initialize it from the mbuf */
    packet->tot_data_buf_len = len;

    /*
     * Fill the page buffers with mbuf info starting at index
     * HV_RF_NUM_TX_RESERVED_PAGE_BUFS.
     */
    int i = HV_RF_NUM_TX_RESERVED_PAGE_BUFS;
    for (struct pbuf * q = p; q != NULL; q = q->next) {
        if (q->len) {
            u64 paddr = physical_from_virtual(q->payload);
            assert(paddr != INVALID_PHYSICAL);
            packet->page_buffers[i].gpa_page =
                paddr >> PAGELOG;
            packet->page_buffers[i].gpa_ofs =
                paddr & (PAGESIZE - 1);
            packet->page_buffers[i].gpa_len = q->len;
            i++;
        }
    }

    packet->device = hn->hn_dev_obj;

    int retries = 0;
retry_send:
    /* Set the completion routine */
    packet->compl.send.on_send_completion = netvsc_xmit_completion;
    packet->compl.send.send_completion_context = packet;
    packet->compl.send.send_completion_tid = (uint64_t)p;

    /* Removed critical_enter(), does not appear necessary */
    int ret = hv_rf_on_send(hn->hn_dev_obj, packet);

    if (ret == 0) {
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
    } else {
        retries++;
        if (retries < 4) {
            goto retry_send;
        }

        /*
         * Null the mbuf pointer so the completion function
         * does not free the mbuf chain.  We just pushed the
         * mbuf chain back on the if_snd queue.
         */
        packet->compl.send.send_completion_tid = 0;

        /*
         * Release the resources since we will not get any
         * send completion
         */
        netvsc_xmit_completion(packet);

        // TODO - error code?
        netvsc_debug("%s: hv_rf_on_send() failed %d times, giving up", __func__, retries);
        return ERR_TIMEOUT;
    }

    return ERR_OK;
}

void lwip_status_callback(struct netif *netif);

static err_t
vmxif_init(struct netif *netif)
{
    netif->hostname = "uniboot"; // from config

    netif->name[0] = DEVICE_NAME[0];
    netif->name[1] = DEVICE_NAME[1];
    netif->output = etharp_output;
    netif->linkoutput = low_level_output;
    netif->hwaddr_len = ETHARP_HWADDR_LEN;
    netif->status_callback = lwip_status_callback;
    netif->mtu = 1500;

    /* device capabilities */
    /* don't set NETIF_FLAG_ETHARP if this device is not an ethernet one */
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP | NETIF_FLAG_UP;

    return ERR_OK;
}

static status
netvsc_attach(kernel_heaps kh, hv_device* device)
{
    heap h = heap_general(kh);

    hn_softc_t *hn = allocate(h, sizeof(hn_softc_t));
    assert(hn != INVALID_ADDRESS);

    hn->general = heap_general(kh);
    hn->contiguous = heap_backed(kh);

    hn->hn_dev_obj = device;
    device->device = hn;

    hn->rxbuflen = NETVSC_RX_MAXSEGSIZE;
    hn->rxbuffers = allocate_objcache(hn->general, hn->contiguous,
                      hn->rxbuflen + sizeof(struct xpbuf), PAGESIZE_2M);
    spin_lock_init(&hn->rx_buflock);

    struct netif *netif = allocate(h, sizeof(struct netif));
    assert(netif != INVALID_ADDRESS);
    hn->netif = netif;

    int ret = hv_rf_on_device_add(device, hn->netif);
    if (ret != 0)
        return timm("err", "err");

    ret = hv_rf_on_open(device);
    if (ret != 0)
        return timm("err", "err");

    netif_add(hn->netif,
              0, 0, 0,
              hn,
              vmxif_init,
              ethernet_input);

    netvsc_debug("%s: hwaddr %02x:%02x:%02x:%02x:%02x:%02x", __func__,
                 netif->hwaddr[0], netif->hwaddr[1], netif->hwaddr[2],
                 netif->hwaddr[3], netif->hwaddr[4], netif->hwaddr[5]);
    return STATUS_OK;
}

closure_function(1, 3, boolean, netvsc_probe,
                 kernel_heaps, kh,
                 struct hv_device*, device,
                 storage_attach, unused,
                 boolean*, unused1)
{
    status s = netvsc_attach(bound(kh), device);
    if (!is_ok(s)) {
        msg_err("attach failed with status %v\n", s);
        return false;
    }
    return true;
}

/* {F8615163-DF3E-46c5-913F-F2D2F965ED0E} */
static const struct hyperv_guid hn_guid = {
    .hv_guid = {
        0x63, 0x51, 0x61, 0xf8, 0x3e, 0xdf, 0xc5, 0x46,
        0x91, 0x3f, 0xf2, 0xd2, 0xf9, 0x65, 0xed, 0x0e }
};

void init_netvsc(kernel_heaps kh)
{
    register_vmbus_driver(&hn_guid, closure(heap_general(kh), netvsc_probe, kh));
}

/*
 * Append the specified data to the indicated mbuf chain,
 * Extend the mbuf chain if the new data does not fit in
 * existing space.
 *
 * This is a minor rewrite of m_append() from sys/kern/uipc_mbuf.c.
 * There should be an equivalent in the kernel mbuf code,
 * but there does not appear to be one yet.
 *
 * Differs from m_append() in that additional mbufs are
 * allocated with cluster size MJUMPAGESIZE, and filled
 * accordingly.
 *
 * Return 1 if able to complete the job; otherwise 0.
 */
static int
netvsc_m_append(hn_softc_t *hn, xpbuf m0, int len, uint8_t *cp)
{
    xpbuf m;

    for (m = m0; m->p.pbuf.next != NULL; m = (xpbuf)m->p.pbuf.next)
        ;
    int remainder = len;
    int space = hn->rxbuflen - m->p.pbuf.len;
    if (space > 0) {
        /*
         * Copy into available space.
         */
        if (space > remainder)
            space = remainder;
        runtime_memcpy(m->p.pbuf.payload + m->p.pbuf.len, cp, space);
        m->p.pbuf.len += space;
        m->p.pbuf.tot_len += space;
        m0->p.pbuf.tot_len += space;
        cp += space;
        remainder -= space;
    }
    while (remainder > 0) {
        /*
         * Allocate a new mbuf; could check space
         * and allocate a cluster instead.
         */
        xpbuf n = receive_buffer_alloc(hn);

        struct pbuf* np = &n->p.pbuf;
        np->len = MIN(sizeof(struct xpbuf) + hn->rxbuflen, remainder);
        np->tot_len = np->len;
        m0->p.pbuf.tot_len += np->len;
        runtime_memcpy(np->payload, cp, np->len);
        cp += np->len;
        remainder -= np->len;
        m->p.pbuf.next = np;
        m = n;
    }
    return (remainder == 0);
}

int
netvsc_recv(struct hv_device *device_ctx, netvsc_packet *packet)
{
    hn_softc_t *hn = device_ctx->device;

    /*
     * Bail out if packet contains more data than configured MTU.
     */
    if (packet->tot_data_buf_len > (hn->netif->mtu + SIZEOF_ETH_HDR)) {
        return (0);
    }

    xpbuf x = receive_buffer_alloc(hn);
    x->p.pbuf.len = 0;
    x->p.pbuf.tot_len = 0;

   /*
     * Remove trailing junk from RX data buffer.
     * Fixme:  This will not work for multiple Hyper-V RX buffers.
     * Fortunately, the channel gathers all RX data into one buffer.
     *
     * L2 frame length, with L2 header, not including CRC
     */
    packet->page_buffers[0].gpa_len = packet->tot_data_buf_len;

    /*
     * Copy the received packet to one or more mbufs.
     * The copy is required since the memory pointed to by netvsc_packet
     * cannot be deallocated
     */
    for (int i=0; i < packet->page_buf_count; i++) {
        /* Shift virtual page number to form virtual page address */
        uint8_t *vaddr = (uint8_t *)(packet->page_buffers[i].gpa_page << PAGELOG);

        netvsc_m_append(hn, x, packet->page_buffers[i].gpa_len,
            vaddr + packet->page_buffers[i].gpa_ofs);
    }

    err_enum_t err = hn->netif->input((struct pbuf *)x, hn->netif);
    if (err != ERR_OK) {
        msg_err("netvsc: rx drop by stack, err %d\n", err);
        receive_buffer_release((struct pbuf *)x);
    }
    return 0;
}

/*
 * Link up/down notification
 */
void
netvsc_linkstatus_callback(struct hv_device *device_obj, uint32_t status)
{
    //nothing to do
}
