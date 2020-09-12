#include <kernel.h>
#include <page.h>
#include "lwip/opt.h"
#include "lwip/def.h"
#include "lwip/mem.h"
#include "lwip/pbuf.h"
#include "lwip/stats.h"
#include "lwip/snmp.h"
#include "lwip/ethip6.h"
#include "lwip/etharp.h"
#include "lwip/dhcp.h"
#include <pci.h>
#include "netif/ethernet.h"
#include "vmxnet3.h"
#include "vmxnet3_queue.h"
#include "vmxnet3_net.h"

#ifdef VMXNET3_NET_DEBUG
# define vmxnet3_net_debug rprintf
#else
# define vmxnet3_net_debug(...) do { } while (0)
#endif // defined(VMXNET3_NET_DEBUG)

typedef struct vmxnet3 {
    vmxnet3_pci dev;
    heap rxbuffers;
    struct spinlock rx_buflock;
    int rxbuflen;
    thunk rx_intr_handler;
    thunk rx_service;           /* for bhqueue processing */
    queue rx_servicequeue;
    struct netif *n;
} *vmxnet3;

typedef struct xpbuf
{
    struct pbuf_custom p;
    vmxnet3 vn;
    struct list l;
} *xpbuf;

static void vmxnet3_interrupts_enable(vmxnet3_pci dev)
{
    struct vmxnet3_rxqueue *rxq = dev->vmx_rxq[0];
    pci_bar_write_4(&dev->bar0, VMXNET3_BAR0_IMASK(rxq->vxrxq_intr_idx), 0);
}

boolean vmxnet3_probe(pci_dev d)
{
    if (pci_get_vendor(d) != VMXNET3_VMWARE_VENDOR_ID)
        return false;

    u16 device = pci_get_device(d);
    if (device != VMXNET3_VMWARE_DEVICE_ID)
        return false;

    return true;
}

static void vmxnet3_write_cmd(vmxnet3_pci dev, u32 cmd)
{
    pci_bar_write_4(&dev->bar1, VMXNET3_BAR1_CMD, cmd);
}

static u32 vmxnet3_read_cmd(vmxnet3_pci dev, u32 cmd)
{
    vmxnet3_write_cmd(dev, cmd);
    memory_barrier();
    return (pci_bar_read_4(&dev->bar1, VMXNET3_BAR1_CMD));
}

static void vmxnet3_alloc_mcast_table(vmxnet3_pci dev)
{
    struct vmxnet3_driver_shared *vmx_ds = dev->vmx_ds;

    /* Multicast table state shared with the device */
    u64 mcast_table_size = VMXNET3_MULTICAST_MAX * ETHER_ADDR_LEN;
    dev->vmxnet3_mcast_table_mem = allocate_zero(dev->contiguous, mcast_table_size);
    assert(dev->vmxnet3_mcast_table_mem != INVALID_ADDRESS);
    //aligment
    assert((u64)dev->vmxnet3_mcast_table_mem == pad((u64)dev->vmxnet3_mcast_table_mem, VMXNET_ALIGN_MULTICAST));

    u64 ph = physical_from_virtual(dev->vmxnet3_mcast_table_mem);
    assert(ph != INVALID_PHYSICAL);
    vmx_ds->mcast_table = ph;
    vmx_ds->mcast_tablelen = mcast_table_size;
}

void init_vmxnet3_driver_shared(vmxnet3_pci dev)
{
    struct vmxnet3_driver_shared *vmx_ds = dev->vmx_ds;

    vmx_ds->magic = VMXNET3_REV1_MAGIC;

    //Driver Info
    vmx_ds->version = VMXNET3_DRIVER_VERSION;
    vmx_ds->guest = VMXNET3_GOS_LINUX |
        (sizeof(void*) == sizeof(u32) ? VMXNET3_GOS_32BIT : VMXNET3_GOS_64BIT);

    vmx_ds->vmxnet3_revision = VMXNET3_REVISION;
    vmx_ds->upt_version = VMXNET3_UPT_VERSION;
    vmx_ds->upt_features = UPT1_F_CSUM | UPT1_F_LRO;
    vmx_ds->driver_data = physical_from_virtual(dev);
    assert(vmx_ds->driver_data != INVALID_PHYSICAL);
    vmx_ds->driver_data_len = sizeof(struct vmxnet3);
    // queue_shared & queue_shared_len are in
    // vmxnet3_queues_shared_alloc()
    vmx_ds->mtu = 1500;
    vmx_ds->nrxsg_max = VMXNET3_MAX_RX_SEGS;
    vmx_ds->ntxqueue = VMXNET3_DEF_TX_QUEUES;
    vmx_ds->nrxqueue = VMXNET3_DEF_RX_QUEUES;

    vmx_ds->automask = 0;
    vmx_ds->nintr = 2;
    vmx_ds->evintr = 0;

    vmx_ds->rxmode = VMXNET3_RXMODE_UCAST | VMXNET3_RXMODE_MCAST | VMXNET3_RXMODE_BCAST |
        VMXNET3_RXMODE_ALLMULTI;

    vmxnet3_alloc_mcast_table(dev);

    u64 ph = physical_from_virtual(vmx_ds);
    assert(ph != INVALID_PHYSICAL);
    pci_bar_write_4(&dev->bar1, VMXNET3_BAR1_DSL, ph);
    pci_bar_write_4(&dev->bar1, VMXNET3_BAR1_DSH, ph >> 32);

    vmxnet3_write_cmd(dev, VMXNET3_CMD_SET_FILTER);
    vmxnet3_write_cmd(dev, VMXNET3_CMD_SET_RXMODE);
}

static void vmxnet3_interrupts_disable(vmxnet3_pci dev)
{
    struct vmxnet3_rxqueue *rxq = dev->vmx_rxq[0];
    struct vmxnet3_txqueue *txq = dev->vmx_txq[0];
    pci_bar_write_4(&dev->bar0, VMXNET3_BAR0_IMASK(rxq->vxrxq_intr_idx), 1);
    pci_bar_write_4(&dev->bar0, VMXNET3_BAR0_IMASK(txq->vxtxq_intr_idx), 1);
}

static void kick_pending(vmxnet3_pci dev)
{
    struct vmxnet3_txqueue* vmx_txq = dev->vmx_txq[0];
    if (vmx_txq->vxtxq_ts->npending) {
        vmx_txq->vxtxq_ts->npending = 0;
        pci_bar_write_4(&dev->bar0, VMXNET3_BAR0_TXH(0), vmx_txq->vxtxq_cmd_ring.vxtxr_head);
    }
}

static err_t low_level_output(struct netif *netif, struct pbuf *p)
{
    vmxnet3 vn = netif->state;

    err_t e = vmxnet3_isc_txd_encap(vn->dev, p);
    if (e != ERR_OK)
        return e;
    kick_pending(vn->dev)

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

static void vmxnet3_get_mac(vmxnet3 vx)
{
    u32 ml = vmxnet3_read_cmd(vx->dev, VMXNET3_CMD_GET_MACL);
    u32 mh = vmxnet3_read_cmd(vx->dev, VMXNET3_CMD_GET_MACH);

    struct netif* netif = vx->n;

    netif->hwaddr[0] = ml;
    netif->hwaddr[1] = ml >> 8;
    netif->hwaddr[2] = ml >> 16;
    netif->hwaddr[3] = ml >> 24;
    netif->hwaddr[4] = mh;
    netif->hwaddr[5] = mh >> 8;
}

static void vmxnet3_check_version(vmxnet3_pci dev)
{
    u32 version = pci_bar_read_4(&dev->bar1, VMXNET3_BAR1_VRRS);
    if ((version & 0x01) == 0) {
        halt("unsupported hardware version %x\n", version);
    }
    pci_bar_write_4(&dev->bar1, VMXNET3_BAR1_VRRS, VMXNET3_REVISION);

    version = pci_bar_read_4(&dev->bar1, VMXNET3_BAR1_UVRS);
    if ((version & VMXNET3_UPT_VERSION) == 0) {
        halt("unsupported UPT version %x\n", version);
    }
    pci_bar_write_4(&dev->bar1, VMXNET3_BAR1_UVRS, VMXNET3_UPT_VERSION);
}

void lwip_status_callback(struct netif *netif);

static err_t vmxif_init(struct netif *netif)
{
    vmxnet3 vn = netif->state;
    netif->hostname = "uniboot"; // from config

    netif->name[0] = DEVICE_NAME[0];
    netif->name[1] = DEVICE_NAME[1];
    netif->output = etharp_output;
    netif->linkoutput = low_level_output;
    netif->hwaddr_len = ETHARP_HWADDR_LEN;
    netif->status_callback = lwip_status_callback;
    vmxnet3_get_mac(vn);
    vmxnet3_net_debug("%s: hwaddr %02x:%02x:%02x:%02x:%02x:%02x\n",
        __func__,
        netif->hwaddr[0], netif->hwaddr[1], netif->hwaddr[2],
        netif->hwaddr[3], netif->hwaddr[4], netif->hwaddr[5]);
    netif->mtu = 1500;

    /* device capabilities */
    /* don't set NETIF_FLAG_ETHARP if this device is not an ethernet one */
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP | NETIF_FLAG_UP;

    return ERR_OK;
}

static void process_interrupt(vmxnet3 vn);

closure_function(1, 0, void, rx_interrupt,
                 vmxnet3, vn)
{
    vmxnet3 vn = bound(vn);
    process_interrupt(vn);
}

static void receive_buffer_release(struct pbuf *p)
{
    xpbuf x  = (void *)p;
    u64 flags = spin_lock_irq(&x->vn->rx_buflock);
    deallocate(x->vn->rxbuffers, x, x->vn->rxbuflen + sizeof(struct xpbuf));
    spin_unlock_irq(&x->vn->rx_buflock, flags);
}

closure_function(1, 0, void, vmxnet3_rx_service_bh,
                 vmxnet3, vn)
{
    vmxnet3 vn = bound(vn);
    list l;
    while ((l = (list)dequeue(vn->rx_servicequeue)) != INVALID_ADDRESS) {
        struct list q;
        assert(l);
        assert(l->prev);
        list_insert_before(l, &q); /* restore list head */
        list_foreach(&q, i) {
            assert(i);
            xpbuf rxb = struct_from_list(i, xpbuf, l);
            list_delete(i);
            err_enum_t err = vn->n->input((struct pbuf *)rxb, vn->n);
            if (err != ERR_OK) {
                msg_err("vmxnet3: rx drop by stack, err %d\n", err);
                receive_buffer_release((struct pbuf *)rxb);
            }
        }
    }
}

void vmxnet3_newbuf(vmxnet3 vdev, int rid);

static void test_shared(vmxnet3 vn)
{

#ifdef VMXNET3_NET_DEBUG
    vmxnet3_pci dev = vn->dev;
    // queue shared
    assert(physical_from_virtual(dev->queues_shared_mem) == dev->vmx_ds->queue_shared);

    struct vmxnet3_txq_shared *vxtxq_ts = dev->vmx_txq[0]->vxtxq_ts;
    assert(dev->queues_shared_mem == vxtxq_ts);

    assert(vxtxq_ts->npending == 0);
    assert(vxtxq_ts->intr_threshold == 0);

    assert(vxtxq_ts->cmd_ring == physical_from_virtual(dev->tx_desc_mem));
    assert(vxtxq_ts->data_ring == 0);
    assert(vxtxq_ts->comp_ring == physical_from_virtual(dev->tx_compdesc_mem));
    assert(vxtxq_ts->driver_data == physical_from_virtual(dev->vmx_txq[0]));
    assert(vxtxq_ts->cmd_ring_len == VMXNET3_MAX_TX_NDESC);
    assert(vxtxq_ts->data_ring_len == 0);
    assert(vxtxq_ts->comp_ring_len == VMXNET3_MAX_TX_NDESC);
    assert(vxtxq_ts->driver_data_len == sizeof(*dev->vmx_txq[0]));
    assert(vxtxq_ts->intr_idx == 0);
    assert(vxtxq_ts->stopped == 0);
    assert(vxtxq_ts->error == 0);

    struct vmxnet3_rxq_shared *vxrxq_rs = dev->vmx_rxq[0]->vxrxq_rs;
    assert(dev->queues_shared_mem + sizeof(struct vmxnet3_txq_shared) == vxrxq_rs);

    assert(vxrxq_rs->update_rxhead == 0);
    assert(vxrxq_rs->cmd_ring[0] == physical_from_virtual(dev->rx_desc_mem));
    assert(vxrxq_rs->cmd_ring[1] == physical_from_virtual(((caddr_t)dev->rx_desc_mem) + sizeof(struct vmxnet3_rxdesc)*VMXNET3_MAX_RX_NDESC));
    assert(vxrxq_rs->comp_ring == physical_from_virtual(dev->rx_compdesc_mem));
    assert(vxrxq_rs->driver_data == physical_from_virtual(dev->vmx_rxq[0]));
    assert(vxrxq_rs->cmd_ring_len[0] == VMXNET3_MAX_RX_NDESC);
    assert(vxrxq_rs->cmd_ring_len[1] == VMXNET3_MAX_RX_NDESC);
    assert(vxrxq_rs->comp_ring_len == VMXNET3_MAX_RX_NCOMPDESC);
    assert(vxrxq_rs->comp_ring_len == VMXNET3_MAX_RX_NCOMPDESC);
    assert(vxrxq_rs->driver_data_len == sizeof(*dev->vmx_rxq[0]));
    assert(vxrxq_rs->intr_idx == 1);
    assert(dev->vmx_rxq[0]->vxrxq_intr_idx == 1);

    assert(vxrxq_rs->stopped == 0);
    assert(vxrxq_rs->error == 0);

    //rx bufs
    for(int i = 0; i < VMXNET3_RXRINGS_PERQ; ++i) {
        struct vmxnet3_rxring *rxr = &dev->vmx_rxq[0]->vxrxq_cmd_ring[i];
        assert(rxr->vxrxr_ndesc == VMXNET3_MAX_RX_NDESC);
        assert(rxr->vxrxr_gen == (VMXNET3_INIT_GEN ^ 1));
        assert(rxr->vxrxr_paddr == physical_from_virtual(rxr->vxrxr_rxd));
        assert(rxr->vxrxr_desc_skips == 0);
        assert(rxr->vxrxr_refill_start == 0);
        for(int j = 0; j<rxr->vxrxr_ndesc; ++j) {
            assert(rxr->vxrxr_rxd[j].addr == physical_from_virtual(dev->rx_pbuf[i][j]->payload));
            assert(rxr->vxrxr_rxd[j].btype == (i == 0 ? VMXNET3_BTYPE_HEAD : VMXNET3_BTYPE_BODY));
            assert(rxr->vxrxr_rxd[j].dtype == 0);
            assert(rxr->vxrxr_rxd[j].len == vn->rxbuflen);
            assert(rxr->vxrxr_rxd[j].gen == VMXNET3_INIT_GEN);
        }
    }

    //rx descs buf
    struct vmxnet3_comp_ring *rxc = &dev->vmx_rxq[0]->vxrxq_comp_ring;
    assert(rxc->vxcr_next == 0);
    assert(rxc->vxcr_gen == VMXNET3_INIT_GEN);
    assert(rxc->vxcr_ndesc == VMXNET3_MAX_RX_NCOMPDESC);
    for(int j = 0; j < rxc->vxcr_ndesc; ++j) {
        struct vmxnet3_rxcompdesc* rxcd = rxc->vxcr_u.rxcd;
        assert(rxcd->rxd_idx == 0);
        assert(rxcd->len == 0);
    }
#endif
}

static void vmxnet3_net_attach(heap general, heap page_allocator, pci_dev d)
{
    struct vmxnet3_pci *dev = allocate(general, sizeof(struct vmxnet3_pci));
    assert(dev != INVALID_ADDRESS);

    dev->_dev = *d;
    dev->dev = &dev->_dev;

    pci_bar_init(dev->dev, &dev->bar0, 0, 0, -1);
    pci_bar_init(dev->dev, &dev->bar1, 1, 0, -1);

    pci_set_bus_master(dev->dev);
    assert(pci_detect_and_enable_msix(dev->dev));

    dev->general = general;
    dev->contiguous = page_allocator;

    vmxnet3_write_cmd(dev, VMXNET3_CMD_DISABLE);
    vmxnet3_write_cmd(dev, VMXNET3_CMD_RESET);

    vmxnet3 vn = allocate(dev->general, sizeof(struct vmxnet3));
    assert(vn != INVALID_ADDRESS);
    vn->dev = dev;
    vn->n = allocate(dev->general, sizeof(struct netif));
    assert(vn->n != INVALID_ADDRESS);

    vn->rxbuflen = VMXNET3_RX_MAXSEGSIZE;
    vn->rxbuffers = allocate_objcache(dev->general, page_allocator,
                      vn->rxbuflen + sizeof(struct xpbuf), PAGESIZE_2M);
    assert(vn->rxbuffers != INVALID_ADDRESS);
    spin_lock_init(&vn->rx_buflock);

    dev->vmx_ds = allocate_zero(dev->contiguous, sizeof(struct vmxnet3_driver_shared));
    assert(dev->vmx_ds != INVALID_ADDRESS);

    vn->rx_servicequeue = allocate_queue(dev->general, VMXNET3_RX_SERVICEQUEUE_DEPTH);
    assert(vn->rx_servicequeue != INVALID_ADDRESS);
    vn->rx_service = closure(dev->general, vmxnet3_rx_service_bh, vn);

    vn->rx_intr_handler = closure(dev->general, rx_interrupt, vn);
    pci_setup_msix(dev->dev, 1, vn->rx_intr_handler, "vmxnet3 rx");
    // interrupts are not used for tx

    vmxnet3_tx_queues_alloc(dev);
    vmxnet3_rx_queues_alloc(dev);

    vmxnet3_queues_shared_alloc(dev);

    for (int i = 0; i < VMXNET3_RXRINGS_PERQ; i++) {
        for (int idx = 0; idx < VMXNET3_MAX_RX_NDESC; idx++)
            vmxnet3_newbuf(vn, i);
    }

    vmxnet3_init_shared_data(dev);

    /* Check device versions */
    vmxnet3_check_version(dev);

    vmxnet3_set_interrupt_idx(dev);

    vmxnet3_interrupts_disable(dev);

    /* enable device */
    init_vmxnet3_driver_shared(dev);
    test_shared(vn);
    vmxnet3_read_cmd(dev, VMXNET3_CMD_ENABLE);
    pci_bar_write_4(&dev->bar0, VMXNET3_BAR0_RXH1(0), 0);
    pci_bar_write_4(&dev->bar0, VMXNET3_BAR0_RXH2(0), 0);

    netif_add(vn->n,
              0, 0, 0,
              vn,
              vmxif_init,
              ethernet_input);

    vmxnet3_interrupts_enable(dev);
}

closure_function(2, 1, boolean, vmxnet3_net_probe,
                 heap, general, heap, page_allocator,
                 pci_dev, d)
{
    if (!vmxnet3_probe(d))
        return false;

    vmxnet3_net_debug("FOUND VMXNET3!\n");
    vmxnet3_net_attach(bound(general), bound(page_allocator), d);
    vmxnet3_net_debug("ATTACHED VMXNET3!\n");
    return true;
}

void init_vmxnet3_network(kernel_heaps kh)
{
    heap h = heap_general(kh);
    register_pci_driver(closure(h, vmxnet3_net_probe, h, heap_backed(kh)));
}

static void vmxnet3_discard(vmxnet3_pci dev, int rid, int idx)
{
    struct vmxnet3_rxqueue *rxq = dev->vmx_rxq[0];
    struct vmxnet3_rxring *rxr = &rxq->vxrxq_cmd_ring[rid];
    struct vmxnet3_rxdesc *rxd = &rxr->vxrxr_rxd[idx];
    rxd->gen = rxr->vxrxr_gen;
    if (++rxr->vxrxr_refill_start == rxr->vxrxr_ndesc) {
        rxr->vxrxr_refill_start = 0;
        rxr->vxrxr_gen ^= 1;
    }
}

void vmxnet3_newbuf(vmxnet3 vdev, int rid)
{
    vmxnet3_pci dev = vdev->dev;
    struct vmxnet3_rxqueue *rxq = dev->vmx_rxq[0];
    struct vmxnet3_rxring *rxr = &rxq->vxrxq_cmd_ring[rid];

    int idx = rxr->vxrxr_refill_start;
    struct vmxnet3_rxdesc *rxd = &rxr->vxrxr_rxd[idx];

    xpbuf x = allocate(vdev->rxbuffers, sizeof(struct xpbuf) + vdev->rxbuflen);
    assert(x != INVALID_ADDRESS);
    x->vn = vdev;
    x->p.custom_free_function = receive_buffer_release;
    pbuf_alloced_custom(PBUF_RAW,
                        vdev->rxbuflen,
                        PBUF_REF,
                        &x->p,
                        x+1,
                        vdev->rxbuflen);

    dev->rx_pbuf[rid][idx] = (struct pbuf*)x;

    rxd->addr = physical_from_virtual(x+1);
    assert(rxd->addr != INVALID_PHYSICAL);
    rxd->len = vdev->rxbuflen;

    rxd->btype = (rid == 0 && (idx % 1) == 0) ? VMXNET3_BTYPE_HEAD : VMXNET3_BTYPE_BODY;
    rxd->gen = rxr->vxrxr_gen;

    if (++rxr->vxrxr_refill_start == rxr->vxrxr_ndesc) {
        rxr->vxrxr_refill_start = 0;
        rxr->vxrxr_gen ^= 1;
    }
}

static inline void vmxnet3_newbuf_lock(vmxnet3 dev, int rid)
{
    spin_lock(&dev->rx_buflock);
    vmxnet3_newbuf(dev, rid);
    spin_unlock(&dev->rx_buflock);
}

void vmxnet3_receive(vmxnet3 vdev, struct list *l)
{
    vmxnet3_pci dev = vdev->dev;
    struct vmxnet3_rxqueue *rxq = dev->vmx_rxq[0];
    struct vmxnet3_comp_ring *rxc = &rxq->vxrxq_comp_ring;

    for(;;) {
        struct vmxnet3_rxcompdesc *rxcd = &rxc->vxcr_u.rxcd[rxc->vxcr_next];

        if (rxcd->gen != rxc->vxcr_gen)
            break;
        read_barrier();

        assert(rxcd->qid <= 2);

        if (++rxc->vxcr_next == rxc->vxcr_ndesc) {
            rxc->vxcr_next = 0;
            rxc->vxcr_gen ^= 1;
        }

        u32 rid = rxcd->qid;
        u32 idx = rxcd->rxd_idx;
        u32 length = rxcd->len;
        struct vmxnet3_rxring *rxr = &rxq->vxrxq_cmd_ring[rid];
        struct vmxnet3_rxdesc *rxd = &rxr->vxrxr_rxd[idx];
        struct pbuf *m = dev->rx_pbuf[rid][idx];

        assert(m != NULL);

        while (rxr->vxrxr_refill_start != idx) {
            rxd[rxr->vxrxr_refill_start].gen = rxr->vxrxr_gen;
            if (++rxr->vxrxr_refill_start == rxr->vxrxr_ndesc) {
                rxr->vxrxr_refill_start = 0;
                rxr->vxrxr_gen ^= 1;
            }
        }

        if (rxcd->eop && rxcd->error) {
            vmxnet3_discard(dev, rid, idx);
            goto next;
        }

        /* Check and handle SOP/EOP state errors */
        if (rxcd->sop && dev->currpkt_head) {
            receive_buffer_release(dev->currpkt_head);
            dev->currpkt_head = dev->currpkt_tail =  NULL;
        } else if (!rxcd->sop && !dev->currpkt_head) {
            vmxnet3_discard(dev, rid, idx);
            goto next;
        }

       if (rxcd->sop) {
            assert(rxd->btype == VMXNET3_BTYPE_HEAD);
            assert((idx % 1) == 0);
            assert(dev->currpkt_head == NULL);

            if (length == 0) {
                vmxnet3_discard(dev, rid, idx);
                goto next;
            }

            vmxnet3_newbuf_lock(vdev, rid);

            m->tot_len = length;
            m->len = length;

            dev->currpkt_head = dev->currpkt_tail = m;
        } else {
            assert(rxd->btype == VMXNET3_BTYPE_BODY);
            assert(dev->currpkt_head != NULL);

            vmxnet3_newbuf_lock(vdev, rid);

            m->len = length;
            dev->currpkt_head->tot_len += length;
            dev->currpkt_tail->next = m;
            dev->currpkt_tail = m;
        }

        if (rxcd->eop) {
            list_insert_before(l, &((struct xpbuf*)dev->currpkt_head)->l);
            dev->currpkt_head = dev->currpkt_tail = NULL;
        }

next:
        if (rxq->vxrxq_rs->update_rxhead) {
            idx = (idx + 1) % rxr->vxrxr_ndesc;

            if (rid == 0)
                pci_bar_write_4(&dev->bar0, VMXNET3_BAR0_RXH1(0), idx);
            else
                pci_bar_write_4(&dev->bar0, VMXNET3_BAR0_RXH2(0), idx);
        }
    }

}

static void process_interrupt(vmxnet3 vn)
{
    vmxnet3_pci dev = vn->dev;
    struct list q;
    list_init(&q);

    vmxnet3_interrupts_disable(dev);
    while (vmxnet3_rxq_available(dev)) {
        vmxnet3_receive(vn, &q);
    }
    vmxnet3_interrupts_enable(dev);
    list l = list_get_next(&q);
    if (l) {
        /* trick: remove (local) head and queue first element */
        list_delete(&q);
        assert(enqueue(vn->rx_servicequeue, l));
        enqueue(bhqueue, vn->rx_service);
    }
}
