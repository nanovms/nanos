#include <kernel.h>
#include <lwip.h>
#include <lwip/prot/tcp.h>
#include <netif/ethernet.h>
#include <pci.h>

#include "gve.h"

#define PCI_VENDOR_ID_GOOGLE    0x1ae0
#define PCI_DEV_ID_GVNIC        0x0042

//#define GVE_DEBUG
#ifdef GVE_DEBUG
#define gve_debug(x, ...) do {rprintf("GVE: " x "\n", ##__VA_ARGS__);} while(0)
#else
#define gve_debug(x, ...)
#endif

#define GVE_REGISTER_BAR    0
#define GVE_DOORBELL_BAR    2

/* Register BAR */
#define GVE_REG_DEVICE_STATUS   0x00
#define GVE_REG_DRIVER_STATUS   0x04
#define GVE_REG_MAX_TX_QUEUES   0x08
#define GVE_REG_MAX_RX_QUEUES   0x0C
#define GVE_REG_ADMINQ_PFN      0x10
#define GVE_REG_ADMINQ_DOORBELL 0x14
#define GVE_REG_ADMINQ_EVT_CNT  0x18
#define GVE_REG_DRIVER_VERSION  0x1F

#define GVE_DEVICE_STATUS_RESET         htobe32(U32_FROM_BIT(1))
#define GVE_DEVICE_STATUS_LINK_STATUS   htobe32(U32_FROM_BIT(2))
#define GVE_DEVICE_STATUS_REPORT_STATS  htobe32(U32_FROM_BIT(3))

enum gve_adminq_opcode {
    GVE_ADMINQ_DESCRIBE_DEVICE = 1,
    GVE_ADMINQ_CONFIGURE_DEVICE_RESOURCES,
    GVE_ADMINQ_REGISTER_PAGE_LIST,
    GVE_ADMINQ_UNREGISTER_PAGE_LIST,
    GVE_ADMINQ_CREATE_TX_QUEUE,
    GVE_ADMINQ_CREATE_RX_QUEUE,
    GVE_ADMINQ_DESTROY_TX_QUEUE,
    GVE_ADMINQ_DESTROY_RX_QUEUE,
    GVE_ADMINQ_DECONFIGURE_DEVICE_RESOURCES,
    GVE_ADMINQ_SET_DRIVER_PARAMETER = 11,
    GVE_ADMINQ_REPORT_STATS,
    GVE_ADMINQ_REPORT_LINK_SPEED,
    GVE_ADMINQ_GET_PTYPE_MAP,
};

enum gve_adminq_status {
    GVE_ADMINQ_COMMAND_UNSET = 0,
    GVE_ADMINQ_COMMAND_PASSED,
    GVE_ADMINQ_COMMAND_ERROR_ABORTED = -16,
    GVE_ADMINQ_COMMAND_ERROR_ALREADY_EXISTS,
    GVE_ADMINQ_COMMAND_ERROR_CANCELLED,
    GVE_ADMINQ_COMMAND_ERROR_DATALOSS,
    GVE_ADMINQ_COMMAND_ERROR_DEADLINE_EXCEEDED,
    GVE_ADMINQ_COMMAND_ERROR_FAILED_PRECONDITION,
    GVE_ADMINQ_COMMAND_ERROR_INTERNAL_ERROR,
    GVE_ADMINQ_COMMAND_ERROR_INVALID_ARGUMENT,
    GVE_ADMINQ_COMMAND_ERROR_NOT_FOUND,
    GVE_ADMINQ_COMMAND_ERROR_OUT_OF_RANGE,
    GVE_ADMINQ_COMMAND_ERROR_PERMISSION_DENIED,
    GVE_ADMINQ_COMMAND_ERROR_UNAUTHENTICATED,
    GVE_ADMINQ_COMMAND_ERROR_RESOURCE_EXHAUSTED,
    GVE_ADMINQ_COMMAND_ERROR_UNAVAILABLE,
    GVE_ADMINQ_COMMAND_ERROR_UNIMPLEMENTED,
    GVE_ADMINQ_COMMAND_ERROR_UNKNOWN_ERROR,
};

struct gve_device_descriptor {
    u64 max_registered_pages;
    u16 reserved1;
    u16 tx_queue_entries;
    u16 rx_queue_entries;
    u16 default_num_queues;
    u16 mtu;
    u16 counters;
    u16 tx_pages_per_qpl;
    u16 rx_pages_per_qpl;
    u8 mac[ETH_HWADDR_LEN];
    u16 num_device_options;
    u16 total_length;
    u8 reserved2[6];
} __attribute__((packed));

struct gve_adminq_describe_device {
    u64 device_descriptor_addr;
    u32 device_descriptor_version;
    u32 available_length;
} __attribute__((packed));

enum gve_queue_format {
    GVE_QUEUE_FORMAT_UNSPECIFIED = 0,
    GVE_GQI_RDA_FORMAT,
    GVE_GQI_QPL_FORMAT,
    GVE_DQO_RDA_FORMAT,
};

struct gve_adminq_configure_device_resources {
    u64 counter_array;
    u64 irq_db_addr;
    u32 num_counters;
    u32 num_irq_dbs;
    u32 irq_db_stride;
    u32 ntfy_blk_msix_base_idx;
    u8 queue_format;    /* enum gve_queue_format */
} __attribute__((packed));

struct gve_adminq_register_page_list {
    u32 page_list_id;
    u32 num_pages;
    u64 page_address_list_addr;
} __attribute__((packed));

struct gve_adminq_unregister_page_list {
    u32 page_list_id;
} __attribute__((packed));

struct gve_adminq_create_tx_queue {
    u32 queue_id;
    u32 reserved;
    u64 queue_resources_addr;
    u64 tx_ring_addr;
    u32 queue_page_list_id;
    u32 ntfy_id;
    u64 tx_comp_ring_addr;
    u16 tx_ring_size;
    u16 tx_comp_ring_size;
    u8 padding[4];
} __attribute__((packed));

struct gve_adminq_create_rx_queue {
    u32 queue_id;
    u32 index;
    u32 reserved;
    u32 ntfy_id;
    u64 queue_resources_addr;
    u64 rx_desc_ring_addr;
    u64 rx_data_ring_addr;
    u32 queue_page_list_id;
    u16 rx_ring_size;
    u16 packet_buffer_size;
    u16 rx_buff_ring_size;
    u8 enable_rsc;
    u8 padding[5];
} __attribute__((packed));

struct gve_adminq_destroy_tx_queue {
    u32 queue_id;
} __attribute__((packed));

struct gve_adminq_destroy_rx_queue {
    u32 queue_id;
} __attribute__((packed));

struct gve_adminq_command {
    u32 opcode;
    u32 status;
    union {
        struct gve_adminq_describe_device describe_device;
        struct gve_adminq_configure_device_resources cfg_dev_resources;
        struct gve_adminq_register_page_list register_page_list;
        struct gve_adminq_unregister_page_list unregister_page_list;
        struct gve_adminq_create_tx_queue create_tx_queue;
        struct gve_adminq_create_rx_queue create_rx_queue;
        struct gve_adminq_destroy_tx_queue destroy_tx_queue;
        struct gve_adminq_destroy_rx_queue destroy_rx_queue;
        u8 padding[56]; /* to make the struct size 64 bytes */
    };
} __attribute__((packed));

#define GVE_IRQ_EVENT   htobe32(U32_FROM_BIT(29))
#define GVE_IRQ_MASK    htobe32(U32_FROM_BIT(30))
#define GVE_IRQ_ACK     htobe32(U32_FROM_BIT(31))

struct gve_irq_db {
    u32 index;
} __attribute__((aligned(64))); /* cacheline alignment */

struct gve_queue_resources {
    u32 db_index;
    u32 counter_index;
    u8 reserved[56];
} __attribute__((packed));

#define GVE_TXD_STD 0x00
#define GVE_TXD_TSO 0x10
#define GVE_TXD_SEG 0x20
#define GVE_TXD_MTD 0x30

struct gve_tx_pkt_desc {
    u8 type_flags;
    u8 l4_csum_offset;
    u8 l4_hdr_offset;
    u8 desc_cnt;
    u16 len;
    u16 seg_len;
    u64 seg_addr;
} __attribute__((packed));

struct gve_tx_seg_desc {
    u8 type_flags;
    u8 l3_offset;
    u16 reserved;
    u16 mss;
    u16 seg_len;
    u64 seg_addr;
} __attribute__((packed));

#define GVE_RXF_FRAG        htobe16(1 << 6)
#define GVE_RXF_IPV4        htobe16(1 << 7)
#define GVE_RXF_IPV6        htobe16(1 << 8)
#define GVE_RXF_TCP         htobe16(1 << 9)
#define GVE_RXF_UDP         htobe16(1 << 10)
#define GVE_RXF_ERR         htobe16(1 << 11)
#define GVE_RXF_PKT_CONT    htobe16(1 << 13)

#define GVE_IRQ_DB_COUNT    2   /* one for TX, one for RX */

/* padding added at the beginning of received Ethernet frames */
#define GVE_RX_PADDING  2

struct gve_rx_desc {
    u8  padding[48];
    u32 rss_hash;
    u16 mss;
    u16 reserved;
    u8 hdr_len;
    u8 hdr_off;
    u16 csum;
    u16 len;
    u16 flags_seq;
} __attribute__((packed));

typedef struct gve_tx_queue {
    u32 head, tail;
    u32 qpl_head, qpl_available;
    struct gve *adapter;
    u16 mask;
    void *qpl_base; /* first page of queue page list */
    u32 qpl_size;
    union {
        struct gve_tx_pkt_desc pkt;
        struct gve_tx_seg_desc seg;
    } *desc;
    u32 *qpl_allocated;
    struct gve_queue_resources *q_res;
} *gve_tx_queue;

declare_closure_struct(0, 0, void, gve_rx_irq);
declare_closure_struct(0, 0, void, gve_rx_service);
typedef struct gve_rx_queue {
    struct spinlock lock;
    u32 head, tail;
    u32 qpl_head, qpl_available;
    struct gve *adapter;
    u16 mask;
    void *qpl_base; /* first page of queue page list */
    u32 qpl_count;  /* number of RX buffers */
    struct gve_rx_desc *desc;
    u64 *data;
    struct pbuf *pbufs;
    u32 *irq_db_index;
    closure_struct(gve_rx_irq, irq_handler);
    closure_struct(gve_rx_service, service);
    struct gve_queue_resources *q_res;
} *gve_rx_queue;

declare_closure_struct(0, 0, void, gve_mgmt_irq);
declare_closure_struct(0, 0, void, gve_link_status_handler);
typedef struct gve {
    heap general, contiguous;
    pci_dev pdev;
    struct pci_bar reg_bar;
    struct pci_bar db_bar;
    struct gve_adminq_command *adminq;
    u32 adminq_head;
    u32 adminq_mask;
    u16 tx_desc_cnt, rx_desc_cnt;
    u16 tx_pages_per_qpl, rx_data_slot_cnt;
    u16 num_event_counters;
    u32 *event_counters;
    struct gve_irq_db *irq_db_indices;
    struct gve_tx_queue tx;
    struct gve_rx_queue rx;
    closure_struct(gve_mgmt_irq, mgmt_irq_handler);
    closure_struct(gve_link_status_handler, link_status_handler);
    struct netif net_if;
    u16 mtu;
} *gve;

static boolean gve_adminq_wait(gve adapter, u32 cmd_index)
{
    int retries = 0;
    do {
        if (retries)
            kernel_delay(milliseconds(20));
        u32 tail = be32toh(pci_bar_read_4(&adapter->reg_bar, GVE_REG_ADMINQ_EVT_CNT));
        if (((s32)(tail - cmd_index)) >= 0)
            return true;
    } while (retries++ < 64);
    return false;
}

static struct gve_adminq_command *gve_adminq_new_cmd(gve adapter)
{
    struct gve_adminq_command *cmd = &adapter->adminq[adapter->adminq_head & adapter->adminq_mask];
    zero(cmd, sizeof(*cmd));
    return cmd;
}

static u32 gve_adminq_issue_cmd(gve adapter)
{
    write_barrier();
    pci_bar_write_4(&adapter->reg_bar, GVE_REG_ADMINQ_DOORBELL, htobe32(++adapter->adminq_head));
    return adapter->adminq_head;
}

static boolean gve_adminq_execute_cmd(gve adapter, struct gve_adminq_command *cmd)
{
    u32 index = gve_adminq_issue_cmd(adapter);
    if (!gve_adminq_wait(adapter, index)) {
        msg_err("command %d timed out\n", be32toh(cmd->opcode));
        return false;
    }
    read_barrier();
    u32 status = be32toh(cmd->status);
    gve_debug("cmd %d, status %d", be32toh(cmd->opcode), status);
    return (status == GVE_ADMINQ_COMMAND_PASSED);
}

static boolean gve_describe_device(gve adapter)
{
    struct gve_device_descriptor *desc = allocate(adapter->contiguous, PAGESIZE);
    if (desc == INVALID_ADDRESS)
        return false;
    struct gve_adminq_command *cmd = gve_adminq_new_cmd(adapter);
    cmd->opcode = htobe32(GVE_ADMINQ_DESCRIBE_DEVICE);
    cmd->describe_device.device_descriptor_addr = htobe64(physical_from_virtual(desc));
    cmd->describe_device.device_descriptor_version = htobe32(1);
    cmd->describe_device.available_length = htobe32(PAGESIZE);
    boolean success = gve_adminq_execute_cmd(adapter, cmd);
    if (success) {
        u8 *mac = adapter->net_if.hwaddr;
        runtime_memcpy(mac, desc->mac, sizeof(desc->mac));
        adapter->mtu = be16toh(desc->mtu);
        adapter->num_event_counters = be16toh(desc->counters);
        adapter->tx_desc_cnt = be16toh(desc->tx_queue_entries);
        adapter->rx_desc_cnt = be16toh(desc->rx_queue_entries);
        adapter->tx_pages_per_qpl = be16toh(desc->tx_pages_per_qpl);
        adapter->rx_data_slot_cnt = be16toh(desc->rx_pages_per_qpl);
        gve_debug("MAC %02x:%02x:%02x:%02x:%02x:%02x, MTU %d, TX descriptors %d, RX descriptors %d",
                  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], adapter->mtu,
                  adapter->tx_desc_cnt, adapter->rx_desc_cnt);
    }
    deallocate(adapter->contiguous, desc, PAGESIZE);
    return success;
}

static boolean gve_cfg_device_resources(gve adapter)
{
    /* The memory area for event counters must be page-aligned. */
    u64 evt_cnt_size = MAX(adapter->num_event_counters * sizeof(u32), PAGESIZE);
    adapter->event_counters = allocate(adapter->contiguous, evt_cnt_size);
    if (adapter->event_counters == INVALID_ADDRESS)
        return false;

    u64 irq_db_size = sizeof(struct gve_irq_db) * GVE_IRQ_DB_COUNT;
    adapter->irq_db_indices = allocate(adapter->contiguous, irq_db_size);
    if (adapter->irq_db_indices == INVALID_ADDRESS)
        goto err;
    struct gve_adminq_command *cmd = gve_adminq_new_cmd(adapter);
    cmd->opcode = htobe32(GVE_ADMINQ_CONFIGURE_DEVICE_RESOURCES);
    cmd->cfg_dev_resources.counter_array = htobe64(physical_from_virtual(adapter->event_counters));
    cmd->cfg_dev_resources.irq_db_addr = htobe64(physical_from_virtual(adapter->irq_db_indices));
    cmd->cfg_dev_resources.num_counters = htobe32(adapter->num_event_counters);
    cmd->cfg_dev_resources.num_irq_dbs = htobe32(2);
    cmd->cfg_dev_resources.irq_db_stride = htobe32(sizeof(*adapter->irq_db_indices));
    cmd->cfg_dev_resources.ntfy_blk_msix_base_idx = htobe32(0); /* management vector is last */
    cmd->cfg_dev_resources.queue_format = GVE_GQI_QPL_FORMAT;
    boolean success = gve_adminq_execute_cmd(adapter, cmd);
    if (success)
        return success;
    deallocate(adapter->contiguous, adapter->irq_db_indices, irq_db_size);
  err:
    deallocate(adapter->contiguous, adapter->event_counters, evt_cnt_size);
    return false;
}

static void gve_free_device_resources(gve adapter)
{
    struct gve_adminq_command *cmd = gve_adminq_new_cmd(adapter);
    cmd->opcode = htobe32(GVE_ADMINQ_DECONFIGURE_DEVICE_RESOURCES);
    gve_adminq_execute_cmd(adapter, cmd);
    deallocate(adapter->contiguous, adapter->irq_db_indices,
               sizeof(struct gve_irq_db) * GVE_IRQ_DB_COUNT);
    deallocate(adapter->contiguous, adapter->event_counters,
               MAX(adapter->num_event_counters * sizeof(u32), PAGESIZE));
}

define_closure_function(0, 0, void, gve_link_status_handler)
{
    gve adapter = struct_from_field(closure_self(), gve, link_status_handler);
    u32 status = pci_bar_read_4(&adapter->reg_bar, GVE_REG_DEVICE_STATUS);
    gve_debug("link status handler, status 0x%x", status);
    if (status & GVE_DEVICE_STATUS_LINK_STATUS)
        netif_set_link_up(&adapter->net_if);
    else
        netif_set_link_down(&adapter->net_if);
}

define_closure_function(0, 0, void, gve_mgmt_irq)
{
    gve adapter = struct_from_field(closure_self(), gve, mgmt_irq_handler);
    u32 status = pci_bar_read_4(&adapter->reg_bar, GVE_REG_DEVICE_STATUS);
    gve_debug("mgmt irq, status 0x%x", status);
    boolean dev_up = !!(status & GVE_DEVICE_STATUS_LINK_STATUS);
    boolean netif_up = netif_is_link_up(&adapter->net_if);
    if (dev_up != netif_up) {
        gve_debug("link status %d -> %d", netif_up, dev_up);
        async_apply_bh((thunk)&adapter->link_status_handler);
    }
}

static void gve_tx_cleanup(gve_tx_queue tx) {
    u32 tail = be32toh(tx->adapter->event_counters[be32toh(tx->q_res->counter_index)]);
    gve_debug("TX tail %d -> %d, QPL available %d", tx->tail, tail, tx->qpl_available);
    for (; tx->tail != tail; tx->tail++)
        tx->qpl_available += tx->qpl_allocated[tx->tail & tx->mask];
}

static void gve_tx_qpl_cpy(gve_tx_queue tx, struct pbuf *p, u32 *offset, u32 *allocated)
{
    u32 padded_len = pad(p->len, 64);   /* to align the next packet to a cacheline boundary */
    *allocated = padded_len;
    if (tx->qpl_head + padded_len <= tx->qpl_size) {
        tx->qpl_head += padded_len;
    } else {
        *allocated += tx->qpl_size - tx->qpl_head;
        tx->qpl_head = padded_len;
    }
    *offset = tx->qpl_head - padded_len;
    runtime_memcpy(tx->qpl_base + *offset, p->payload, p->len);
    tx->qpl_available -= *allocated;
}

err_t gve_linkoutput(struct netif *netif, struct pbuf *p)
{
    gve adapter = netif->state;
    gve_tx_queue tx = &adapter->tx;
    gve_tx_cleanup(tx);
    int seg_count = 0;
    u32 head = tx->qpl_head;
    for (struct pbuf *q = p; q != NULL; q = q->next) {
        u32 padded_len = pad(q->len, 64);
        seg_count++;
        if (head + padded_len <= tx->qpl_size)
            head += padded_len;
        else
            head = padded_len;
    }
    gve_debug("TX len %d (%d segments)", p->tot_len, seg_count);
    if (head < tx->qpl_head)
        head += tx->qpl_size;
    if ((tx->head - tx->tail + seg_count > tx->adapter->tx_desc_cnt) ||
            (head - tx->qpl_head > tx->qpl_available)) {
        gve_debug("cannot transmit (%d available descriptors, %d bytes of QPL space)",
                  tx->adapter->tx_desc_cnt - tx->head + tx->tail, tx->qpl_available);
        return ERR_MEM;
    }
    u32 offset;
    gve_tx_qpl_cpy(tx, p, &offset, &tx->qpl_allocated[tx->head & tx->mask]);
    struct gve_tx_pkt_desc *pkt = &tx->desc[tx->head++ & tx->mask].pkt;
    pkt->type_flags = GVE_TXD_STD;
    pkt->l4_csum_offset = 0;
    pkt->l4_hdr_offset = 0;
    pkt->desc_cnt = seg_count;
    pkt->len = htobe16(p->tot_len);
    pkt->seg_len = htobe16(p->len);
    pkt->seg_addr = htobe64(offset);
    for (struct pbuf *q = p->next; q != NULL; q = q->next) {
        gve_tx_qpl_cpy(tx, q, &offset, &tx->qpl_allocated[tx->head & tx->mask]);
        struct gve_tx_seg_desc *seg = &tx->desc[tx->head++ & tx->mask].seg;
        seg->type_flags = GVE_TXD_SEG;
        seg->seg_len = htobe16(q->len);
        pkt->seg_addr = htobe64(offset);
    }
    gve_debug("TX head %d, QPL available %d", tx->head, tx->qpl_available);
    write_barrier();
    pci_bar_write_4(&adapter->db_bar, be32toh(tx->q_res->db_index) * sizeof(u32),
                    htobe32(tx->head));
    return ERR_OK;
}

static void gve_rx_fill(gve_rx_queue rx)
{
    gve adapter = rx->adapter;
    int slot_count;
    gve_debug("RX fill: head %d, tail %d, available %d", rx->head, rx->tail, rx->qpl_available);
    for (slot_count = 0; (rx->head < rx->tail + adapter->rx_desc_cnt) && rx->qpl_available;
         rx->head++, slot_count++, rx->qpl_available--) {
        u64 offset = rx->qpl_head * PAGESIZE;
        if (rx->pbufs[rx->qpl_head].ref > 1) {
            /* The packet previously received at this slot is still in use. If the slots left to be
             * filled are below a certain threshold, stop here, to give a chance to the upper layers
             * to consume the packet, so that this buffer can be reused and thus a copy of the next
             * packet that will be received at this slot can be avoided. */
            if (rx->tail + adapter->rx_desc_cnt - rx->head < (rx->mask + 1) / 4)
                break;
            offset += PAGESIZE / 2;
        }
        rx->data[rx->head & rx->mask] = htobe64(offset);
        if (++rx->qpl_head == rx->qpl_count)
            rx->qpl_head = 0;
    }
    gve_debug("filled %d slots", slot_count);
    if (slot_count)
        pci_bar_write_4(&adapter->db_bar, be32toh(rx->q_res->db_index) * sizeof(u32),
                        htobe32(rx->head));
}

define_closure_function(0, 0, void, gve_rx_irq)
{
    gve_debug("RX irq");
    gve_rx_queue rx = struct_from_field(closure_self(), gve_rx_queue, irq_handler);
    async_apply_bh((thunk)&rx->service);
    /* further interrupts are masked until this interrupt is acked in the RX service thunk */
}

define_closure_function(0, 0, void, gve_rx_service)
{
    gve_rx_queue rx = struct_from_field(closure_self(), gve_rx_queue, service);
    gve adapter = rx->adapter;
    struct netif *net_if = &adapter->net_if;
    u32 tail;
    boolean irq_acked = false;
    spin_lock(&rx->lock);
  begin:
    tail = be32toh(adapter->event_counters[be32toh(rx->q_res->counter_index)]);
    gve_debug("RX tail %d -> %d", rx->tail, tail);
    for (; rx->tail != tail; rx->qpl_available++, rx->tail++) {
        struct gve_rx_desc *desc = &rx->desc[rx->tail & rx->mask];
        u16 length = be16toh(desc->len);
        if (length <= GVE_RX_PADDING)
            continue;
        if (desc->flags_seq & (GVE_RXF_ERR | GVE_RXF_PKT_CONT)) {
            msg_err("unexpected flags 0x%x\n", desc->flags_seq);
            continue;
        }
        u32 qpl_index = rx->qpl_head + rx->qpl_available;
        if (qpl_index >= rx->qpl_count)
            qpl_index -= rx->qpl_count;
        u32 qpl_offset = be64toh(rx->data[rx->tail & rx->mask]);
        void *payload = rx->qpl_base + qpl_offset + GVE_RX_PADDING;
        length -= GVE_RX_PADDING;
        struct pbuf *p;
        if (qpl_offset == qpl_index * PAGESIZE) {
            p = &rx->pbufs[qpl_index];
            p->payload = payload;
            p->len = p->tot_len = length;
            pbuf_ref(p);
        } else {
            gve_debug("RX packet copy");
            p = pbuf_alloc(PBUF_RAW, length, PBUF_RAM);
            if (p) {
                pbuf_take(p, payload, length);
            } else {
                msg_err("failed to allocate pbuf\n");
                continue;
            }
        }
        err_t err = net_if->input(p, net_if);
        if (err != ERR_OK)
            pbuf_free(p);
    }
    if (rx->head - rx->tail <= (rx->mask + 1) / 2)
        gve_rx_fill(rx);
    if (!irq_acked) {
        pci_bar_write_4(&adapter->db_bar, be32toh(*rx->irq_db_index) * sizeof(u32), GVE_IRQ_ACK);
        irq_acked = true;

        /* Check the event counter again, to avoid missing any events that may have occurred between
         * the last check and the interrupt ack. */
        memory_barrier();
        goto begin;
    }
    spin_unlock(&rx->lock);
}

static boolean gve_init_interrupts(gve adapter)
{
    int msix_avail = pci_enable_msix(adapter->pdev);
    if (msix_avail < 3) /* TX irq, RX irq, management irq */
        return false;
    if (pci_setup_msix(adapter->pdev, 2, init_closure(&adapter->mgmt_irq_handler, gve_mgmt_irq),
                       ss("gve_mgmt")) == INVALID_PHYSICAL)
        goto error;
    if (pci_setup_msix(adapter->pdev, 1, init_closure(&adapter->rx.irq_handler, gve_rx_irq),
                       ss("gve_rx")) == INVALID_PHYSICAL)
        goto err_disable_mgmt;
    return true;
  err_disable_mgmt:
    pci_teardown_msix(adapter->pdev, 2);
  error:
    pci_disable_msix(adapter->pdev);
    return false;
}

static void gve_deinit_interrupts(gve adapter)
{
    pci_teardown_msix(adapter->pdev, 1);
    pci_teardown_msix(adapter->pdev, 2);
    pci_disable_msix(adapter->pdev);
}

static void *gve_create_qpl(gve adapter, u16 num_pages, u32 id)
{
    void *qpl_base = allocate(adapter->contiguous, num_pages * PAGESIZE);
    if (qpl_base == INVALID_ADDRESS)
        return qpl_base;
    u64 *page_list = allocate(adapter->contiguous, num_pages * sizeof(*page_list));
    if (page_list == INVALID_ADDRESS)
        goto error;
    u64 page_addr = physical_from_virtual(qpl_base);
    for (u16 page = 0; page < num_pages; page++) {
        page_list[page] = htobe64(page_addr);
        page_addr += PAGESIZE;
    }
    struct gve_adminq_command *cmd = gve_adminq_new_cmd(adapter);
    cmd->opcode = htobe32(GVE_ADMINQ_REGISTER_PAGE_LIST);
    cmd->register_page_list.page_list_id = htobe32(id);
    cmd->register_page_list.num_pages = htobe32(num_pages);
    cmd->register_page_list.page_address_list_addr = htobe64(physical_from_virtual(page_list));
    boolean success = gve_adminq_execute_cmd(adapter, cmd);
    deallocate(adapter->contiguous, page_list, num_pages * sizeof(*page_list));
    if (success)
        return qpl_base;
  error:
    deallocate(adapter->contiguous, qpl_base, num_pages * PAGESIZE);
    return INVALID_ADDRESS;
}

static void gve_destroy_qpl(gve adapter, void *qpl_base, u16 num_pages, u32 id)
{
    struct gve_adminq_command *cmd = gve_adminq_new_cmd(adapter);
    cmd->opcode = htobe32(GVE_ADMINQ_UNREGISTER_PAGE_LIST);
    cmd->unregister_page_list.page_list_id = htobe32(id);
    gve_adminq_execute_cmd(adapter, cmd);
    deallocate(adapter->contiguous, qpl_base, num_pages * PAGESIZE);
}

static boolean gve_create_tx_queue(gve adapter, gve_tx_queue tx, u32 index)
{
    u16 num_pages = adapter->tx_pages_per_qpl;
    u32 id = index; /* used for both QPL and notify block */
    tx->qpl_base = gve_create_qpl(adapter, num_pages, id);
    if (tx->qpl_base == INVALID_ADDRESS)
        return false;
    tx->desc = allocate(adapter->contiguous, adapter->tx_desc_cnt * sizeof(*tx->desc));
    if (tx->desc == INVALID_ADDRESS)
        goto err1;
    tx->qpl_allocated = allocate(adapter->general,
                                 adapter->tx_desc_cnt * sizeof(*tx->qpl_allocated));
    if (tx->qpl_allocated == INVALID_ADDRESS)
        goto err2;
    tx->q_res = allocate(adapter->contiguous, sizeof(*tx->q_res));
    if (tx->q_res == INVALID_ADDRESS)
        goto err3;
    struct gve_adminq_command *cmd = gve_adminq_new_cmd(adapter);
    cmd->opcode = htobe32(GVE_ADMINQ_CREATE_TX_QUEUE);
    cmd->create_tx_queue.queue_id = htobe32(index);
    cmd->create_tx_queue.queue_resources_addr = htobe64(physical_from_virtual(tx->q_res));
    cmd->create_tx_queue.tx_ring_addr = htobe64(physical_from_virtual(tx->desc));
    cmd->create_tx_queue.queue_page_list_id = htobe32(id);
    cmd->create_tx_queue.ntfy_id = htobe32(id);
    boolean success = gve_adminq_execute_cmd(adapter, cmd);
    if (!success)
        goto err4;
    tx->mask = adapter->tx_desc_cnt - 1;
    tx->head = tx->tail = 0;
    tx->qpl_head = 0;
    tx->qpl_available = tx->qpl_size = num_pages * PAGESIZE;
    tx->adapter = adapter;
    return true;
  err4:
    deallocate(adapter->contiguous, tx->q_res, sizeof(*tx->q_res));
  err3:
    deallocate(adapter->general, tx->qpl_allocated,
               adapter->tx_desc_cnt * sizeof(*tx->qpl_allocated));
  err2:
    deallocate(adapter->contiguous, tx->desc, adapter->tx_desc_cnt * sizeof(*tx->desc));
  err1:
    gve_destroy_qpl(adapter, tx->qpl_base, num_pages, id);
    return false;
}

static void gve_destroy_tx_queue(gve adapter, gve_tx_queue tx, u32 index)
{
    struct gve_adminq_command *cmd = gve_adminq_new_cmd(adapter);
    cmd->opcode = htobe32(GVE_ADMINQ_DESTROY_TX_QUEUE);
    cmd->destroy_tx_queue.queue_id = htobe32(index);
    gve_adminq_execute_cmd(adapter, cmd);
    deallocate(adapter->contiguous, tx->q_res, sizeof(*tx->q_res));
    deallocate(adapter->general, tx->qpl_allocated,
               adapter->tx_desc_cnt * sizeof(*tx->qpl_allocated));
    deallocate(adapter->contiguous, tx->desc, adapter->tx_desc_cnt * sizeof(*tx->desc));
    gve_destroy_qpl(adapter, tx->qpl_base, adapter->tx_pages_per_qpl, index);
}

static boolean gve_create_rx_queue(gve adapter, gve_rx_queue rx, u32 index)
{
    u16 num_pages = adapter->rx_data_slot_cnt;
    u32 id = 1 + index; /* used for both QPL and notify block */
    rx->qpl_base = gve_create_qpl(adapter, num_pages, id);
    if (rx->qpl_base == INVALID_ADDRESS)
        return false;
    rx->qpl_available = rx->qpl_count = num_pages;
    rx->pbufs = allocate(adapter->general, rx->qpl_count * sizeof(*rx->pbufs));
    if (rx->pbufs == INVALID_ADDRESS)
        goto err1;
    rx->desc = allocate(adapter->contiguous, adapter->rx_desc_cnt * sizeof(*rx->desc));
    if (rx->desc == INVALID_ADDRESS)
        goto err2;
    rx->data = allocate(adapter->contiguous, adapter->rx_data_slot_cnt * sizeof(*rx->data));
    if (rx->data == INVALID_ADDRESS)
        goto err3;
    rx->q_res = allocate(adapter->contiguous, sizeof(*rx->q_res));
    if (rx->q_res == INVALID_ADDRESS)
        goto err4;
    struct gve_adminq_command *cmd = gve_adminq_new_cmd(adapter);
    cmd->opcode = htobe32(GVE_ADMINQ_CREATE_RX_QUEUE);
    cmd->create_rx_queue.queue_id = cmd->create_rx_queue.index = htobe32(index);
    cmd->create_rx_queue.ntfy_id = htobe32(id);
    cmd->create_rx_queue.queue_resources_addr = htobe64(physical_from_virtual(rx->q_res));
    cmd->create_rx_queue.rx_desc_ring_addr = htobe64(physical_from_virtual(rx->desc));
    cmd->create_rx_queue.rx_data_ring_addr = htobe64(physical_from_virtual(rx->data));
    cmd->create_rx_queue.queue_page_list_id = htobe32(id);
    cmd->create_rx_queue.packet_buffer_size = htobe16(PAGESIZE / 2);
    boolean success = gve_adminq_execute_cmd(adapter, cmd);
    if (!success)
        goto err5;
    rx->mask = adapter->rx_desc_cnt - 1;
    rx->head = rx->tail = 0;
    rx->qpl_head = 0;
    for (u32 i = 0; i < rx->qpl_count; i++) {
        struct pbuf *p = &rx->pbufs[i];
        p->next = NULL;
        p->type_internal = PBUF_REF;
        p->flags = 0;
        p->ref = 1;
        p->if_idx = NETIF_NO_INDEX;
    }
    rx->irq_db_index = &adapter->irq_db_indices[id].index;
    rx->adapter = adapter;
    init_closure(&rx->service, gve_rx_service);
    spin_lock_init(&rx->lock);
    gve_rx_fill(rx);
    return true;
  err5:
    deallocate(adapter->contiguous, rx->q_res, sizeof(*rx->q_res));
  err4:
    deallocate(adapter->contiguous, rx->data, adapter->rx_data_slot_cnt * sizeof(*rx->data));
  err3:
    deallocate(adapter->contiguous, rx->desc, adapter->rx_desc_cnt * sizeof(*rx->desc));
  err2:
    deallocate(adapter->general, rx->pbufs, rx->qpl_count * sizeof(*rx->pbufs));
  err1:
    gve_destroy_qpl(adapter, rx->qpl_base, num_pages, id);
    return false;
}

static boolean gve_setup_queues(gve adapter)
{
    if (!gve_create_tx_queue(adapter, &adapter->tx, 0))
        return false;
    if (!gve_create_rx_queue(adapter, &adapter->rx, 0)) {
        gve_destroy_tx_queue(adapter, &adapter->tx, 0);
        return false;
    }
    return true;
}

static boolean gve_init(gve adapter)
{
    adapter->adminq = allocate(adapter->contiguous, PAGESIZE);
    if (adapter->adminq == INVALID_ADDRESS)
        return false;
    pci_bar_init(adapter->pdev, &adapter->reg_bar, GVE_REGISTER_BAR, 0, -1);
    pci_bar_init(adapter->pdev, &adapter->db_bar, GVE_DOORBELL_BAR, 0, -1);
    pci_enable_io_and_memory(adapter->pdev);
    init_closure(&adapter->link_status_handler, gve_link_status_handler);
    adapter->adminq_head = 0;
    adapter->adminq_mask = PAGESIZE / sizeof(struct gve_adminq_command) - 1;
    pci_bar_write_4(&adapter->reg_bar, GVE_REG_ADMINQ_PFN,
                    htobe32(physical_from_virtual(adapter->adminq) >> PAGELOG));
    if (!gve_describe_device(adapter)) {
        msg_err("failed to describe device\n");
        goto err1;
    }
    if (!gve_cfg_device_resources(adapter)) {
        msg_err("failed to configure device resources\n");
        goto err1;
    }
    if (!gve_init_interrupts(adapter)) {
        msg_err("failed to initialize interrupts\n");
        goto err2;
    }
    if (!gve_setup_queues(adapter)) {
        msg_err("failed to set up TX/RX queues\n");
        goto err3;
    }
    return true;
  err3:
    gve_deinit_interrupts(adapter);
  err2:
    gve_free_device_resources(adapter);
  err1:
    pci_bar_deinit(&adapter->db_bar);
    pci_bar_deinit(&adapter->reg_bar);
    deallocate(adapter->contiguous, adapter->adminq, PAGESIZE);
    return false;
}

static err_t gve_if_init(struct netif *netif)
{
    gve adapter = netif->state;
    netif = &adapter->net_if;
    netif->hostname = sstring_empty();
    netif->name[0] = 'e';
    netif->name[1] = 'n';
    netif->mtu = adapter->mtu;
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_UP;
    netif->output = etharp_output;
    netif->linkoutput = gve_linkoutput;
    netif->hwaddr_len = ETH_HWADDR_LEN;
    return ERR_OK;
}

closure_function(2, 1, boolean, gve_probe,
        heap, general, heap, contiguous,
        pci_dev, d)
{
    if ((pci_get_vendor(d) != PCI_VENDOR_ID_GOOGLE) || (pci_get_device(d) != PCI_DEV_ID_GVNIC))
        return false;
    gve_debug("probing device");
    heap h = bound(general);
    gve adapter = allocate(h, sizeof(struct gve));
    if (adapter == INVALID_ADDRESS)
        return false;
    adapter->general = h;
    adapter->contiguous = bound(contiguous);
    adapter->pdev = d;
    if (gve_init(adapter)) {
        gve_debug("registering network interface");
        netif_add(&adapter->net_if, 0, 0, 0, adapter, gve_if_init, ethernet_input);
        thunk t = (thunk)&adapter->link_status_handler;
        apply(t);
        return true;
    } else {
        deallocate(h, adapter, sizeof(struct gve));
        return false;
    }
}

void init_gve(kernel_heaps kh)
{
    heap h = heap_locked(kh);
    pci_probe probe = closure(h, gve_probe, h, (heap)heap_linear_backed(kh));
    assert(probe != INVALID_ADDRESS);
    register_pci_driver(probe, 0);
}
