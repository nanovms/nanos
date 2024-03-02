#include <kernel.h>
#include <vsock.h>

#include "virtio_internal.h"
#include "virtio_mmio.h"
#include "virtio_pci.h"
#include "virtio_socket.h"

/* VirtIO feature flags */
#define VIRTIO_VSOCK_F_STREAM   0x0001  /* stream socket type is supported */

#define VIRTIO_VSOCK_TYPE_STREAM    1
#define VIRTIO_VSOCK_TYPE_SEQPACKET 2

#define VIRTIO_VSOCK_OP_INVALID         0
#define VIRTIO_VSOCK_OP_REQUEST         1
#define VIRTIO_VSOCK_OP_RESPONSE        2
#define VIRTIO_VSOCK_OP_RST             3
#define VIRTIO_VSOCK_OP_SHUTDOWN        4
#define VIRTIO_VSOCK_OP_RW              5
#define VIRTIO_VSOCK_OP_CREDIT_UPDATE   6
#define VIRTIO_VSOCK_OP_CREDIT_REQUEST  7

#define VIRTIO_VSOCK_SHUTDOWN_F_RECEIVE U64_FROM_BIT(0)
#define VIRTIO_VSOCK_SHUTDOWN_F_SEND    U64_FROM_BIT(1)

struct virtio_vsock_config {
    u64 guest_cid;
} __attribute__((packed));

struct virtio_vsock_hdr {
    u64 src_cid;
    u64 dst_cid;
    u32 src_port;
    u32 dst_port;
    u32 len;
    u16 type;
    u16 op;
    u32 flags;
    u32 buf_alloc;
    u32 fwd_cnt;
} __attribute__((packed));

//#define VIRTIO_SOCK_DEBUG
#ifdef VIRTIO_SOCK_DEBUG
#define virtio_sock_debug(x, ...) do {tprintf(sym(virtio_sock), 0, ss(x "\n"), ##__VA_ARGS__);} while(0)
#else
#define virtio_sock_debug(x, ...)
#endif

#define VIRTIO_SOCK_DRIVER_FEATURES VIRTIO_VSOCK_F_STREAM

/* 2 descriptors per packet (one for the header and one for the optional payload) are needed because
 * AWS Firecracker does not support inserting a received data packet into a single descriptor. */
#define VIRTIO_SOCK_RX_PACKET_DESCS 2

#define VIRTIO_SOCK_RXBUF_SIZE  (4 * KB)

typedef struct virtio_sock {
    heap general;
    backed_heap backed;
    vtdev dev;
    virtqueue rxq, txq, eventq;
    u32 rx_seqno;
    u32 guest_cid;
} *virtio_sock;

typedef struct virtio_sock_connection {
    struct vsock_connection vsock_conn;
    virtio_sock vs;
    u16 type;
    u32 buf_alloc;
    u32 fwd_cnt;
    u32 tx_cnt;
    u32 peer_buf_alloc;
    u32 peer_fwd_cnt;
    closure_struct(thunk, free);
} *virtio_sock_connection;

typedef struct virtio_sock_rxbuf {
    virtio_sock vs;
    u32 seqno;
    closure_struct(vqfinish, complete);
    u8 data[0];
} *virtio_sock_rxbuf;

typedef struct virtio_sock_txbuf {
    virtio_sock vs;
    closure_struct(vqfinish, complete);
    u8 data[0];
} *virtio_sock_txbuf;

static boolean virtio_sock_rxq_submit(virtio_sock vs);

static boolean virtio_sock_dev_attach(heap general, backed_heap backed, vtdev dev)
{
    virtio_sock_debug("dev_features 0x%lx, features 0x%lx", dev->dev_features, dev->features);
    virtio_sock vs = allocate(general, sizeof(*vs));
    if (vs == INVALID_ADDRESS)
        return false;
    vs->guest_cid = vtdev_cfg_read_4(dev, offsetof(struct virtio_vsock_config *, guest_cid));
    virtio_sock_debug("  guest CID %d", vs->guest_cid);
    status s = virtio_alloc_virtqueue(dev, ss("virtio socket rx"), 0, &vs->rxq);
    if (!is_ok(s)) {
        msg_err("failed to allocate rx virtqueue: %v\n", s);
        timm_dealloc(s);
        goto err;
    }
    s = virtio_alloc_virtqueue(dev, ss("virtio socket tx"), 1, &vs->txq);
    if (!is_ok(s)) {
        msg_err("failed to allocate tx virtqueue: %v\n", s);
        timm_dealloc(s);
        goto err;
    }

    /* The event virtqueue is initialized even if not used, otherwise AWS Firecracker complains
     * about an "attempt to use virtio queue that is not marked ready". */
    s = virtio_alloc_virtqueue(dev, ss("virtio socket events"), 2, &vs->eventq);
    if (!is_ok(s)) {
        msg_err("failed to allocate event virtqueue: %v\n", s);
        timm_dealloc(s);
        goto err;
    }

    virtqueue_set_polling(vs->txq, true);
    vs->general = general;
    vs->backed = backed;
    vs->dev = dev;
    if (!virtio_sock_rxq_submit(vs))
        goto err;
    vs->rx_seqno = 0;
    vtdev_set_status(dev, VIRTIO_CONFIG_STATUS_DRIVER_OK);
    vsock_set_transport(vs);
    return true;
  err:
    deallocate(general, vs, sizeof(*vs));
    return false;
}

closure_function(2, 1, boolean, vtpci_sock_probe,
                 heap, general, backed_heap, backed,
                 pci_dev d)
{
    if (!vtpci_probe(d, VIRTIO_ID_VSOCK))
        return false;
    heap general = bound(general);
    backed_heap backed = bound(backed);
    vtdev v = (vtdev)attach_vtpci(general, backed, d, VIRTIO_SOCK_DRIVER_FEATURES);
    return virtio_sock_dev_attach(general, backed, v);
}

closure_function(2, 1, void, vtmmio_sock_probe,
                 heap, general, backed_heap, backed,
                 vtmmio d)
{
    if ((vtmmio_get_u32(d, VTMMIO_OFFSET_DEVID) != VIRTIO_ID_VSOCK) ||
        (d->memsize < VTMMIO_OFFSET_CONFIG + sizeof(struct virtio_vsock_config)))
        return;
    heap general = bound(general);
    backed_heap backed = bound(backed);
    if (attach_vtmmio(general, backed, d, VIRTIO_SOCK_DRIVER_FEATURES))
        virtio_sock_dev_attach(general, backed, &d->virtio_dev);
}

void init_virtio_socket(kernel_heaps kh)
{
    heap h = heap_locked(kh);
    backed_heap backed = heap_linear_backed(kh);
    pci_probe probe = closure(h, vtpci_sock_probe, h, backed);
    assert(probe != INVALID_ADDRESS);
    register_pci_driver(probe, 0);
    vtmmio_probe_devs(stack_closure(vtmmio_sock_probe, h, backed));
}

u32 virtio_sock_get_guest_cid(void *priv)
{
    virtio_sock vs = priv;
    return vs->guest_cid;
}

closure_func_basic(thunk, void, virtio_sock_conn_free)
{
    virtio_sock_connection c = struct_from_field(closure_self(), virtio_sock_connection, free);
    deallocate(c->vs->general, c, sizeof(*c));
}

closure_func_basic(vqfinish, void, virtio_sock_tx_complete,
                   u64 len)
{
    virtio_sock_txbuf txbuf = struct_from_field(closure_self(), virtio_sock_txbuf, complete);
    struct virtio_vsock_hdr *hdr = (struct virtio_vsock_hdr *)txbuf->data;
    virtio_sock_debug("tx complete, len %d", hdr->len);
    deallocate((heap)txbuf->vs->backed, txbuf, sizeof(*txbuf) + sizeof(*hdr) + hdr->len);
}

static boolean virtio_sock_tx_hdr(virtio_sock vs, virtio_sock_connection conn, u16 op, u32 flags)
{
    u64 phys;
    virtio_sock_txbuf txbuf = alloc_map(vs->backed,
                                        sizeof(*txbuf) + sizeof(struct virtio_vsock_hdr), &phys);
    if (txbuf == INVALID_ADDRESS)
        return false;
    txbuf->vs = vs;
    struct virtio_vsock_hdr *hdr = (struct virtio_vsock_hdr *)txbuf->data;
    hdr->src_cid = vs->guest_cid;
    hdr->dst_cid = conn->vsock_conn.id.peer_cid;
    hdr->src_port = conn->vsock_conn.id.local_port;
    hdr->dst_port = conn->vsock_conn.id.peer_port;
    hdr->len = 0;
    hdr->type = conn->type;
    hdr->op = op;
    hdr->flags = flags;
    hdr->buf_alloc = conn->buf_alloc;
    hdr->fwd_cnt = conn->fwd_cnt;
    virtio_sock_debug("tx op %d, fwd_cnt %d", op, hdr->fwd_cnt);
    virtqueue vq = vs->txq;
    vqmsg m = allocate_vqmsg(vq);
    if (m == INVALID_ADDRESS) {
        dealloc_unmap(vs->backed, txbuf, phys, sizeof(*txbuf) + sizeof(*hdr));
        return false;
    }
    vqmsg_push(vq, m, phys + offsetof(virtio_sock_txbuf, data), sizeof(*hdr), false);
    vqmsg_commit(vq, m, init_closure_func(&txbuf->complete, vqfinish, virtio_sock_tx_complete));
    return true;
}

static void virtio_socket_conn_update(virtio_sock_connection conn, struct virtio_vsock_hdr *hdr)
{
    u64 old_buf_space = conn->peer_buf_alloc - (conn->tx_cnt - conn->peer_fwd_cnt);
    conn->peer_buf_alloc = hdr->buf_alloc;
    conn->peer_fwd_cnt = hdr->fwd_cnt;
    u64 new_buf_space = conn->peer_buf_alloc - (conn->tx_cnt - conn->peer_fwd_cnt);
    if (new_buf_space > old_buf_space)
        vsock_buf_space_notify(&conn->vsock_conn, new_buf_space);
}

closure_func_basic(vqfinish, void, virtio_sock_rx_complete,
                   u64 len)
{
    virtio_sock_rxbuf rxbuf = struct_from_field(closure_self(), virtio_sock_rxbuf, complete);
    virtio_sock vs = rxbuf->vs;
    boolean free_buf = true;

    /* Ensure received messages are processed in the same order as they are received.
     * This is necessary in order to satisfy the requirements of the stream socket type, which
     * guarantees delivery of ordered packets. */
    u32 attempts = 0;
    while ((volatile u32)vs->rx_seqno != rxbuf->seqno) {
        if (++attempts == 0)
            goto out;
        kern_pause();
    }

    struct virtio_vsock_hdr *hdr = (struct virtio_vsock_hdr *)rxbuf->data;
    if ((len < sizeof(*hdr)) || (hdr->dst_cid != vs->guest_cid) || (hdr->len != len - sizeof(*hdr)))
        goto out;
    virtio_sock_debug("rx from %ld:%d to :%d, len %d, type %d, op %d, buf_alloc %d, fwd_cnt %d",
                      hdr->src_cid, hdr->src_port, hdr->dst_port, hdr->len, hdr->type, hdr->op,
                      hdr->buf_alloc, hdr->fwd_cnt);
    if (hdr->type != VIRTIO_VSOCK_TYPE_STREAM) {    /* unknown type value */
        struct virtio_sock_connection dummy_conn = {
            .vsock_conn = {
                .id = {
                    .local_port = hdr->dst_port,
                    .peer_cid = hdr->src_cid,
                    .peer_port = hdr->src_port,
                },
            },
            .type = hdr->type,
            .buf_alloc = 0,
            .fwd_cnt = 0,
        };
        virtio_sock_tx_hdr(vs, &dummy_conn, VIRTIO_VSOCK_OP_RST, 0);
        goto out;
    }
    struct vsock_conn_id conn_id;
    virtio_sock_connection conn = 0;
    conn_id.local_port = hdr->dst_port;
    conn_id.peer_cid = hdr->src_cid;
    conn_id.peer_port = hdr->src_port;
    switch (hdr->op) {
    case VIRTIO_VSOCK_OP_REQUEST:
        conn = (virtio_sock_connection)virtio_sock_conn_new(vs, conn_id.local_port,
                                                            conn_id.peer_cid, conn_id.peer_port,
                                                            vsock_get_buf_size());
        if (conn != INVALID_ADDRESS) {
            vsock_conn_lock(&conn->vsock_conn);
            boolean success = vsock_connect_request(&conn->vsock_conn);
            if (success) {
                if (!virtio_sock_tx_hdr(vs, conn, VIRTIO_VSOCK_OP_RESPONSE, 0)) {
                    vsock_conn_unlock(&conn->vsock_conn);
                    vsock_conn_release(&conn->vsock_conn);
                    vsock_conn_reset(&conn_id);
                    goto out;
                }
            } else {
                virtio_sock_tx_hdr(vs, conn, VIRTIO_VSOCK_OP_RST, 0);
            }
            if (success) {
                conn->peer_buf_alloc = hdr->buf_alloc;
                conn->peer_fwd_cnt = hdr->fwd_cnt;
            }
            vsock_conn_unlock(&conn->vsock_conn);
            if (!success)
                vsock_conn_release(&conn->vsock_conn);
        }
        goto out;
    case VIRTIO_VSOCK_OP_RESPONSE:
        conn = (virtio_sock_connection)vsock_connect_complete(&conn_id, true);
        break;
    case VIRTIO_VSOCK_OP_RST:
        vsock_conn_reset(&conn_id);
        break;
    case VIRTIO_VSOCK_OP_SHUTDOWN: {
        int flags = (hdr->flags & VIRTIO_VSOCK_SHUTDOWN_F_RECEIVE) ? VSOCK_SHUTDOWN_TX : 0;
        if (hdr->flags & VIRTIO_VSOCK_SHUTDOWN_F_SEND)
            flags |= VSOCK_SHUTDOWN_RX;
        boolean conn_close;
        conn = (virtio_sock_connection)vsock_shutdown_request(&conn_id, flags, &conn_close);
        if (conn && conn_close)
            virtio_sock_tx_hdr(vs, conn, VIRTIO_VSOCK_OP_RST, 0);
        break;
    }
    case VIRTIO_VSOCK_OP_RW:
        conn = (virtio_sock_connection)vsock_rx(&conn_id, hdr + 1, hdr->len);
        free_buf = false;
        break;
    case VIRTIO_VSOCK_OP_CREDIT_UPDATE:
        conn = (virtio_sock_connection)vsock_get_conn(&conn_id);
        break;
    case VIRTIO_VSOCK_OP_CREDIT_REQUEST:
        conn = (virtio_sock_connection)vsock_get_conn(&conn_id);
        if (conn)
            virtio_sock_tx_hdr(vs, conn, VIRTIO_VSOCK_OP_CREDIT_UPDATE, 0);
        break;
    }
    if (conn) {
        virtio_socket_conn_update(conn, hdr);
        vsock_conn_unlock(&conn->vsock_conn);
        vsock_conn_release(&conn->vsock_conn);
    }
  out:
    vs->rx_seqno++;
    if (free_buf)
        deallocate((heap)vs->backed, rxbuf, VIRTIO_SOCK_RXBUF_SIZE);
    virtio_sock_rxq_submit(vs);
}

static boolean virtio_sock_rxq_submit(virtio_sock vs)
{
    virtqueue vq = vs->rxq;
    int free_entries = virtqueue_free_entries(vq);
    virtio_sock_debug("rxq submit: %d free entries", free_entries);
    int new_entries = 0;
    u64 phys;
    while (new_entries < free_entries) {
        virtio_sock_rxbuf rxbuf = alloc_map(vs->backed, VIRTIO_SOCK_RXBUF_SIZE, &phys);
        if (rxbuf == INVALID_ADDRESS)
            break;
        vqmsg m = allocate_vqmsg(vq);
        if (m == INVALID_ADDRESS) {
            dealloc_unmap(vs->backed, rxbuf, phys, VIRTIO_SOCK_RXBUF_SIZE);
            break;
        }
        u64 data_offset = offsetof(virtio_sock_rxbuf, data);
        vqmsg_push(vq, m, phys + data_offset, sizeof(struct virtio_vsock_hdr), true);
        data_offset += sizeof(struct virtio_vsock_hdr);
        vqmsg_push(vq, m, phys + data_offset, VIRTIO_SOCK_RXBUF_SIZE - data_offset, true);
        rxbuf->vs = vs;
        new_entries += VIRTIO_SOCK_RX_PACKET_DESCS;
        vqmsg_commit_seqno(vq, m,
                           init_closure_func(&rxbuf->complete, vqfinish, virtio_sock_rx_complete),
                           &rxbuf->seqno, new_entries >= free_entries);
    }
    if (new_entries == 0)
        return false;
    if (new_entries < free_entries)
        virtqueue_kick(vq);
    return true;
}

vsock_connection virtio_sock_conn_new(void *priv, u32 local_port, u32 peer_cid, u32 peer_port,
                                      u32 buf_size)
{
    virtio_sock vs = priv;
    virtio_sock_connection c = allocate(vs->general, sizeof(*c));
    if (c == INVALID_ADDRESS)
        return INVALID_ADDRESS;
    vsock_conn_init(&c->vsock_conn, local_port, peer_cid, peer_port,
                    init_closure_func(&c->free, thunk, virtio_sock_conn_free));
    c->vs = vs;
    c->type = VIRTIO_VSOCK_TYPE_STREAM;
    c->buf_alloc = buf_size;
    c->fwd_cnt = c->tx_cnt = 0;
    return &c->vsock_conn;
}

boolean virtio_sock_connect(vsock_connection conn)
{
    virtio_sock_connection c = (virtio_sock_connection)conn;
    virtio_sock vs = c->vs;
    return virtio_sock_tx_hdr(vs, c, VIRTIO_VSOCK_OP_REQUEST, 0);
}

boolean virtio_sock_connect_abort(vsock_connection conn)
{
    virtio_sock_connection c = (virtio_sock_connection)conn;
    virtio_sock vs = c->vs;
    return virtio_sock_tx_hdr(vs, c, VIRTIO_VSOCK_OP_RST, 0);
}

void *virtio_sock_alloc_txbuf(void *priv, u64 size)
{
    virtio_sock vs = priv;
    virtio_sock_txbuf txbuf = allocate((heap)vs->backed,
                                       sizeof(*txbuf) + sizeof(struct virtio_vsock_hdr) + size);
    if (txbuf == INVALID_ADDRESS)
        return INVALID_ADDRESS;
    txbuf->vs = vs;
    struct virtio_vsock_hdr *hdr = (struct virtio_vsock_hdr *)txbuf->data;
    hdr->len = size;
    return hdr + 1;
}

void virtio_sock_free_txbuf(void *priv, void *buf)
{
    virtio_sock vs = priv;
    struct virtio_vsock_hdr *hdr = buf - sizeof(*hdr);
    virtio_sock_txbuf txbuf = (void *)hdr - offsetof(virtio_sock_txbuf, data);
    deallocate((heap)vs->backed, txbuf, sizeof(*txbuf) + hdr->len);
}

void virtio_sock_free_rxbuf(void *priv, void *buf)
{
    virtio_sock vs = priv;
    virtio_sock_rxbuf rxbuf = buf - sizeof(struct virtio_vsock_hdr) -
                              offsetof(virtio_sock_rxbuf, data);
    deallocate((heap)vs->backed, rxbuf, VIRTIO_SOCK_RXBUF_SIZE);
}

u64 virtio_sock_get_buf_space(vsock_connection conn)
{
    virtio_sock_connection c = (virtio_sock_connection)conn;
    return c->peer_buf_alloc - (c->tx_cnt - c->peer_fwd_cnt);
}

boolean virtio_sock_tx(vsock_connection conn, void *data)
{
    virtio_sock_connection c = (virtio_sock_connection)conn;
    virtio_sock vs = c->vs;
    struct virtio_vsock_hdr *hdr = data - sizeof(*hdr);
    virtio_sock_txbuf txbuf = struct_from_field(hdr, virtio_sock_txbuf, data);
    hdr->src_cid = vs->guest_cid;
    hdr->dst_cid = conn->id.peer_cid;
    hdr->src_port = conn->id.local_port;
    hdr->dst_port = conn->id.peer_port;
    hdr->type = c->type;
    hdr->op = VIRTIO_VSOCK_OP_RW;
    hdr->flags = 0;
    hdr->buf_alloc = c->buf_alloc;
    hdr->fwd_cnt = c->fwd_cnt;
    virtio_sock_debug("tx data, fwd_cnt %d", hdr->fwd_cnt);
    virtqueue vq = vs->txq;
    vqmsg m = allocate_vqmsg(vq);
    if (m == INVALID_ADDRESS)
        return false;
    c->tx_cnt += hdr->len;
    u64 phys = physical_from_virtual(hdr);

    /* 2 descriptors (one for the header and one for the payload) are needed because AWS Firecracker
     * does not support handling a data packet from a single descriptor. */
    vqmsg_push(vq, m, phys, sizeof(*hdr), false);
    vqmsg_push(vq, m, phys + sizeof(*hdr), hdr->len, false);

    vqmsg_commit(vq, m, init_closure_func(&txbuf->complete, vqfinish, virtio_sock_tx_complete));
    return true;
}

void virtio_sock_recved(vsock_connection conn, u64 length)
{
    virtio_sock_debug("recved %ld", length);
    virtio_sock_connection c = (virtio_sock_connection)conn;
    c->fwd_cnt += length;
    virtio_sock_tx_hdr(c->vs, c, VIRTIO_VSOCK_OP_CREDIT_UPDATE, 0);
}

boolean virtio_sock_shutdown(vsock_connection conn, int flags)
{
    virtio_sock_connection c = (virtio_sock_connection)conn;
    virtio_sock vs = c->vs;
    u32 virtio_sock_flags = (flags & VSOCK_SHUTDOWN_TX) ? VIRTIO_VSOCK_SHUTDOWN_F_SEND : 0;
    if (flags & VSOCK_SHUTDOWN_RX)
        virtio_sock_flags |= VIRTIO_VSOCK_SHUTDOWN_F_RECEIVE;
    return virtio_sock_tx_hdr(vs, c, VIRTIO_VSOCK_OP_SHUTDOWN, virtio_sock_flags);
}
