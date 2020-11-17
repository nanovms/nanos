#include <kernel.h>
#include <lwip.h>
#include <net.h>

//#define DIRECT_DEBUG
#ifdef DIRECT_DEBUG
#define direct_debug(x, ...) do {log_printf("DNET", "%s: " x, __func__, ##__VA_ARGS__);} while(0)
#else
#define direct_debug(x, ...)
#endif

typedef struct direct {
    connection_handler new;
    struct tcp_pcb *p;
    heap h;
    struct list conn_head;
} *direct;

declare_closure_struct(1, 1, status, direct_conn_send,
                       struct direct_conn *, dc,
                       buffer, b);

typedef struct direct_conn {
    direct d;
    struct spinlock send_lock;
    struct list l;              /* direct list */
    struct tcp_pcb *p;
    struct list sendq_head;
    closure_struct(direct_conn_send, send_bh);
    buffer_handler receive_bh;
    err_t pending_err;          /* lwIP */
} *direct_conn;

/* suppose this could store a completion if a client needs it */
typedef struct qbuf {
    struct list l;
    buffer b;
} *qbuf;

static void direct_conn_dealloc(direct_conn dc);

static direct direct_alloc(heap h, connection_handler ch)
{
    direct d = allocate(h, sizeof(struct direct));
    if (d == INVALID_ADDRESS)
        return d;
    d->p = tcp_new_ip_type(IPADDR_TYPE_ANY);
    if (!d->p) {
        msg_err("PCB creation failed\n");
        deallocate(h, d, sizeof(struct direct));
        return INVALID_ADDRESS;
    }
    d->h = h;
    d->new = ch;
    tcp_arg(d->p, d);
    return d;
}

static void direct_dealloc(direct d)
{
    if (d->p) {
        tcp_arg(d->p, 0);
        tcp_close(d->p);
    }
    deallocate(d->h, d, sizeof(struct direct));
}

static status direct_conn_closed(direct_conn dc)
{
    status s = apply(dc->receive_bh, 0);
    direct d = dc->d;
    boolean client = (dc->p == d->p);
    if (!client)
        list_delete(&dc->l);
    direct_conn_dealloc(dc);
    if (client) {
        d->p = 0;
        direct_dealloc(d);
    }
    return s;
}

static void direct_conn_send_internal(direct_conn dc, qbuf q)
{
    direct_debug("dc %p\n", dc);
    list next;

    /* It appears TCP_EVENT_SENT is only called from tcp_input. If in
       the future it could ever be invoked as a result of a call to
       tcp_write or tcp_output, this will need to be revised to avoid
       deadlock. */
    spin_lock(&dc->send_lock);
    if (q)
        list_insert_before(&dc->sendq_head, &q->l);
    while ((next = list_get_next(&dc->sendq_head))) {
        qbuf q = struct_from_list(next, qbuf, l);
        if (!q->b) {
            /* close connection - should check error, but would need status handler... */
            direct_debug("connection close by sender\n");
            tcp_arg(dc->p, 0);
            tcp_close(dc->p);
            list_delete(&q->l);
            deallocate(dc->d->h, q, sizeof(struct qbuf));
            direct_conn_closed(dc);
            break;
        }

        int avail = tcp_sndbuf(dc->p);
        if (avail == 0)
            break;

        int write_len = MIN(avail, buffer_length(q->b));
        /* Fix interface: can send with PSH flag clear
           (TCP_WRITE_FLAG_MORE) if we know more data is on the way... */
        direct_debug("write %p, len %d\n", buffer_ref(q->b, 0), write_len);
        err_t err = tcp_write(dc->p, buffer_ref(q->b, 0), write_len, TCP_WRITE_FLAG_COPY);
        if (err == ERR_MEM)
            break;

        err = tcp_output(dc->p);
        if (err != ERR_OK) {
            msg_err("tcp_output failed with %d\n", err);
            break;
        }

        buffer_consume(q->b, write_len);
        direct_debug("remaining %d\n", buffer_length(q->b));

        /* pop off qbuf if work finished, else loop around to attempt to send more */
        if (!q->b || buffer_length(q->b) == 0) {
            if (q->b)
                deallocate_buffer(q->b);
            list_delete(&q->l);
            deallocate(dc->d->h, q, sizeof(struct qbuf));
        }
    }
    spin_unlock(&dc->send_lock);
}

static err_t direct_conn_sent(void *arg, struct tcp_pcb *pcb, u16 len)
{
    assert(arg);
    direct_conn_send_internal((direct_conn)arg, 0);
    return ERR_OK;
}

define_closure_function(1, 1, status, direct_conn_send,
                 direct_conn, dc,
                 buffer, b)
{
    direct_debug("dc %p, b %p, len %ld\n", bound(dc), b, b ? buffer_length(b) : 0);
    status s = STATUS_OK;
    direct_conn dc = bound(dc);

    /* enqueue qbuf, even if !b */
    qbuf q = allocate(dc->d->h, sizeof(struct qbuf));
    if (q == INVALID_ADDRESS) {
        s = timm("result", "%s: failed to allocate qbuf", __func__);
    } else {
        /* queue even if b == 0 (acts as close connection command) */
        q->b = b;
        direct_conn_send_internal(dc, q);
    }
    return s;
}

err_t direct_conn_input(void *z, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
    direct_debug("dc %p, pcb %p, pbuf %p, err %d\n", z, pcb, p, err);
    direct_conn dc = z;
    status s;
    /* XXX err */
    if (p) {
        /* handler must consume entire buffer */
        s = apply(dc->receive_bh, alloca_wrap_buffer(p->payload, p->len));
        tcp_recved(pcb, p->len);
    } else {
        /* connection closed */
        s = direct_conn_closed(dc);
    }

    if (!is_ok(s)) {
        /* report here? handler should be able to dispatch error... */
        msg_err("handler failed with status %v; aborting connection\n", s);
        return ERR_ABRT;
    }
    return ERR_OK;
}

static void direct_conn_err(void *z, err_t err)
{
    direct_debug("dc %p, err %d\n", z, err);
    status s;
    direct_conn dc = z;
    switch (err) {
    case ERR_ABRT:
    case ERR_RST:
    case ERR_CLSD:
        /* connection closed */
        s = direct_conn_closed(dc);
        if (!is_ok(s))
            rprintf("%s: failed to close: %v\n", __func__, s);
        return;
    }
    rprintf("%s: dc %p, err %d\n", __func__, dc, err);
    dc->pending_err = err;
}

static direct_conn direct_conn_alloc(direct d, struct tcp_pcb *pcb)
{
    direct_conn dc = allocate(d->h, sizeof(struct direct_conn));
    if (dc == INVALID_ADDRESS)
        goto fail;
    spin_lock_init(&dc->send_lock);
    dc->d = d;
    dc->p = pcb;
    list_init(&dc->sendq_head);
    buffer_handler bh = apply(d->new, init_closure(&dc->send_bh, direct_conn_send, dc));
    if (bh == INVALID_ADDRESS)
        goto fail_dealloc;
    dc->receive_bh = bh;
    dc->pending_err = ERR_OK;
    tcp_arg(pcb, dc);
    tcp_err(pcb, direct_conn_err);
    tcp_recv(pcb, direct_conn_input);
    tcp_sent(pcb, direct_conn_sent);
    return dc;
  fail_dealloc:
    deallocate(d->h, dc, sizeof(struct direct_conn));
  fail:
    msg_err("failed to establish direct connection\n");
    return INVALID_ADDRESS;
}

static void direct_conn_dealloc(direct_conn dc)
{
    deallocate(dc->d->h, dc, sizeof(struct direct_conn));
}

static void direct_listen_err(void *z, err_t err)
{
    direct d = z;
    rprintf("%s: d %p, err %d\n", __func__, d, err);
    /* XXX TODO */
}

static err_t direct_accept(void *z, struct tcp_pcb *pcb, err_t b)
{
    direct_debug("d %p, pcb %p, err %d\n", z, pcb, b);
    direct d = z;
    direct_conn dc = direct_conn_alloc(d, pcb);
    if (dc != INVALID_ADDRESS) {
        list_insert_before(&d->conn_head, &dc->l);
        return ERR_OK;
    } else {
        return ERR_ABRT;
    }
}

status listen_port(heap h, u16 port, connection_handler c)
{
    direct_debug("port %d, c %p\n", port, c);
    status s = STATUS_OK;
    char *op;
    err_t err = ERR_OK;
    direct d = direct_alloc(h, c);
    if (d == INVALID_ADDRESS) {
        op = "allocate";
        goto fail;
    }
    list_init(&d->conn_head);

    err = tcp_bind(d->p, IP_ANY_TYPE, port);
    if (err != ERR_OK) {
        op = "tcp_bind";
        goto fail_dealloc;
    }
    d->p = tcp_listen(d->p);
    tcp_err(d->p, direct_listen_err);
    tcp_accept(d->p, direct_accept);
    return s;
  fail_dealloc:
    direct_dealloc(d);
  fail:
    s = timm("result", "%s: %s failed", __func__, op);
    if (err != ERR_OK)
        timm_append(s, "lwip_error", "%d", err);
    return s;
}

static err_t direct_connect_complete(void* arg, struct tcp_pcb* pcb, err_t err)
{
    direct d = arg;
    direct_debug("d %p, err %d\n", d, err);
    return (direct_conn_alloc(d, pcb) != INVALID_ADDRESS) ? ERR_OK : ERR_ABRT;
}

static void direct_connect_err(void *arg, err_t err)
{
    direct d = arg;
    direct_debug("d %p, err %d\n", d, err);
    apply(d->new, 0);
    d->p = 0;
    direct_dealloc(d);
}

status direct_connect(heap h, ip_addr_t *addr, u16 port, connection_handler ch)
{
    direct_debug("addr %s, port %d, ch %F\n", ipaddr_ntoa(addr), port, ch);
    direct d = direct_alloc(h, ch);
    if (d == INVALID_ADDRESS)
        return timm("result", "%s: alloc failed", __func__);
    tcp_err(d->p, direct_connect_err);
    err_t err = tcp_connect(d->p, addr, port, direct_connect_complete);
    if (err == ERR_OK) {
        return STATUS_OK;
    } else {
        direct_dealloc(d);
        return timm("result", "connect failed (%d)", err);
    }
}
KLIB_EXPORT(direct_connect);
