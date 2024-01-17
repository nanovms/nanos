#include <kernel.h>
#include <lwip.h>
#include <net.h>

//#define DIRECT_DEBUG
#ifdef DIRECT_DEBUG
#define direct_debug(x, ...) do {log_printf(ss("DNET"), ss("%s: " x), func_ss, ##__VA_ARGS__);} while(0)
#else
#define direct_debug(x, ...)
#endif

declare_closure_struct(1, 0, void, direct_receive_service,
                       struct direct *, d);

typedef struct direct {
    connection_handler new;
    struct tcp_pcb *p;
    heap h;
    struct spinlock conn_lock;
    struct list conn_head;
    closure_struct(direct_receive_service, receive_service);
    u32 receive_service_scheduled;
} *direct;

#define DIRECT_CONN_RECEIVE_QUEUE_SIZE 1024

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
    input_buffer_handler receive_bh;
    queue receive_queue;
    err_t pending_err;          /* lwIP */
} *direct_conn;

/* suppose this could store a completion if a client needs it */
typedef struct qbuf {
    struct list l;
    buffer b;
} *qbuf;

static boolean direct_conn_closed(direct_conn dc);

define_closure_function(1, 0, void, direct_receive_service,
                        direct, d)
{
    direct d = bound(d);
    d->receive_service_scheduled = 0;
    write_barrier();
    spin_lock(&d->conn_lock);
    list_foreach(&d->conn_head, l) {
        direct_conn dc = struct_from_list(l, direct_conn, l);
        if (!dc->receive_bh) {
            input_buffer_handler bh = apply(d->new, (buffer_handler)&dc->send_bh);
            if (bh == INVALID_ADDRESS) {
                tcp_lock(dc->p);
                tcp_arg(dc->p, 0);
                tcp_close(dc->p);
                tcp_unlock(dc->p);
                boolean done = direct_conn_closed(dc);
                if (done)
                    return;
                continue;
            }
            dc->receive_bh = bh;
        }
        boolean client = (d->p == 0);
        input_buffer_handler ibh = dc->receive_bh;
        while (true) {
            struct pbuf *p = dequeue(dc->receive_queue);
            if (p == INVALID_ADDRESS)
                break;
            if (p) {
                buffer b = alloca_wrap_buffer(p->payload, p->len);
                boolean done = apply(ibh, b);
                if (!done) {
                    struct pbuf *q = p->next;
                    while (q) {
                        bytes len = q->len;
                        init_buffer(b, len, true, 0, q->payload);
                        buffer_produce(b, len);
                        done = apply(ibh, b);
                        if (done)
                            break;
                        q = q->next;
                    }
                }
                if (!done) {
                    tcp_lock(dc->p);
                    tcp_recved(dc->p, p->len);
                    tcp_unlock(dc->p);
                }
                pbuf_free(p);
                if (done) {
                    if (client)
                        return;
                    break;
                }
            } else {
                boolean done = direct_conn_closed(dc);
                if (done)
                    return;
                break;
            }
        }
    }
    spin_unlock(&d->conn_lock);
}

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
    spin_lock_init(&d->conn_lock);
    list_init(&d->conn_head);
    init_closure(&d->receive_service, direct_receive_service, d);
    d->receive_service_scheduled = 0;
    d->new = ch;
    tcp_arg(d->p, d);
    tcp_ref(d->p);
    return d;
}

/* lwIP locked on entry */
static void direct_dealloc(direct d)
{
    if (d->p) {
        tcp_lock(d->p);
        tcp_arg(d->p, 0);
        tcp_close(d->p);
        tcp_unlock(d->p);
        tcp_unref(d->p);
    }
    deallocate(d->h, d, sizeof(struct direct));
}

/* lwIP locked on entry */
static boolean direct_conn_closed(direct_conn dc)
{
    if (dc->receive_bh)
        apply(dc->receive_bh, 0);
    direct d = dc->d;
    boolean client = (d->p == 0);
    tcp_unref(dc->p);
    list_delete(&dc->l);
    heap h = dc->d->h;
    struct list *send_elem;
    while ((send_elem = list_get_next(&dc->sendq_head))) {
        qbuf q = struct_from_list(send_elem, qbuf, l);
        if (q->b)
            deallocate_buffer(q->b);
        list_delete(&q->l);
        deallocate(h, q, sizeof(struct qbuf));
    }
    while (!queue_empty(dc->receive_queue)) {
        struct pbuf *p = dequeue(dc->receive_queue);
        if (p)
            pbuf_free(p);
    }
    deallocate_queue(dc->receive_queue);
    deallocate(h, dc, sizeof(struct direct_conn));
    if (client)
        direct_dealloc(d);
    return client;
}

static void direct_conn_send_internal(direct_conn dc, qbuf q, boolean lwip_locked)
{
    direct_debug("dc %p\n", dc);
    list next;

    if (!lwip_locked)
        tcp_lock(dc->p);
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
            if (!lwip_locked)
                tcp_unlock(dc->p);
            list_delete(&q->l);
            deallocate(dc->d->h, q, sizeof(struct qbuf));
            direct_conn_closed(dc);
            dc = 0;
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
    if (dc) {
        spin_unlock(&dc->send_lock);
        if (!lwip_locked)
            tcp_unlock(dc->p);
    }
}

static err_t direct_conn_sent(void *arg, struct tcp_pcb *pcb, u16 len)
{
    assert(arg);
    direct_conn_send_internal((direct_conn)arg, 0, true);
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
        s = timm("result", "%s: failed to allocate qbuf", func_ss);
    } else {
        /* queue even if b == 0 (acts as close connection command) */
        q->b = b;
        direct_conn_send_internal(dc, q, false);
    }
    return s;
}

static void direct_conn_enqueue(direct_conn dc, struct pbuf *p)
{
    assert(enqueue(dc->receive_queue, p));
    if (compare_and_swap_32(&dc->d->receive_service_scheduled, 0, 1))
        async_apply((thunk)&dc->d->receive_service);
}

err_t direct_conn_input(void *z, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
    direct_debug("dc %p, pcb %p, pbuf %p, err %d\n", z, pcb, p, err);
    if (p)
        direct_conn_enqueue(z, p);
    return ERR_OK;
}

static void direct_conn_err(void *z, err_t err)
{
    direct_debug("dc %p, err %d\n", z, err);
    direct_conn dc = z;
    switch (err) {
    case ERR_ABRT:
    case ERR_RST:
    case ERR_CLSD:
        /* connection closed */
        direct_conn_enqueue(dc, 0);
        return;
    }
    msg_err("dc %p, err %d\n", dc, err);
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
    init_closure(&dc->send_bh, direct_conn_send, dc);
    dc->receive_bh = 0;
    dc->receive_queue = allocate_queue(d->h, DIRECT_CONN_RECEIVE_QUEUE_SIZE);
    if (dc->receive_queue == INVALID_ADDRESS)
        goto fail_dealloc;
    dc->pending_err = ERR_OK;
    if (pcb == d->p)
        d->p = 0;
    else
        tcp_ref(pcb);
    tcp_arg(pcb, dc);
    tcp_err(pcb, direct_conn_err);
    tcp_recv(pcb, direct_conn_input);
    tcp_sent(pcb, direct_conn_sent);
    spin_lock(&d->conn_lock);
    list_insert_before(&d->conn_head, &dc->l);
    spin_unlock(&d->conn_lock);
    if (compare_and_swap_32(&d->receive_service_scheduled, 0, 1))
        async_apply((thunk)&d->receive_service);
    return dc;
  fail_dealloc:
    deallocate(d->h, dc, sizeof(struct direct_conn));
  fail:
    msg_err("failed to establish direct connection\n");
    return INVALID_ADDRESS;
}

static void direct_listen_err(void *z, err_t err)
{
    direct d = z;
    msg_err("d %p, err %d\n", d, err);
    /* XXX TODO */
}

static err_t direct_accept(void *z, struct tcp_pcb *pcb, err_t b)
{
    direct_debug("d %p, pcb %p, err %d\n", z, pcb, b);
    direct d = z;
    direct_conn dc = direct_conn_alloc(d, pcb);
    if (dc != INVALID_ADDRESS) {
        return ERR_OK;
    } else {
        return ERR_ABRT;
    }
}

status listen_port(heap h, u16 port, connection_handler c)
{
    direct_debug("port %d, c %p\n", port, c);
    status s = STATUS_OK;
    sstring op;
    err_t err = ERR_OK;
    direct d = direct_alloc(h, c);
    if (d == INVALID_ADDRESS) {
        op = ss("allocate");
        goto fail;
    }
    err = tcp_bind(d->p, IP_ANY_TYPE, port);
    if (err != ERR_OK) {
        op = ss("tcp_bind");
        goto fail_unlock_dealloc;
    }
    tcp_unref(d->p);
    d->p = tcp_listen(d->p);
    tcp_ref(d->p);
    tcp_err(d->p, direct_listen_err);
    tcp_accept(d->p, direct_accept);
    return s;
  fail_unlock_dealloc:
    direct_dealloc(d);
  fail:
    s = timm("result", "%s: %s failed", func_ss, op);
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
    status s = STATUS_OK;
#ifdef DIRECT_DEBUG
    char addr_str[IPADDR_STRLEN_MAX];
    direct_debug("addr %s, port %d, ch %F\n",
                 isstring(addr_str, ipaddr_ntoa_r(addr, addr_str, sizeof(addr_str))), port, ch);
#endif
    direct d = direct_alloc(h, ch);
    if (d == INVALID_ADDRESS)
        return timm("result", "%s: alloc failed", func_ss);
    tcp_lock(d->p);
    tcp_err(d->p, direct_connect_err);
    err_t err = tcp_connect(d->p, addr, port, direct_connect_complete);
    tcp_unlock(d->p);
    if (err != ERR_OK) {
        direct_dealloc(d);
        s = timm("result", "connect failed (%d)", err);
    }
    return s;
}
