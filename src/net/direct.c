#include <kernel.h>
#include <lwip.h>
#include <tfs.h> // XXX fix headers
#include <unix.h>
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

typedef struct direct_conn {
    direct d;
    boolean running;            /* background processing started */
    struct list l;              /* direct list */
    struct tcp_pcb *p;
    struct list sendq_head;
    buffer_handler receive_bh;
    err_t pending_err;          /* lwIP */
} *direct_conn;

/* suppose this could store a completion if a client needs it */
typedef struct qbuf {
    struct list l;
    buffer b;
} *qbuf;

/* return true if sendq empty */
static boolean direct_conn_send_internal(direct_conn dc)
{
    direct_debug("dc %p\n", dc);
    list next;

    while ((next = list_get_next(&dc->sendq_head))) {
        qbuf q = struct_from_list(next, qbuf, l);
        if (!q->b) {
            /* close connection - should check error, but would need status handler... */
            direct_debug("connection close by sender\n");
            tcp_close(dc->p);
            list_delete(&q->l);
            deallocate(dc->d->h, q, sizeof(struct qbuf));
            return true;
        }

        int avail = tcp_sndbuf(dc->p);
        if (avail == 0)
            return false;

        int write_len = MIN(avail, buffer_length(q->b));
        /* Fix interface: can send with PSH flag clear
           (TCP_WRITE_FLAG_MORE) if we know more data is on the way... */
        direct_debug("write %p, len %d\n", buffer_ref(q->b, 0), write_len);
        err_t err = tcp_write(dc->p, buffer_ref(q->b, 0), write_len, TCP_WRITE_FLAG_COPY);
        if (err == ERR_MEM)
            return false;

        err = tcp_output(dc->p);
        if (err != ERR_OK) {
            msg_err("tcp_output failed with %d\n", err);
            return false;
        }

        /* should handle some other way */
        if (err != ERR_OK) {
            /* XXX */
            return false;
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
    return true;
}

closure_function(1, 0, void, direct_conn_send_bh,
                 direct_conn, dc)
{
    if (direct_conn_send_internal(bound(dc))) {
        direct_debug("finished\n");
        bound(dc)->running = false;
        closure_finish();
    } else {
        direct_debug("re-enqueue\n");
        enqueue(runqueue, closure_self());
    }
}

closure_function(1, 1, status, direct_conn_send,
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
        u64 flags = irq_disable_save();
        list_insert_before(&dc->sendq_head, &q->l); /* really need CAS version */
        irq_restore(flags);
        if (!direct_conn_send_internal(dc)) {
            if (!dc->running) {
                thunk t = closure(dc->d->h, direct_conn_send_bh, dc);
                dc->running = true;
                assert(enqueue(runqueue, t));
            }
        }
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
        s = apply(dc->receive_bh, 0);
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
        s = apply(dc->receive_bh, 0);
        if (!is_ok(s))
            rprintf("%s: failed to close: %v\n", __func__, s);
        return;
    }
    rprintf("%s: dc %p, err %d\n", __func__, dc, err);
    dc->pending_err = err;
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
    direct_conn dc = allocate(d->h, sizeof(struct direct_conn));
    if (dc == INVALID_ADDRESS)
        goto fail;
    dc->d = d;
    dc->running = false;
    dc->p = pcb;
    list_init(&dc->sendq_head);
    buffer_handler bh = apply(d->new, closure(d->h, direct_conn_send, dc));
    if (bh == INVALID_ADDRESS)
        goto fail_dealloc;
    dc->receive_bh = bh;
    dc->pending_err = ERR_OK;
    list_insert_before(&d->conn_head, &dc->l);
    tcp_arg(pcb, dc);
    tcp_err(pcb, direct_conn_err);
    tcp_recv(pcb, direct_conn_input);
    return ERR_OK;
  fail_dealloc:
    deallocate(d->h, dc, sizeof(struct direct_conn));
  fail:
    msg_err("failed to establish direct connection\n");
    return ERR_ABRT;
}

status listen_port(heap h, u16 port, connection_handler c)
{
    direct_debug("port %d, c %p\n", port, c);
    status s = STATUS_OK;
    char *op;
    err_t err = ERR_OK;
    direct d = allocate(h, sizeof(struct direct));
    if (d == INVALID_ADDRESS) {
        op = "allocate";
        goto fail;
    }
    d->new = c;
    d->p = tcp_new_ip_type(IPADDR_TYPE_ANY);
    if (!d->p) {
        op = "tcp_new_ip_type";
        goto fail_dealloc;
    }
    d->h = h;
    list_init(&d->conn_head);

    err = tcp_bind(d->p, IP_ANY_TYPE, port);
    if (err != ERR_OK) {
        op = "tcp_bind";
        goto fail_dealloc;
    }
    d->p = tcp_listen(d->p);
    tcp_arg(d->p, d);
    tcp_err(d->p, direct_listen_err);
    tcp_accept(d->p, direct_accept);
    return s;
  fail_dealloc:
    deallocate(h, d, sizeof(struct direct));
  fail:
    s = timm("result", "%s: %s failed", __func__, op);
    if (err != ERR_OK)
        timm_append(s, "lwip_error", "%d", err);
    return s;
}
