#include <runtime.h>
#include <lwip.h>
#include <tfs.h> // XXX fix
#include <unix.h>
#include <net.h>

typedef struct direct {
    connection_handler new;
    struct tcp_pcb *p;
    heap h;
} *direct;

closure_function(1, 1, status, direct_send,
                 struct tcp_pcb *, pcb,
                 buffer, b)
{
    err_t err;
    if (!b) {
        /* close connection */
        err = tcp_close(bound(pcb));
        if (err != ERR_OK)
            return timm("result", "%s: tcp_close returned with error %d", __func__, err);
        return STATUS_OK;
    }
    /* Fix interface: can send with PSH flag clear
       (TCP_WRITE_FLAG_MORE) if we know more data is on the way... */
    err = tcp_write(bound(pcb), buffer_ref(b, 0), buffer_length(b), TCP_WRITE_FLAG_COPY);
    if (err != ERR_OK)
        return timm("result", "%s: tcp_write returned with error %d", __func__, err);
    return STATUS_OK;
}

err_t direct_input(void *z, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
    buffer_handler bh = z;
    status s;
    if (p) {
        /* handler must consume entire buffer */
        s = apply(bh, alloca_wrap_buffer(p->payload, p->len));
        tcp_recved(pcb, p->len);
    } else {
        /* connection closed */
        s = apply(bh, 0);
    }
    if (!is_ok(s)) {
        /* report here? handler should be able to dispatch error... */
        msg_err("handler failed with status %v; aborting connection\n", s);
        return ERR_ABRT;
    }
    return ERR_OK;
}

/* XXX store error and report later */
static void direct_conn_err(void *z, err_t err)
{
    buffer_handler bh = z;
    rprintf("%s: bh %p, err %d\n", __func__, bh, err);
}

static void direct_listen_err(void *z, err_t err)
{
    direct g = z;
    rprintf("%s: g %p, err %d\n", __func__, g, err);
}

/* XXX per-connection descriptor as tcp arg? */
static err_t direct_accept(void *z, struct tcp_pcb *pcb, err_t b)
{
    direct g = z;
    buffer_handler bh = apply(g->new, closure(g->h, direct_send, pcb));
    if (bh == INVALID_ADDRESS) {
        msg_err("failed to establish direct connection\n");
        return ERR_ABRT;
    }
    tcp_arg(pcb, bh);
    tcp_err(pcb, direct_conn_err);
    tcp_recv(pcb, direct_input);
    return ERR_OK;
}

void listen_port(heap h, u16 port, connection_handler c)
{
    direct g = allocate(h, sizeof(struct direct));
    g->p = tcp_new_ip_type(IPADDR_TYPE_ANY);
    g->h = h;
    g->new = c;
    tcp_bind(g->p, IP_ANY_TYPE, port);
    g->p = tcp_listen(g->p);
    tcp_arg(g->p, g);
    tcp_err(g->p, direct_listen_err);
    tcp_accept(g->p, direct_accept);    
}
