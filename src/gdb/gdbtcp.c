#include <gdb_internal.h>

typedef struct tcpgdb{
    buffer_handler input;
    struct tcp_pcb *p;
} *tcpgdb;
    
closure_function(1, 1, status, gdb_send,
                 tcpgdb, g,
                 buffer b)
{
    /* invoked exclusively by gdbserver_input with lwIP lock held */
    err_t err = tcp_write(bound(g)->p, buffer_ref(b, 0), buffer_length(b), TCP_WRITE_FLAG_COPY);
    if (err != ERR_OK)
        return timm("result", "%s: tcp_write returned with error %d", func_ss, err);
    return STATUS_OK;
}

err_t gdb_input(void *z, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
    tcpgdb g = z;
    g->p = pcb;
    // i guess this is a close?
    if (p) {
        apply(g->input, alloca_wrap_buffer(p->payload, p->len));
        // not necessarily
        tcp_recved(pcb, p->len);
    }
    return ERR_OK;
}

static err_t gdb_accept(void *z, struct tcp_pcb *pcb, err_t b)
{
    tcpgdb g = z;
    tcp_arg(pcb, g);    
    tcp_recv(pcb, gdb_input);
    return ERR_OK;
}

// should use unix api?
void init_tcp_gdb(heap h, process p, u16 port)
{
    tcpgdb g = (tcpgdb) allocate(h, sizeof(struct tcpgdb));
    assert(g != INVALID_ADDRESS);
    g->p = tcp_new_ip_type(IPADDR_TYPE_ANY);
    // XXX threads lock taken here...shouldn't be issue but validate
    g->input = init_gdb(h, p, closure(h, gdb_send, g));
    tcp_bind(g->p, IP_ANY_TYPE, port);
    g->p = tcp_listen(g->p);
    tcp_arg(g->p, g);
    tcp_accept(g->p, gdb_accept);
}
