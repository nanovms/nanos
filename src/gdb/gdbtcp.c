#include <gdb_internal.h>

typedef struct tcpgdb{
    buffer_handler input;
    struct tcp_pcb *p;
} *tcpgdb;
    
static CLOSURE_1_1(gdb_send, void, tcpgdb, buffer);
static void gdb_send(tcpgdb g, buffer b)
{
    //    u64 len = tcp_sndbuf(g->pcb);
    // flags can force a stack copy or toggle push
    // pool?
    tcp_write(g->p, buffer_ref(b, 0), buffer_length(b), TCP_WRITE_FLAG_COPY);
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
    g->p = tcp_new_ip_type(IPADDR_TYPE_ANY); 
    g->input = init_gdb(h, p, closure(h, gdb_send, g));
    tcp_bind(g->p, IP_ANY_TYPE, port);
    g->p = tcp_listen(g->p);
    tcp_arg(g->p, g);    
    tcp_accept(g->p, gdb_accept);    
}
