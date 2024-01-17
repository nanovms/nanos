#include <kernel.h>
#include <lwip.h>
#include "console.h"
#include "netconsole.h"

typedef struct netconsole_driver {
    struct console_driver c;
    heap h;
    struct udp_pcb *pcb;
    ip_addr_t dst_ip;
    u16 port;
    boolean setup;
} *netconsole_driver;

#define MAX_PAYLOAD 512
#define DEFAULT_IP "10.0.2.2"
#define DEFAULT_PORT 4444

closure_function(2, 0, void, netconsole_async_write,
                 netconsole_driver, nd, struct pbuf *, pb)
{
    netconsole_driver nd = bound(nd);
    struct pbuf *pb = bound(pb);
    udp_sendto(nd->pcb, pb, &nd->dst_ip, nd->port);
    pbuf_free(pb);
    closure_finish();
}

static void netconsole_write(void *_d, const char *s, bytes count)
{
    netconsole_driver nd = _d;
    if (!nd->setup)
        return;
    bytes off = 0;
    /* XXX It may not be safe to assume we cannot be in an interrupt handler.
       If so, the pbuf_alloc should be happening elsewhere (e.g. background
       task and queued to free list) */
    assert(!in_interrupt());
    while (count > 0) {
        bytes len = MIN(count, MAX_PAYLOAD);
        struct pbuf *pb = pbuf_alloc(PBUF_TRANSPORT, len, PBUF_RAM);
        if (pb == 0)
            break;
        runtime_memcpy(pb->payload, s + off, len);
        thunk t = closure(nd->h, netconsole_async_write, nd, pb);
        async_apply(t);
        count -= len;
        off += len;
    }
}

static void netconsole_config(void *_d, tuple r)
{
    netconsole_driver nd = _d;
    nd->pcb = udp_new_ip_type(IPADDR_TYPE_ANY);
    if (!nd->pcb) {
        msg_err("failed to allocate pcb\n");
        return;
    }

    buffer dst_ip = get(r, sym(netconsole_ip));
    sstring b = dst_ip ? buffer_to_sstring(dst_ip) : ss(DEFAULT_IP);

    if (b.len > IPADDR_STRLEN_MAX) {
        msg_err("ip address too long\n");
        return;
    }

    if (!ipaddr_aton(b, &nd->dst_ip)) {
        msg_err("failed to translate ip address\n");
        return;
    }

    buffer dst_port = get(r, sym(netconsole_port));
    u64 port = DEFAULT_PORT;
    if (dst_port && !parse_int(dst_port, 10, &port)) {
        msg_err("failed to parse port\n");
        return;
    }
    if (port >= U64_FROM_BIT(16)) {
        msg_err("port out of range\n");
        return;
    }
    nd->port = (u16)port;
    nd->setup = true;
}

void netconsole_register(kernel_heaps kh, console_attach a)
{
    heap h = heap_locked(kh);
    netconsole_driver nd = allocate_zero(h, sizeof(struct netconsole_driver));
    assert(nd != INVALID_ADDRESS);
    nd->h = h;
    nd->c.write = netconsole_write;
    nd->c.name = ss("net");
    nd->c.disabled = true;
    nd->c.config = netconsole_config;
    apply(a, &nd->c);
}
