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

#define MAX_PAYLOAD 1472
#define DEFAULT_IP "10.0.2.2"
#define DEFAULT_PORT 4444

static void netconsole_write(void *_d, const char *s, bytes count)
{
    netconsole_driver nd = _d;
    if (!nd->setup)
        return;
    bytes off = 0;
    while (count > 0) {
        bytes len = MIN(count, MAX_PAYLOAD);
        struct pbuf *pb = pbuf_alloc(PBUF_TRANSPORT, len, PBUF_RAM);
        if (pb == 0)
            return;
        runtime_memcpy(pb->payload, s + off, len);
        udp_sendto(nd->pcb, pb, &nd->dst_ip, nd->port);
        pbuf_free(pb);
        count -= len;
        off += len;
    }
}

static void netconsole_config(void *_d, tuple r)
{
    netconsole_driver nd = _d;

    if ((nd->pcb = udp_new()) == 0) {
        msg_err("failed to allocate pcb\n");
        return;
    }

    buffer dst_ip = table_find(r, sym(netconsole_ip));
    char *s = dst_ip ? buffer_ref(dst_ip, 0) : DEFAULT_IP;
    bytes len = dst_ip ? buffer_length(dst_ip) : runtime_strlen(DEFAULT_IP);

    if (len > IPADDR_STRLEN_MAX) {
        msg_err("%s: ip address too long\n");
        return;
    }

    char b[IPADDR_STRLEN_MAX+1];
    runtime_memcpy(b, s, len);
    s[len] = 0;
    if (!ipaddr_aton(s, &nd->dst_ip)) {
        msg_err("%s: failed to translate ip address\n");
        return;
    }

    buffer dst_port = table_find(r, sym(netconsole_port));
    u64 port = DEFAULT_PORT;
    if (dst_port && !parse_int(dst_port, 10, &port)) {
        msg_err("%s: failed to parse port\n");
        return;
    }
    if (port >= U64_FROM_BIT(16)) {
        msg_err("%s: port out of range\n");
        return;
    }
    nd->port = (u16)port;
    nd->setup = true;
}

void netconsole_register(kernel_heaps kh, console_attach a)
{
    heap h = heap_general(kh);
    netconsole_driver nd = allocate_zero(h, sizeof(struct netconsole_driver));
    assert(nd != INVALID_ADDRESS);
    nd->c.write = netconsole_write;
    nd->c.name = "net";
    nd->c.disabled = true;
    nd->c.config = netconsole_config;
    apply(a, &nd->c);
}
