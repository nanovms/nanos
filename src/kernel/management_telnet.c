#include <kernel.h>
#include <net.h>

//#define MGMT_DEBUG
#ifdef MGMT_DEBUG
#define mgmt_debug(x, ...) do {tprintf(sym(mgmt), 0, ss(x), ##__VA_ARGS__);} while(0)
#else
#define mgmt_debug(x, ...)
#endif

closure_function(3, 1, status, telnet_recv,
                 heap, h, buffer_handler, out, parser, p,
                 buffer b)
{
    buffer_handler out = bound(out);
    if (!b) {
        // XXX need tuple parser dealloc
        mgmt_debug("%s: remote closed\n", func_ss);
        return STATUS_OK;
    }
    mgmt_debug("%s: got request \"%b\"\n", func_ss, b);
    switch (*((u8*)buffer_ref(b, 0))) {
    case 0x04:                  /* EOT */
        mgmt_debug("   remote sent quit\n");
        management_reset();
        apply(out, 0);
        break;
    default:
        parser_feed(bound(p), b);
    }
    return STATUS_OK;
}

closure_function(1, 1, buffer_handler, each_telnet_connection,
                 heap, h,
                 buffer_handler out)
{
    heap h = bound(h);
    mgmt_debug("telnet: connection\n");
    parser p = management_parser(out);
    return closure(h, telnet_recv, h, out, p);
}

void init_management_telnet(heap h, value meta)
{
    // XXX config port
    listen_port(h, 9090, closure(h, each_telnet_connection, h));
    msg_info("Debug telnet server started on port 9090");
}
