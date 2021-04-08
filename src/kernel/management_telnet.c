#include <kernel.h>
#include <net.h>
#include <management.h>

closure_function(3, 1, status, telnet_recv,
                 heap, h, buffer_handler, out, parser, p,
                 buffer, b)
{
    buffer_handler out = bound(out);
    if (!b) {
        // XXX need tuple parser dealloc
        rprintf("telnet: remote closed\n");
        return STATUS_OK;
    }
    rprintf("%s: got request \"%b\"\n", __func__, b);
    switch (*((u8*)buffer_ref(b, 0))) {
    case 0x04:                  /* EOT */
        rprintf("telnet: remote sent quit\n");
        apply(out, 0);
        break;
    default:
        parser_feed(bound(p), b);
    }
    return STATUS_OK;
}

closure_function(1, 1, buffer_handler, each_telnet_connection,
                 heap, h,
                 buffer_handler, out)
{
    heap h = bound(h);
    buffer response = allocate_buffer(h, 1024);
    rprintf("telnet: connection\n"); // XXX
    bprintf(response, "nanos tuple interface\r\n");
    apply(out, response);
    parser p = management_parser(out);
    return closure(h, telnet_recv, h, out, p);
}

void init_management_telnet(heap h, value meta)
{
    // XXX config port
    listen_port(h, 9090, closure(h, each_telnet_connection, h));
    rprintf("Debug telnet server started on port 9090\n");
}
