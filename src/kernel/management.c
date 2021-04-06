#include <kernel.h>
#include <net.h>

static struct management {
    heap h;
    tuple root;
} management;

closure_function(0, 2, boolean, dump_syms,
                 symbol, a, value, v)
{
    rprintf("sym %v\n", a);
    return true;
}

static value resolve_tuple_path(tuple n, string path)
{
    vector v = split(management.h, (buffer) /* XXX */ path, '/');
    buffer i;
    vector_foreach(v, i) {
        /* null entries ("//") are skipped in path */
        if (buffer_length(i) == 0)
            continue;
        if (0)
            iterate(n, stack_closure(dump_syms));
        n = (tuple)get(n, intern(i));
        if (!n)
            return n;
    }
    return n;
}

closure_function(1, 1, void, mgmt_tuple_parsed,
                 buffer_handler, out,
                 void *, p)
{
    tuple t = (tuple)p;
    tuple args;
    buffer b = allocate_buffer(management.h, 256);
    assert(b != INVALID_ADDRESS);

    /* XXX need to formalize ack / err */
    if ((args = get_tuple(t, sym(get)))) {
        string path = get_string(args, sym(path));
        if (path) {
            tuple target = resolve_tuple_path(management.root, path);
            if (target) {
                string depthstr = get_string(args, sym(depth));
                u64 depth = 1;
                if (depthstr) {
                    if (!u64_from_value(depthstr, &depth)) {
                        bprintf(b, "unable to parse depth value\n");
                        goto out;
                    }
                }
                bprintf(b, "%V\n", target, depth);
            } else {
                bprintf(b, "not found\n");
            }
        } else {
            bprintf(b, "get: could not parse path attribute\n");
        }
    } else {
        bprintf(b, "unable to parse request\n");
    }
  out:
    apply(bound(out), b);
}

closure_function(1, 1, void, mgmt_tuple_parse_error,
                 buffer_handler, out,
                 string, s)
{
    buffer b = allocate_buffer(management.h, 128);
    assert(b != INVALID_ADDRESS);
    bprintf(b, "failed to parse request tuple: %b\n", s);
    apply(bound(out), b);
}

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
    parser p = tuple_parser(h, closure(h, mgmt_tuple_parsed, out),
                            closure(h, mgmt_tuple_parse_error, out));
    return closure(h, telnet_recv, h, out, p);
}

void init_telnet_management(heap general, tuple root)
{
    management.h = general;
    management.root = root;
    // XXX config port
    listen_port(general, 9090, closure(general, each_telnet_connection, general));
    rprintf("Debug telnet server started on port 9090\n");
}
