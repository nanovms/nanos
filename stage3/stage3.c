#include <runtime.h>
#include <tfs.h>
#include <unix.h>
#include <net.h>
#include <http.h>
#include <gdb.h>
#include <virtio/virtio.h>

closure_function(2, 1, status, read_program_complete,
                 process, kp, tuple, root,
                 buffer, b)
{
    tuple root = bound(root);
    if (table_find(root, sym(trace))) {
        rprintf("read program complete: %p ", root);
        rprintf("gitversion: %s ", gitversion);

        /* XXX - disable this until we can be assured that print_root
           won't go haywire on a large manifest... */
#if 0
        buffer b = allocate_buffer(transient, 64);
        print_root(b, root);
        buffer_print(b);
        deallocate_buffer(b);
        rprintf("\n");
#endif
       
    }
    exec_elf(b, bound(kp));
    closure_finish();
    return STATUS_OK;
}

closure_function(0, 1, void, read_program_fail,
                 status, s)
{
    closure_finish();
    halt("read program failed %v\n", s);
}

/* XXX Note: temporarily putting these connection tests here until we
   get tracing hooked up... */

/* limited to 1M on general heap at the moment... */
#define BULK_TEST_BUFSIZ (1ull << 20)
static buffer bulk_test_buffer(heap h)
{
    buffer b = allocate_buffer(h, BULK_TEST_BUFSIZ);
    for (int i = 0; i < (BULK_TEST_BUFSIZ / 10); i += 8) {
        bprintf(b, "%8d %8d %8d %8d %8d %8d %8d %8d\r\n",
                i, i + 1, i + 2, i + 3, i + 4, i + 5, i + 6, i + 7);
    }
    return b;
}

closure_function(2, 1, void, debugport_value_set,
                 tuple, parent, symbol, k,
                 void *, v)
{
    rprintf("%s: parent %p, value %v\n", __func__, bound(parent), v);
    table_set(bound(parent), bound(k), v);
}

closure_function(1, 1, void, debugport_parse_error,
                 buffer, orig,
                 buffer, err)
{
    rprintf("%s: error %b\n", __func__, err);
}

/* raw tcp socket test */
closure_function(3, 1, status, debugport_recv,
                 heap, h,
                 tuple, root,
                 buffer_handler, out,
                 buffer, b)
{
    heap h = bound(h);
    buffer response = allocate_buffer(h, 1024);
    buffer_handler out = bound(out);
    if (!b) {
        rprintf("debugport: remote closed\n");
        return STATUS_OK;
    }
    apply(out, response);

    int len;
    char *str, *end;
    value v;

    /* sadly this really needs to be a state machine / parser */
    switch (*((u8*)buffer_ref(b, 0))) {
    case 'q':
        rprintf("debugport: remote sent quit\n");
        apply(out, 0);
        break;
    case 'b':
        rprintf("debugport: remote requested bulk buffer\n");
        apply(out, bulk_test_buffer(h));
        break;
    case '?':
        buffer_consume(b, 1);
        len = buffer_length(b);
        str = buffer_ref(b, 0);
        end = runtime_strchr(str, '\r');
        if (!end) {
            buffer_consume(b, len);
            apply(out, aprintf(h, "failed to parse get\r\n"));
            break;
        }
        *end = '\0';

        rprintf("debugport: remote requested value of ");
        if (str[0] != '\0') {
            rprintf("symbol \"%s\"\n", str);
            v = table_find(bound(root), sym_this(str));
            if (!v) {
                apply(out, aprintf(h, "symbol \"%s\" not found\r\n", str));
            } else {
                apply(out, aprintf(h, "(%s: %v)\r\n", str, v));
            }
        } else {
            /* no key -> assume root requested */
            rprintf("root\n");
            apply(out, aprintf(h, "<root>: %v\r\n", bound(root)));
        }
        buffer_consume(b, len);
        break;
    case '!':
        buffer_consume(b, 1);
        len = buffer_length(b);
        str = buffer_ref(b, 0);
        end = runtime_strchr(str, ' ');
        if (!end) {
            buffer_consume(b, len);
            end = runtime_strchr(str, '\r');
            if (!end || str == end) {
                apply(out, aprintf(h, "failed to parse symbol\r\n"));
                break;
            }

            *end = '\0';
            symbol k = sym_this(str); /* XXX path resolve */
            rprintf("debugport: unset %s\n", str);
            table_set(bound(root), k, 0);
            break;
        }

        *end = '\0';
        rprintf("debugport: remote setting value of %s\n", str);
        symbol k = sym_this(str);

        buffer_consume(b, runtime_strlen(str) + 1);
        len = buffer_length(b);
        str = buffer_ref(b, 0);
        end = runtime_strchr(str, '\r');
        if (!end || str == end) {
            buffer_consume(b, len);
            apply(out, aprintf(h, "failed to parse value\r\n"));
            break;
        }
        *end = '\0';
        int slen = runtime_strlen(str);
        buffer bt = allocate_buffer(h, slen);
        buffer_write(bt, str, slen);
        buffer_consume(b, len);

        parser p = tuple_parser(h, closure(transient, debugport_value_set, bound(root), k),
                                closure(transient, debugport_parse_error, bt));
        assert(p != INVALID_ADDRESS);
        parser_feed(p, bt);
        deallocate_buffer(bt);
        break;
    }
    return STATUS_OK;
}

closure_function(2, 1, buffer_handler, debugport_connection,
                 heap, h,
                 tuple, root,
                 buffer_handler, out)
{
    heap h = bound(h);
    buffer response = allocate_buffer(h, 1024);
    rprintf("debugport: connection\n");
//    bprintf(response, "nanos telnet test interface\r\n");
    apply(out, response);
    return closure(h, debugport_recv, h, bound(root), out);
}

/* http debug test */
#if 0
closure_function(1, 3, void, each_test_request,
                 heap, h,
                 http_method, m, buffer_handler, out, value, v)
{
    status s = STATUS_OK;
    bytes total = 0;
    heap h = bound(h);
    rprintf("http: %s request via http: %v\n", http_request_methods[m], v);
    buffer u = table_find(v, sym(relative_uri));
    if (u && buffer_compare_with_cstring(u, "chunk")) {
        rprintf("chunked response\n");
        s = send_http_chunked_response(out, timm("Content-Type", "text/html"));

        if (!is_ok(s))
            goto out_fail;

        for (int i = 0; i < 10; i++) {
            buffer b = bulk_test_buffer(h);
            total += buffer_length(b);
            s = send_http_chunk(out, b);
            if (!is_ok(s))
                goto out_fail;
        }

        s = send_http_chunk(out, 0);
        if (!is_ok(s))
            goto out_fail;
    } else {
        buffer b = bulk_test_buffer(h);
        total += buffer_length(b);
        s = send_http_response(out, timm("Content-Type", "text/html"), b);
        if (!is_ok(s))
            goto out_fail;
    }

    rprintf("sent %d bytes\n", total);
    return;
  out_fail:
    msg_err("output buffer handler failed: %v\n", s);
}
#endif

closure_function(3, 0, void, startup,
                 kernel_heaps, kh, tuple, root, filesystem, fs)
{
    kernel_heaps kh = bound(kh);
    tuple root = bound(root);
    filesystem fs = bound(fs);

    /* kernel process is used as a handle for unix */
    process kp = init_unix(kh, root, fs);
    if (kp == INVALID_ADDRESS) {
	halt("unable to initialize unix instance; halt\n");
    }
    heap general = heap_general(kh);
    buffer_handler pg = closure(general, read_program_complete, kp, root);

    if (table_find(root, sym(debugport))) {
        listen_port(general, 9090, closure(general, debugport_connection, general, root));
        rprintf("Debug telnet server started on port 9090\n");
    }

#if 0
    http_listener hl = allocate_http_listener(general, 9090);
    assert(hl != INVALID_ADDRESS);
    http_register_uri_handler(hl, "test", closure(general, each_test_request, general));

    if (table_find(root, sym(http))) {
        status s = listen_port(general, 9090, connection_handler_from_http_listener(hl));
        if (!is_ok(s))
            halt("listen_port failed for http listener: %v\n", s);
        rprintf("Debug http server started on port 9090\n");
    }
#endif
    value p = table_find(root, sym(program));
    assert(p);
    tuple pro = resolve_path(root, split(general, p, '/'));
    init_network_iface(root);
    filesystem_read_entire(fs, pro, heap_backed(kh), pg, closure(general, read_program_fail));
    closure_finish();
}

thunk create_init(kernel_heaps kh, tuple root, filesystem fs)
{
    return closure(heap_general(kh), startup, kh, root, fs);
}
