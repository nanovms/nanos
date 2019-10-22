#include <runtime.h>
#include <tfs.h>
#include <unix.h>
#include <net.h>
#include <gdb.h>
#include <virtio/virtio.h>

closure_function(2, 1, void, read_program_complete,
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
}

closure_function(0, 1, void, read_program_fail,
                 status, s)
{
    closure_finish();
    halt("read program failed %v\n", s);
}

closure_function(2, 1, void, test_recv,
                 heap, h,
                 buffer_handler, out,
                 buffer, b)
{
    buffer response = allocate_buffer(bound(h), 1024);
    buffer_handler out = bound(out);
    if (!b) {
        rprintf("remote closed\n");
        return;
    }
    bprintf(response, "read: %b", b);
    apply(out, response);
    if (*((u8*)buffer_ref(b, 0)) == 'q')
        apply(out, 0);
}

closure_function(1, 1, buffer_handler, each_connection,
                 heap, h,
                 buffer_handler, out)
{
    heap h = bound(h);
//    return allocate_http_parser(h, closure(h, each_request, h, out);
    buffer response = allocate_buffer(h, 1024);
    bprintf(response, "hi thanks for coming\r\n");
    apply(out, response);
    return closure(h, test_recv, h, out);
}

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

    if (table_find(root, sym(socktest))) {
        listen_port(general, 8079, closure(general, each_connection, general));
        rprintf("socktest start 8079\n");
    }

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
