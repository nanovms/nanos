#include <runtime.h>
#include <http.h>
#include <socket_user.h>
#include <sys/epoll.h>

closure_function(2, 1, void, each_request,
                 heap, h, buffer_handler, out,
                 value, v)
{
    send_http_response(bound(out),
                       timm("ContentType", "text/html"),
                       aprintf(bound(h), "unibooty!"));
}

closure_function(1, 1, buffer_handler, conn,
                 heap, h,
                 buffer_handler, out)
{
    heap h = bound(h);
    return allocate_http_parser(h, closure(h, each_request, h, out));
}

// no good place to put this
table parse_arguments(heap h, int argc, char **argv);

int main(int argc, char **argv)
{
    heap h = init_process_runtime();
    tuple t = parse_arguments(h, argc, argv);
    notifier n = table_find(t, sym(select)) ? create_select_notifier(h) :
        table_find(t, sym(poll)) ? create_poll_notifier(h) :
	create_epoll_notifier(h);
    u16 port = 8080;
    listen_port(h, n, port, closure(h, conn, h));
    rprintf("Server started on port %d\n", port);
    notifier_spin(n);
    return 0;
}
