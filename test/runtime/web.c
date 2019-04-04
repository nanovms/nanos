#include <runtime.h>
#include <http.h>
#include <socket_user.h>
#include <sys/epoll.h>


static CLOSURE_2_1(each_request, void, heap, buffer_handler, value);
static void each_request(heap h, buffer_handler out, value v)
{
    send_http_response(out,
                       timm("ContentType", "text/html"),
                       aprintf(h, "unibooty!"));
}

CLOSURE_1_1(conn, buffer_handler, heap, buffer_handler);
buffer_handler conn(heap h, buffer_handler out)
{
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
