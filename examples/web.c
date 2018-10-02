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

void main(int argc, char **argv)
{
    heap h = init_process_runtime();
    tuple t = parse_arguments(h, argc, argv);
    notifier n = table_find(t, sym(select)) ? create_select_notifier(h) :
	create_epoll_notifier(h);
    listen_port(h, n, 8080, closure(h, conn, h));
    notifier_spin(n);
}

