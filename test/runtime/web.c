#include <runtime.h>
#include <http.h>
#include <socket_user.h>
#include <sys/epoll.h>

closure_function(1, 3, void, each_request,
                 heap, h,
                 http_method m, http_responder out, value v)
{
    send_http_response(out,
                       timm("ContentType", "text/html"),
                       aprintf(bound(h), "unibooty!"));
}

int main(int argc, char **argv)
{
    heap h = init_process_runtime();
    tuple t = parse_arguments(h, argc, argv);
    notifier n = get(t, sym(select)) ? create_select_notifier(h) :
        get(t, sym(poll)) ? create_poll_notifier(h) :
        create_epoll_notifier(h);
    u16 port = 8080;
    http_listener hl = allocate_http_listener(h, port);
    http_register_default_handler(hl, closure(h, each_request, h));
    listen_port(h, n, port, connection_handler_from_http_listener(hl));
    rprintf("Server started on port %d\n", port);
    notifier_spin(n);
    return 0;
}
