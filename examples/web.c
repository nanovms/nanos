#include <unix_process_runtime.h>
#include <http.h>
#include <socket_user.h>
#include <sys/epoll.h>


static CLOSURE_2_1(each_request, void, heap, buffer_handler, value);
static void each_request(heap h, buffer_handler out, value v)
{
    rprintf("web request %v\n", v);
    send_http_response(out,
                       timm("ContentType", "text/html"),
                       aprintf(h, "unibooty!"));
}

CLOSURE_1_1(conn, buffer_handler, heap, buffer_handler);
buffer_handler conn(heap h, buffer_handler out)
{
    return allocate_http_parser(h, closure(h, each_request, h, out));
}

void main(int argc, char **argv)
{
    int service;
    heap h = init_process_runtime();
    
    int e = epoll_create(1);
    rprintf ("epool creat %d\n", e);
    listen_port(h, e, 8080, closure(h, conn, h));
    epoll_spin(e);
}

