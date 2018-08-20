#include <unix_process_runtime.h>
#include <http.h>
#include <socket_user.h>
#include <sys/epoll.h>


static void send_request(buffer_handler out)
{
    http_request(out, timm("url", "/", "fizz", "bun"));
}

static CLOSURE_2_1(value_in, void, heap, buffer_handler, value);
static void value_in(heap h, buffer_handler out, value v)
{
    rprintf ("value in %v\n", v);
    send_request(out);
}


// asynch connection
CLOSURE_1_1(conn, buffer_handler, heap, buffer_handler);
buffer_handler conn(heap h, buffer_handler out)
{
    send_request(out);
    return allocate_http_parser(h, closure(h, value_in, h, out));
}

void main(int argc, char **argv)
{
    heap h = init_process_runtime();
    int e = epoll_create(1);
    connection(h, e,
               alloca_wrap_buffer(argv[1], runtime_strlen(argv[1])),
               closure(h, conn, h));
    epoll_spin(e);
}

