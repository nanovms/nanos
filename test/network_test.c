#include <unix_process_runtime.h>
#include <http.h>
#include <socket_user.h>
#include <sys/epoll.h>


static CLOSURE_3_1(conn, buffer_handler, heap, descriptor, buffer, buffer_handler);

static void send_request(buffer_handler out)
{
    http_request(out, timm("url", "/", "fizz", "bun"));
}

static CLOSURE_4_1(value_in, void, heap, buffer_handler, descriptor, buffer, value);
static void value_in(heap h, buffer_handler out, descriptor e, buffer target, value v)
{
    rprintf ("value in %v %b\n", v, target);
    connection(h, e, target, closure(h, conn, h, e, target));    
    //    send_request(out);
}

static buffer_handler conn(heap h, descriptor e, buffer target, buffer_handler out)
{
    send_request(out);
    return allocate_http_parser(h,closure(h, value_in, h, out, e, target));
}

void main(int argc, char **argv)
{
    heap h = init_process_runtime();
    descriptor e = epoll_create(1);
    buffer target = wrap_buffer(h, argv[1], runtime_strlen(argv[1]));
    connection(h, e, target, closure(h, conn, h, e, target));
    epoll_spin(e);
}

