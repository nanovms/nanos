#include <unix_process_runtime.h>
#include <http.h>
#include <socket_user.h>
#include <sys/epoll.h>

static CLOSURE_0_1(value_in, void, value);
static void value_in(value v)
{
    rprintf ("value in %v\n", v);
}

// asynch connection
CLOSURE_1_1(conn, buffer_handler, heap, buffer_handler);
buffer_handler conn(heap h, buffer_handler in)
{
    return http_transact(h,
                         timm("url", "/", "fizz", "bun"),
                         in, 
                         closure(h, value_in));
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

