#include <runtime.h>
#include <socket_user.h>
#include <sys/epoll.h>

// status
static CLOSURE_0_1(connected_expect_fail, void, status);
static void connected_expect_fail(status s)
{
    rprintf("connection failed %v\n", s);
}

// status
CLOSURE_0_1(dont_expect_fail, buffer_handler, buffer_handler);
buffer_handler dont_expect_fail(buffer_handler out)
{
    rprintf("connected!\n");
    return 0;
}

CLOSURE_1_1(conn, buffer_handler, heap, buffer_handler);
buffer_handler conn(heap h, buffer_handler out)
{
    rprintf("connected!\n");    
    return (buffer_handler)ignore;
}

void main()
{
    heap h = init_process_runtime();
    int e = epoll_create(1);    
    connection(h, e, aprintf(h, "18.0.0.1:8080"),
               closure(h, conn, h), // different conn
               closure(h, connected_expect_fail));
    /// xxx port any - find bound port
    listen_port(h, e, 8079, closure(h, conn, h));
    connection(h, e, aprintf(h, "127.0.0.1:8079"),
               closure(h, dont_expect_fail),
               closure(h, connected_expect_fail));
    epoll_spin(e);               
}
