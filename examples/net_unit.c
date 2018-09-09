#include <runtime.h>
#include <socket_user.h>
#include <sys/epoll.h>

CLOSURE_0_1(connected, buffer_handler, buffer_handler);
buffer_handler connected(buffer_handler out)
{
    rprintf("connected!\n");
    return 0;
}

CLOSURE_1_1(conn, buffer_handler, heap, buffer_handler);
buffer_handler conn(heap h, buffer_handler out)
{
    apply(out, 0);
    return (buffer_handler)ignore;
}

void main()
{
    heap h = init_process_runtime();
    int e = epoll_create(1);    
    connection(h, e, aprintf(h, "18.0.0.1:8080"), closure(h, connected));
    /// xxx port any
    listen_port(h, e, 0, closure(h, conn, h));    
    epoll_spin(e);               
}
