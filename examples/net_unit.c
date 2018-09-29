#include <runtime.h>
#include <socket_user.h>
#include <sys/epoll.h>

CLOSURE_1_1(active_input, void, buffer_handler, buffer);
void active_input(buffer_handler out, buffer b)
{
    apply(out, b);
    rprintf ("active input %b\n", b);
}


// status
static CLOSURE_0_1(connected_expect_fail, void, status);
static void connected_expect_fail(status s)
{
    rprintf("connection expected failure %v\n", s);
}

// status
CLOSURE_1_1(expect_success, buffer_handler, heap, buffer_handler);
buffer_handler expect_success(heap h, buffer_handler out)
{
    rprintf("csucc\n");
    //    apply(out, aprintf(h, "acto!"));
    return closure(h, active_input, out);
}

CLOSURE_2_1(passive_input, void, buffer_handler, u64 *, buffer);
void passive_input(buffer_handler out, u64 *count, buffer b)
{
    *count = *count+1;
    if (*count < 100)  {
        rprintf ("passive input %b %d\n", b, *count);        
        apply(out, b);
    } else {
        apply(out, 0);
    }
}


CLOSURE_1_1(conn, buffer_handler, heap, buffer_handler);
buffer_handler conn(heap h, buffer_handler out)
{
    apply(out, aprintf(h, "foo!\n"));
    u64 *count = allocate_zero(h, sizeof(u64));
    return(closure(h, passive_input, out, count));
}

void main()
{
    heap h = init_process_runtime();
    int e = epoll_create(1);    
    connection(h, e, aprintf(h, "0.0.0.1:8080"),
               closure(h, conn, h), // different conn
               closure(h, connected_expect_fail));
    
    /// xxx port any - find bound port
    listen_port(h, e, 8079, closure(h, conn, h));
    connection(h, e, aprintf(h, "127.0.0.1:8079"),
               closure(h, expect_success, h),
               closure(h, connected_expect_fail));
    epoll_spin(e);               
}
