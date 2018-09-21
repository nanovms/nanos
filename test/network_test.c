#include <runtime.h>
#include <http.h>
#include <socket_user.h>
#include <sys/epoll.h>
#include <stdlib.h>

static CLOSURE_3_1(conn, buffer_handler,
                   heap, merge, thunk, 
                   buffer_handler);

static void send_request(buffer_handler out)
{
    http_request(out, timm("url", "/", "fizz", "bun"));
}

#define LENGTH 3
static CLOSURE_5_1(value_in, void,
                   heap, buffer_handler, u64 *, status_handler, thunk,
                   value);

static void value_in(heap h,
                     buffer_handler out,
                     u64 *count,
                     status_handler completed,
                     thunk newconn, 
                     value v)
{
    if (*count == 0)
        apply(newconn);
    *count = *count + 1;
    if (*count < LENGTH) {
        send_request(out);
    } else {
        apply(out, 0);
        apply(completed, 0);
    }
}

static buffer_handler conn(heap h, merge m, thunk newconn, 
                           buffer_handler out)
{
    u64 *count = allocate_zero(h, sizeof(u64));
    status_handler c = apply(m);
    send_request(out);
    return allocate_http_parser(h, closure(h, value_in, h, out, count, c, newconn));
}

static CLOSURE_6_0(startconn, void, heap, descriptor, merge, buffer, thunk *, status_handler);
static void startconn(heap h, descriptor e, merge m, buffer target, thunk *self, status_handler err)
{
    connection(h, e, target, closure(h, conn, h, m, *self), err);
}

CLOSURE_0_1(connection_error, void, status);
void connection_error(status s)
{
    exit(-1);
}

CLOSURE_0_1(finished, void, status);
void finished(status s)
{
    exit(0);
}

void main(int argc, char **argv)
{
    if(argc < 2) {
      return;
    }
    heap h = init_process_runtime();
    descriptor e = epoll_create(1);
    buffer target = wrap_buffer(h, argv[1], runtime_strlen(argv[1]));
    thunk *newconn = allocate(h, sizeof(thunk));
    merge m = allocate_merge(h, closure(h, finished));
    // there are other solutions for y
    status_handler err = closure(h, connection_error);
    *newconn = (thunk)closure(h, startconn, h, e, m, target, newconn, err);
    apply(*newconn);
    epoll_spin(e);
}

