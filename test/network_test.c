#include <runtime.h>
#include <http.h>
#include <socket_user.h>
#include <sys/epoll.h>
#include <stdlib.h>


static CLOSURE_4_1(conn, buffer_handler,
                   heap, descriptor, buffer, merge,
                   buffer_handler);

static void send_request(buffer_handler out)
{
    http_request(out, timm("url", "/", "fizz", "bun"));
}

#define LENGTH 3
static CLOSURE_7_1(value_in, void,
                   heap, buffer_handler, descriptor, buffer, u64 *, merge, status_handler,
                   value);
static void value_in(heap h,
                     buffer_handler out,
                     descriptor e,
                     buffer target,
                     u64 *count,
                     merge m,
                     status_handler completed, 
                     value v)
{
    if (*count == 0)
        connection(h, e, target, closure(h, conn, h, e, target, m));
    *count = *count + 1;
    if (*count < LENGTH) {
        send_request(out);
    } else {
        apply(out, 0);
        apply(completed, 0);
    }
}

static buffer_handler conn(heap h, descriptor e, buffer target, merge m, buffer_handler out)
{
    u64 *count = allocate(h, sizeof(u64));
    *count = 0;
    status_handler c = apply(m);
    send_request(out);
    return allocate_http_parser(h,closure(h, value_in, h, out, e, target, count, m, c));
}

CLOSURE_0_1(finished, void, status);
void finished(status s)
{
    exit(0);
}

void main(int argc, char **argv)
{
    heap h = init_process_runtime();
    descriptor e = epoll_create(1);
    buffer target = wrap_buffer(h, argv[1], runtime_strlen(argv[1]));
    merge m = allocate_merge(h, closure(h, finished));
    // merge reference here
    connection(h, e, target, closure(h, conn, h, e, target, m));
    epoll_spin(e);
}

