#include <runtime.h>
#include <http.h>
#include <socket_user.h>
#include <sys/epoll.h>
#include <stdlib.h>

typedef struct stats {
    u32 connections;
    u32 responses;
    u32 requests;
} *stats;


static CLOSURE_5_1(conn, buffer_handler,
                   heap, merge, thunk, stats, tuple, 
                   buffer_handler);

static void send_request(heap h, stats s, buffer_handler out, tuple t)
{
    s->requests++;
    http_request(h, out, t);
}

#define REQUESTS_PER_CONNECTION 500
#define TOTAL_CONNECTIONS 2000
static CLOSURE_7_1(value_in, void,
                   heap, buffer_handler, u64 *, status_handler, thunk, stats, tuple, 
                   value);

static void value_in(heap h,
                     buffer_handler out,
                     u64 *count,
                     status_handler completed,
                     thunk newconn,
                     stats s,
                     tuple req, 
                     value v)
{
    s->responses++;

    static int report = 1;
    if (s->responses  > report) {
        rprintf("c: %d req: %d resp: %d\n", s->connections, s->requests, s->responses);
        report *= 2;
    }
    
    if (*count == 0) {
        if (s->connections < TOTAL_CONNECTIONS) 
            apply(newconn);
    }
    *count = *count + 1;
    if (*count < REQUESTS_PER_CONNECTION) {
        send_request(h, s, out, req);
    } else {
        apply(out, 0);
        h->destroy(h); // wrapper?
        apply(completed, 0);
    }
}

heap make_tiny_heap(heap parent);

static buffer_handler conn(heap h, merge m, thunk newconn, stats s, tuple t, 
                           buffer_handler out)
{
    heap pages = allocate_mmapheap(h, 4096);
    heap c = make_tiny_heap(pages);
    
    u64 *count = allocate_zero(c, sizeof(u64));
    s->connections++;
    status_handler sth = apply(m);
    send_request(c, s, out, t);
    return allocate_http_parser(c, closure(c, value_in, c, out, count, sth, newconn, s, t));

}

static CLOSURE_8_0(startconn, void, heap, descriptor, merge, buffer, thunk *, stats, status_handler, tuple);
static void startconn(heap h, descriptor e, merge m, buffer target, thunk *self, stats s, status_handler err, tuple req)
{
    connection(h, e, target, closure(h, conn, h, m, *self, s, req), err);
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
    stats s = allocate_zero(h, sizeof(struct stats));
    zero(s, sizeof(struct stats)); //?
    tuple t = timmf("url", "/", "fizz", "bun", "Host", "tenny");
    *newconn = (thunk)closure(h, startconn, h, e, m, target, newconn, s, err, t);
    apply(*newconn);
    epoll_spin(e);
}

