#include <runtime.h>
#include <http.h>
#include <socket_user.h>
#include <stdlib.h>

typedef struct stats {
    u32 connections;
    u32 connections_outstanding;
    u32 active;    
    u32 requests;
    u32 responses;
} *stats;


static void send_request(heap h, stats s, buffer_handler out, tuple t)
{
    s->requests++;
    http_request(h, out, t);
}

u64 requests_per_connection;
u64 total_connections;
u64 window;

static CLOSURE_1_0(print_stats, void, stats);
static void print_stats(stats s)
{
    rprintf("connections: %d outstanding: %d active: %d req: %d resp: %d\r",
            s->connections, s->connections_outstanding, s->active, s->requests, s->responses);
}

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

    static time last;
    time t = now();

    if ((t - last) > (1ull<<32)){
        last = t;
        print_stats(s);
    }
    
    if (*count == 0) {
        if (s->connections < total_connections) 
            apply(newconn);
    }
    int window_growth = 1;
    for (int i = 0; i < window_growth; i++) {
        *count = *count + 1;
        if (*count < requests_per_connection) {
            send_request(h, s, out, req);
        } else {
            s->active--;
            apply(out, 0);
            h->destroy(h); // wrapper?
            apply(completed, 0);
            return;
        }
    }
}

heap make_tiny_heap(heap parent);

static CLOSURE_5_1(newconn, buffer_handler, heap, thunk, stats, tuple, status_handler,  
                   buffer_handler);
static buffer_handler newconn(heap h, thunk newconn, stats s, tuple t, status_handler sth,
                           buffer_handler out)
{
    heap pages = allocate_mmapheap(h, 4096);
    heap c = make_tiny_heap(pages);
    u64 *count = allocate_zero(c, sizeof(u64));
    s->connections++;
    s->connections_outstanding--;    
    s->active++;
    for (int i = 0; i < window; i++)
        send_request(c, s, out, t);
    return allocate_http_parser(c, closure(c, value_in, c, out, count, sth, newconn, s, t));

}

static CLOSURE_8_0(startconn, void, heap, notifier, merge, buffer, thunk *, stats, status_handler, tuple);
static void startconn(heap h, notifier n, merge m, buffer target, thunk *self, stats s, status_handler err, tuple req)
{
    status_handler sth = apply(m);

    s->connections_outstanding++;
    connection(h, n, target, closure(h, newconn, h, *self, s, req, sth), err);
}

CLOSURE_0_1(connection_error, void, status);
void connection_error(status s)
{
    rprintf("connection error! %v\n", s);
    exit(-1);
}

CLOSURE_1_1(finished, void, stats, status);
void finished(stats st, status s)
{
    print_stats(st);
    rprintf("\n");
    exit(0);
}

// no good place to put this
table parse_arguments(heap h, int argc, char **argv);

u64 extract_u64_with_default(tuple t, symbol n, u64 otherwise)
{
    value v = table_find(t, n);
    if (v) {
        return u64_from_value(v);
    }
    return otherwise;
}


void main(int argc, char **argv)
{
    heap h = init_process_runtime();    
    tuple t = parse_arguments(h, argc, argv);
    value unassoc = table_find(t, sym(unassociated));
    if (!unassoc) {
        halt("must provide target\n");
    }

    notifier n = table_find(t, sym(select)) ? create_select_notifier(h) :
	create_epoll_notifier(h);
    buffer target = vector_pop(vector_from_tuple(h, unassoc));
    thunk *newconn = allocate(h, sizeof(thunk));
    // there are other solutions for y

    requests_per_connection = extract_u64_with_default(t, sym(requests), 10);
    total_connections = extract_u64_with_default(t, sym(connections), 10);
    window = extract_u64_with_default(t, sym(window), 3);    
    rprintf("%p %p %p\n", requests_per_connection, total_connections, window);
    
    status_handler err = closure(h, connection_error);
    stats s = allocate_zero(h, sizeof(struct stats));
    merge m = allocate_merge(h, closure(h, finished, s));

    zero(s, sizeof(struct stats)); //?

    register_periodic_timer(seconds(1), closure(h, print_stats, s));
    tuple req = timmf("url", "/", "fizz", "bun", "Host", "tenny");
    rprintf("request %v\n", req);
    *newconn = (thunk)closure(h, startconn, h, n, m, target, newconn, s, err, req);

    apply(*newconn);
    notifier_spin(n);
}

