#include <runtime.h>
#include <stdlib.h>
#include <http.h>
#include <socket_user.h>

typedef struct stats {
    u32 connections;
    u32 responses;
    u32 active;    
    u32 requests;
} *stats;


static void send_request(heap h, stats s, buffer_handler out, tuple t)
{
    s->requests++;
    http_request(h, out, HTTP_REQUEST_METHOD_POST, t, 0);
}

u64 requests_per_connection;
u64 total_connections;

static void print_stats(stats s)
{
    rprintf("c: %d active: %d req: %d resp: %d\r", s->connections, s->active, s->requests, s->responses);
}

closure_function(7, 1, void, value_in,
                 heap, h, buffer_handler, out, u64 *, count, status_handler, completed, thunk, newconn, stats, s, tuple, req,
                 value v)
{
    stats s = bound(s);
    s->responses++;

    static timestamp last;
    timestamp t = now(CLOCK_ID_MONOTONIC);
    u64 *count = bound(count);

    if ((t - last) > (1ull<<32)){
        last = t;
        print_stats(s);
    }
    
    if (*count == 0) {
        if (s->connections < total_connections) 
            apply(bound(newconn));
    }
    int window = 1;
    for (int i = 0; i < window; i++) {
        *count = *count + 1;
        if (*count < requests_per_connection) {
            send_request(bound(h), s, bound(out), bound(req));
        } else {
            s->active--;
            apply(bound(out), 0);
            destroy_heap(bound(h));
            apply(bound(completed), 0);
            return;
        }
    }
}

heap make_tiny_heap(heap parent);

closure_function(1, 1, boolean, ibh_parser_wrap,
                 buffer_handler, bh,
                 buffer b)
{
    status s = apply(bound(bh), b);
    if (s != STATUS_OK) {
        timm_dealloc(s);
    }
    return false;
}

closure_function(5, 1, input_buffer_handler, newconn,
                 heap, h, thunk, newconn, stats, s, tuple, t, status_handler, sth,
                 buffer_handler out)
{
    stats s = bound(s);
    tuple t = bound(t);
    heap pages = allocate_mmapheap(bound(h), 4096);
    heap c = make_tiny_heap(pages);
    u64 *count = allocate_zero(c, sizeof(u64));
    s->connections++;
    s->active++;
    send_request(c, s, out, t);
    send_request(c, s, out, t);
    send_request(c, s, out, t);
    buffer_handler bh = allocate_http_parser(c, closure(c, value_in, c, out, count, bound(sth), bound(newconn), s, t));
    return closure(c, ibh_parser_wrap, bh);
}

closure_function(8, 0, void, startconn,
                 heap, h, notifier, n, merge, m, buffer, target, thunk *, self, stats, s, status_handler, err, tuple, req)
{
    heap h = bound(h);
    status_handler sth = apply_merge(bound(m));
    connection(h, bound(n), bound(target), closure(h, newconn, h, *bound(self), bound(s), bound(req), sth), bound(err));
}

closure_func_basic(status_handler, void, connection_error,
                   status s)
{
    msg_err("connection error %v", s);
    exit(1);
}

closure_function(1, 1, void, finished,
                 stats, st,
                 status s)
{
    print_stats(bound(st));
    rprintf("\n");
    exit(0);
}

u64 extract_u64_with_default(tuple t, symbol n, u64 otherwise)
{
    u64 result;
    if (get_u64(t, n, &result))
        return result;
    return otherwise;
}


int main(int argc, char **argv)
{
    heap h = init_process_runtime();    
    tuple t = parse_arguments(h, argc, argv);
    vector unassoc = get_vector(t, sym(unassociated));
    if (!unassoc) {
        halt("must provide target\n");
    }

    notifier n = get(t, sym(select)) ? create_select_notifier(h) :
        get(t, sym(poll)) ? create_poll_notifier(h) :
#ifndef NO_EPOLL
	create_epoll_notifier(h);
#else
	create_poll_notifier(h);
#endif
    buffer target = vector_pop(unassoc);
    thunk *newconn = allocate(h, sizeof(thunk));
    // there are other solutions for y

    requests_per_connection = extract_u64_with_default(t, sym(requests), 10);
    total_connections = extract_u64_with_default(t, sym(connections), 10);
                                                   
    status_handler err = closure_func(h, status_handler, connection_error);
    stats s = allocate_zero(h, sizeof(struct stats));
    merge m = allocate_merge(h, closure(h, finished, s));

    zero(s, sizeof(struct stats)); //?
    tuple req = timm("url", "/");
    req = timm_append(req, "fizz", "bun");
    req = timm_append(req, "Host", "tenny");
    *newconn = (thunk)closure(h, startconn, h, n, m, target, newconn, s, err, req);
    apply(*newconn);
    notifier_spin(n);
    return 0;
}

