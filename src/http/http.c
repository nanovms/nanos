#include <kernel.h>
#include <http.h>

#define STATE_INIT 0
#define STATE_START_LINE 1
#define STATE_HEADER 2
#define STATE_VALUE 3
#define STATE_BODY 4

typedef struct http_parser {
    heap h;
    vector start_line;
    int state;
    buffer word;
    symbol s;
    tuple header;
    value_handler each;
    u64 content_length;
} *http_parser;

static void each_header(buffer dest, symbol n, value v)
{
    if (n != sym(url))
        bprintf(dest, "%v: %v\r\n", n, v);
}

static void http_header(buffer dest, tuple t)
{
    // asynch in new world
    table_foreach(t, k , v) each_header(dest, k, v);
    bprintf(dest, "\r\n");    
}

status http_request(heap h, buffer_handler bh, tuple headers)
{
    buffer b = allocate_buffer(h, 100);
    buffer url = table_find(headers, sym(url));
    bprintf(b, "GET %b HTTP/1.1\r\n", url);
    http_header(b, headers);
    status s = apply(bh, b);
    if (!is_ok(s)) {
        deallocate_buffer(b);
        return timm_up(s, "result", "%s failed to send", __func__);
    }
    return STATUS_OK;
}

static status send_http_headers(buffer_handler out, tuple t)
{
    status s;
    buffer d = allocate_buffer(transient, 128);
    bprintf(d, "HTTP/1.1 ");
    value v;
    symbol ss = sym(status);
    if ((v = table_find(t, ss)))
        bprintf(d, "%b\r\n", (buffer)v);
    else
        bprintf(d, "200 OK\r\n");

    /* destructive */
    table_foreach(t, k, v) {
        if (k != ss)
            each_header(d, k, v);
        if (v) {
            /* XXX assert tag type */
            deallocate_buffer((buffer)v);
        }
    }
    deallocate_tuple(t);
    bprintf(d, "\r\n");

    s = apply(out, d);
    if (!is_ok(s)) {
        deallocate_buffer(d);
        return timm_up(s, "%s failed to send", __func__);
    }
    return STATUS_OK;
}

/* consumes c, c == 0 indicates terminate */
status send_http_chunk(buffer_handler out, buffer c)
{
    if (c)
        assert(!buffer_is_wrapped(c));

    status s = STATUS_OK;
    buffer d = allocate_buffer(transient, 32);
    int len = c ? buffer_length(c) : 0;
    bprintf(d, "%x\r\n", len);
    s = apply(out, d);
    if (!is_ok(s))
        goto out_fail;

    if (!c)
        c = allocate_buffer(transient, 2);

    bprintf(c, "\r\n");
    s = apply(out, c);
    if (!is_ok(s))
        goto out_fail;

    /* could support trailers... */
    return s;
  out_fail:
    s = timm_up(s, "%s: failed to send", __func__);
    return s;
}

/* consumes t */
status send_http_chunked_response(buffer_handler out, tuple t)
{
    table_set(t, sym(Transfer-Encoding), aprintf(transient, "chunked"));
    status s = send_http_headers(out, t);
    if (!is_ok(s))
        return timm_up(s, "%s failed to send", __func__);
    return s;
}

/* consumes t and c */
status send_http_response(buffer_handler out, tuple t, buffer c)
{
    if (c) {
        assert(!buffer_is_wrapped(c));
        table_set(t, sym(Content-Length), aprintf(transient, "%d", buffer_length(c)));
    }

    status s = send_http_headers(out, t);
    if (!is_ok(s))
        goto out_fail;

    if (c) {
        s = apply(out, c);
        if (!is_ok(s)) {
            deallocate_buffer(c);
            goto out_fail;
        }
    }
    return STATUS_OK;
  out_fail:
    return timm_up(s, "%s failed to send", __func__);
}

static void reset_parser(http_parser p)
{
    p->state = STATE_INIT;
    p->header = allocate_tuple();
    p->word = allocate_buffer(p->h, 10);
    p->start_line = allocate_vector(p->h, 3);
    p->content_length = 0;
}

// we're going to patch the connection together by looking at the
// leftover bits in buffer...defer until we need to actually
// switch protocols
closure_function(1, 1, status, http_recv,
                 http_parser, p,
                 buffer, b)
{
    http_parser p = bound(p);
    tuple start_line;

    /* content may be delimited by close rather than content length */
    if (!b) {
        if (p->state == STATE_BODY)
            goto content_finish;
        if (p->state == STATE_INIT)
            return STATUS_OK;   /* XXX teardown */
        return timm("result", "http_recv: connection closed before finished parsing (state %d)", p->state);
    }
    
    for (bytes i = b->start; i < b->end; i++) {
        char x = ((unsigned char *)b->contents)[i];
        switch (p->state) {
        case STATE_INIT:
            p->state = STATE_START_LINE;
        case STATE_START_LINE:
            switch (x){
            case '\r':
                p->state = STATE_HEADER;
            case ' ':
                vector_push(p->start_line, p->word);
                p->word = allocate_buffer(p->h, 0);
                break;
            default:
                push_u8(p->word, x);
            }
            break;
            
        case STATE_HEADER:
            switch(x) {
            case ' ':
                p->state = STATE_VALUE;
                p->s = intern(p->word);
                buffer_clear(p->word);
                break;
            case '\r':
                p->state = STATE_BODY;
                break;
            case '\n':
            case ':':
                break;
            default:
                push_u8(p->word, x);
            }
            break;
            
        case STATE_VALUE:
            if (x == '\r') {
                if (p->s == sym(Content-Length)) {
                    if (!parse_int(p->word, 10, &p->content_length))
                        msg_err("failed to parse content length\n");
                }
                table_set(p->header, p->s, p->word);
                p->word = allocate_buffer(p->h, 0);                
                p->state = STATE_HEADER;
            } else {
                push_u8(p->word, x);
            }
            break;
            
        case STATE_BODY:
            push_u8(p->word, x);            
            --p->content_length;
        }

        if ((p->state == STATE_BODY) && (p->content_length == 0))
            goto content_finish;
    }

  content_finish:
    // XXX change from vector to tuple
    start_line = allocate_tuple();
    for (u64 i = 0; i < vector_length(p->start_line); i++) {
        buffer a = vector_get(p->start_line, i);
        table_set(start_line, intern_u64(i), a);
    }
    table_set(p->header, sym(start_line), start_line);
    table_set(p->header, sym(content), p->word);
    apply(p->each, p->header);
    reset_parser(p);
    return STATUS_OK;
}

buffer_handler allocate_http_parser(heap h, value_handler each)
{
    http_parser p = allocate(h, sizeof(struct http_parser));
    p->h = h;
    p->each = each;
    reset_parser(p);
    return closure(h, http_recv, p);
}

const char *http_request_methods[] = {
    [HTTP_REQUEST_METHOD_GET] = "GET",
    [HTTP_REQUEST_METHOD_HEAD] = "HEAD",
    [HTTP_REQUEST_METHOD_POST] = "POST",
    [HTTP_REQUEST_METHOD_PUT] = "PUT",
    [HTTP_REQUEST_METHOD_DELETE] = "DELETE",
    [HTTP_REQUEST_METHOD_TRACE] = "TRACE",
    [HTTP_REQUEST_METHOD_OPTIONS] = "OPTIONS",
    [HTTP_REQUEST_METHOD_CONNECT] = "CONNECT",
    [HTTP_REQUEST_METHOD_PATCH] = "PATCH"
};

typedef struct http_listener_registrant {
    struct list l;
    const char *uri;
    http_request_handler each;
} *http_listener_registrant;

typedef struct http_listener {
    heap h;
    http_request_handler default_handler;
    struct list registrants;
} *http_listener;

closure_function(2, 1, void, each_http_request,
                 http_listener, hl, buffer_handler, out,
                 value, v)
{
    http_method method;
    http_listener hl = bound(hl);
    vector vsl = vector_from_tuple(hl->h, table_find(v, sym(start_line)));
    if (!vsl || vsl == INVALID_ADDRESS)
        goto not_found;

    buffer mb = vector_get(vsl, 0);
    for (method = 0; method < HTTP_REQUEST_METHODS; method++) {
        if (buffer_compare(mb, alloca_wrap_buffer(http_request_methods[method],
                                                  runtime_strlen(http_request_methods[method]))))
            break;
    }

    if (method == HTTP_REQUEST_METHODS)
        goto not_found;

    /* support absoluteURI? */
    buffer uri = vector_get(vsl, 1);
    if (!uri || buffer_length(uri) < 1 || *(u8*)buffer_ref(uri, 0) != '/')
        goto not_found;
    buffer_consume(uri, 1);

    /* whatever test for default page */
    if (buffer_length(uri) == 0) {
        if (!hl->default_handler)
            goto not_found;
        apply(hl->default_handler, method, bound(out), v);
        return;
    }

    int total_len = buffer_length(uri);
    int top_len = 0;
    char * top = buffer_ref(uri, 0);
    for (int i = 0; i < total_len; i++) {
        if (top[i] == '/') {
            buffer_consume(uri, 1);
            break;
        }
        top_len++;
    }
    buffer_consume(uri, top_len);

    if (buffer_length(uri) > 0)
        table_set(v, sym(relative_uri), uri);

    list_foreach(&hl->registrants, l) {
        http_listener_registrant r = struct_from_list(l, http_listener_registrant, l);
        if (top_len == runtime_strlen(r->uri) &&
            runtime_memcmp(top, r->uri, top_len) == 0) {
            apply(r->each, method, bound(out), v);
            return;
        }
    }
  not_found:
    send_http_response(bound(out), timm("status", "404 Not Found"),
                       aprintf(hl->h, "<html><head><title>404 Not Found</title></head>"
                               "<body><h1>Not Found</h1></body></html>\r\n"));
}

closure_function(1, 1, buffer_handler, each_http_connection,
                 http_listener, hl,
                 buffer_handler, out)
{
    http_listener hl = bound(hl);
    return allocate_http_parser(hl->h, closure(hl->h, each_http_request, hl, out));
}

/* just top level of abs_path */
void http_register_uri_handler(http_listener hl, const char *uri, http_request_handler each)
{
    http_listener_registrant r = allocate(hl->h, sizeof(struct http_listener_registrant));
    assert(r != INVALID_ADDRESS); /* no error path, this is pretty much init only */
    r->uri = uri;
    r->each = each;
    list_insert_before(&hl->registrants, &r->l);
}

void http_register_default_handler(http_listener hl, http_request_handler each)
{
    hl->default_handler = each;
}

connection_handler connection_handler_from_http_listener(http_listener hl)
{
    return closure(hl->h, each_http_connection, hl);
}

/* should take address? */
http_listener allocate_http_listener(heap h, u16 port)
{
    http_listener hl = allocate(h, sizeof(struct http_listener));
    if (hl == INVALID_ADDRESS)
        return hl;

    hl->h = h;
    hl->default_handler = 0;
    list_init(&hl->registrants);
    return hl;
}

void deallocate_http_listener(heap h, http_listener hl)
{
    deallocate(h, hl, sizeof(struct http_listener));
}
