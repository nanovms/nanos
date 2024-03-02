#include <runtime.h>
#include <http.h>

#define HTTP_VER(x, y) (((x)<<16)|((y)&MASK(16)))
#define HTTP_MAJ(v) ((v)>>16)
#define HTTP_MIN(v) ((v)&MASK(16))

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

struct http_responder {
    heap h;
    buffer_handler out;
    u32 http_version;
    boolean keepalive;
};

closure_function(3, 2, boolean, each_header,
                 buffer, dest, symbol, ignore, boolean, dealloc,
                 value n, value v)
{
    if (n != bound(ignore)) {
        // XXX string
        if (is_tuple(v) || is_symbol(v))
            bprintf(bound(dest), "%v: %v\r\n", n, v);
        else
            bprintf(bound(dest), "%v: %b\r\n", n, (buffer)v);
    }

    if (bound(dealloc)) {
        assert(!is_tuple(v));
        deallocate_value(v);
    }
    return true;
}

static void http_header(buffer dest, tuple t)
{
    iterate(t, stack_closure(each_header, dest, sym(url), false));
    bprintf(dest, "\r\n");    
}

status http_request(heap h, buffer_handler bh, http_method method, tuple headers, buffer body)
{
    buffer b = allocate_buffer(h, 100);
    buffer url = get(headers, sym(url));
    bprintf(b, "%s %b HTTP/1.1\r\n", http_request_methods[method], url);
    if (body) {
        buffer content_len = little_stack_buffer(16);
        bprintf(content_len, "%ld", buffer_length(body));
        set(headers, sym(Content-Length), content_len);
    }
    http_header(b, headers);
    status s = apply(bh, b);
    if (!is_ok(s)) {
        deallocate_buffer(b);
        return timm_up(s, "result", "%s failed to send", func_ss);
    }
    if (body)
        s = apply(bh, body);
    return s;
}

static status send_http_headers(http_responder out, tuple t)
{
    status s;
    if (out->keepalive && out->http_version <= HTTP_VER(1,0))
        set(t, sym(connection), aprintf(out->h, "keep-alive"));
    else if (!out->keepalive && out->http_version >= HTTP_VER(1,1))
        set(t, sym(connection), aprintf(out->h, "close"));
    buffer d = allocate_buffer(transient, 128);
    bprintf(d, "HTTP/%d.%d ", HTTP_MAJ(out->http_version), HTTP_MIN(out->http_version));
    symbol ss = sym(status);
    string sstr = get_string(t, ss);
    if (sstr)
        bprintf(d, "%b\r\n", sstr);
    else
        bprintf(d, "200 OK\r\n");

    /* destructive */
    iterate(t, stack_closure(each_header, d, ss, true));
    deallocate_value(t);
    bprintf(d, "\r\n");

    s = apply(out->out, d);
    if (!is_ok(s)) {
        deallocate_buffer(d);
        return timm_up(s, "result", "%s failed to send", func_ss);
    }
    return STATUS_OK;
}

/* consumes c, c == 0 indicates terminate */
status send_http_chunk(http_responder out, buffer c)
{
    if (c)
        assert(!buffer_is_wrapped(c));

    status s = STATUS_OK;
    buffer d = allocate_buffer(transient, 32);
    int len = c ? buffer_length(c) : 0;
    bprintf(d, "%x\r\n", len);
    s = apply(out->out, d);
    if (!is_ok(s))
        goto out_fail;

    if (!c)
        c = allocate_buffer(transient, 2);

    bprintf(c, "\r\n");
    s = apply(out->out, c);
    if (!is_ok(s))
        goto out_fail;
    if (len == 0 && !out->keepalive)
        apply(out->out, 0);
    /* could support trailers... */
    return s;
  out_fail:
    s = timm_up(s, "result", "%s failed to send", func_ss);
    return s;
}

/* consumes t */
status send_http_chunked_response(http_responder out, tuple t)
{
    set(t, sym(Transfer-Encoding), aprintf(transient, "chunked"));
    status s = send_http_headers(out, t);
    if (!is_ok(s))
        return timm_up(s, "result", "%s failed to send", func_ss);
    return s;
}

/* consumes t and c */
status send_http_response(http_responder out, tuple t, buffer c)
{
    if (c) {
        assert(!buffer_is_wrapped(c));
        set(t, sym(Content-Length), aprintf(transient, "%d", buffer_length(c)));
    }

    status s = send_http_headers(out, t);
    if (!is_ok(s))
        goto out_fail;

    if (c) {
        s = apply(out->out, c);
        if (!is_ok(s)) {
            deallocate_buffer(c);
            goto out_fail;
        }
    }
    if (!out->keepalive)
        apply(out->out, 0);
    return STATUS_OK;
  out_fail:
    return timm_up(s, "result", "%s failed to send", func_ss);
}

static void reset_parser(http_parser p)
{
    p->state = STATE_INIT;
    p->header = allocate_tuple();
    p->word = allocate_buffer(p->h, 10);
    p->start_line = allocate_tagged_vector(3);
    p->content_length = 0;
}

static void cleanup_parser(http_parser p)
{
    if (p->word != INVALID_ADDRESS)
        deallocate_buffer(p->word);
    destruct_value(p->header, true);
}

static void deallocate_parser(http_parser p)
{
    cleanup_parser(p);
    deallocate_closure(p->each);
    deallocate(p->h, p, sizeof(*p));
}

// we're going to patch the connection together by looking at the
// leftover bits in buffer...defer until we need to actually
// switch protocols
closure_function(1, 1, status, http_recv,
                 http_parser, p,
                 buffer b)
{
    http_parser p = bound(p);

    /* content may be delimited by close rather than content length */
    if (!b) {
        int state = p->state;
        if (state == STATE_BODY)
            goto content_finish;
        deallocate_parser(p);
        closure_finish();
        if (state == STATE_INIT)
            return STATUS_OK;   /* XXX teardown */
        return timm("result", "http_recv: connection closed before finished parsing (state %d)", state);
    }
    
    for (bytes i = b->start; i < b->end; i++) {
        char x = ((unsigned char *)b->contents)[i];
        switch (p->state) {
        case STATE_INIT:
            p->state = STATE_START_LINE;
        case STATE_START_LINE:
            switch (x){
            case '\n':
                p->state = STATE_HEADER;
                break;
            case '\r':
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
            case '\n':
                p->state = STATE_BODY;
                break;
            case '\r':
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

                    /* unconsume the bytes consumed by parse_int() */
                    p->word->start = 0;
                }
                set(p->header, p->s, p->word);
                p->word = allocate_buffer(p->h, 0);                
            } else if (x == '\n') {
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
    if ((p->state != STATE_BODY) || (p->content_length != 0))
        /* Incomplete HTTP message; parsing can continue when the next packet arrives. */
        return STATUS_OK;

  content_finish:
    set(p->header, sym(start_line), p->start_line);
    set(p->header, sym(content), p->word);
    p->word = INVALID_ADDRESS;
    apply(p->each, p->header);
    if (b) {
        cleanup_parser(p);
        reset_parser(p);
    } else {
        deallocate_parser(p);
        closure_finish();
    }
    return STATUS_OK;
}

buffer_handler allocate_http_parser(heap h, value_handler each)
{
    http_parser p = allocate(h, sizeof(struct http_parser));
    if (p == INVALID_ADDRESS)
        return INVALID_ADDRESS;
    p->h = h;
    p->each = each;
    reset_parser(p);
    return closure(h, http_recv, p);
}

const sstring http_request_methods[] = {
    [HTTP_REQUEST_METHOD_GET] = ss_static_init("GET"),
    [HTTP_REQUEST_METHOD_HEAD] = ss_static_init("HEAD"),
    [HTTP_REQUEST_METHOD_POST] = ss_static_init("POST"),
    [HTTP_REQUEST_METHOD_PUT] = ss_static_init("PUT"),
    [HTTP_REQUEST_METHOD_DELETE] = ss_static_init("DELETE"),
    [HTTP_REQUEST_METHOD_TRACE] = ss_static_init("TRACE"),
    [HTTP_REQUEST_METHOD_OPTIONS] = ss_static_init("OPTIONS"),
    [HTTP_REQUEST_METHOD_CONNECT] = ss_static_init("CONNECT"),
    [HTTP_REQUEST_METHOD_PATCH] = ss_static_init("PATCH")
};

typedef struct http_listener_registrant {
    struct list l;
    sstring uri;
    http_request_handler each;
} *http_listener_registrant;

typedef struct http_listener {
    heap h;
    http_request_handler default_handler;
    struct list registrants;
} *http_listener;

/* consumes the buffer */
static void get_http_ver(buffer b, u32 *ver)
{
    u64 ma, mi;
    *ver = HTTP_VER(1, 1);
    if (buffer_strstr(b, ss("HTTP/")) != 0)
        return;
    buffer_consume(b, 5);
    if (!parse_int(b, 10, &ma))
        return;
    if (pop_u8(b) != '.')
        return;
    if (!parse_int(b, 10, &mi))
        return;
    *ver = HTTP_VER(ma, mi);
}

closure_function(2, 2, boolean, find_header,
                 value *, pv, sstring, m,
                 value k, value v)
{
    if (!is_symbol(k) && !is_string(v))
        return true;
    if (!buffer_compare_with_sstring_ci(symbol_string(k), bound(m))) {
        *bound(pv) = v;
        return false;
    }
    return true;
}

static void check_keepalive(http_responder hr, tuple v)
{
    if (hr->http_version < HTTP_VER(1, 1))
        hr->keepalive = false;
    else
        hr->keepalive = true;
    value conn;
    if (iterate(v, stack_closure(find_header, &conn, ss("Connection"))))
        return;
    if (!buffer_strcasecmp(conn, "close"))
        hr->keepalive = false;
    else if (!buffer_strcasecmp(conn, "keep-alive")) {
        hr->keepalive = true;
    }
}

/* XXX need refcount of outstanding http handlers for safe dealloc */
closure_function(2, 1, void, each_http_request,
                 http_listener, hl, struct http_responder, hr,
                 value v)
{
    http_method method;
    http_listener hl = bound(hl);
    http_responder hr = &bound(hr);
    vector vsl = get_vector(v, sym(start_line));
    if (!vsl || vsl == INVALID_ADDRESS)
        goto not_found;

    buffer ver = vector_get(vsl, 2);
    if (ver) {
        get_http_ver(alloca_wrap(ver), &hr->http_version);
        if (hr->http_version > HTTP_VER(1, 1))
            goto bad_ver;

        check_keepalive(hr, v);
    }

    buffer mb = vector_get(vsl, 0);
    for (method = 0; method < HTTP_REQUEST_METHODS; method++) {
        if (buffer_compare(mb, alloca_wrap_sstring(http_request_methods[method])))
            break;
    }

    if (method == HTTP_REQUEST_METHODS)
        goto not_found;

    buffer uri = vector_get(vsl, 1);
    if (!uri || buffer_length(uri) < 1 || *(u8*)buffer_ref(uri, 0) != '/')
        goto not_found;

    /* whatever test for default page */
    if (buffer_length(uri) == 1) {
        if (!hl->default_handler)
            goto not_found;
        apply(hl->default_handler, method, hr, v);
        return;
    }

    buffer rel_uri = clone_buffer(hl->h, uri);
    assert(rel_uri != INVALID_ADDRESS);
    buffer_consume(rel_uri, 1);
    int total_len = buffer_length(rel_uri);
    int top_len = 0;
    char *top = buffer_ref(rel_uri, 0);
    for (int i = 0; i < total_len; i++) {
        if (top[i] == '/') {
            buffer_consume(rel_uri, 1);
            break;
        }
        top_len++;
    }

    http_listener_registrant match = 0;
    list_foreach(&hl->registrants, l) {
        http_listener_registrant r = struct_from_list(l, http_listener_registrant, l);
        if ((top_len == r->uri.len) && !runtime_memcmp(top, r->uri.ptr, top_len)) {
            match = r;
            break;
        }
    }

    buffer_consume(rel_uri, top_len);
    if (buffer_length(rel_uri) > 0)
        set(v, sym(relative_uri), rel_uri);
    else
        deallocate_buffer(rel_uri);

    if (match)
        apply(match->each, method, hr, v);
    return;
  not_found:
    send_http_response(hr, timm("status", "404 Not Found"),
                       aprintf(hl->h, "<html><head><title>404 Not Found</title></head>"
                               "<body><h1>Not Found</h1></body></html>\r\n"));
    return;
  bad_ver:
    send_http_response(hr, timm("status", "505 HTTP Version Not Supported"),
                       aprintf(hl->h, "<html><head><title>505 HTTP Version Not Supported</title></head>"
                               "<body><h1>Use HTTP/1.1</h1></body></html>\r\n"));

}

closure_function(1, 1, boolean, http_ibh,
                 buffer_handler, parser,
                 buffer b)
{
    status s = apply(bound(parser), b);
    if (!b)
        closure_finish();
    if (s == STATUS_OK)
        return false;
    timm_dealloc(s);
    return true;
}

closure_function(1, 1, input_buffer_handler, each_http_connection,
                 http_listener, hl,
                 buffer_handler out)
{
    http_listener hl = bound(hl);
    struct http_responder hr;
    hr.h = hl->h;
    hr.keepalive = true;
    hr.out = out;
    hr.http_version = HTTP_VER(1, 1);
    buffer_handler parser = allocate_http_parser(hl->h, closure(hl->h, each_http_request, hl, hr));
    if (parser == INVALID_ADDRESS)
        return INVALID_ADDRESS;
    input_buffer_handler ibh = closure(hl->h, http_ibh, parser);
    if (ibh != INVALID_ADDRESS)
        return ibh;
    apply(parser, 0);
    return INVALID_ADDRESS;
}

/* just top level of abs_path */
void http_register_uri_handler(http_listener hl, sstring uri, http_request_handler each)
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
