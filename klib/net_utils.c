#include <kernel.h>
#include <lwip.h>
#include <tls.h>

#include "net_utils.h"

typedef struct net_http_req_data {
    heap h;
    struct net_http_req_params params;
    closure_struct(connection_handler, ch);
    buffer_handler out;
    closure_struct(input_buffer_handler, ibh);
    buffer_handler parser;
    closure_struct(value_handler, vh);
} *net_http_req_data;

static void net_http_dealloc(net_http_req_data data)
{
    apply(data->parser, 0);
    buffer req_body = data->params.body;
    if (req_body)
        deallocate_buffer(req_body);
    value_handler resp_handler = data->params.resp_handler;
    if (resp_handler)
        apply(resp_handler, 0);
    deallocate(data->h, data, sizeof(*data));
}

static status net_http_req_internal(const ip_addr_t *addr, net_http_req_data data)
{
    net_http_req_params params = &data->params;
    u16 port = params->port;
    connection_handler ch = (connection_handler)&data->ch;
    status s;
    if (!params->tls) {
        s = direct_connect(data->h, (ip_addr_t *)addr, port, ch);
    } else {
        if (tls_connect((ip_addr_t *)addr, port, ch) == 0)
            s =  STATUS_OK;
        else
            s = timm("result", "failed to establish TLS connection with HTTP server");
    }
    return s;
}

static void net_http_dns_cb(sstring hostname, const ip_addr_t *addr, void *callback_arg)
{
    net_http_req_data req_data = callback_arg;
    boolean success;
    if (addr) {
        status s = net_http_req_internal(addr, req_data);
        success = is_ok(s);
        if (!success)
            timm_dealloc(s);
    } else {
        success = true;
    }
    if (!success)
        net_http_dealloc(req_data);
}

closure_func_basic(connection_handler, input_buffer_handler, net_http_ch,
                   buffer_handler out)
{
    net_http_req_data req_data = struct_from_closure(net_http_req_data, ch);
    input_buffer_handler in = INVALID_ADDRESS;
    if (out) {    /* connection succeeded */
        req_data->out = out;
        net_http_req_params params = &req_data->params;
        tuple req = params->req;
        set(req, sym(Host), alloca_wrap_sstring(params->host));
        set(req, sym(Connection), alloca_wrap_cstring("close"));
        status s = http_request(req_data->h, out, params->method, req, params->body);
        if (is_ok(s)) {
            /* The body of the request, if present, will be deallocated by the output buffer
             * handler. */
            params->body = 0;

            in = (input_buffer_handler)&req_data->ibh;
        } else {
            timm_dealloc(s);
        }
    }
    if (in == INVALID_ADDRESS)
        net_http_dealloc(req_data);
    return in;
}

closure_func_basic(input_buffer_handler, boolean, net_http_ibh,
                   buffer data)
{
    net_http_req_data req_data = struct_from_closure(net_http_req_data, ibh);
    if (data) {
        status s = apply(req_data->parser, data);
        boolean close_conn = !is_ok(s) || !req_data->params.resp_handler;
        timm_dealloc(s);
        if (close_conn) {
            apply(req_data->out, 0);
            return true;
        }
    } else {
        net_http_dealloc(req_data);
    }
    return false;
}

closure_func_basic(value_handler, void, net_http_vh,
                   value resp)
{
    net_http_req_data req_data = struct_from_closure(net_http_req_data, vh);
    value_handler resp_handler = req_data->params.resp_handler;
    if (resp_handler) {
        apply(resp_handler, resp);

        /* Signal to the input buffer handler that the response handler has been invoked and the
         * connection can be closed. */
        req_data->params.resp_handler = 0;
    }
}

status net_http_req(net_http_req_params params)
{
    heap h = heap_locked(get_kernel_heaps());
    net_http_req_data req_data = allocate(h, sizeof(*req_data));
    if (req_data == INVALID_ADDRESS)
        return timm_oom;
    req_data->parser = allocate_http_parser(h, init_closure_func(&req_data->vh, value_handler,
                                                                 net_http_vh));
    if (req_data->parser == INVALID_ADDRESS) {
        deallocate(h, req_data, sizeof(*req_data));
        return timm_oom;
    }
    req_data->h = h;
    runtime_memcpy(&req_data->params, params, sizeof(*params));
    init_closure_func(&req_data->ch, connection_handler, net_http_ch);
    init_closure_func(&req_data->ibh, input_buffer_handler, net_http_ibh);
    ip_addr_t addr;
    sstring host = params->host;
    err_t err = dns_gethostbyname(host, &addr, net_http_dns_cb, req_data);
    status s;
    switch (err) {
    case ERR_OK:
        s = net_http_req_internal(&addr, req_data);
        break;
    case ERR_INPROGRESS:
        return STATUS_OK;
    default:
        s = timm("result", "failed to resolve hostname '%s' (%d)", host, err);
    }
    if (!is_ok(s)) {
        req_data->params.body = 0;  /* so that it's not deallocated in net_http_dealloc() */
        req_data->params.resp_handler = 0;  /* so that it's not invoked in net_http_dealloc() */
        net_http_dealloc(req_data);
    }
    return s;
}
