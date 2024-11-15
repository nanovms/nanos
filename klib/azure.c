#include <kernel.h>
#include <lwip.h>
#include <net_utils.h>

#include "azure.h"

#ifdef AZURE_DEBUG
#define azure_debug(fmt, ...)   tprintf(sym(azure), 0, ss(fmt "\n"), ##__VA_ARGS__)
#else
#define azure_debug(fmt, ...)
#endif

#define AZURE_INSTANCE_MD_ADDR  ss("169.254.169.254")

typedef struct az_instance_md_req {
    az_instance_md_handler complete;
    tuple req;
    struct buffer query;
    struct buffer md_header;
    closure_struct(value_handler, vh);
} *az_instance_md_req;

static struct azure {
    heap h;
    tuple instance_md;
} azure;

int init(status_handler complete)
{
    tuple root = get_root_tuple();
    if (!root)
        return KLIB_INIT_FAILED;
    tuple az_config = get_tuple(root, sym_this("azure"));
    if (!az_config)
        return KLIB_INIT_OK;
    azure.h = heap_locked(get_kernel_heaps());
    tuple diag = get_tuple(az_config, sym_this("diagnostics"));
    if (diag) {
        int res = azure_diag_init(diag);
        if (res != KLIB_INIT_OK)
            return res;
    }
    return KLIB_INIT_OK;
}

closure_function(1, 1, void, azure_instance_md_parsed,
                 tuple *, result,
                 void *v)
{
    *bound(result) = v;
}

closure_func_basic(parse_error, void, azure_instance_md_err,
                   string data)
{
    msg_err("%s: failed to parse JSON: %b", func_ss, data);
}

closure_func_basic(value_handler, void, azure_instance_md_vh,
                   value v)
{
    az_instance_md_req req_data = struct_from_closure(az_instance_md_req, vh);
    deallocate_value(req_data->req);
    if (!v) {
        msg_err("%s: failed to retrieve metadata", func_ss);
        goto done;
    }
    value start_line = get(v, sym(start_line));
    azure_debug("instance metadata server status %v", start_line);
    buffer status_code = get(start_line, integer_key(1));
    buffer content;
    if (status_code && !buffer_strcmp(status_code, "200"))
        content = get(v, sym_this("content"));
    else
        content = 0;
    if (!content) {
        msg_err("%s: unexpected server response %v", func_ss, v);
        goto done;
    }
    tuple md = 0;
    parser p = json_parser(azure.h, stack_closure(azure_instance_md_parsed, &md),
                           stack_closure_func(parse_error, azure_instance_md_err));
    p = parser_feed(p, content);
    p = apply(p, CHARACTER_INVALID);
    json_parser_free(p);
    if (md) {
        if (!compare_and_swap_64((u64 *)&azure.instance_md, 0, u64_from_pointer(md)))
            destruct_value(md, true);
    }
  done:
    apply(req_data->complete, azure.instance_md);
    deallocate(azure.h, req_data, sizeof(*req_data));
}

void azure_instance_md_get(az_instance_md_handler complete)
{
    tuple md = azure.instance_md;
    if (md) {
        apply(complete, md);
        return;
    }
    struct net_http_req_params req_params;
    req_params.host = AZURE_INSTANCE_MD_ADDR;
    req_params.port = 80;
    req_params.tls = false;
    req_params.method = HTTP_REQUEST_METHOD_GET;
    az_instance_md_req req_data = allocate(azure.h, sizeof(*req_data));
    if (req_data == INVALID_ADDRESS) {
        msg_err("%s: out of memory", func_ss);
        goto error;
    }
    tuple req = allocate_tuple();
    if (req == INVALID_ADDRESS) {
        msg_err("%s: out of memory", func_ss);
        deallocate(azure.h, req_data, sizeof(*req_data));
        goto error;
    }
    buffer_init_from_string(&req_data->query,
                            "/metadata/instance?api-version=2021-01-01&format=json");
    set(req, sym_this("url"), &req_data->query);
    buffer_init_from_string(&req_data->md_header, "true");
    set(req, sym_this("Metadata"), &req_data->md_header);
    req_data->req = req_params.req = req;
    req_params.body = 0;
    req_params.resp_handler = init_closure_func(&req_data->vh, value_handler, azure_instance_md_vh);
    req_data->complete = complete;
    azure_debug("retrieving instance metadata");
    status s = net_http_req(&req_params);
    if (is_ok(s))
        return;
    deallocate_value(req);
    deallocate(azure.h, req_data, sizeof(*req_data));
  error:
    apply(complete, 0);
}

void iso8601_write_interval(timestamp interval, buffer out)
{
    push_u8(out, 'P');
    u64 seconds = sec_from_timestamp(interval);
    int years = seconds / (365 * 24 * 60 * 60);
    if (years != 0) {
        bprintf(out, "%dY", years);
        seconds -= years * 365 * 24 * 60 * 60;
    }
    int days = seconds / (24 * 60 * 60);
    if (days != 0) {
        bprintf(out, "%dD", days);
        seconds -= days * 24 * 60 * 60;
    }
    if (seconds == 0)
        return;
    push_u8(out, 'T');
    int hours = seconds / (60 * 60);
    if (hours != 0) {
        bprintf(out, "%dH", hours);
        seconds -= hours * 60 * 60;
    }
    int minutes = seconds / 60;
    if (minutes != 0) {
        bprintf(out, "%dM", minutes);
        seconds -= minutes * 60;
    }
    if (seconds != 0)
        bprintf(out, "%dS", seconds);
}
