#include <unix_internal.h>
#include <cloud_init.h>
#include <drivers/dmi.h>
#include <filesystem.h>
#include <http.h>
#include <lwip.h>
#include <tls.h>

#define AZURE_CHASSIS   "7783-7084-3265-9085-8269-3286-77"

enum cloud {
    CLOUD_ERROR,
    CLOUD_AZURE,
    CLOUD_UNKNOWN
};

enum cloud_init_task_op {
    CLOUD_INIT_TASK_OP_START,
    CLOUD_INIT_TASK_OP_DELETE,
};

typedef closure_type(cloud_init_task, void, enum cloud_init_task_op, void *);

typedef closure_type(download_recv, boolean, buffer_handler, buffer);

declare_closure_struct(2, 2, void, cloud_download_task,
                       download_recv, recv, thunk, cleanup,
                       int, op, void *, arg);
declare_closure_struct(2, 1, void, cloud_download_done,
                       struct cloud_download_cfg *, cfg, status_handler, complete,
                       status, s);

typedef struct cloud_download_cfg {
    struct buffer server_host;
    u16 server_port;
    struct buffer server_path;
    boolean tls;
    boolean optional;   /* if true, a download error is not fatal */
    boolean done;
    buffer auth_header;
    closure_struct(cloud_download_task, task);
    closure_struct(cloud_download_done, complete);
} *cloud_download_cfg;

declare_closure_struct(4, 2, boolean, cloud_download_file_recv,
                       buffer_handler, parser, bytes, content_len, bytes, received, status_handler, sh,
                       buffer_handler, out, buffer, data);
declare_closure_struct(0, 0, void, cloud_download_file_cleanup);
typedef struct cloud_download_file {
    struct cloud_download_cfg download;
    buffer file_path;
    closure_struct(cloud_download_file_recv, recv);
    closure_struct(cloud_download_file_cleanup, cleanup);
} *cloud_download_file;

declare_closure_struct(1, 1, void, cloud_download_setenv,
                       status *, s,
                       value, v);
declare_closure_struct(2, 2, boolean, cloud_download_env_recv,
                       buffer_handler, parser, status, s,
                       buffer_handler, out, buffer, data);
declare_closure_struct(0, 0, void, cloud_download_env_cleanup);
typedef struct cloud_download_env_cfg {
    struct cloud_download_cfg download;
    vector attribute_path;
    closure_struct(cloud_download_setenv, setenv);
    closure_struct(cloud_download_env_recv, recv);
    closure_struct(cloud_download_env_cleanup, cleanup);
} *cloud_download_env;

static heap cloud_heap;

static enum cloud cloud_detect(void)
{
    sstring chassis_asset_tag = dmi_get_string(DMI_CHASSIS_ASSET_TAG);
    if (sstring_is_null(chassis_asset_tag))
        return CLOUD_UNKNOWN;
    if (!runtime_strcmp(chassis_asset_tag, ss(AZURE_CHASSIS)))
        return CLOUD_AZURE;
    return CLOUD_UNKNOWN;
}

static int cloud_init_parse_vector(value config, int (*parse_each)(tuple, vector), vector tasks)
{
    if (!is_composite(config))
        return KLIB_INIT_FAILED;
    /* allow parsing either tuple or vector for backward compatibility with older ops/tfs... */
    value v;
    for (int i = 0; (v = get(config, integer_key(i))); i++) {
        if (!is_tuple(v))
            return KLIB_INIT_FAILED;
        int ret = parse_each(v, tasks);
        if (ret != KLIB_INIT_OK)
            return ret;
    }
    return KLIB_INIT_OK;
}

static int cloud_download_parse(tuple config, cloud_download_cfg parsed_cfg)
{
    buffer src = get(config, sym(src));
    if (!src) {
        rprintf("cloud_init: missing download source in %v\n", config);
        return KLIB_INIT_FAILED;
    }
    if (!is_string(src) || (buffer_length(src) < 8)) {
        rprintf("cloud_init: invalid download source %v\n", src);
        return KLIB_INIT_FAILED;
    }
    if (!runtime_memcmp(buffer_ref(src, 0), "http://", 7)) {
        parsed_cfg->server_host.start = 7;
        parsed_cfg->server_port = 80;
        parsed_cfg->tls = false;
    } else if (!runtime_memcmp(buffer_ref(src, 0), "https://", 8)) {
        parsed_cfg->server_host.start = 8;
        parsed_cfg->server_port = 443;
        parsed_cfg->tls = true;
    } else {
        rprintf("cloud_init: invalid download source %b\n", src);
        return KLIB_INIT_FAILED;
    }
    parsed_cfg->server_host.contents = buffer_ref(src, 0);
    parsed_cfg->server_host.end = parsed_cfg->server_host.length = buffer_length(src);
    int host_end = buffer_strchr(&parsed_cfg->server_host, '/');
    if (host_end < 0) {
        parsed_cfg->server_path.contents = "/";
        parsed_cfg->server_path.start = 0;
        parsed_cfg->server_path.end = parsed_cfg->server_path.length = 1;
    } else {
        parsed_cfg->server_host.end = parsed_cfg->server_host.start + host_end;
        parsed_cfg->server_path.contents = buffer_ref(src, 0);
        parsed_cfg->server_path.start = parsed_cfg->server_host.end;
        parsed_cfg->server_path.end = parsed_cfg->server_path.length = buffer_length(src);
    }
    parsed_cfg->server_path.wrapped = true;
    host_end = buffer_strchr(&parsed_cfg->server_host, ':');
    if (host_end >= 0) {
        if (host_end == buffer_length(&parsed_cfg->server_host) - 1) {
            rprintf("cloud_init: invalid download source %b\n", src);
            return KLIB_INIT_FAILED;
        }
        buffer b = alloca_wrap_buffer(buffer_ref(&parsed_cfg->server_host, host_end + 1),
            buffer_length(&parsed_cfg->server_host) - host_end - 1);
        u64 port;
        if (!u64_from_value(b, &port) || (port > U16_MAX)) {
            rprintf("invalid server port in download source %b\n", src);
            return KLIB_INIT_FAILED;
        }
        parsed_cfg->server_port = port;
        parsed_cfg->server_host.end = parsed_cfg->server_host.start + host_end;
    }
    parsed_cfg->server_host.wrapped = true;
    parsed_cfg->optional = parsed_cfg->done = false;
    parsed_cfg->auth_header = get(config, sym(auth));
    return KLIB_INIT_OK;
}

define_closure_function(2, 1, void, cloud_download_done,
                        cloud_download_cfg, cfg, status_handler, complete,
                        status, s)
{
    cloud_download_cfg cfg = bound(cfg);
    if (!is_ok(s) && cfg->optional) {
        timm_dealloc(s);
        s = STATUS_OK;
    }
    apply(bound(complete), s);
    cloud_init_task task = (cloud_init_task)&cfg->task;
    apply(task, CLOUD_INIT_TASK_OP_DELETE, 0);
}

closure_function(3, 2, void, cloud_download_save_complete,
                 fsfile, f, buffer, content, status_handler, sh,
                 status, s, bytes, len)
{
    deallocate_buffer(bound(content));
    fsfile_release(bound(f));
    apply(bound(sh), s);
    closure_finish();
}

closure_function(4, 1, void, cloud_download_save,
                 bytes *, content_len, fsfile, f, bytes *, received, merge, m,
                 value, v)
{
    fsfile f = bound(f);
    status_handler sh = apply_merge(bound(m));
    status s;
    buffer content;
    if (*bound(received) == 0) {
        value start_line = get(v, sym(start_line));
        buffer status_code = get(start_line, integer_key(1));
        if (!status_code || (buffer_length(status_code) < 1) || (byte(status_code, 0) != '2')) {
            /* HTTP status code 2xx not found. */
            s = timm("result", "%s: unexpected server response %v", func_ss, start_line);
            goto error;
        }
        buffer b = get(v, sym(Content-Length));
        if (b) {
            if (!parse_int(b, 10, bound(content_len))) {
                s = timm("result", "%s: failed to parse content length '%b'", func_ss, b);
                goto error;
            }
        }
    }
    content = clone_buffer(cloud_heap, get(v, sym(content)));
    if (content != INVALID_ADDRESS) {
        io_status_handler io_sh = closure(cloud_heap, cloud_download_save_complete, f, content, sh);
        if (io_sh == INVALID_ADDRESS) {
            s = timm("result", "%s: failed to allocate I/O status handler", func_ss);
            deallocate_buffer(content);
            goto error;
        }
        bytes len = buffer_length(content);
        filesystem_write_linear(f, buffer_ref(content, 0), irangel(*bound(received), len), io_sh);
        *bound(received) += len;
        return;
    } else {
        s = timm("result", "%s: failed to copy content", func_ss);
    }
  error:
    *bound(content_len) = (bytes)-1;    /* special value that indicates error */
    fsfile_release(f);
    apply(sh, s);
}

define_closure_function(4, 2, boolean, cloud_download_file_recv,
                        buffer_handler, parser, bytes, content_len, bytes, received, status_handler, sh,
                        buffer_handler, out, buffer, data)
{
    cloud_download_file cfg = struct_from_field(closure_self(), cloud_download_file, recv);
    status_handler sh = bound(sh);
    status s = STATUS_OK;
    if (data) {
        if (bound(parser) == INVALID_ADDRESS) {
            /* This is the first chunk of data received after connection establishment. */
            fsfile f = fsfile_open_or_create(buffer_to_sstring(cfg->file_path), true);
            if (!f) {
                s = timm("result", "%s: failed to open file '%b'", func_ss, cfg->file_path);
                goto error;
            }

            /* Now that the file has been truncated, any download/save error will be fatal. */
            cfg->download.optional = false;

            merge m = allocate_merge(cloud_heap, sh);
            sh = bound(sh) = apply_merge(m);
            value_handler vh = closure(cloud_heap, cloud_download_save, &bound(content_len), f,
                                       &bound(received), m);
            if (vh == INVALID_ADDRESS) {
                s = timm("result", "%s: failed to allocate value handler", func_ss);
                fsfile_release(f);
                goto error;
            }
            bound(parser) = allocate_http_parser(cloud_heap, vh);
            if (bound(parser) == INVALID_ADDRESS) {
                s = timm("result", "%s: failed to allocate HTTP parser", func_ss);
                deallocate_closure(vh);
                fsfile_release(f);
                goto error;
            }
        }
    }
    if (bound(parser) != INVALID_ADDRESS) {
        s = apply(bound(parser), data);
        if (!is_ok(s)) {
            bound(parser) = INVALID_ADDRESS;    /* the parser deallocated itself */
            if (sh) {
                s = timm_up(s, "result", "%s: failed to parse HTTP response", func_ss);
                goto error;
            } else {
                timm_dealloc(s);
            }
        }
    }
    if (data) {
        bytes content_len = bound(content_len);
        if ((content_len == (bytes)-1) || ((content_len > 0) && (bound(received) >= content_len))) {
            apply(out, 0);  /* close connection */
            return true;
        }
    } else {  /* connection closed */
        if (sh && (s == STATUS_OK)) {
            bytes content_len = bound(content_len);
            if (content_len == (bytes)-1)
                ;   /* error status has been set by cloud_download_save() */
            else if (bound(received) == 0)
                s = timm("result", "empty file %b", cfg->file_path);
            else if (bound(received) < content_len)
                s = timm("result", "incomplete file %b (%ld/%ld)", cfg->file_path,
                         bound(received), content_len);
        }
        if (sh)
            apply(sh, s);
        closure_finish();
    }
    return false;
  error:
    apply(sh, s);
    bound(sh) = 0;  /* so that it's not applied again after the connection is closed */
    apply(out, 0);  /* close connection */
    return true;
}

define_closure_function(0, 0, void, cloud_download_file_cleanup)
{
    cloud_download_file cfg = struct_from_field(closure_self(), cloud_download_file, cleanup);
    deallocate(cloud_heap, cfg, sizeof(*cfg));
}

static boolean cloud_download_retry(connection_handler ch);

closure_function(2, 1, boolean, cloud_download_recv,
                 download_recv, recv, buffer_handler, out,
                 buffer, data)
{
    return apply(bound(recv), bound(out), data);
}

closure_function(2, 1, input_buffer_handler, cloud_download_ch,
                 cloud_download_cfg, cfg, download_recv, recv,
                 buffer_handler, out)
{
    cloud_download_cfg cfg = bound(cfg);
    status_handler sh = (status_handler)&cfg->complete;
    input_buffer_handler in = INVALID_ADDRESS;
    if (!out) {
        if (!cloud_download_retry((connection_handler)closure_self())) {
            apply(sh, timm("result", "%s: failed to schedule retry", func_ss));
            goto done;
        }
        return in;
    }
    tuple req = allocate_tuple();
    if (req == INVALID_ADDRESS) {
        apply(sh, timm("result", "%s: failed to allocate tuple", func_ss));
        goto done;
    }
    set(req, sym(url), &cfg->server_path);
    set(req, sym(Host), &cfg->server_host);
    set(req, sym(Authorization), cfg->auth_header);
    set(req, sym(Connection), alloca_wrap_cstring("close"));
    status s = http_request(cloud_heap, out, HTTP_REQUEST_METHOD_GET, req, 0);
    deallocate_value(req);
    if (is_ok(s)) {
        in = closure(cloud_heap, cloud_download_recv, bound(recv), out);
        if (in == INVALID_ADDRESS)
            apply(sh, timm("result", "%s: failed to allocate buffer handler", func_ss));
    } else {
        apply(sh, s);
    }
  done:
    closure_finish();
    return in;
}

static status cloud_download_connect(ip_addr_t *addr, connection_handler ch)
{
    cloud_download_cfg cfg = closure_member(cloud_download_ch, ch, cfg);
    if (cfg->tls) {
        if (tls_connect(addr, cfg->server_port, ch) == 0)
            return STATUS_OK;
        return timm("result",
            "cloud_init: failed to establish TLS connection with download server %b",
            &cfg->server_host);
    } else {
        return direct_connect(cloud_heap, addr, cfg->server_port, ch);
    }
}

static void cloud_download_dns_cb(sstring name, const ip_addr_t *ipaddr, void *callback_arg)
{
    connection_handler ch = (connection_handler)callback_arg;
    status s;
    if (ipaddr)
        s = cloud_download_connect((ip_addr_t *)ipaddr, ch);
    else
        s = timm("result", "cloud_init: failed to resolve server hostname '%s'", name);
    if (is_ok(s))
        return;
    cloud_download_cfg cfg = closure_member(cloud_download_ch, ch, cfg);
    status_handler sh = (status_handler)&cfg->complete;
    apply(sh, s);
    deallocate_closure(ch);
}

static void cloud_download(connection_handler ch)
{
    cloud_download_cfg cfg = closure_member(cloud_download_ch, ch, cfg);
    status_handler sh = (status_handler)&cfg->complete;
    status s;
    sstring host = buffer_to_sstring(&cfg->server_host);
    ip_addr_t addr;
    err_t err;

    /* Before attempting to connect to the server or resolve its host name, check that the
     * networking stack is correctly configured with a suitable IP address (by checking the network
     * interface from which outgoing packets will be routed), and retry later if this check fails.
     * This prevents klib initialization errors from occurring if this klib is loaded before an IP
     * address is acquired via DHCP.  */
    if (ipaddr_aton(host, &addr)) {
        struct netif *n = ip_route(&ip_addr_any, &addr);
        if (n) {
            netif_unref(n);
            err = ERR_OK;
        } else {
            err = ERR_RTE;
        }
    } else {
        const ip_addr_t *dns = dns_getserver(0);
        struct netif *n = ip_route(&ip_addr_any, dns);
        if (n) {
            netif_unref(n);
            err = dns_gethostbyname(host, &addr, cloud_download_dns_cb, ch);
        } else {
            err = ERR_RTE;
        }
    }

    switch (err) {
    case ERR_OK:
        s = cloud_download_connect(&addr, ch);
        if (!is_ok(s))
            goto error;
        break;
    case ERR_INPROGRESS:
        break;
    case ERR_RTE:
        if (!cloud_download_retry(ch)) {
            s = timm("result", "cloud_init: failed to schedule download retry");
            goto error;
        }
        break;
    default:
        s = timm("result", "cloud_init: failed to resolve server hostname '%s' (%d)", host, err);
        goto error;
    }
    return;
  error:
    apply(sh, s);
    deallocate_closure(ch);
}

closure_function(2, 2, void, cloud_download_retry_func,
                 struct timer, timer, connection_handler, ch,
                 u64, expiry, u64, overruns)
{
    if (overruns != timer_disabled)
        cloud_download(bound(ch));
    closure_finish();
}

static boolean cloud_download_retry(connection_handler ch)
{
    struct timer retry_timer = {0};
    init_timer(&retry_timer);
    timer_handler th = closure(cloud_heap, cloud_download_retry_func, retry_timer, ch);
    if (th == INVALID_ADDRESS)
        return false;
    register_timer(kernel_timers, &closure_member(cloud_download_retry_func, th, timer),
                   CLOCK_ID_MONOTONIC, seconds(1), false, 0, th);
    return true;
}

static void cloud_download_start(cloud_download_cfg cfg, download_recv recv, status_handler sh)
{
    init_closure(&cfg->complete, cloud_download_done, cfg, sh);
    connection_handler ch = closure(cloud_heap, cloud_download_ch, cfg, recv);
    if (ch == INVALID_ADDRESS) {
        apply(sh, timm("result", "%s: failed to allocate connection handler", func_ss));
        return;
    }
    cloud_download(ch);
}

define_closure_function(2, 2, void, cloud_download_task,
                        download_recv, recv, thunk, cleanup,
                        int, op, void *, arg)
{
    cloud_download_cfg cfg = struct_from_field(closure_self(), cloud_download_cfg, task);
    switch (op) {
    case CLOUD_INIT_TASK_OP_START:
        cloud_download_start(cfg, bound(recv), arg);
        break;
    case CLOUD_INIT_TASK_OP_DELETE:
        apply(bound(cleanup));
        break;
    }
}

static int cloud_download_file_parse(tuple config, vector tasks)
{
    cloud_download_file parsed_cfg = allocate(cloud_heap, sizeof(*parsed_cfg));
    assert(parsed_cfg != INVALID_ADDRESS);
    status_handler sh = (status_handler)&parsed_cfg->download.complete;
    download_recv recv = init_closure(&parsed_cfg->recv, cloud_download_file_recv,
                                      INVALID_ADDRESS, 0, 0, sh);
    thunk cleanup = init_closure(&parsed_cfg->cleanup, cloud_download_file_cleanup);
    vector_push(tasks, init_closure(&parsed_cfg->download.task, cloud_download_task,
                                    recv, cleanup));
    int ret = cloud_download_parse(config, &parsed_cfg->download);
    if (ret != KLIB_INIT_OK)
        return ret;
    parsed_cfg->file_path = get(config, sym(dest));
    if (!parsed_cfg->file_path) {
        rprintf("cloud_init: missing download destination in %v\n", config);
        return KLIB_INIT_FAILED;
    }
    if (!is_string(parsed_cfg->file_path)) {
        rprintf("cloud_init: invalid download destination %v\n", parsed_cfg->file_path);
        return KLIB_INIT_FAILED;
    }
    fsfile f = fsfile_open_or_create(buffer_to_sstring(parsed_cfg->file_path), false);
    if (!f) {
        rprintf("cloud_init: download destination file '%b' cannot be created\n",
            parsed_cfg->file_path);
        return KLIB_INIT_FAILED;
    }
    if (fsfile_get_length(f) > 0) {
        if (get(config, sym(overwrite)))
            parsed_cfg->download.optional = true;
        else
            parsed_cfg->download.done = true;
    }
    fsfile_release(f);
    return KLIB_INIT_OK;
}

closure_function(1, 2, boolean, cloud_download_env_each,
                 tuple, env,
                 value, k, value, v)
{
    if (is_string(v)) {
        buffer b = clone_buffer(cloud_heap, v);
        if (b == INVALID_ADDRESS)
            return false;
        set(bound(env), k, b);
    }
    return true;
}

closure_function(2, 1, void, cloud_download_env_set,
                 cloud_download_env, cfg, status *, result,
                 void *, v)
{
    tuple env = v;
    vector attr_path = bound(cfg)->attribute_path;
    if (attr_path) {
        string attr;
        vector_foreach(attr_path, attr) {
            if (buffer_length(attr) == 0)
                continue;
            env = get_tuple(env, intern(attr));
            if (!env) {
                *bound(result) = timm("result", "download_env: invalid JSON attribute '%b'", attr);
                goto out;
            }
        }
    }
    if (!iterate(env, stack_closure(cloud_download_env_each, get_environment())))
        *bound(result) = timm("result", "failed to set environment variables");
  out:
    destruct_value(v, true);
}

closure_function(1, 1, void, cloud_download_env_err,
                 status *, result,
                 string, data)
{
    if (*bound(result) == STATUS_OK)
        *bound(result) = timm("result", "failed to parse JSON: %b", data);
}

define_closure_function(1, 1, void, cloud_download_setenv,
                        status *, s,
                        value, v)
{
    cloud_download_env cfg = struct_from_field(closure_self(), cloud_download_env, setenv);
    value start_line = get(v, sym(start_line));
    buffer status_code = get(start_line, integer_key(1));
    if (!status_code || (buffer_length(status_code) < 1) || (byte(status_code, 0) != '2')) {
        /* HTTP status code 2xx not found */
        *bound(s) = timm("result", "cloud_init download_env: unexpected server response %v",
                         start_line);
        goto done;
    }
    status *s = bound(s);
    parser p = json_parser(cloud_heap, stack_closure(cloud_download_env_set, cfg, s),
                           stack_closure(cloud_download_env_err, s));
    p = parser_feed(p, get_string(v, sym(content)));
    p = apply(p, CHARACTER_INVALID);
    json_parser_free(p);
  done:
    cfg->download.done = true;
}

define_closure_function(2, 2, boolean, cloud_download_env_recv,
                        buffer_handler, parser, status, s,
                        buffer_handler, out, buffer, data)
{
    cloud_download_env cfg = struct_from_field(closure_self(), cloud_download_env, recv);
    if (data && (bound(parser) == INVALID_ADDRESS)) {
        value_handler vh = init_closure(&cfg->setenv, cloud_download_setenv, &bound(s));
        bound(parser) = allocate_http_parser(cloud_heap, vh);
        if (bound(parser) == INVALID_ADDRESS) {
            bound(s) = timm("result", "%s: failed to allocate HTTP parser", func_ss);
            goto close_conn;
        }
    }
    if (bound(parser) != INVALID_ADDRESS) {
        status s = apply(bound(parser), data);
        if (data && cfg->download.done)
            goto close_conn;
        if (!is_ok(s)) {
            bound(parser) = INVALID_ADDRESS;    /* the parser deallocated itself */
            bound(s) = timm_up(s, "result", "%s: failed to parse HTTP response", func_ss);
            if (data)
                goto close_conn;
        }
    }
    if (!data) {    /* connection closed */
        status_handler sh = (status_handler)&cfg->download.complete;
        apply(sh, bound(s));
    }
    return false;
  close_conn:
    apply(out, 0);   /* close connection */
    return true;
}

define_closure_function(0, 0, void, cloud_download_env_cleanup)
{
    cloud_download_env cfg = struct_from_field(closure_self(), cloud_download_env, cleanup);
    deallocate(cloud_heap, cfg, sizeof(*cfg));
}

static int cloud_download_env_parse(tuple config, vector tasks)
{
    cloud_download_env cfg = allocate(cloud_heap, sizeof(*cfg));
    assert(cfg != INVALID_ADDRESS);
    download_recv recv = init_closure(&cfg->recv, cloud_download_env_recv,
                                      INVALID_ADDRESS, STATUS_OK);
    thunk cleanup = init_closure(&cfg->cleanup, cloud_download_env_cleanup);
    vector_push(tasks, init_closure(&cfg->download.task, cloud_download_task, recv, cleanup));
    int ret = cloud_download_parse(config, &cfg->download);
    if (ret != KLIB_INIT_OK)
        return ret;
    value path = get(config, sym(path));
    if (path) {
        if (!is_string(path)) {
            rprintf("download_env: invalid path %v\n", path);
            return KLIB_INIT_FAILED;
        }
        cfg->attribute_path = split(cloud_heap, path, '/');
    } else {
        cfg->attribute_path = 0;
    }
    return KLIB_INIT_OK;
}

int init(status_handler complete)
{
    cloud_heap = heap_locked(get_kernel_heaps());
    if (first_boot()) {
        enum cloud c = cloud_detect();
        switch (c) {
        case CLOUD_ERROR:
            return KLIB_INIT_FAILED;
        case CLOUD_AZURE:
            if (!azure_cloud_init(cloud_heap))
                return KLIB_INIT_FAILED;
            break;
        default:
            break;
        }
    }
    tuple config = get(get_root_tuple(), sym(cloud_init));
    if (!config)
        return KLIB_INIT_OK;
    if (!is_tuple(config)) {
        rprintf("invalid cloud_init configuration\n");
        return KLIB_INIT_FAILED;
    }
    vector tasks = allocate_vector(cloud_heap, 8);
    assert(tasks != INVALID_ADDRESS);
    int ret;
    value download = get(config, sym(download));
    if (download) {
        ret = cloud_init_parse_vector(download, cloud_download_file_parse, tasks);
        if (ret != KLIB_INIT_OK) {
            rprintf("invalid cloud_init download configuration\n");
            goto error;
        }
    }
    value download_env = get(config, sym(download_env));
    if (download_env) {
        ret = cloud_init_parse_vector(download_env, cloud_download_env_parse, tasks);
        if (ret != KLIB_INIT_OK) {
            rprintf("invalid cloud_init download_env configuration\n");
            goto error;
        }
    }
    cloud_init_task task;
    if (vector_length(tasks) != 0) {
        merge m = allocate_merge(cloud_heap, complete);
        complete = apply_merge(m);
        vector_foreach(tasks, task) {
            apply(task, CLOUD_INIT_TASK_OP_START, apply_merge(m));
        }
        apply(complete, STATUS_OK);
        ret = KLIB_INIT_IN_PROGRESS;
    } else {
        ret = KLIB_INIT_OK;
    }
  out:
    deallocate_vector(tasks);
    return ret;
  error:
    vector_foreach(tasks, task) {
        apply(task, CLOUD_INIT_TASK_OP_DELETE, 0);
    }
    ret = KLIB_INIT_FAILED;
    goto out;
}
