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

declare_closure_struct(2, 1, void, cloud_download_done,
                       struct cloud_download_cfg *, cfg, status_handler, complete,
                       status, s);

typedef struct cloud_download_cfg {
    struct buffer server_host;
    u16 server_port;
    struct buffer server_path;
    boolean tls;
    buffer file_path;
    boolean optional;   /* if true, a download error is not fatal */
    boolean done;
    closure_struct(cloud_download_done, complete);
} *cloud_download_cfg;

static heap cloud_heap;

static enum cloud cloud_detect(void)
{
    const char *chassis_asset_tag = dmi_get_string(DMI_CHASSIS_ASSET_TAG);
    if (!chassis_asset_tag)
        return CLOUD_UNKNOWN;
    if (!runtime_strcmp(chassis_asset_tag, AZURE_CHASSIS))
        return CLOUD_AZURE;
    return CLOUD_UNKNOWN;
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
    parsed_cfg->file_path = get(config, sym(dest));
    if (!parsed_cfg->file_path) {
        rprintf("cloud_init: missing download destination in %v\n", config);
        return KLIB_INIT_FAILED;
    }
    if (!is_string(parsed_cfg->file_path)) {
        rprintf("cloud_init: invalid download destination %v\n", parsed_cfg->file_path);
        return KLIB_INIT_FAILED;
    }
    parsed_cfg->optional = parsed_cfg->done = false;
    fsfile f = fsfile_open_or_create(parsed_cfg->file_path);
    if (!f) {
        rprintf("cloud_init: download destination file '%b' cannot be created\n",
            parsed_cfg->file_path);
        return KLIB_INIT_FAILED;
    }
    if (fsfile_get_length(f) > 0) {
        if (get(config, sym(overwrite)))
            parsed_cfg->optional = true;
        else
            parsed_cfg->done = true;
    }
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
    deallocate(cloud_heap, cfg, sizeof(struct cloud_download_cfg));
    apply(bound(complete), s);
}

closure_function(3, 2, void, cloud_download_save_complete,
                 value, v, buffer, content, status_handler, sh,
                 status, s, bytes, len)
{
    value v = bound(v);
    if (v)
        destruct_tuple(v, true);
    else
        deallocate_buffer(bound(content));
    apply(bound(sh), s);
    closure_finish();
}

closure_function(5, 1, void, cloud_download_save,
                 buffer, content, bytes *, content_len, fsfile, f, bytes *, received, status_handler, sh,
                 value, v)
{
    status_handler sh = bound(sh);
    status s;
    buffer content;
    if (v) {
        /* This is the beginning of the HTTP response from the server, parsed by the HTTP parser. */
        tuple start_line = get_tuple(v, sym(start_line));
        buffer status_code = get(start_line, sym(1));
        if (!status_code || (buffer_length(status_code) < 1) || (byte(status_code, 0) != '2')) {
            /* HTTP status code 2xx not found. */
            s = timm("result", "%s: unexpected server response %v", __func__, start_line);
            goto error;
        }
        buffer b = get(v, sym(Content-Length));
        if (b) {
            if (!parse_int(b, 10, bound(content_len))) {
                s = timm("result", "%s: failed to parse content length '%b'", __func__, b);
                goto error;
            }
        }
        content = get(v, sym(content));
    } else {
        /* This is a chunk of the body of the HTTP response from the server. */
        bytes len = buffer_length(bound(content));
        content = allocate_buffer(cloud_heap, len);
        if (content != INVALID_ADDRESS) {
            runtime_memcpy(buffer_ref(content, 0), buffer_ref(bound(content), 0), len);
            buffer_produce(content, len);
        } else {
            content = 0;
        }
    }
    if (content) {
        io_status_handler io_sh = closure(cloud_heap, cloud_download_save_complete, v, content, sh);
        if (io_sh == INVALID_ADDRESS) {
            s = timm("result", "%s: failed to allocate I/O status handler", __func__);
            if (!v)
                deallocate_buffer(content);
            goto error;
        }
        bytes len = buffer_length(content);
        filesystem_write_linear(bound(f), buffer_ref(content, 0),
            irangel(*bound(received), len), io_sh);
        *bound(received) += len;
        return;
    } else {
        s = timm("result", "%s: no HTTP content", __func__);
    }
  error:
    *bound(content_len) = (bytes)-1;    /* special value that indicates error */
    if (v)
        destruct_tuple(v, true);
    apply(sh, s);
}

closure_function(7, 1, status, cloud_download_recv,
                 cloud_download_cfg, cfg, buffer_handler, out, value_handler, vh, bytes, content_len, bytes, received, status_handler, sh, merge, m,
                 buffer, data)
{
    cloud_download_cfg cfg = bound(cfg);
    status_handler sh = bound(sh);
    if (data) {
        if (!bound(m)) {
            /* This is the first chunk of data received after connection establishment. */
            fsfile f = fsfile_open_or_create(cfg->file_path);
            if (!f) {
                rprintf("%s: failed to open file '%b'\n", __func__, cfg->file_path);
                goto error;
            }
            fs_status fss = fsfile_truncate(f, 0);
            if (fss != FS_STATUS_OK) {
                rprintf("%s: failed to truncate file '%b' (%d)\n",
                    __func__, cfg->file_path, fss);
                goto error;
            }

            /* Now that the file has been truncated, any download/save error will be fatal. */
            cfg->optional = false;

            bound(m) = allocate_merge(cloud_heap, sh);
            sh = bound(sh) = apply_merge(bound(m));
            bound(vh) = closure(cloud_heap, cloud_download_save, 0, &bound(content_len), f,
                &bound(received), apply_merge(bound(m)));
            if (bound(vh) == INVALID_ADDRESS) {
                rprintf("%s: failed to allocate value handler\n", __func__);
                goto error;
            }
            buffer_handler parser = allocate_http_parser(cloud_heap, bound(vh));
            if (parser != INVALID_ADDRESS) {
                status s = apply(parser, data);
                if (!is_ok(s)) {
                    rprintf("%s: failed to parse HTTP response %v\n", __func__, s);
                    timm_dealloc(s);
                    goto error;
                }
            } else {
                rprintf("%s: failed to allocate HTTP parser\n", __func__);
                goto error;
            }
        } else {
            closure_member(cloud_download_save, bound(vh), content) = data;
            apply_merge(bound(m));
            apply(bound(vh), 0);
        }
        bytes content_len = bound(content_len);
        if ((content_len == (bytes)-1) || ((content_len > 0) && (bound(received) >= content_len)))
            apply(bound(out), 0);   /* close connection */
    } else {  /* connection closed */
        bytes content_len = bound(content_len);
        status s;
        if (content_len == (bytes)-1)
            s = STATUS_OK;  /* error status has been set by cloud_download_save() */
        else if (bound(received) == 0)
            s = timm("result", "empty file %b", cfg->file_path);
        else if (bound(received) < content_len)
            s = timm("result", "incomplete file %b (%ld/%ld)", cfg->file_path,
                bound(received), content_len);
        else
            s = STATUS_OK;
        apply(sh, s);
        if (bound(vh) != INVALID_ADDRESS)
            deallocate_closure(bound(vh));
        closure_finish();
    }
    return STATUS_OK;
  error:
    apply(bound(out), 0);   /* close connection */
    return STATUS_OK;
}

static boolean cloud_download_retry(connection_handler ch);

closure_function(1, 1, buffer_handler, cloud_download_ch,
                 cloud_download_cfg, cfg,
                 buffer_handler, out)
{
    cloud_download_cfg cfg = bound(cfg);
    status_handler sh = (status_handler)&cfg->complete;
    buffer_handler in = 0;
    if (!out) {
        if (!cloud_download_retry((connection_handler)closure_self())) {
            apply(sh, timm("result", "%s: failed to schedule retry", __func__));
            goto done;
        }
        return in;
    }
    tuple req = allocate_tuple();
    if (req == INVALID_ADDRESS) {
        apply(sh, timm("result", "%s: failed to allocate tuple", __func__));
        goto done;
    }
    set(req, sym(url), &cfg->server_path);
    set(req, sym(Host), &cfg->server_host);
    set(req, sym(Connection), alloca_wrap_cstring("close"));
    status s = http_request(cloud_heap, out, HTTP_REQUEST_METHOD_GET, req, 0);
    deallocate_value(req);
    if (is_ok(s)) {
        in = closure(cloud_heap, cloud_download_recv, cfg, out, INVALID_ADDRESS, 0, 0, sh, 0);
        if (in == INVALID_ADDRESS)
            apply(sh, timm("result", "%s: failed to allocate buffer handler", __func__));
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

static void cloud_download_dns_cb(const char *name, const ip_addr_t *ipaddr, void *callback_arg)
{
    if (ipaddr)
        return;
    connection_handler ch = (connection_handler)callback_arg;
    status s = timm("result", "cloud_init: failed to resolve server hostname '%s'", name);
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
    bytes host_len = buffer_length(&cfg->server_host);
    char host[host_len + 1];
    runtime_memcpy(host, buffer_ref(&cfg->server_host, 0), host_len);
    host[host_len] = '\0';                                \
    ip_addr_t addr;
    lwip_lock();
    err_t err = dns_gethostbyname(host, &addr, cloud_download_dns_cb, ch);
    lwip_unlock();
    switch (err) {
    case ERR_OK:
        s = cloud_download_connect(&addr, ch);
        if (!is_ok(s))
            goto error;
        break;
    case ERR_INPROGRESS:
    case ERR_VAL:
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

static void cloud_download_start(cloud_download_cfg cfg, status_handler sh)
{
    cloud_download_cfg cfg_copy = allocate(cloud_heap, sizeof(*cfg_copy));
    if (cfg_copy == INVALID_ADDRESS) {
        apply(sh, timm("result", "%s: failed to allocate configuration", __func__));
        return;
    }
    runtime_memcpy(cfg_copy, cfg, sizeof(*cfg_copy));
    init_closure(&cfg_copy->complete, cloud_download_done, cfg_copy, sh);
    connection_handler ch = closure(cloud_heap, cloud_download_ch, cfg_copy);
    if (ch == INVALID_ADDRESS) {
        deallocate(cloud_heap, cfg_copy, sizeof(*cfg_copy));
        apply(sh, timm("result", "%s: failed to allocate connection handler", __func__));
        return;
    }
    cloud_download(ch);
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
    tuple download = get(config, sym(download));
    if (download) {
        if (!is_tuple(download)) {
            rprintf("invalid cloud_init download configuration\n");
            return KLIB_INIT_FAILED;
        }
        int num_entries;
        for (num_entries = 0; get(download, intern_u64(num_entries)); num_entries++)
            ;
        struct cloud_download_cfg cfg[num_entries];
        for (int i = 0; i < num_entries; i++) {
            value d = get(download, intern_u64(i));
            if (!is_tuple(d)) {
                rprintf("invalid cloud_init download configuration\n");
                return KLIB_INIT_FAILED;
            }
            int ret = cloud_download_parse(d, &cfg[i]);
            if (ret != KLIB_INIT_OK)
                return ret;
        }
        merge m = allocate_merge(cloud_heap, complete);
        complete = apply_merge(m);
        for (int i = 0; i < num_entries; i++)
            if (!cfg[i].done)
                cloud_download_start(&cfg[i], apply_merge(m));
        apply(complete, STATUS_OK);
        return KLIB_INIT_IN_PROGRESS;
    }
    return KLIB_INIT_OK;
}
