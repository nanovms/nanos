#include <kernel.h>
#include <drivers/console.h>
#include <http.h>
#include <lwip.h>
#include <mktime.h>
#include <tls.h>

#define GCP_MD_SERVER_ADDR  IPADDR4_INIT_BYTES(169, 254, 169, 254)

#define GCP_LOG_SERVER_NAME "logging.googleapis.com"
#define GCP_LOG_MAX_ENTRIES 8192

declare_closure_struct(1, 1, void, gcp_setup_complete,
                       timestamp, retry_backoff,
                       status, s);
declare_closure_struct(0, 2, void, gcp_log_timer_handler,
                       u64, expiry, u64, overruns);
declare_closure_struct(0, 1, input_buffer_handler, gcp_log_conn_handler,
                       buffer_handler, out)
declare_closure_struct(0, 1, boolean, gcp_log_in_handler,
                       buffer, data);
declare_closure_struct(0, 1, void, gcp_log_vh,
                       value, v);

static struct gcp {
    heap h;
    struct console_driver log_driver;
    closure_struct(gcp_setup_complete, setup_complete);
    buffer auth_hdr;
    buffer project_id;
    boolean log_inited;
    buffer log_id;
    vector log_entries;
    struct timer log_timer;
    closure_struct(gcp_log_timer_handler, log_timer_handler);
    closure_struct(gcp_log_conn_handler, log_conn_handler);
    buffer_handler log_out;
    closure_struct(gcp_log_in_handler, log_in_handler);
    int log_pending;
    boolean log_resp_recved;
    closure_struct(gcp_log_vh, log_vh);
    buffer_handler log_resp_parser;
    struct spinlock lock;
} gcp;

typedef struct gcp_log_entry {
    timestamp t;
    bytes msg_len;
    char msg[0];
} *gcp_log_entry;

static boolean gcp_instance_md_available(void)
{
    ip_addr_t md_server = GCP_MD_SERVER_ADDR;
    struct netif *n = ip_route(&ip_addr_any, &md_server);
    if (n) {
        netif_unref(n);
        return true;
    }
    return false;
}

closure_function(1, 1, void, gcp_project_id_vh,
                 status_handler, sh,
                 value, v)
{
    gcp.project_id = clone_buffer(gcp.h, get(v, sym(content)));
    status s;
    if (gcp.project_id != INVALID_ADDRESS) {
        s = STATUS_OK;
    } else {
        gcp.project_id = 0;
        s = timm("result", "failed to allocate project ID buffer");
    }
    apply(bound(sh), s);
}

closure_function(1, 1, void, gcp_hostname_vh,
                 status_handler, sh,
                 value, v)
{
    gcp.log_id = clone_buffer(gcp.h, get(v, sym(content)));
    status s;
    if (gcp.log_id != INVALID_ADDRESS) {
        s = STATUS_OK;
    } else {
        gcp.log_id = 0;
        s = timm("result", "failed to allocate log ID buffer");
    }
    apply(bound(sh), s);
}

closure_function(1, 1, void, gcp_access_token_vh,
                 status_handler, sh,
                 value, v)
{
    tuple resp = get_tuple(v, sym(start_line));
    buffer status_code = get(resp, intern_u64(1));
    buffer content = get(v, sym(content));
    status s;
    if (!status_code || buffer_strcmp(status_code, "200")) {
        s = timm("result", "failed to get access token: %b", content);
        goto done;
    }
    int ptr = buffer_strstr(content, "access_token");
    if (ptr < 0)
        goto parse_error;
    buffer_consume(content, ptr);
    ptr = buffer_strchr(content, ':');
    if (ptr < 0)
        goto parse_error;
    buffer_consume(content, ptr);
    int value_start = buffer_strchr(content, '"');
    if (value_start < 0)
        goto parse_error;
    buffer_consume(content, value_start + 1);
    int value_end = buffer_strchr(content, '"');
    if (value_end < 0)
        goto parse_error;
    spin_lock(&gcp.lock);
    buffer_clear(gcp.auth_hdr);
    buffer_write_cstring(gcp.auth_hdr, "Bearer ");
    buffer_write(gcp.auth_hdr, buffer_ref(content, 0), value_end);
    spin_unlock(&gcp.lock);
    s = STATUS_OK;
    goto done;
  parse_error:
    s = timm("result", "failed to parse response (%b)\n", content);
  done:
    apply(bound(sh), s);
}

closure_function(4, 1, boolean, gcp_instance_md_in,
                 buffer_handler, out, buffer_handler, parser, value_handler, vh, status_handler, sh,
                 buffer, data)
{
    buffer_handler out = bound(out);
    status_handler sh = bound(sh);
    status s;
    if (data) {
        if (bound(parser) == INVALID_ADDRESS) {
            value_handler vh = bound(vh);
            bound(parser) = allocate_http_parser(gcp.h, vh);
            if (bound(parser) == INVALID_ADDRESS) {
                s = timm("result", "failed to allocate HTTP parser");
                deallocate_closure(vh);
                goto error;
            }
        }
        s = apply(bound(parser), data);
        if (is_ok(s)) {
            return false;
        } else {
            s = timm_up(s, "result", "failed to parse HTTP response");
            goto error;
        }
    } else {  /* connection closed */
        buffer_handler parser = bound(parser);
        if (parser != INVALID_ADDRESS)
            apply(parser, 0);   /* deallocates the parser */
        closure_finish();
        return true;
    }
  error:
    apply(out, 0);
    apply(sh, s);
    return true;
}

closure_function(3, 1, input_buffer_handler, gcp_instance_md_ch,
                 const char *, url, value_handler, vh, status_handler, sh,
                 buffer_handler, out)
{
    status_handler sh = bound(sh);
    status s;
    if (!out) {
        s = timm("result", "failed to connect to GCP instance metadata server");
        goto error;
    }
    tuple req = allocate_tuple();
    if (req == INVALID_ADDRESS) {
        s = timm("result", "failed to allocate request");
        goto error;
    }
    set(req, sym(url), alloca_wrap_cstring(bound(url)));
    set(req, sym(Connection), alloca_wrap_cstring("close"));
    set(req, sym(Metadata-Flavor), alloca_wrap_cstring("Google"));
    s = http_request(gcp.h, out, HTTP_REQUEST_METHOD_GET, req, 0);
    deallocate_value(req);
    if (!is_ok(s)) {
        s = timm_up(s, "result", "failed to send HTTP request");
        goto error;
    }
    value_handler vh = bound(vh);
    closure_finish();
    return closure(gcp.h, gcp_instance_md_in, out, INVALID_ADDRESS, vh, sh);
  error:
    closure_finish();
    apply(sh, s);
    return INVALID_ADDRESS;
}

static void gcp_instance_md_get(connection_handler ch, status_handler sh)
{
    ip_addr_t md_server = GCP_MD_SERVER_ADDR;
    status s = direct_connect(gcp.h, &md_server, 80, ch);
    if (!is_ok(s))
        apply(sh, timm_up(s, "result", "failed to connect to GCP instance metadata server"));
}

static void gcp_project_id_get(status_handler sh)
{
    value_handler vh = closure(gcp.h, gcp_project_id_vh, sh);
    if (vh == INVALID_ADDRESS) {
        apply(sh, timm("result", "failed to allocate project ID value handler"));
        return;
    }
    connection_handler ch = closure(gcp.h, gcp_instance_md_ch,
                                    "/computeMetadata/v1/project/project-id", vh, sh);
    if (ch == INVALID_ADDRESS) {
        deallocate_closure(vh);
        apply(sh, timm("result", "failed to allocate project ID connection handler"));
        return;
    }
    gcp_instance_md_get(ch, sh);
}

static void gcp_hostname_get(status_handler sh)
{
    value_handler vh = closure(gcp.h, gcp_hostname_vh, sh);
    if (vh == INVALID_ADDRESS) {
        apply(sh, timm("result", "failed to allocate hostname value handler"));
        return;
    }
    connection_handler ch = closure(gcp.h, gcp_instance_md_ch,
                                    "/computeMetadata/v1/instance/hostname", vh, sh);
    if (ch == INVALID_ADDRESS) {
        deallocate_closure(vh);
        apply(sh, timm("result", "failed to allocate hostname connection handler"));
        return;
    }
    gcp_instance_md_get(ch, sh);
}

static void gcp_access_token_get(status_handler sh)
{
    value_handler vh = closure(gcp.h, gcp_access_token_vh, sh);
    if (vh == INVALID_ADDRESS) {
        apply(sh, timm("result", "failed to allocate access token value handler"));
        return;
    }
    connection_handler ch = closure(gcp.h, gcp_instance_md_ch,
                                    "/computeMetadata/v1/instance/service-accounts/default/token",
                                    vh, sh);
    if (ch == INVALID_ADDRESS) {
        deallocate_closure(vh);
        apply(sh, timm("result", "failed to allocate access token connection handler"));
        return;
    }
    gcp_instance_md_get(ch, sh);
}

static void gcp_log_send_async(void)
{
    if ((gcp.log_pending == 0) && (vector_length(gcp.log_entries) > 0) &&
        !timer_is_active(&gcp.log_timer))
        register_timer(kernel_timers, &gcp.log_timer, CLOCK_ID_MONOTONIC, seconds(10), false, 0,
                       (timer_handler)&gcp.log_timer_handler);
}

static void gcp_setup(void)
{
    status_handler completion = (status_handler)&gcp.setup_complete;
    if (!gcp_instance_md_available()) {
        apply(completion, timm("result", "GCP instance metadata not available"));
        return;
    }
    merge m = allocate_merge(gcp.h, completion);
    status_handler sh = apply_merge(m);
    if (!gcp.project_id)
        gcp_project_id_get(apply_merge(m));
    if (gcp.log_entries && !gcp.log_id)
        gcp_hostname_get(apply_merge(m));
    gcp_access_token_get(apply_merge(m));
    apply(sh, STATUS_OK);
}

closure_function(1, 2, void, gcp_setup_retry,
                 struct timer, t,
                 u64, expiry, u64, overruns)
{
    if (overruns != timer_disabled)
        gcp_setup();
    closure_finish();
}

define_closure_function(1, 1, void, gcp_setup_complete,
                        timestamp, retry_backoff,
                        status, s)
{
    if (is_ok(s)) {
        bound(retry_backoff) = seconds(1);
        if (gcp.log_entries) {
            spin_lock(&gcp.lock);
            gcp.log_inited = true;
            gcp_log_send_async();
            spin_unlock(&gcp.lock);
        }
    } else {
        timestamp retry_backoff = bound(retry_backoff);

        /* Do not print error messages for transient issues in the metadata server which can be seen
         * right after instance startup (e.g. HTTP 500 response with "Failed to authenticate request
         * (Type 0)". */
        if (retry_backoff > seconds(1))
            msg_err("setup failed: %v\n", s);

        timm_dealloc(s);
        if (retry_backoff < seconds(3600))
            bound(retry_backoff) <<= 1;
        struct timer t = {0};
        init_timer(&t);
        timer_handler setup_retry = closure(gcp.h, gcp_setup_retry, t);
        if (setup_retry != INVALID_ADDRESS)
            register_timer(kernel_timers, &closure_member(gcp_setup_retry, setup_retry, t),
                           CLOCK_ID_MONOTONIC, retry_backoff, false, 0, setup_retry);
    }
}

static void gcp_dns_cb(const char *name, const ip_addr_t *addr, void *cb_arg)
{
    connection_handler ch = cb_arg;
    if (addr) {
        if (tls_connect((ip_addr_t *)addr, 443, ch) < 0) {
            msg_err("failed to connect to server %s\n", name);
            apply(ch, 0);
        }
    } else {
        msg_err("failed to resolve server name %s\n", name);
        apply(ch, 0);
    }
}

static void gcp_connect(const char *server, connection_handler ch)
{
    ip_addr_t addr;
    err_t err = dns_gethostbyname(server, &addr, gcp_dns_cb, ch);
    switch (err) {
    case ERR_OK:
        gcp_dns_cb(server, &addr, ch);
        break;
    case ERR_INPROGRESS:
        break;
    default:
        gcp_dns_cb(server, 0, ch);
    }
}

static void gcp_log_write(void *d, const char *s, bytes count)
{
    if (count == 0)
        return;
    spin_lock(&gcp.lock);
    if (vector_length(gcp.log_entries) < GCP_LOG_MAX_ENTRIES) {
        gcp_log_entry e = allocate(gcp.h, sizeof(*e) + count);
        if (e != INVALID_ADDRESS) {
            e->t = kern_now(CLOCK_ID_REALTIME);
            e->msg_len = count;
            runtime_memcpy(e->msg, s, count);
            vector_push(gcp.log_entries, e);
        }
    }
    gcp_log_send_async();
    spin_unlock(&gcp.lock);
}

static void gcp_log_pending_delete(void)
{
    spin_lock(&gcp.lock);
    int log_entries = gcp.log_pending;
    for (int i = 0; i < log_entries; i++)
        deallocate(gcp.h, vector_get(gcp.log_entries, i), sizeof(struct gcp_log_entry));
    vector_delete_range(gcp.log_entries, 0, log_entries);
    spin_unlock(&gcp.lock);
}

define_closure_function(0, 1, void, gcp_log_vh,
                        value, v)
{
    tuple resp = get_tuple(v, sym(start_line));
    buffer status_code = get(resp, intern_u64(1));
    if (status_code) {
        if (!buffer_strcmp(status_code, "200")) {
            gcp_log_pending_delete();
        } else if (!buffer_strcmp(status_code, "401")) {
            /* The access token must have expired: renew it. */
            gcp_setup();
        } else {
            msg_err("unexpected response %v\n", v);
            gcp_log_pending_delete();
        }
        gcp.log_resp_recved = true;
    }
}

define_closure_function(0, 1, boolean, gcp_log_in_handler,
                        buffer, data)
{
    if (data) {
        status s = apply(gcp.log_resp_parser, data);
        if (is_ok(s)) {
            if (gcp.log_resp_recved) {
                apply(gcp.log_out, 0);
                return true;
            }
        } else {
            msg_err("failed to parse response: %v\n", s);
            timm_dealloc(s);
            apply(gcp.log_out, 0);
            return true;
        }
    } else {    /* connection closed */
        spin_lock(&gcp.lock);
        gcp.log_pending = 0;
        gcp_log_send_async();
        spin_unlock(&gcp.lock);
    }
    return false;
}

static boolean gcp_log_post(void)
{
    boolean success = false;
    tuple req = allocate_tuple();
    if (req == INVALID_ADDRESS)
        goto error;
    set(req, sym(url), alloca_wrap_cstring("/v2/entries:write"));
    set(req, sym(Connection), alloca_wrap_cstring("close"));
    set(req, sym(Authorization), gcp.auth_hdr);
    set(req, sym(Host), alloca_wrap_cstring(GCP_LOG_SERVER_NAME));
    set(req, sym(Accept), alloca_wrap_cstring("application/json"));
    set(req, sym(Content-Type), alloca_wrap_cstring("application/json"));
    buffer body = allocate_buffer(gcp.h, 128);
    if (body == INVALID_ADDRESS)
        goto req_dealloc;
    bprintf(body, "{\"logName\":\"projects/%b/logs/%b\",\"resource\":{\"type\":\"gce_instance\"},"
                  "\"entries\":[", gcp.project_id, gcp.log_id);
    int log_events = vector_length(gcp.log_entries);
    for (int i = 0; i < log_events; i++) {
        gcp_log_entry e = vector_get(gcp.log_entries, i);
        if (i > 0)
            push_u8(body, ',');
        u64 seconds = sec_from_timestamp(e->t);
        struct tm tm;
        gmtime_r(&seconds, &tm);
        bprintf(body, "{\"timestamp\":\"%d-%02d-%02dT%02d:%02d:%02d.%09dZ\",\"textPayload\":\"",
                1900 + tm.tm_year, 1 + tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
                (truncate_seconds(e->t) * BILLION) / TIMESTAMP_SECOND);
        for (int j = 0; j < e->msg_len; j++) {
            /* Escape JSON special characters. */
            char c = e->msg[j];
            switch (c) {
            case '\n':
                if (!buffer_write_cstring(body, "\\n"))
                    goto req_done;
                break;
            case '"':
                if (!buffer_write_cstring(body, "\\\""))
                    goto req_done;
                break;
            case '/':
                if (!buffer_write_cstring(body, "\\/"))
                    goto req_done;
                break;
            case '\\':
                if (!buffer_write_cstring(body, "\\\\"))
                    goto req_done;
                break;
            case '\t':
                if (!buffer_write_cstring(body, "\\t"))
                    goto req_done;
                break;
            case '\r':
                if (!buffer_write_cstring(body, "\\r"))
                    goto req_done;
                break;
            case '\b':
                if (!buffer_write_cstring(body, "\\b"))
                    goto req_done;
                break;
            case '\f':
                if (!buffer_write_cstring(body, "\\f"))
                    goto req_done;
                break;
            default:
                push_u8(body, c);
            }
        }
        if (!buffer_write_cstring(body, "\"}"))
            goto req_done;
    }
    if (!buffer_write_cstring(body, "]}"))
        goto req_done;
    gcp.log_resp_recved = false;
    status s = http_request(gcp.h, gcp.log_out, HTTP_REQUEST_METHOD_POST, req, body);
    success = is_ok(s);
    if (!success) {
        msg_err("%v\n", s);
        timm_dealloc(s);
    }
  req_done:
    if (success)
        gcp.log_pending = log_events;
    else
        deallocate_buffer(body);
  req_dealloc:
    deallocate_value(req);
    if (!success)
  error:
        gcp_log_send_async();
    return success;
}

define_closure_function(0, 1, input_buffer_handler, gcp_log_conn_handler,
                        buffer_handler, out)
{
    input_buffer_handler ibh;
    spin_lock(&gcp.lock);
    if (out) {
        gcp.log_out = out;
        if (gcp_log_post())
            ibh = (input_buffer_handler)&gcp.log_in_handler;
        else
            ibh = 0;
    } else {
        gcp_log_send_async();
        ibh = 0;
    }
    spin_unlock(&gcp.lock);
    return ibh;
}

define_closure_function(0, 2, void, gcp_log_timer_handler,
                        u64, expiry, u64, overruns)
{
    if (overruns == timer_disabled)
        return;
    if (gcp.log_inited)
        gcp_connect(GCP_LOG_SERVER_NAME, (connection_handler)&gcp.log_conn_handler);
}

int init(status_handler complete)
{
    tuple root = get_root_tuple();
    if (!root)
        return KLIB_INIT_FAILED;
    tuple gcp_config = get_tuple(root, sym(gcp));
    if (!gcp_config)
        return KLIB_INIT_OK;
    gcp.h = heap_locked(get_kernel_heaps());
    gcp.auth_hdr = allocate_buffer(gcp.h, 2 * KB);
    assert(gcp.auth_hdr != INVALID_ADDRESS);
    boolean config_empty = true;
    tuple logging = get_tuple(gcp_config, sym(logging));
    if (logging) {
        gcp.log_id = get_string(logging, sym(log_id));
        gcp.log_entries = allocate_vector(gcp.h, GCP_LOG_MAX_ENTRIES);
        assert(gcp.log_entries != INVALID_ADDRESS);
        init_closure(&gcp.log_conn_handler, gcp_log_conn_handler);
        init_closure(&gcp.log_in_handler, gcp_log_in_handler);
        gcp.log_resp_parser = allocate_http_parser(gcp.h, init_closure(&gcp.log_vh, gcp_log_vh));
        assert(gcp.log_resp_parser != INVALID_ADDRESS);
        init_closure(&gcp.log_timer_handler, gcp_log_timer_handler);
        gcp.log_driver.write = gcp_log_write;
        gcp.log_driver.name = "gcp";
        attach_console_driver(&gcp.log_driver);
        config_empty = false;
    }
    if (!config_empty) {
        init_closure(&gcp.setup_complete, gcp_setup_complete, seconds(1));
        gcp_setup();
    }
    return KLIB_INIT_OK;
}
