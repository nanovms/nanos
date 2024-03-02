#include <kernel.h>
#include <drivers/console.h>
#include <http.h>
#include <lwip.h>
#include <mktime.h>
#include <pagecache.h>
#include <tls.h>
#include <storage.h>
#include <fs.h>

#define GCP_MD_SERVER_ADDR  IPADDR4_INIT_BYTES(169, 254, 169, 254)

#define GCP_LOG_SERVER_NAME "logging.googleapis.com"
#define GCP_LOG_MAX_ENTRIES 8192

#define GCP_METRICS_SERVER_NAME "monitoring.googleapis.com"

declare_closure_struct(1, 1, void, gcp_setup_complete,
                       timestamp, retry_backoff,
                       status s);
static struct gcp {
    heap h;
    struct console_driver log_driver;
    closure_struct(gcp_setup_complete, setup_complete);
    buffer auth_hdr;
    buffer project_id;
    buffer zone;
    buffer instance_id;
    boolean log_inited;
    buffer log_id;
    vector log_entries;
    struct timer log_timer;
    closure_struct(timer_handler, log_timer_handler);
    closure_struct(connection_handler, log_conn_handler);
    buffer_handler log_out;
    closure_struct(input_buffer_handler, log_in_handler);
    int log_pending;
    boolean log_resp_recved;
    closure_struct(value_handler, log_vh);
    buffer_handler log_resp_parser;
    timestamp metrics_interval;
    boolean metrics_disk;
    boolean metrics_disk_include_readonly;
    buffer metrics_url;
    boolean metrics_pending;
    struct timer metrics_timer;
    closure_struct(timer_handler, metrics_timer_handler);
    closure_struct(connection_handler, metrics_conn_handler);
    buffer_handler metrics_out;
    closure_struct(input_buffer_handler, metrics_in_handler);
    buffer_handler metrics_resp_parser;
    closure_struct(value_handler, metrics_value_handler);
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
                 value v)
{
    gcp.project_id = clone_buffer(gcp.h, get(v, sym(content)));
    status s;
    if (gcp.project_id != INVALID_ADDRESS) {
        if (gcp.metrics_interval) {
            /* Allocate a buffer large enough to contain the fixed strings concatenated with the
             * project ID. */
            gcp.metrics_url = allocate_buffer(gcp.h, 24 + buffer_length(gcp.project_id));
            if (gcp.metrics_url != INVALID_ADDRESS) {
                buffer_write_cstring(gcp.metrics_url, "/v3/projects/");
                push_buffer(gcp.metrics_url, gcp.project_id);
                buffer_write_cstring(gcp.metrics_url, "/timeSeries");
                s = STATUS_OK;
            } else {
                deallocate_buffer(gcp.project_id);
                gcp.project_id = 0;
                s = timm("result", "failed to allocate metrics URL buffer");
            }
        } else {
            s = STATUS_OK;
        }
    } else {
        gcp.project_id = 0;
        s = timm("result", "failed to allocate project ID buffer");
    }
    apply(bound(sh), s);
}

closure_function(1, 1, void, gcp_hostname_vh,
                 status_handler, sh,
                 value v)
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

closure_function(1, 1, void, gcp_zone_vh,
                 status_handler, sh,
                 value v)
{
    buffer content = get(v, sym(content));
    status s;

    /* content is in the following format: projects/PROJECT_NUM/zones/ZONE */
    int offset = buffer_strstr(content, ss("/zones/"));
    if (offset < 0) {
        s = timm("result", "unknown zone format '%b'", content);
        goto out;
    }
    offset += sizeof("/zones/") - 1;
    int length = buffer_length(content) - offset;
    if (length == 0) {
        s = timm("result", "empty zone");
        goto out;
    }

    gcp.zone = allocate_buffer(gcp.h, length);
    if (gcp.zone != INVALID_ADDRESS) {
        buffer_write(gcp.zone, buffer_ref(content, offset), length);
        s = STATUS_OK;
    } else {
        gcp.zone = 0;
        s = timm("result", "failed to allocate zone buffer");
    }
  out:
    apply(bound(sh), s);
}

closure_function(1, 1, void, gcp_instance_id_vh,
                 status_handler, sh,
                 value v)
{
    gcp.instance_id = clone_buffer(gcp.h, get(v, sym(content)));
    status s;
    if (gcp.instance_id != INVALID_ADDRESS) {
        s = STATUS_OK;
    } else {
        gcp.instance_id = 0;
        s = timm("result", "failed to allocate instance ID buffer");
    }
    apply(bound(sh), s);
}

closure_function(1, 1, void, gcp_access_token_vh,
                 status_handler, sh,
                 value v)
{
    value resp = get(v, sym(start_line));
    buffer status_code = get(resp, integer_key(1));
    buffer content = get(v, sym(content));
    status s;
    if (!status_code || buffer_strcmp(status_code, "200")) {
        s = timm("result", "failed to get access token: %b", content);
        goto done;
    }
    int ptr = buffer_strstr(content, ss("access_token"));
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
                 buffer data)
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
                 sstring, url, value_handler, vh, status_handler, sh,
                 buffer_handler out)
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
    set(req, sym(url), alloca_wrap_sstring(bound(url)));
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
                                    ss("/computeMetadata/v1/project/project-id"), vh, sh);
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
                                    ss("/computeMetadata/v1/instance/hostname"), vh, sh);
    if (ch == INVALID_ADDRESS) {
        deallocate_closure(vh);
        apply(sh, timm("result", "failed to allocate hostname connection handler"));
        return;
    }
    gcp_instance_md_get(ch, sh);
}

static void gcp_zone_get(status_handler sh)
{
    value_handler vh = closure(gcp.h, gcp_zone_vh, sh);
    if (vh == INVALID_ADDRESS) {
        apply(sh, timm("result", "failed to allocate zone value handler"));
        return;
    }
    connection_handler ch = closure(gcp.h, gcp_instance_md_ch,
                                    ss("/computeMetadata/v1/instance/zone"), vh, sh);
    if (ch == INVALID_ADDRESS) {
        deallocate_closure(vh);
        apply(sh, timm("result", "failed to allocate zone connection handler"));
        return;
    }
    gcp_instance_md_get(ch, sh);
}

static void gcp_instance_id_get(status_handler sh)
{
    value_handler vh = closure(gcp.h, gcp_instance_id_vh, sh);
    if (vh == INVALID_ADDRESS) {
        apply(sh, timm("result", "failed to allocate instance ID value handler"));
        return;
    }
    connection_handler ch = closure(gcp.h, gcp_instance_md_ch,
                                    ss("/computeMetadata/v1/instance/id"), vh, sh);
    if (ch == INVALID_ADDRESS) {
        deallocate_closure(vh);
        apply(sh, timm("result", "failed to allocate instance ID connection handler"));
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
                                    ss("/computeMetadata/v1/instance/service-accounts/default/token"),
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
    if (gcp.metrics_interval) {
        if (!gcp.zone)
            gcp_zone_get(apply_merge(m));
        if (!gcp.instance_id)
            gcp_instance_id_get(apply_merge(m));
    }
    gcp_access_token_get(apply_merge(m));
    apply(sh, STATUS_OK);
}

closure_function(1, 2, void, gcp_setup_retry,
                 struct timer, t,
                 u64 expiry, u64 overruns)
{
    if (overruns != timer_disabled)
        gcp_setup();
    closure_finish();
}

define_closure_function(1, 1, void, gcp_setup_complete,
                        timestamp, retry_backoff,
                        status s)
{
    if (is_ok(s)) {
        bound(retry_backoff) = seconds(1);
        if (gcp.log_entries) {
            spin_lock(&gcp.lock);
            gcp.log_inited = true;
            gcp_log_send_async();
            spin_unlock(&gcp.lock);
        }
        if (gcp.metrics_interval && !timer_is_active(&gcp.metrics_timer))
            register_timer(kernel_timers, &gcp.metrics_timer, CLOCK_ID_MONOTONIC, 0, false,
                           gcp.metrics_interval, (timer_handler)&gcp.metrics_timer_handler);
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

static void gcp_dns_cb(sstring name, const ip_addr_t *addr, void *cb_arg)
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

static void gcp_connect(sstring server, connection_handler ch)
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

closure_func_basic(value_handler, void, gcp_log_vh,
                   value v)
{
    value resp = get(v, sym(start_line));
    buffer status_code = get(resp, integer_key(1));
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

closure_func_basic(input_buffer_handler, boolean, gcp_log_in_handler,
                   buffer data)
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

closure_func_basic(connection_handler, input_buffer_handler, gcp_log_conn_handler,
                   buffer_handler out)
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

closure_func_basic(timer_handler, void, gcp_log_timer_handler,
                   u64 expiry, u64 overruns)
{
    if (overruns == timer_disabled)
        return;
    if (gcp.log_inited)
        gcp_connect(ss(GCP_LOG_SERVER_NAME), (connection_handler)&gcp.log_conn_handler);
}

closure_func_basic(timer_handler, void, gcp_metrics_timer_handler,
                   u64 expiry, u64 overruns)
{
    if ((overruns == timer_disabled) || gcp.metrics_pending)
        return;
    gcp.metrics_pending = true;
    gcp_connect(ss(GCP_METRICS_SERVER_NAME), (connection_handler)&gcp.metrics_conn_handler);
}

static void gcp_metrics_add_memory(buffer body, boolean first, sstring type, sstring state,
                                   u64 value, sstring interval)
{
    bprintf(body, "%s{\"resource\":{\"type\":\"gce_instance\""
                  ",\"labels\":{\"zone\":\"%b\",\"instance_id\":\"%b\"}}"
                  ",\"metric\":{\"type\":\"agent.googleapis.com/memory/%s\""
                  ",\"labels\":{\"state\":\"%s\"}}"
                  ",\"points\":[{\"value\":{\"doubleValue\":%ld},\"interval\":%s}]}",
                  first ? sstring_empty() : ss(","), gcp.zone, gcp.instance_id, type, state, value,
                  interval);
}

static void gcp_metrics_add_disk(buffer body, boolean first, sstring type, sstring state,
                                   u64 value, sstring interval, buffer device)
{
    bprintf(body, "%s{\"resource\":{\"type\":\"gce_instance\""
                  ",\"labels\":{\"zone\":\"%b\",\"instance_id\":\"%b\"}}"
                  ",\"metric\":{\"type\":\"agent.googleapis.com/disk/%s\""
                  ",\"labels\":{\"device\":\"%b\",\"state\":\"%s\"}}"
                  ",\"points\":[{\"value\":{\"doubleValue\":%ld},\"interval\":%s}]}",
                  first ? sstring_empty() : ss(","), gcp.zone, gcp.instance_id, type, device, state,
                  value, interval);
}

closure_function(3, 4, void, gcp_metrics_disk_vh,
                 buffer, b, sstring, interval, boolean, include_readonly,
                 u8 *uuid, sstring label, filesystem fs, inode mount_point)
{
    if (filesystem_is_readonly(fs) && !bound(include_readonly))
        return;
    int block_size = fs_blocksize(fs);
    u64 total_blocks = fs_totalblocks(fs);
    u64 free_blocks = fs_freeblocks(fs);
    u64 percent_used_free = free_blocks * 100 / total_blocks;
    buffer b = bound(b);
    sstring interval = bound(interval);
    buffer device;
    if (!sstring_is_empty(label)) {
        device = alloca_wrap_sstring(label);
    } else {
        device = little_stack_buffer(2 * UUID_LEN + 4);
        print_uuid(device, uuid);
    }
    gcp_metrics_add_disk(b, false, ss("bytes_used"), ss("free"), free_blocks * block_size, interval,
                         device);
    gcp_metrics_add_disk(b, false, ss("bytes_used"), ss("used"),
                         (total_blocks - free_blocks) * block_size, interval, device);
    gcp_metrics_add_disk(b, false, ss("percent_used"), ss("free"), percent_used_free, interval,
                         device);
    gcp_metrics_add_disk(b, false, ss("percent_used"), ss("used"), 100 - percent_used_free,
                         interval, device);
}

closure_function(2, 4, void, gcp_disk_count_vh,
                 u64 *, count, boolean, include_readonly,
                 u8 *uuid, sstring label, filesystem fs, inode mount_point)
{
    if (filesystem_is_readonly(fs) && !bound(include_readonly))
        return;
    (*bound(count))++;
}

static boolean gcp_metrics_post(void)
{
    tuple req = allocate_tuple();
    if (req == INVALID_ADDRESS)
        return false;
    set(req, sym(url), gcp.metrics_url);
    set(req, sym(Connection), alloca_wrap_cstring("close"));
    set(req, sym(Authorization), gcp.auth_hdr);
    set(req, sym(Host), alloca_wrap_cstring(GCP_METRICS_SERVER_NAME));
    buffer app_json = alloca_wrap_cstring("application/json");
    set(req, sym(Accept), app_json);
    set(req, sym(Content-Type), app_json);
    boolean success = false;
    u64 metrics_heap_size_kb = 2; // memory metrics
    u64 metrics_disk_count = 0;
    if (gcp.metrics_disk) {
        storage_iterate(stack_closure(gcp_disk_count_vh, &metrics_disk_count, gcp.metrics_disk_include_readonly));
        metrics_heap_size_kb += metrics_disk_count * 2; // add disk x 2KiB
    }
    buffer body = allocate_buffer(gcp.h, metrics_heap_size_kb * KB);
    if (body == INVALID_ADDRESS)
        goto req_dealloc;
    heap phys = (heap)heap_physical(get_kernel_heaps());
    u64 total = heap_total(phys);
    u64 free = total - heap_allocated(phys);
    u64 cached = pagecache_get_occupancy();
    u64 used = total - free - cached;
    u64 seconds = sec_from_timestamp(kern_now(CLOCK_ID_REALTIME));
    struct tm tm;
    gmtime_r(&seconds, &tm);
    char interval[40];
    sstring interval_ss = isstring(interval,
                                   rsnprintf(interval, sizeof(interval),
                                            "{\"endTime\":\"%d-%02d-%02dT%02d:%02d:%02dZ\"}",
                                            1900 + tm.tm_year, 1 + tm.tm_mon, tm.tm_mday,
                                            tm.tm_hour, tm.tm_min, tm.tm_sec));
    buffer_write_cstring(body, "{\"timeSeries\":[");
    gcp_metrics_add_memory(body, true, ss("bytes_used"), ss("cached"), cached, interval_ss);
    gcp_metrics_add_memory(body, false, ss("bytes_used"), ss("free"), free, interval_ss);
    gcp_metrics_add_memory(body, false, ss("bytes_used"), ss("used"), used, interval_ss);
    gcp_metrics_add_memory(body, false, ss("percent_used"), ss("cached"), cached * 100 / total,
                           interval_ss);
    gcp_metrics_add_memory(body, false, ss("percent_used"), ss("free"), free * 100 / total,
                           interval_ss);
    gcp_metrics_add_memory(body, false, ss("percent_used"), ss("used"), used * 100 / total,
                           interval_ss);
    if (gcp.metrics_disk && metrics_disk_count)
        storage_iterate(stack_closure(gcp_metrics_disk_vh, body, interval_ss,
                                      gcp.metrics_disk_include_readonly));
    if (!buffer_write_cstring(body, "]}"))
        goto req_done;
    status s = http_request(gcp.h, gcp.metrics_out, HTTP_REQUEST_METHOD_POST, req, body);
    success = is_ok(s);
    if (!success) {
        msg_err("%v\n", s);
        timm_dealloc(s);
    }
  req_done:
    if (!success)
        deallocate_buffer(body);
  req_dealloc:
    deallocate_value(req);
    return success;
}

closure_func_basic(connection_handler, input_buffer_handler, gcp_metrics_conn_handler,
                   buffer_handler out)
{
    input_buffer_handler ibh;
    if (out) {
        gcp.metrics_out = out;
        if (gcp_metrics_post())
            ibh = (input_buffer_handler)&gcp.metrics_in_handler;
        else
            ibh = 0;
    } else {
        ibh = 0;
    }
    if (!ibh)
        gcp.metrics_pending = false;
    return ibh;
}

closure_func_basic(input_buffer_handler, boolean, gcp_metrics_in_handler,
                   buffer data)
{
    if (data) {
        status s = apply(gcp.metrics_resp_parser, data);
        if (is_ok(s)) {
            if (!gcp.metrics_out)
                return true;
        } else {
            msg_err("failed to parse response: %v\n", s);
            timm_dealloc(s);
            apply(gcp.metrics_out, 0);
            return true;
        }
    } else {    /* connection closed */
        gcp.metrics_pending = false;
    }
    return false;
}

closure_func_basic(value_handler, void, gcp_metrics_value_handler,
                   value v)
{
    value resp = get(v, sym(start_line));
    buffer status_code = get(resp, integer_key(1));
    if (status_code) {
        if (!buffer_strcmp(status_code, "401")) {
            /* The access token must have expired: renew it. */
            gcp_setup();
        } else if (buffer_strcmp(status_code, "200")) {
            msg_err("unexpected response %v\n", v);
        }
    }
    apply(gcp.metrics_out, 0);
    gcp.metrics_out = 0;    /* signal to input buffer handler that connection is closed */
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
        init_closure_func(&gcp.log_conn_handler, connection_handler, gcp_log_conn_handler);
        init_closure_func(&gcp.log_in_handler, input_buffer_handler, gcp_log_in_handler);
        gcp.log_resp_parser = allocate_http_parser(gcp.h,
                                                   init_closure_func(&gcp.log_vh, value_handler,
                                                                     gcp_log_vh));
        assert(gcp.log_resp_parser != INVALID_ADDRESS);
        init_closure_func(&gcp.log_timer_handler, timer_handler, gcp_log_timer_handler);
        gcp.log_driver.write = gcp_log_write;
        gcp.log_driver.name = ss("gcp");
        attach_console_driver(&gcp.log_driver);
        config_empty = false;
    }
    tuple metrics = get_tuple(gcp_config, sym(metrics));
    if (metrics) {
        const u64 min_interval = 60;
        u64 interval;
        if (get_u64(metrics, sym(interval), &interval)) {
            if (interval < min_interval) {
                rprintf("GCP: invalid metrics interval (minimum allowed value %ld seconds)\n",
                        min_interval);
                return KLIB_INIT_FAILED;
            }
        } else {
            interval = min_interval;
        }
        gcp.metrics_interval = seconds(interval);
        tuple metrics_disk = get_tuple(metrics, sym(disk));
        if (metrics_disk) {
            gcp.metrics_disk = true;
            if (get(metrics_disk, sym(include_readonly)))
                gcp.metrics_disk_include_readonly = true;
        }
        init_timer(&gcp.metrics_timer);
        init_closure_func(&gcp.metrics_timer_handler, timer_handler, gcp_metrics_timer_handler);
        init_closure_func(&gcp.metrics_conn_handler, connection_handler, gcp_metrics_conn_handler);
        init_closure_func(&gcp.metrics_in_handler, input_buffer_handler, gcp_metrics_in_handler);
        gcp.metrics_resp_parser = allocate_http_parser(gcp.h,
                                                       init_closure_func(&gcp.metrics_value_handler,
                                                           value_handler,
                                                           gcp_metrics_value_handler));
        assert(gcp.metrics_resp_parser != INVALID_ADDRESS);
        config_empty = false;
    }
    if (!config_empty) {
        init_closure(&gcp.setup_complete, gcp_setup_complete, seconds(1));
        gcp_setup();
    }
    return KLIB_INIT_OK;
}
