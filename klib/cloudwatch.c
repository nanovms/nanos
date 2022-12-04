#include <kernel.h>
#include <aws.h>
#include <http.h>
#include <lwip.h>
#include <mktime.h>
#include <pagecache.h>

#define CLOUDWATCH_SERVICE_NAME "monitoring"

declare_closure_struct(1, 1, void, cw_aws_cred_handler,
                       status_handler, complete,
                       aws_cred, cred);
declare_closure_struct(1, 1, void, cw_aws_setup_complete,
                       timestamp, retry_backoff,
                       status, s);
declare_closure_struct(0, 2, void, cw_metrics_timer_handler,
                       u64, expiry, u64, overruns);
declare_closure_struct(0, 1, input_buffer_handler, cw_metrics_conn_handler,
                       buffer_handler, out);
declare_closure_struct(1, 1, boolean, cw_metrics_in_handler,
                       buffer_handler, out,
                       buffer, data);

static struct cw {
    heap h;
    char region[16], hostname[64], servername[64];
    char access_key[32], secret[64], token[2 * KB];
    closure_struct(cw_aws_cred_handler, aws_cred_handler);
    closure_struct(cw_aws_setup_complete, aws_setup_complete);
    timestamp metrics_interval;
    struct timer metrics_timer;
    closure_struct(cw_metrics_timer_handler, metrics_timer_handler);
    closure_struct(cw_metrics_conn_handler, metrics_conn_handler);
    closure_struct(cw_metrics_in_handler, metrics_in_handler);
} cw;

static boolean cw_aws_setup(void);

closure_function(4, 1, status, cw_aws_metadata_handler,
                 const char *, name, char *, dest, bytes, dest_len, status_handler, complete,
                 buffer, data)
{
    const char *name = bound(name);
    char *dest = bound(dest);
    bytes dest_len = bound(dest_len);
    status_handler complete = bound(complete);
    if (data) {
        bytes len = buffer_length(data);
        if (len < dest_len) {
            buffer_read(data, dest, len);
            dest[len] = '\0';
            apply(complete, STATUS_OK);
        } else {
            apply(complete,
                  timm("result", "invalid AWS %s length %ld (max %ld)", name, len, dest_len));
        }
    } else {
        apply(complete, timm("result", "failed to get AWS %s", name));
    }
    closure_finish();
    return STATUS_OK;
}

define_closure_function(1, 1, void, cw_aws_cred_handler,
                        status_handler, complete,
                        aws_cred, cred)
{
    status s;
    if (!cred) {
        s = timm("result", "failed to get AWS credentials");
        goto done;
    }
    bytes len = buffer_length(cred->access_key);
    if (len < sizeof(cw.access_key)) {
        buffer_read(cred->access_key, cw.access_key, len);
        cw.access_key[len] = '\0';
    } else {
        s = timm("result", "invalid AWS access key length %ld", len);
        goto done;
    }
    len = buffer_length(cred->secret);
    if (len < sizeof(cw.secret)) {
        buffer_read(cred->secret, cw.secret, len);
        cw.secret[len] = '\0';
    } else {
        s = timm("result", "invalid AWS secret length %ld", len);
        goto done;
    }
    len = buffer_length(cred->token);
    if (len < sizeof(cw.token)) {
        buffer_read(cred->token, cw.token, len);
        cw.token[len] = '\0';
        s = STATUS_OK;
    } else {
        s = timm("result", "invalid AWS token length %ld", len);
    }
  done:
    apply(bound(complete), s);
}

closure_function(1, 2, void, cw_aws_setup_retry,
                 struct timer, t,
                 u64, expiry, u64, overruns)
{
    if (cw_aws_setup())
        closure_finish();
    else
        register_timer(kernel_timers, &bound(t), CLOCK_ID_MONOTONIC, seconds(5), false, 0,
                       (timer_handler)closure_self());
}

define_closure_function(1, 1, void, cw_aws_setup_complete,
                        timestamp, retry_backoff,
                        status, s)
{
    if (is_ok(s)) {
        rsnprintf(cw.servername, sizeof(cw.servername), CLOUDWATCH_SERVICE_NAME ".%s.amazonaws.com",
                  cw.region);
        bound(retry_backoff) = seconds(1);
        register_timer(kernel_timers, &cw.metrics_timer, CLOCK_ID_MONOTONIC, 0, false,
                       cw.metrics_interval, (timer_handler)&cw.metrics_timer_handler);
    } else {
        msg_err("setup failed: %v\n", s);
        timm_dealloc(s);
        timestamp retry_backoff = bound(retry_backoff);
        if (retry_backoff < seconds(3600))
            bound(retry_backoff) <<= 1;
        struct timer t = {0};
        init_timer(&t);
        timer_handler setup_retry = closure(cw.h, cw_aws_setup_retry, t);
        if (setup_retry != INVALID_ADDRESS)
            register_timer(kernel_timers, &closure_member(cw_aws_setup_retry, setup_retry, t),
                           CLOCK_ID_MONOTONIC, retry_backoff, false, 0, setup_retry);
    }
}

static boolean cw_aws_setup(void)
{
    status_handler completion = (status_handler)&cw.aws_setup_complete;
    if (!aws_metadata_available()) {
        apply(completion, timm("result", "AWS metadata not available"));
        return true;
    }
    merge m = allocate_merge(cw.h, completion);
    status_handler complete = apply_merge(m);
    buffer_handler handler = closure(cw.h, cw_aws_metadata_handler, "region", cw.region,
                                     sizeof(cw.region), apply_merge(m));
    if (handler == INVALID_ADDRESS)
        return false;
    aws_region_get(cw.h, handler);
    handler = closure(cw.h, cw_aws_metadata_handler, "hostname", cw.hostname,
                      sizeof(cw.hostname), apply_merge(m));
    if (handler == INVALID_ADDRESS)
        return false;
    aws_hostname_get(cw.h, handler);
    aws_cred_get(cw.h, init_closure(&cw.aws_cred_handler, cw_aws_cred_handler, apply_merge(m)));
    apply(complete, STATUS_OK);
    return true;
}

static void cw_metric_add_dimensions(buffer dest)
{
    bprintf(dest, ",\"Dimensions\":[{\"Name\":\"host\",\"Value\":\"%s\"}]", cw.hostname);
}

static void cw_metrics_add_bytes(buffer dest, boolean first, const char *metric, u64 val)
{
    if (!first)
        push_u8(dest, ',');
    bprintf(dest, "{\"MetricName\":\"%s\",\"Unit\":\"Bytes\",\"Value\":%ld", metric, val);
    cw_metric_add_dimensions(dest);
    push_u8(dest, '}');
}

static void cw_metrics_add_percent(buffer dest, boolean first, const char *metric, int val)
{
    if (!first)
        push_u8(dest, ',');
    bprintf(dest, "{\"MetricName\":\"%s\",\"Unit\":\"Percent\",\"Value\":%d", metric, val);
    cw_metric_add_dimensions(dest);
    push_u8(dest, '}');
}

define_closure_function(1, 1, boolean, cw_metrics_in_handler,
                        buffer_handler, out,
                        buffer, data)
{
    if (data) {
        if (buffer_strstr(data, "200 OK") < 0) {
            if (buffer_strstr(data, AWS_ERR_TOKEN_EXPIRED) >= 0) {
                remove_timer(kernel_timers, &cw.metrics_timer, 0);
                aws_cred_get(cw.h, init_closure(&cw.aws_cred_handler, cw_aws_cred_handler,
                                                (status_handler)&cw.aws_setup_complete));
            } else {
                msg_err("server response: '%b'\n", data);
            }
        }
        apply(bound(out), 0);
    }
    return true;
}

define_closure_function(0, 1, input_buffer_handler, cw_metrics_conn_handler,
                        buffer_handler, out)
{
    if (!out)
        return INVALID_ADDRESS;
    tuple req = allocate_tuple();
    if (req == INVALID_ADDRESS)
        return INVALID_ADDRESS;
    set(req, sym(url), alloca_wrap_cstring("/"));
    set(req, sym(host), alloca_wrap_cstring(cw.hostname));
    set(req, sym(x-amz-target), alloca_wrap_cstring("GraniteServiceVersion20100801.PutMetricData"));
    u64 seconds = sec_from_timestamp(kern_now(CLOCK_ID_REALTIME));
    struct tm tm;
    gmtime_r(&seconds, &tm);
    buffer timestamp = little_stack_buffer(16);
    bprintf(timestamp, "%d%02d%02dT%02d%02d%02dZ", 1900 + tm.tm_year, 1 + tm.tm_mon, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec);
    set(req, sym(x-amz-date), timestamp);
    set(req, sym(content-type), alloca_wrap_cstring("application/json"));
    set(req, sym(content-encoding), alloca_wrap_cstring("amz-1.0"));
    boolean success = false;
    heap phys = (heap)heap_physical(get_kernel_heaps());
    u64 total = heap_total(phys);
    u64 free = total - heap_allocated(phys);
    u64 cached = pagecache_get_occupancy();
    u64 available = free + cached;
    u64 used = total - available;
    buffer body = buffer_cstring(cw.h, "{\"Namespace\":\"CWAgent\",\"MetricData\":[");
    cw_metrics_add_bytes(body, true, "mem_available", available);
    cw_metrics_add_percent(body, false, "mem_available_percent", available * 100 / total);
    cw_metrics_add_bytes(body, false, "mem_cached", cached);
    cw_metrics_add_bytes(body, false, "mem_free", free);
    cw_metrics_add_bytes(body, false, "mem_total", total);
    cw_metrics_add_bytes(body, false, "mem_used", used);
    cw_metrics_add_percent(body, false, "mem_used_percent", used * 100 / total);
    if (!buffer_write_cstring(body, "]}"))
        goto req_done;
    buffer auth = aws_req_sign(cw.h, cw.region, CLOUDWATCH_SERVICE_NAME, "POST", req, body,
                               cw.access_key, cw.secret);
    if (auth) {
        set(req, sym(Authorization), auth);
        set(req, sym(x-amz-security-token), alloca_wrap_cstring(cw.token));
        status s = http_request(cw.h, out, HTTP_REQUEST_METHOD_POST, req, body);
        if (is_ok(s))
            success = true;
        else
            timm_dealloc(s);
        deallocate_buffer(auth);
    }
  req_done:
    if (!success)
        deallocate_buffer(body);
    deallocate_value(req);
    if (success)
        return init_closure(&cw.metrics_in_handler, cw_metrics_in_handler, out);
    else
        return INVALID_ADDRESS;
}

static void cw_metrics_send(const ip_addr_t *server)
{
    status s = direct_connect(cw.h, (ip_addr_t *)server, 80,
                              (connection_handler)&cw.metrics_conn_handler);
    if (!is_ok(s))
        timm_dealloc(s);
}

closure_function(1, 0, void, cw_metrics_send_async,
                 ip_addr_t, addr)
{
    cw_metrics_send(&bound(addr));
    closure_finish();
}

static void cw_dns_cb(const char *name, const ip_addr_t *ipaddr, void *callback_arg)
{
    if (ipaddr) {
        thunk t = closure(cw.h, cw_metrics_send_async, *ipaddr);
        if (t != INVALID_ADDRESS)
            async_apply(t);
    }
}

define_closure_function(0, 2, void, cw_metrics_timer_handler,
                        u64, expiry, u64, overruns)
{
    if (overruns == timer_disabled)
        return;
    ip_addr_t cw_host;
    lwip_lock();
    err_t err = dns_gethostbyname(cw.servername, &cw_host, cw_dns_cb, 0);
    lwip_unlock();
    if (err == ERR_OK)
        cw_metrics_send(&cw_host);
}

int init(status_handler complete)
{
    tuple root = get_root_tuple();
    if (!root)
        return KLIB_INIT_FAILED;
    tuple cw_config = get_tuple(root, sym(cloudwatch));
    if (!cw_config)
        return KLIB_INIT_OK;
    cw.h = heap_locked(get_kernel_heaps());
    value metrics_interval = get(cw_config, sym(mem_metrics_interval));
    if (metrics_interval) {
        u64 interval;
        if (!u64_from_value(metrics_interval, &interval)) {
            rprintf("CloudWatch: invalid memory metrics interval\n");
            return KLIB_INIT_FAILED;
        }
        cw.metrics_interval = seconds(interval);
    } else {
        cw.metrics_interval = 0;
    }
    if (cw.metrics_interval) {
        init_timer(&cw.metrics_timer);
        init_closure(&cw.metrics_timer_handler, cw_metrics_timer_handler);
        init_closure(&cw.metrics_conn_handler, cw_metrics_conn_handler);
        init_closure(&cw.aws_setup_complete, cw_aws_setup_complete, seconds(1));
        if (!cw_aws_setup())
            return KLIB_INIT_FAILED;
    }
    return KLIB_INIT_OK;
}
