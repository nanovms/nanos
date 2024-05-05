#include <kernel.h>
#include <aws.h>
#include <drivers/console.h>
#include <http.h>
#include <lwip.h>
#include <mktime.h>
#include <pagecache.h>
#include <tls.h>

#define CLOUDWATCH_SERVICE_NAME "monitoring"

#define CLOUDWATCH_LOG_SERVICE_NAME "logs"

#define CW_LOG_NEXT_SEQ_TOK "\"nextSequenceToken\""
#define CW_LOG_EXP_SEQ_TOK  "\"expectedSequenceToken\""

#define CW_LOG_MAX_ENTRIES  8192

declare_closure_struct(1, 1, void, cw_aws_cred_handler,
                       status_handler, complete,
                       aws_cred cred);
declare_closure_struct(1, 1, void, cw_aws_setup_complete,
                       timestamp, retry_backoff,
                       status s);
declare_closure_struct(1, 1, boolean, cw_metrics_in_handler,
                       buffer_handler, out,
                       buffer data);

static struct cw {
    heap h;
    char region[16], hostname[64], servername[64];
    bytes region_len, hostname_len, servername_len;
    char access_key[32], secret[64], token[2 * KB];
    bytes access_key_len, secret_len, token_len;
    closure_struct(cw_aws_cred_handler, aws_cred_handler);
    closure_struct(cw_aws_setup_complete, aws_setup_complete);
    timestamp metrics_interval;
    struct timer metrics_timer;
    closure_struct(timer_handler, metrics_timer_handler);
    closure_struct(connection_handler, metrics_conn_handler);
    closure_struct(cw_metrics_in_handler, metrics_in_handler);
    struct console_driver log_driver;
    char log_servername[64];
    bytes log_servername_len;
    buffer log_group, log_stream, log_seq_token;
    vector log_entries;
    int log_pending;
    closure_struct(connection_handler, log_conn_handler);
    buffer_handler log_out;
    closure_struct(input_buffer_handler, log_in_handler);
    closure_struct(value_handler, log_vh);
    buffer_handler log_resp_parser;
    struct timer log_timer;
    closure_struct(timer_handler, log_timer_handler);
    boolean log_inited, log_resp_recved;
    struct spinlock lock;
} cw;

typedef struct cw_log_entry {
    timestamp t;
    bytes msg_len;
    char msg[0];
} *cw_log_entry;

static boolean cw_aws_setup(void);

closure_function(4, 1, status, cw_aws_metadata_handler,
                 sstring, name, char *, dest, bytes *, dest_len, status_handler, complete,
                 buffer data)
{
    sstring name = bound(name);
    char *dest = bound(dest);
    bytes *dest_len = bound(dest_len);
    status_handler complete = bound(complete);
    if (data) {
        bytes len = buffer_length(data);
        if (len <= *dest_len) {
            buffer_read(data, dest, len);
            *dest_len = len;
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
                        aws_cred cred)
{
    status s;
    if (!cred) {
        s = timm("result", "failed to get AWS credentials");
        goto done;
    }
    bytes len = buffer_length(cred->access_key);
    if (len <= sizeof(cw.access_key)) {
        buffer_read(cred->access_key, cw.access_key, len);
        cw.access_key_len = len;
    } else {
        s = timm("result", "invalid AWS access key length %ld", len);
        goto done;
    }
    len = buffer_length(cred->secret);
    if (len <= sizeof(cw.secret)) {
        buffer_read(cred->secret, cw.secret, len);
        cw.secret_len = len;
    } else {
        s = timm("result", "invalid AWS secret length %ld", len);
        goto done;
    }
    len = buffer_length(cred->token);
    if (len <= sizeof(cw.token)) {
        buffer_read(cred->token, cw.token, len);
        cw.token_len = len;
        s = STATUS_OK;
    } else {
        s = timm("result", "invalid AWS token length %ld", len);
    }
  done:
    apply(bound(complete), s);
}

static boolean cw_aws_req_send(sstring service, sstring target, tuple req, buffer body,
                               buffer_handler out)
{
    set(req, sym(x-amz-target), alloca_wrap_sstring(target));
    buffer auth = aws_req_sign(cw.h, isstring(cw.region, cw.region_len), service, ss("POST"),
                               req, body, isstring(cw.access_key, cw.access_key_len),
                               isstring(cw.secret, cw.secret_len));
    if (!auth)
        return false;
    set(req, sym(Authorization), auth);
    set(req, sym(x-amz-security-token), alloca_wrap_buffer(cw.token, cw.token_len));
    status s = http_request(cw.h, out, HTTP_REQUEST_METHOD_POST, req, body);
    boolean success = is_ok(s);
    if (!success)
        timm_dealloc(s);
    deallocate_buffer(auth);
    return success;
}

closure_function(2, 0, void, cw_send_async,
                 void *, sender, ip_addr_t, addr)
{
    void (*sender)(const ip_addr_t *server) = bound(sender);
    sender(ip_addr_isany(&bound(addr)) ? 0 : &bound(addr));
    closure_finish();
}

static void cw_dns_cb(sstring name, const ip_addr_t *ipaddr, void *callback_arg)
{
    void (*sender)(const ip_addr_t *server) = callback_arg;
    thunk t = closure(cw.h, cw_send_async, sender, ipaddr ? *ipaddr : ip_addr_any);
    if (t != INVALID_ADDRESS)
        async_apply(t);
    else
        msg_err("failed to allocate closure\n");
}

static void cw_connect(sstring server, void (*handler)(const ip_addr_t *server))
{
    ip_addr_t cw_host;
    err_t err = dns_gethostbyname(server, &cw_host, cw_dns_cb, handler);
    switch (err) {
    case ERR_OK:
        cw_dns_cb(server, &cw_host, handler);
        break;
    case ERR_INPROGRESS:
        break;
    default:
        cw_dns_cb(server, 0, handler);
    }
}

static void cw_log_send_async(void)
{
    if ((cw.log_pending == 0) && (vector_length(cw.log_entries) > 0) &&
        !timer_is_active(&cw.log_timer))
        register_timer(kernel_timers, &cw.log_timer, CLOCK_ID_MONOTONIC, seconds(10), false, 0,
                       (timer_handler)&cw.log_timer_handler);
}

closure_function(1, 1, void, cw_logstream_vh,
                 boolean, parsed,
                 value v)
{
    bound(parsed) = true;
    value resp = get(v, sym(start_line));
    if (resp) {
        buffer word;
        for (u64 i = 0; (word = get(resp, integer_key(i))); i++)
            if (buffer_strstr(word, ss("OK")) == 0)
                goto success;
    }
    buffer content = get_string(v, sym(content));
    if (content && (buffer_strstr(content, ss("ResourceAlreadyExistsException")) >= 0))
        goto success;
    msg_err("unexpected response %v\n", v);
    return;
  success:
    spin_lock(&cw.lock);
    cw.log_inited = true;
    cw_log_send_async();
    spin_unlock(&cw.lock);
}

closure_function(3, 1, boolean, cw_log_meta_ibh,
                 buffer_handler, parser, boolean *, parsed, buffer_handler, out,
                 buffer data)
{
    status s = apply(bound(parser), data);
    if (!is_ok(s)) {
        msg_err("failed to parse response: %v\n", s);
        timm_dealloc(s);
        if (data) {
            apply(bound(out), 0);
            return true;
        }
    }
    if (!data) {
        closure_finish();
    } else if (*bound(parsed)) {
        apply(bound(out), 0);
        return true;
    }
    return false;
}

closure_function(2, 1, input_buffer_handler, cw_logstream_ch,
                 buffer_handler, parser, boolean *, parsed,
                 buffer_handler out)
{
    buffer_handler parser = bound(parser);
    boolean success = false;
    if (!out) {
        msg_err("connection failed\n");
        goto exit;
    }
    tuple req = allocate_tuple();
    if (req == INVALID_ADDRESS) {
        msg_err("failed to allocate request\n");
        goto exit;
    }
    set(req, sym(url), alloca_wrap_cstring("/"));
    set(req, sym(host), alloca_wrap_buffer(cw.log_servername, cw.log_servername_len));
    aws_req_set_date(req, little_stack_buffer(16));
    set(req, sym(accept), alloca_wrap_cstring("application/json"));
    set(req, sym(content-type), alloca_wrap_cstring("application/x-amz-json-1.1"));
    buffer body = allocate_buffer(cw.h, 64);
    if (body == INVALID_ADDRESS)
        goto req_dealloc;
    bprintf(body, "{\"logGroupName\":\"%b\",\"logStreamName\":\"%b\"}",
            cw.log_group, cw.log_stream);
    input_buffer_handler ibh = closure(cw.h, cw_log_meta_ibh, parser, bound(parsed), out);
    if (ibh == INVALID_ADDRESS) {
        msg_err("failed to allocate input buffer handler\n");
        goto req_done;
    }
    success = cw_aws_req_send(ss(CLOUDWATCH_LOG_SERVICE_NAME), ss("Logs_20140328.CreateLogStream"),
                              req, body, out);
    if (!success)
        deallocate_closure(ibh);
  req_done:
    if (!success)
        deallocate_buffer(body);
  req_dealloc:
    deallocate_value(req);
  exit:
    closure_finish();
    if (success) {
        return ibh;
    } else {
        apply(parser, 0);
        return INVALID_ADDRESS;
    }
}

static void cw_logstream_create(const ip_addr_t *server)
{
    if (!server) {
        msg_err("failed to get server address\n");
        return;
    }
    value_handler vh = closure(cw.h, cw_logstream_vh, false);
    if (vh == INVALID_ADDRESS) {
        msg_err("failed to allocate value handler\n");
        return;
    }
    buffer_handler parser = allocate_http_parser(cw.h, vh);
    if (parser == INVALID_ADDRESS) {
        msg_err("failed to allocate HTTP parser\n");
        deallocate_closure(vh);
        return;
    }
    connection_handler ch = closure(cw.h, cw_logstream_ch, parser,
                                    &closure_member(cw_logstream_vh, vh, parsed));
    if (ch == INVALID_ADDRESS) {
        msg_err("failed to allocate connection handler\n");
        goto dealloc_parser;
    }
    if (tls_connect((ip_addr_t *)server, 443, ch) == 0)
        return;
    msg_err("failed to connect to server\n");
    deallocate_closure(ch);
  dealloc_parser:
    apply(parser, 0);
}

closure_function(1, 1, void, cw_loggroup_vh,
                 boolean, parsed,
                 value v)
{
    bound(parsed) = true;
    value resp = get(v, sym(start_line));
    if (resp) {
        buffer word;
        for (u64 i = 0; (word = get(resp, integer_key(i))); i++)
            if (buffer_strstr(word, ss("OK")) == 0)
                goto success;
    }
    buffer content = get_string(v, sym(content));
    if (content && (buffer_strstr(content, ss("ResourceAlreadyExistsException")) >= 0))
        goto success;
    msg_err("unexpected response %v\n", v);
    return;
  success:
    cw_connect(isstring(cw.log_servername, cw.log_servername_len), cw_logstream_create);
}

closure_function(2, 1, input_buffer_handler, cw_loggroup_ch,
                 buffer_handler, parser, boolean *, parsed,
                 buffer_handler out)
{
    buffer_handler parser = bound(parser);
    boolean success = false;
    if (!out) {
        msg_err("connection failed\n");
        goto exit;
    }
    tuple req = allocate_tuple();
    if (req == INVALID_ADDRESS) {
        msg_err("failed to allocate request\n");
        goto exit;
    }
    set(req, sym(url), alloca_wrap_cstring("/"));
    set(req, sym(host), alloca_wrap_buffer(cw.log_servername, cw.log_servername_len));
    aws_req_set_date(req, little_stack_buffer(16));
    set(req, sym(accept), alloca_wrap_cstring("application/json"));
    set(req, sym(content-type), alloca_wrap_cstring("application/x-amz-json-1.1"));
    buffer body = allocate_buffer(cw.h, 32);
    if (body == INVALID_ADDRESS)
        goto req_dealloc;
    bprintf(body, "{\"logGroupName\":\"%b\"}", cw.log_group);
    input_buffer_handler ibh = closure(cw.h, cw_log_meta_ibh, parser, bound(parsed), out);
    if (ibh == INVALID_ADDRESS) {
        msg_err("failed to allocate input buffer handler\n");
        goto req_done;
    }
    success = cw_aws_req_send(ss(CLOUDWATCH_LOG_SERVICE_NAME), ss("Logs_20140328.CreateLogGroup"),
                              req, body, out);
    if (!success)
        deallocate_closure(ibh);
  req_done:
    if (!success)
        deallocate_buffer(body);
  req_dealloc:
    deallocate_value(req);
  exit:
    closure_finish();
    if (success) {
        return ibh;
    } else {
        apply(parser, 0);
        return INVALID_ADDRESS;
    }
}

static void cw_loggroup_create(const ip_addr_t *server)
{
    if (!server) {
        msg_err("failed to get server address\n");
        return;
    }
    value_handler vh = closure(cw.h, cw_loggroup_vh, false);
    if (vh == INVALID_ADDRESS) {
        msg_err("failed to allocate value handler\n");
        return;
    }
    buffer_handler parser = allocate_http_parser(cw.h, vh);
    if (parser == INVALID_ADDRESS) {
        msg_err("failed to allocate HTTP parser\n");
        deallocate_closure(vh);
        return;
    }
    connection_handler ch = closure(cw.h, cw_loggroup_ch, parser,
                                    &closure_member(cw_loggroup_vh, vh, parsed));
    if (ch == INVALID_ADDRESS) {
        msg_err("failed to allocate connection handler\n");
        goto dealloc_parser;
    }
    if (tls_connect((ip_addr_t *)server, 443, ch) == 0)
        return;
    msg_err("failed to connect to server\n");
    deallocate_closure(ch);
  dealloc_parser:
    apply(parser, 0);
}

static void cw_log_setup(void)
{
    spin_lock(&cw.lock);
    if (!cw.log_stream) {
        cw.log_stream = wrap_string(cw.hostname, cw.hostname_len);
        assert(cw.log_stream != INVALID_ADDRESS);
    }
    if (!cw.log_inited) {
        cw.log_servername_len = MIN(rsnprintf(cw.log_servername, sizeof(cw.log_servername),
                                              CLOUDWATCH_LOG_SERVICE_NAME ".%s.amazonaws.com",
                                              isstring(cw.region, cw.region_len)),
                                    sizeof(cw.log_servername));
        cw_connect(isstring(cw.log_servername, cw.log_servername_len), cw_loggroup_create);
    }
    spin_unlock(&cw.lock);
}

closure_function(1, 2, void, cw_aws_setup_retry,
                 struct timer, t,
                 u64 expiry, u64 overruns)
{
    if (cw_aws_setup())
        closure_finish();
    else
        register_timer(kernel_timers, &bound(t), CLOCK_ID_MONOTONIC, seconds(5), false, 0,
                       (timer_handler)closure_self());
}

define_closure_function(1, 1, void, cw_aws_setup_complete,
                        timestamp, retry_backoff,
                        status s)
{
    if (is_ok(s)) {
        cw.servername_len = MIN(rsnprintf(cw.servername, sizeof(cw.servername),
                                          CLOUDWATCH_SERVICE_NAME ".%s.amazonaws.com",
                                          isstring(cw.region, cw.region_len)),
                                sizeof(cw.servername));
        bound(retry_backoff) = seconds(1);
        if (cw.metrics_interval)
            register_timer(kernel_timers, &cw.metrics_timer, CLOCK_ID_MONOTONIC, 0, false,
                           cw.metrics_interval, (timer_handler)&cw.metrics_timer_handler);
        if (cw.log_entries)
            cw_log_setup();
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
    cw.region_len = sizeof(cw.region);
    buffer_handler handler = closure(cw.h, cw_aws_metadata_handler, ss("region"), cw.region,
                                     &cw.region_len, apply_merge(m));
    if (handler == INVALID_ADDRESS)
        return false;
    aws_region_get(cw.h, handler);
    cw.hostname_len = sizeof(cw.hostname);
    handler = closure(cw.h, cw_aws_metadata_handler, ss("hostname"), cw.hostname, &cw.hostname_len,
                      apply_merge(m));
    if (handler == INVALID_ADDRESS)
        return false;
    aws_hostname_get(cw.h, handler);
    aws_cred_get(cw.h, init_closure(&cw.aws_cred_handler, cw_aws_cred_handler, apply_merge(m)));
    apply(complete, STATUS_OK);
    return true;
}

static void cw_metric_add_dimensions(buffer dest)
{
    bprintf(dest, ",\"Dimensions\":[{\"Name\":\"host\",\"Value\":\"%s\"}]",
            isstring(cw.hostname, cw.hostname_len));
}

static void cw_metrics_add_bytes(buffer dest, boolean first, sstring metric, u64 val)
{
    if (!first)
        push_u8(dest, ',');
    bprintf(dest, "{\"MetricName\":\"%s\",\"Unit\":\"Bytes\",\"Value\":%ld", metric, val);
    cw_metric_add_dimensions(dest);
    push_u8(dest, '}');
}

static void cw_metrics_add_percent(buffer dest, boolean first, sstring metric, int val)
{
    if (!first)
        push_u8(dest, ',');
    bprintf(dest, "{\"MetricName\":\"%s\",\"Unit\":\"Percent\",\"Value\":%d", metric, val);
    cw_metric_add_dimensions(dest);
    push_u8(dest, '}');
}

define_closure_function(1, 1, boolean, cw_metrics_in_handler,
                        buffer_handler, out,
                        buffer data)
{
    if (data) {
        if (buffer_strstr(data, ss("200 OK")) < 0) {
            if (buffer_strstr(data, ss(AWS_ERR_TOKEN_EXPIRED)) >= 0) {
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

closure_func_basic(connection_handler, input_buffer_handler, cw_metrics_conn_handler,
                   buffer_handler out)
{
    if (!out)
        return INVALID_ADDRESS;
    tuple req = allocate_tuple();
    if (req == INVALID_ADDRESS)
        return INVALID_ADDRESS;
    set(req, sym(url), alloca_wrap_cstring("/"));
    set(req, sym(host), alloca_wrap_buffer(cw.hostname, cw.hostname_len));
    aws_req_set_date(req, little_stack_buffer(16));
    set(req, sym(content-type), alloca_wrap_cstring("application/json"));
    set(req, sym(content-encoding), alloca_wrap_cstring("amz-1.0"));
    boolean success = false;
    heap phys = (heap)heap_physical(get_kernel_heaps());
    u64 total = heap_total(phys);
    u64 free = total - heap_allocated(phys);
    u64 cached = pagecache_get_occupancy();
    u64 available = free + cached;
    u64 used = total - available;
    string body = wrap_string_cstring("{\"Namespace\":\"CWAgent\",\"MetricData\":[");
    cw_metrics_add_bytes(body, true, ss("mem_available"), available);
    cw_metrics_add_percent(body, false, ss("mem_available_percent"), available * 100 / total);
    cw_metrics_add_bytes(body, false, ss("mem_cached"), cached);
    cw_metrics_add_bytes(body, false, ss("mem_free"), free);
    cw_metrics_add_bytes(body, false, ss("mem_total"), total);
    cw_metrics_add_bytes(body, false, ss("mem_used"), used);
    cw_metrics_add_percent(body, false, ss("mem_used_percent"), used * 100 / total);
    if (!buffer_write_cstring(body, "]}"))
        goto req_done;
    success = cw_aws_req_send(ss(CLOUDWATCH_SERVICE_NAME),
                              ss("GraniteServiceVersion20100801.PutMetricData"), req, body, out);
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
    if (server) {
        status s = direct_connect(cw.h, (ip_addr_t *)server, 80,
                                  (connection_handler)&cw.metrics_conn_handler);
        if (!is_ok(s))
            timm_dealloc(s);
    }
}

closure_func_basic(timer_handler, void, cw_metrics_timer_handler,
                   u64 expiry, u64 overruns)
{
    if (overruns == timer_disabled)
        return;
    cw_connect(isstring(cw.servername, cw.servername_len), cw_metrics_send);
}

static void cw_log_write(void *d, const char *s, bytes count)
{
    if (count == 0)
        return;
    spin_lock(&cw.lock);
    if (vector_length(cw.log_entries) < CW_LOG_MAX_ENTRIES) {
        cw_log_entry e = allocate(cw.h, sizeof(*e) + count);
        if (e != INVALID_ADDRESS) {
            e->t = kern_now(CLOCK_ID_REALTIME);
            e->msg_len = count;
            runtime_memcpy(e->msg, s, count);
            vector_push(cw.log_entries, e);
        }
    }
    cw_log_send_async();
    spin_unlock(&cw.lock);
}

static void cw_log_connect(const ip_addr_t *server)
{
    if (!server ||
        (tls_connect((ip_addr_t *)server, 443, (connection_handler)&cw.log_conn_handler) < 0)) {
        spin_lock(&cw.lock);
        cw_log_send_async();
        spin_unlock(&cw.lock);
    }
}

static boolean cw_log_token_get(buffer resp, sstring label)
{
    int tok_start = buffer_strstr(resp, label);
    if (tok_start >= 0) {
        buffer_consume(resp, tok_start + label.len);
        tok_start = buffer_strchr(resp, '"');
        if (tok_start >= 0) {
            buffer_consume(resp, tok_start + 1);
            int tok_end = buffer_strchr(resp, '"');
            if (tok_end >= 0) {
                buffer_clear(cw.log_seq_token);
                return buffer_write(cw.log_seq_token, buffer_ref(resp, 0), tok_end);
            }
        }
    }
    return false;
}

static void cw_log_pending_delete(void)
{
    spin_lock(&cw.lock);
    int log_entries = cw.log_pending;
    for (int i = 0; i < log_entries; i++)
        deallocate(cw.h, vector_get(cw.log_entries, i), sizeof(struct cw_log_entry));
    vector_delete_range(cw.log_entries, 0, log_entries);
    spin_unlock(&cw.lock);
}

closure_func_basic(value_handler, void, cw_log_vh,
                   value v)
{
    buffer content = get_string(v, sym(content));
    if (content) {
        if (cw_log_token_get(content, ss(CW_LOG_NEXT_SEQ_TOK))) {
            cw_log_pending_delete();
        } else if (cw_log_token_get(content, ss(CW_LOG_EXP_SEQ_TOK))) {
            /* resend log entries at the next timer interval */
        } else if (buffer_strstr(content, ss(AWS_ERR_TOKEN_EXPIRED)) >= 0) {
            aws_cred_get(cw.h, init_closure(&cw.aws_cred_handler, cw_aws_cred_handler,
                         (status_handler)&cw.aws_setup_complete));
        } else {
            msg_err("unexpected response %v\n", v);
            cw_log_pending_delete();
        }
    }
    cw.log_resp_recved = true;
}

closure_func_basic(input_buffer_handler, boolean, cw_log_in_handler,
                   buffer data)
{
    if (data) {
        status s = apply(cw.log_resp_parser, data);
        if (is_ok(s)) {
            if (cw.log_resp_recved) {
                apply(cw.log_out, 0);
                return true;
            }
        } else {
            msg_err("failed to parse response: %v\n", s);
            timm_dealloc(s);
            apply(cw.log_out, 0);
            return true;
        }
    } else {    /* connection closed */
        spin_lock(&cw.lock);
        cw.log_pending = 0;
        cw.log_out = 0;
        cw_log_send_async();
        spin_unlock(&cw.lock);
    }
    return false;
}

static void cw_log_post(void)
{
    tuple req = allocate_tuple();
    if (req == INVALID_ADDRESS)
        goto error;
    set(req, sym(url), alloca_wrap_cstring("/"));
    set(req, sym(host), alloca_wrap_buffer(cw.log_servername, cw.log_servername_len));
    aws_req_set_date(req, little_stack_buffer(16));
    set(req, sym(accept), alloca_wrap_cstring("application/json"));
    set(req, sym(content-type), alloca_wrap_cstring("application/x-amz-json-1.1"));
    boolean success = false;
    buffer body = allocate_buffer(cw.h, 128);
    if (body == INVALID_ADDRESS)
        goto req_dealloc;
    bprintf(body, "{\"logGroupName\":\"%b\",\"logStreamName\":\"%b\"", cw.log_group, cw.log_stream);
    if (buffer_length(cw.log_seq_token) > 0)
        bprintf(body, ",\"sequenceToken\":\"%b\"", cw.log_seq_token);
    if (!buffer_write_cstring(body, ",\"logEvents\":["))
        goto req_done;
    int log_events = vector_length(cw.log_entries);
    for (int i = 0; i < log_events; i++) {
        cw_log_entry e = vector_get(cw.log_entries, i);
        if (i > 0)
            push_u8(body, ',');
        bprintf(body, "{\"timestamp\":%ld,\"message\":\"", msec_from_timestamp(e->t));
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
    cw.log_resp_recved = false;
    success = cw_aws_req_send(ss(CLOUDWATCH_LOG_SERVICE_NAME), ss("Logs_20140328.PutLogEvents"),
                              req, body, cw.log_out);
  req_done:
    if (success)
        cw.log_pending = log_events;
    else
        deallocate_buffer(body);
  req_dealloc:
    deallocate_value(req);
    if (!success)
  error:
        cw_log_send_async();
}

static void cw_log_send(void)
{
    if (!cw.log_out)
        cw_connect(isstring(cw.log_servername, cw.log_servername_len), cw_log_connect);
    else
        cw_log_post();
}

closure_func_basic(connection_handler, input_buffer_handler, cw_log_conn_handler,
                   buffer_handler out)
{
    input_buffer_handler ibh;
    spin_lock(&cw.lock);
    if (out && !cw.log_out) {
        cw.log_out = out;
        cw_log_post();
        ibh = (input_buffer_handler)&cw.log_in_handler;
    } else {
        cw_log_send_async();
        ibh = INVALID_ADDRESS;
    }
    spin_unlock(&cw.lock);
    return ibh;
}

closure_func_basic(timer_handler, void, cw_log_timer_handler,
                   u64 expiry, u64 overruns)
{
    if (overruns == timer_disabled)
        return;
    spin_lock(&cw.lock);
    if (cw.log_inited)
        cw_log_send();
    spin_unlock(&cw.lock);
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
    boolean cw_config_empty = true;
    value metrics_interval = get(cw_config, sym(mem_metrics_interval));
    if (metrics_interval) {
        u64 interval;
        if (!u64_from_value(metrics_interval, &interval)) {
            rprintf("CloudWatch: invalid memory metrics interval\n");
            return KLIB_INIT_FAILED;
        }
        cw.metrics_interval = seconds(interval);
        cw_config_empty = false;
    } else {
        cw.metrics_interval = 0;
    }
    if (cw.metrics_interval) {
        init_timer(&cw.metrics_timer);
        init_closure_func(&cw.metrics_timer_handler, timer_handler, cw_metrics_timer_handler);
        init_closure_func(&cw.metrics_conn_handler, connection_handler, cw_metrics_conn_handler);
    }
    tuple logging = get_tuple(cw_config, sym(logging));
    if (logging) {
        cw.log_group = get_string(logging, sym(log_group));
        if (!cw.log_group) {
            cw.log_group = get(get_environment(), sym(IMAGE_NAME));
            if (!cw.log_group)
                cw.log_group = get(root, sym(program));
        }
        cw.log_stream = get_string(logging, sym(log_stream));
        cw.log_seq_token = allocate_buffer(cw.h, 64);
        assert(cw.log_seq_token != INVALID_ADDRESS);
        cw.log_entries = allocate_vector(cw.h, CW_LOG_MAX_ENTRIES);
        assert(cw.log_entries != INVALID_ADDRESS);
        init_closure_func(&cw.log_conn_handler, connection_handler, cw_log_conn_handler);
        init_closure_func(&cw.log_in_handler, input_buffer_handler, cw_log_in_handler);
        cw.log_resp_parser = allocate_http_parser(cw.h, init_closure_func(&cw.log_vh, value_handler,
                                                                          cw_log_vh));
        assert(cw.log_resp_parser != INVALID_ADDRESS);
        init_closure_func(&cw.log_timer_handler, timer_handler, cw_log_timer_handler);
        cw.log_driver.write = cw_log_write;
        cw.log_driver.name = ss("cloudwatch");
        cw.log_driver.disabled = false;
        attach_console_driver(&cw.log_driver);
        cw_config_empty = false;
    }
    if (!cw_config_empty) {
        spin_lock_init(&cw.lock);
        init_closure(&cw.aws_setup_complete, cw_aws_setup_complete, seconds(1));
        if (!cw_aws_setup())
            return KLIB_INIT_FAILED;
    }
    return KLIB_INIT_OK;
}
