#include <kernel.h>
#include <crc.h>
#include <http.h>
#include <lwip.h>
#include <pagecache.h>

#define DO_SERVER_ADDR  IPADDR4_INIT_BYTES(169, 254, 169, 254)

static struct digitalocean {
    heap h;
    closure_struct(status_handler, setup_complete);
    char server_host[IPADDR_STRLEN_MAX];
    int server_host_len;
    buffer droplet_token;
    struct {
        timestamp interval;
        buffer url;
        struct timer timer;
        closure_struct(timer_handler, th);
        closure_struct(connection_handler, ch);
        buffer_handler out;
        closure_struct(input_buffer_handler, ibh);
        buffer_handler resp_parser;
        closure_struct(value_handler, vh);
        boolean pending;
    } metrics;
    timestamp retry_backoff;
} digitalocean;

/* Metrics are encoded with the Snappy framing format
 * (https://github.com/google/snappy/blob/main/framing_format.txt). */

#define SNAPPY_CHUNK_HDR_LEN    4
#define SNAPPY_CHUNK_CRC_LEN    4

enum snappy_chunk_type {
    snappy_chunk_stream_id = 0xff,
    snappy_chunk_compressed = 0x00,
    snappy_chunk_uncompressed = 0x01,
};

static const u8 snappy_stream_id[] = {
    snappy_chunk_stream_id, 0x06, 0x00, 0x00, 's', 'N', 'a', 'P', 'p', 'Y'
};

static boolean do_instance_md_available(void)
{
    ip_addr_t md_server = DO_SERVER_ADDR;
    struct netif *n = ip_route(&ip_addr_any, &md_server);
    if (n) {
        netif_unref(n);
        return true;
    }
    return false;
}

closure_function(4, 1, boolean, do_instance_md_in,
                 buffer_handler, out, buffer_handler, parser, value_handler, vh, status_handler, complete,
                 buffer data)
{
    buffer_handler out = bound(out);
    status_handler complete = bound(complete);
    status s;
    if (data) {
        if (bound(parser) == INVALID_ADDRESS) {
            value_handler vh = bound(vh);
            bound(parser) = allocate_http_parser(digitalocean.h, vh);
            if (bound(parser) == INVALID_ADDRESS) {
                s = timm_oom;
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
    apply(complete, s);
    return true;
}

closure_function(4, 1, input_buffer_handler, do_instance_md_ch,
                 sstring, url, buffer, auth, value_handler, vh, status_handler, complete,
                 buffer_handler out)
{
    buffer auth = bound(auth);
    value_handler vh = bound(vh);
    status_handler complete = bound(complete);
    status s;
    if (!out) {
        s = timm("result", "failed to connect to DigitalOcean instance metadata server");
        goto error;
    }
    tuple req = allocate_tuple();
    if (req == INVALID_ADDRESS) {
        s = timm_oom;
        goto error;
    }
    set(req, sym(url), alloca_wrap_sstring(bound(url)));
    set(req, sym(Host), alloca_wrap_buffer(digitalocean.server_host, digitalocean.server_host_len));
    if (auth)
        set(req, sym(Authorization), auth);
    set(req, sym(Connection), alloca_wrap_cstring("close"));
    s = http_request(digitalocean.h, out, HTTP_REQUEST_METHOD_GET, req, 0);
    deallocate_value(req);
    if (!is_ok(s)) {
        s = timm_up(s, "result", "failed to send HTTP request");
        goto error;
    }
    if (auth)
        deallocate_buffer(auth);
    closure_finish();
    return closure(digitalocean.h, do_instance_md_in, out, INVALID_ADDRESS, vh, complete);
  error:
    if (auth)
        deallocate_buffer(auth);
    deallocate_closure(vh);
    closure_finish();
    apply(complete, s);
    return INVALID_ADDRESS;
}

static void do_instance_md_get(sstring url, buffer auth, value_handler vh, status_handler complete)
{
    status s;
    connection_handler ch = closure(digitalocean.h, do_instance_md_ch, url, auth, vh, complete);
    if (ch == INVALID_ADDRESS) {
        s = timm_oom;
        goto error;
    }
    ip_addr_t md_server = DO_SERVER_ADDR;
    s = direct_connect(digitalocean.h, &md_server, 80, ch);
    if (!is_ok(s)) {
        s = timm_up(s, "result", "failed to connect to DigitalOcean instance metadata server");
        deallocate_closure(ch);
        goto error;
    }
    return;
  error:
    deallocate_closure(vh);
    deallocate_buffer(auth);
    apply(complete, s);
}

static buffer do_instance_md_get_content(value server_resp)
{
    value start_line = get(server_resp, sym(start_line));
    buffer status_code = get(start_line, integer_key(1));
    if (status_code && !buffer_strcmp(status_code, "200"))
        return get(server_resp, sym_this("content"));
    else
        return 0;
}

closure_function(1, 1, void, do_droplet_id_vh,
                 status_handler, complete,
                 value v)
{
    buffer content = do_instance_md_get_content(v);
    status s;
    if (content) {
        if (push_buffer(digitalocean.metrics.url, content))
            s = STATUS_OK;
        else
            s = timm("result", "failed to store droplet ID");
    } else {
        s = timm("result", "unexpected droplet ID response %v", v);
    }
    apply(bound(complete), s);
}

static void do_get_droplet_id(status_handler complete)
{
    value_handler vh = closure(digitalocean.h, do_droplet_id_vh, complete);
    if (vh != INVALID_ADDRESS)
        do_instance_md_get(ss("/metadata/v1/id"), 0, vh, complete);
    else
        apply(complete, timm_oom);
}

closure_function(1, 1, void, do_droplet_token_vh,
                 status_handler, complete,
                 value v)
{
    buffer content = do_instance_md_get_content(v);
    status s;
    if (content) {
        digitalocean.droplet_token = clone_buffer(digitalocean.h, content);
        if (digitalocean.droplet_token != INVALID_ADDRESS) {
            if ((buffer_length(digitalocean.droplet_token) > 3) &&
                    (peek_char(digitalocean.droplet_token) == '"')) {
                /* remove double quotes surrounding the token and trailing newline */
                digitalocean.droplet_token->start++;
                digitalocean.droplet_token->end -= 2;
            }
            s = STATUS_OK;
        } else {
            s = timm_oom;
        }
    } else {
        s = timm("result", "unexpected droplet token response %v", v);
    }
    apply(bound(complete), s);
}

static void do_get_droplet_token(buffer auth, status_handler complete)
{
    value_handler vh = closure(digitalocean.h, do_droplet_token_vh, complete);
    if (vh != INVALID_ADDRESS) {
        do_instance_md_get(ss("/v1/appkey/droplet-auth-token"), auth, vh, complete);
    } else {
        deallocate_buffer(auth);
        apply(complete, timm_oom);
    }
}

closure_function(1, 1, void, do_auth_token_vh,
                 status_handler, complete,
                 value v)
{
    buffer content = do_instance_md_get_content(v);
    status_handler complete = bound(complete);
    status s;
    if (content) {
        sstring auth_type = ss("DOMETADATA ");
        bytes auth_len = auth_type.len + buffer_length(content);
        buffer auth_token = allocate_buffer(digitalocean.h, auth_len);
        if (auth_token != INVALID_ADDRESS) {
            buffer_write_sstring(auth_token, auth_type);
            push_buffer(auth_token, content);
            do_get_droplet_token(auth_token, complete);
            return;
        }
        s = timm_oom;
    } else {
        s = timm("result", "unexpected auth token response %v", v);
    }
    apply(complete, s);
}

static void do_get_auth_token(status_handler complete)
{
    value_handler vh = closure(digitalocean.h, do_auth_token_vh, complete);
    if (vh != INVALID_ADDRESS)
        do_instance_md_get(ss("/metadata/v1/auth-token"), 0, vh, complete);
    else
        apply(complete, timm_oom);
}

static void do_setup(void)
{
    status_handler complete = (status_handler)&digitalocean.setup_complete;
    status s;
    if (!do_instance_md_available()) {
        s = timm("result", "DigitalOcean instance metadata not available");
        goto out;
    }
    merge m = allocate_merge(digitalocean.h, complete);
    if (m == INVALID_ADDRESS) {
        s = timm_oom;
        goto out;
    }
    complete = apply_merge(m);
    s = STATUS_OK;
    do_get_droplet_id(apply_merge(m));
    do_get_auth_token(apply_merge(m));
  out:
    apply(complete, s);
}

closure_function(1, 2, void, do_setup_retry,
                 struct timer, t,
                 u64 expiry, u64 overruns)
{
    if (overruns != timer_disabled)
        do_setup();
    closure_finish();
}

closure_func_basic(status_handler, void, do_setup_complete,
                   status s)
{
    if (is_ok(s)) {
        digitalocean.retry_backoff = seconds(1);
        if (digitalocean.metrics.interval && !timer_is_active(&digitalocean.metrics.timer))
            register_timer(kernel_timers, &digitalocean.metrics.timer, CLOCK_ID_MONOTONIC, 0, false,
                           digitalocean.metrics.interval, (timer_handler)&digitalocean.metrics.th);
    } else {
        /* Do not print error messages if the instance metadata server is unreachable just after
         * instance startup (a few seconds might elapse before the network interface acquires a DHCP
         * address). */
        if (digitalocean.retry_backoff > seconds(2))
            msg_err("DigitalOcean setup failed: %v", s);

        timm_dealloc(s);
        if (digitalocean.retry_backoff < seconds(3600))
            digitalocean.retry_backoff <<= 1;
        struct timer t = {0};
        init_timer(&t);
        timer_handler setup_retry = closure(digitalocean.h, do_setup_retry, t);
        if (setup_retry != INVALID_ADDRESS)
            register_timer(kernel_timers, &closure_member(do_setup_retry, setup_retry, t),
                           CLOCK_ID_MONOTONIC, digitalocean.retry_backoff, false, 0, setup_retry);
    }
}

closure_func_basic(timer_handler, void, do_metrics_timer_handler,
                   u64 expiry, u64 overruns)
{
    if ((overruns == timer_disabled) || digitalocean.metrics.pending)
        return;
    digitalocean.metrics.pending = true;
    ip_addr_t metrics_server = DO_SERVER_ADDR;
    connection_handler ch = (connection_handler)&digitalocean.metrics.ch;
    status s = direct_connect(digitalocean.h, &metrics_server, 80, ch);
    if (!is_ok(s))
        apply(ch, 0);
}

static boolean do_metrics_init(buffer b)
{
    if (!buffer_extend(b, sizeof(snappy_stream_id) + SNAPPY_CHUNK_HDR_LEN + SNAPPY_CHUNK_CRC_LEN))
        return false;
    buffer_write(b, snappy_stream_id, sizeof(snappy_stream_id));
    buffer_produce(b, SNAPPY_CHUNK_HDR_LEN + SNAPPY_CHUNK_CRC_LEN);
    return true;
}

static boolean do_metrics_add(buffer b, sstring type, u64 value)
{
    /* value is encoded with double-precision floating-point format (IEEE 754) */
    u64 val_msb = msb(value);
    u64 exponent = (value == 0) ? 0 : (1023 + val_msb);    /* 1023 exponent bias */
    u64 fraction = (value == 0) ? 0 : ((value - U64_FROM_BIT(val_msb)) << (52 - val_msb));
    u64 float64_val = (exponent << 52) | fraction;

    return (buffer_write_le16(b, type.len) && buffer_write_sstring(b, type) &&
            buffer_write_le64(b, 0) && buffer_write_le64(b, float64_val));
}

static void do_metrics_commit(buffer b)
{
    u8 *snappy_chunk_hdr = buffer_ref(b, sizeof(snappy_stream_id));
    bytes chunk_len = buffer_length(b) - sizeof(snappy_stream_id) - SNAPPY_CHUNK_HDR_LEN;
    snappy_chunk_hdr[0] = snappy_chunk_uncompressed;
    snappy_chunk_hdr[1] = chunk_len;
    snappy_chunk_hdr[2] = chunk_len >> 8;
    snappy_chunk_hdr[3] = chunk_len >> 16;
    u32 checksum = crc32c(snappy_chunk_hdr + SNAPPY_CHUNK_HDR_LEN + SNAPPY_CHUNK_CRC_LEN,
                          chunk_len - SNAPPY_CHUNK_CRC_LEN);
    u32 *snappy_chunk_crc = (u32 *)(snappy_chunk_hdr + SNAPPY_CHUNK_HDR_LEN);
    *snappy_chunk_crc = ((checksum >> 15) | (checksum << 17)) + 0xa282ead8;
}

static boolean do_metrics_post(void)
{
    tuple req = allocate_tuple();
    if (req == INVALID_ADDRESS)
        return false;
    set(req, sym(url), digitalocean.metrics.url);
    set(req, sym(Host), alloca_wrap_buffer(digitalocean.server_host, digitalocean.server_host_len));
    set(req, sym(X-Auth-Key), digitalocean.droplet_token);
    set(req, sym(Content-Type), alloca_wrap_cstring("application/timeseries-binary-0"));
    set(req, sym(Connection), alloca_wrap_cstring("close"));
    boolean success = false;
    buffer body = allocate_buffer(digitalocean.h, 256);
    if (body == INVALID_ADDRESS)
        goto req_dealloc;
    heap phys = (heap)heap_physical(get_kernel_heaps());
    u64 total = heap_total(phys);
    u64 free = total - heap_allocated(phys);
    u64 cached = pagecache_get_occupancy();
    u64 available = free + cached;
    do_metrics_init(body);

    /* Insert dummy agent version and revision data, otherwise metrics are not shown in the graphs
     * of the DigitalOcean droplet control panel. */
    if (do_metrics_add(body, ss("sonar_build_info\000revision\0003e2db3a\000version\0003.16.7"),
                       1) &&
        do_metrics_add(body, ss("sonar_memory_total"), total) &&
        do_metrics_add(body, ss("sonar_memory_free"), free) &&
        do_metrics_add(body, ss("sonar_memory_cached"), cached) &&
        do_metrics_add(body, ss("sonar_memory_available"), available)) {
        do_metrics_commit(body);
        status s = http_request(digitalocean.h, digitalocean.metrics.out, HTTP_REQUEST_METHOD_POST,
                                req, body);
        success = is_ok(s);
        if (!success) {
            msg_err("%s error %v", func_ss, s);
            timm_dealloc(s);
        }
    }

    if (!success)
        deallocate_buffer(body);
  req_dealloc:
    deallocate_value(req);
    return success;
}

closure_func_basic(connection_handler, input_buffer_handler, do_metrics_conn_handler,
                   buffer_handler out)
{
    input_buffer_handler ibh;
    if (out) {
        digitalocean.metrics.out = out;
        if (do_metrics_post())
            ibh = (input_buffer_handler)&digitalocean.metrics.ibh;
        else
            ibh = 0;
    } else {
        ibh = 0;
    }
    if (!ibh)
        digitalocean.metrics.pending = false;
    return ibh;
}

closure_func_basic(input_buffer_handler, boolean, do_metrics_in_handler,
                   buffer data)
{
    if (data) {
        status s = apply(digitalocean.metrics.resp_parser, data);
        if (is_ok(s)) {
            if (!digitalocean.metrics.out)
                return true;
        } else {
            msg_err("%s: failed to parse response: %v", func_ss, s);
            timm_dealloc(s);
            apply(digitalocean.metrics.out, 0);
            return true;
        }
    } else {    /* connection closed */
        digitalocean.metrics.pending = false;
    }
    return false;
}

closure_func_basic(value_handler, void, do_metrics_value_handler,
                   value v)
{
    value resp = get(v, sym(start_line));
    buffer status_code = get(resp, integer_key(1));
    if (!status_code || peek_char(status_code) != '2')
        msg_err("%s: unexpected response %v", func_ss, v);
    apply(digitalocean.metrics.out, 0);
    digitalocean.metrics.out = 0;   /* signal to input buffer handler that connection is closed */
}

int init(status_handler complete)
{
    tuple root = get_root_tuple();
    if (!root)
        return KLIB_INIT_FAILED;
    tuple do_config = get_tuple(root, sym_this("digitalocean"));
    if (!do_config)
        return KLIB_INIT_OK;
    digitalocean.h = heap_locked(get_kernel_heaps());
    boolean config_empty = true;
    tuple metrics = get_tuple(do_config, sym_this("metrics"));
    if (metrics) {
        const u64 min_interval = 60;
        u64 interval;
        if (get_u64(metrics, sym_this("interval"), &interval)) {
            if (interval < min_interval) {
                msg_err("DigitalOcean: invalid metrics interval (minimum allowed value %ld "
                        "seconds)", min_interval);
                return KLIB_INIT_FAILED;
            }
        } else {
            interval = 120;
        }
        digitalocean.metrics.interval = seconds(interval);
        init_timer(&digitalocean.metrics.timer);
        digitalocean.metrics.url = allocate_buffer(digitalocean.h, 32);
        assert(digitalocean.metrics.url != INVALID_ADDRESS);
        buffer_write_cstring(digitalocean.metrics.url, "/v1/metrics/droplet_id/");
        init_closure_func(&digitalocean.metrics.th, timer_handler, do_metrics_timer_handler);
        init_closure_func(&digitalocean.metrics.ch, connection_handler, do_metrics_conn_handler);
        init_closure_func(&digitalocean.metrics.ibh, input_buffer_handler, do_metrics_in_handler);
        value_handler vh = init_closure_func(&digitalocean.metrics.vh, value_handler,
                                             do_metrics_value_handler);
        digitalocean.metrics.resp_parser = allocate_http_parser(digitalocean.h, vh);
        assert(digitalocean.metrics.resp_parser != INVALID_ADDRESS);
        config_empty = false;
    }
    if (!config_empty) {
        ip_addr_t metrics_server = DO_SERVER_ADDR;
        digitalocean.server_host_len = ipaddr_ntoa_r(&metrics_server, digitalocean.server_host,
                                                     sizeof(digitalocean.server_host));
        digitalocean.retry_backoff = seconds(1);
        init_closure_func(&digitalocean.setup_complete, status_handler, do_setup_complete);
        do_setup();
    }
    return KLIB_INIT_OK;
}
