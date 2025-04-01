#include <kernel.h>
#include <lwip.h>
#include <mktime.h>
#include <net_utils.h>
#include <pagecache.h>
#include <tls.h>

#include "azure.h"

#ifdef AZURE_DIAG_DEBUG
#define azdiag_debug(fmt, ...)   tprintf(sym(azure_diag), 0, ss(fmt "\n"), ##__VA_ARGS__)
#else
#define azdiag_debug(fmt, ...)
#endif

enum azure_metrics_mem {
    AZURE_METRICS_MEMORY_AVAILABLE,
    AZURE_METRICS_MEMORY_USED,
    AZURE_METRICS_MEMORY_AVAILABLE_PERCENT,
    AZURE_METRICS_MEMORY_USED_PERCENT,
    AZURE_METRICS_MEMORY_COUNT
};

typedef struct azure_metric {
    sstring category;
    sstring name;
    u64 count;
    u64 last;
    u64 min;
    u64 max;
    u64 total;
} *azure_metric;

typedef struct az_diag {
    struct azure_ext extension;
    heap h;
    buffer storage_account;
    buffer storage_account_sas;
    struct buffer vm_name;
    struct buffer vm_resource_id;
    closure_struct(status_handler, setup_complete);
    struct {
        timestamp sample_interval;
        timestamp transfer_interval;
        struct buffer table_name;
        struct buffer server;
        struct timer timer;
        closure_struct(timer_handler, th);
        timestamp ts;
        struct azure_metric data[AZURE_METRICS_MEMORY_COUNT];
        closure_struct(connection_handler, ch);
        buffer_handler out;
        closure_struct(input_buffer_handler, ibh);
        buffer_handler resp_parser;
        closure_struct(value_handler, vh);
        timestamp table_switch;
        boolean pending;
    } metrics;
} *az_diag;

declare_closure_struct(1, 1, void, azdiag_instance_md_handler,
                       status_handler, complete,
                       tuple md)
typedef struct azdiag_setup_s {
    az_diag diag;
    closure_struct(azdiag_instance_md_handler, instance_md_handler);
    closure_struct(status_handler, complete);
    closure_struct(timer_handler, retry_th);
    timestamp retry_backoff;
} *azdiag_setup_s;

static boolean azure_metric_get_interval(tuple metrics, sstring name, const u64 min_value,
                                         const u64 default_value, timestamp *result)
{
    u64 interval;
    if (get_u64(metrics, sym_sstring(name), &interval)) {
        if (interval < min_value) {
            msg_err("Azure diagnostics: invalid metrics %s (minimum allowed value %ld seconds)",
                    name, min_value);
            return false;
        }
    } else {
        interval = default_value;
    }
    *result = seconds(interval);
    return true;
}

static void azure_metrics_reset(az_diag diag)
{
    for (int i = 0; i < AZURE_METRICS_MEMORY_COUNT; i++) {
        azure_metric metric = &diag->metrics.data[i];
        metric->count = 0;
        metric->min = U64_MAX;
        metric->max = 0;
        metric->total = 0;
    }
}

define_closure_function(1, 1, void, azdiag_instance_md_handler,
                        status_handler, complete,
                        tuple md)
{
    azdiag_setup_s setup = struct_from_closure(azdiag_setup_s, instance_md_handler);
    az_diag diag = setup->diag;
    status s;
    if (!md) {
        s = timm("result", "failed to get instance metadata");
        goto out;
    }
    tuple compute = get_tuple(md, sym_this("compute"));
    if (!compute) {
        s = timm("result", "missing compute node");
        goto out;
    }
    string name = get_string(compute, sym_this("name"));
    if (!name) {
        s = timm("result", "missing VM name");
        goto out;
    }
    string res_id;
    tuple vmss = get_tuple(compute, sym_this("virtualMachineScaleSet"));
    if (!vmss) {
        azdiag_debug("instance is not in a VM scale set");
        res_id = get_string(compute, sym_this("resourceId"));
    } else {
        azdiag_debug("instance is in a VM scale set");
        res_id = get_string(vmss, sym_this("id"));
    }
    if (!res_id) {
        s = timm("result", "missing resource id");
        goto out;
    }
    if (!push_buffer(&diag->vm_name, name)) {
        s = timm_oom;
        goto out;
    }
    foreach_character(i, c, res_id) {
        if ((c >= 0x20) && (c <= 0x2F))
            bprintf(&diag->vm_resource_id, ":%04X", c);
        else
            push_u8(&diag->vm_resource_id, c);
    }
    azdiag_debug("VM name '%b', resource ID %b", &diag->vm_name, &diag->vm_resource_id);
    s = STATUS_OK;
  out:
    if (!is_ok(s)) {
        buffer_clear(&diag->vm_name);
        buffer_clear(&diag->vm_resource_id);
    }
    apply(bound(complete), s);
    closure_finish();
}

static void azdiag_resolve_cb(sstring name, const ip_addr_t *addr, void *cb_arg)
{
    connection_handler ch = cb_arg;
    if (addr) {
        azdiag_debug("connecting to server (%F)", ch);
        if (tls_connect((ip_addr_t *)addr, 443, ch) < 0) {
            msg_err("%s: failed to connect to server %s", func_ss, name);
            apply(ch, 0);
        }
    } else {
        msg_err("%s: failed to resolve server name %s", func_ss, name);
        apply(ch, 0);
    }
}

static void azure_metrics_connect(az_diag diag)
{
    sstring server = buffer_to_sstring(&diag->metrics.server);
    azdiag_debug("resolving server name %s", server);
    net_resolve(server, azdiag_resolve_cb, &diag->metrics.ch);
}

static boolean azure_metrics_table_post(az_diag diag, sstring resource, buffer content_type,
                                        buffer body, boolean keepalive)
{
    tuple req = allocate_tuple();
    if (req == INVALID_ADDRESS)
        return false;
    buffer query_string = little_stack_buffer(256);
    bprintf(query_string, "/%s?%b&api-version=2024-05-04", resource, diag->storage_account_sas);
    set(req, sym(url), query_string);
    set(req, sym(Host), &diag->metrics.server);
    set(req, sym(Content-Type), content_type);
    set(req, sym(Accept), alloca_wrap_cstring("*/*"));
    set(req, sym(Accept-Charset), alloca_wrap_cstring("UTF-8"));
    set(req, sym(DataServiceVersion), alloca_wrap_cstring("3.0;"));
    set(req, sym(MaxDataServiceVersion), alloca_wrap_cstring("3.0;NetFx"));
    set(req, sym(Connection), alloca_wrap_sstring(keepalive ? ss("keep-alive") : ss("close")));
    status s = http_request(diag->h, diag->metrics.out, HTTP_REQUEST_METHOD_POST, req, body);
    boolean success = is_ok(s);
    if (!success) {
        msg_err("%s error %v", func_ss, s);
        timm_dealloc(s);
    }
    deallocate_value(req);
    return success;
}

static boolean azure_metrics_table_create(az_diag diag, buffer table_name)
{
    azdiag_debug("creating table %b", table_name);
    buffer b = allocate_buffer(diag->h, 128);
    if (b != INVALID_ADDRESS) {
        bprintf(b, "{\"TableName\":\"%b\"}", table_name);
        if (!azure_metrics_table_post(diag, ss("Tables"), alloca_wrap_cstring("application/json"),
                                      b, true)) {
            deallocate_buffer(b);
            return false;
        }
        return true;
    }
    return false;
}

static void azdiag_setup(azdiag_setup_s setup)
{
    az_diag diag = setup->diag;
    merge m = allocate_merge(diag->h, (status_handler)&setup->complete);
    status_handler complete = apply_merge(m);
    if (buffer_length(&diag->vm_name) == 0) {
        az_instance_md_handler complete = init_closure(&setup->instance_md_handler,
                                                       azdiag_instance_md_handler, apply_merge(m));
        azure_instance_md_get(complete);
    }
    apply(complete, STATUS_OK);
}

closure_func_basic(timer_handler, void, azdiag_setup_retry,
                   u64 expiry, u64 overruns)
{
    azdiag_setup_s setup = struct_from_closure(azdiag_setup_s, retry_th);
    if (overruns != timer_disabled)
        azdiag_setup(setup);
}

closure_func_basic(status_handler, void, azdiag_setup_complete,
                   status s)
{
    azdiag_setup_s setup = struct_from_closure(azdiag_setup_s, complete);
    az_diag diag = setup->diag;
    heap h = diag->h;
    if (is_ok(s)) {
        azdiag_debug("setup complete");
        if (diag->metrics.sample_interval)
            register_timer(kernel_timers, &diag->metrics.timer, CLOCK_ID_MONOTONIC, 0, false,
                           diag->metrics.sample_interval, (timer_handler)&diag->metrics.th);
    } else {
        /* Do not print error messages if the instance metadata server is unreachable just after
         * instance startup (a few seconds might elapse before the network interface acquires a DHCP
         * address). */
        if (setup->retry_backoff > seconds(2))
            msg_err("%s error %v", func_ss, s);
        else
            azdiag_debug("setup error %v, retrying", s);

        timm_dealloc(s);
        setup->retry_backoff <<= 1;
        timer retry_timer = allocate_timer(h);
        if (retry_timer != INVALID_ADDRESS) {
            init_timer(retry_timer);
            timer_handler setup_retry = init_closure_func(&setup->retry_th, timer_handler,
                                                          azdiag_setup_retry);
            register_timer(kernel_timers, retry_timer, CLOCK_ID_MONOTONIC, setup->retry_backoff,
                           false, 0, setup_retry);
            return;
        } else {
            msg_err("%s: out of memory", func_ss);
        }
    }
    deallocate(h, setup, sizeof(*setup));
}

static void azure_metrics_mem_add_sample(azure_metric metric, u64 value)
{
    metric->last = value;
    if (value < metric->min)
        metric->min = value;
    if (value > metric->max)
        metric->max = value;
    metric->total += value;
    metric->count++;
}

closure_func_basic(timer_handler, void, azure_metrics_timer_handler,
                   u64 expiry, u64 overruns)
{
    az_diag diag = struct_from_closure(az_diag, metrics.th);
    azdiag_debug("metrics timer (pending %d)", diag->metrics.pending);
    if ((overruns == timer_disabled) || diag->metrics.pending)
        return;
    heap phys = (heap)heap_physical(get_kernel_heaps());
    u64 total = heap_total(phys);
    u64 used = heap_allocated(phys);
    u64 cached = pagecache_get_occupancy();
    u64 available = total - used + cached;
    azure_metrics_mem_add_sample(&diag->metrics.data[AZURE_METRICS_MEMORY_AVAILABLE], available);
    azure_metrics_mem_add_sample(&diag->metrics.data[AZURE_METRICS_MEMORY_USED], used);
    azure_metrics_mem_add_sample(&diag->metrics.data[AZURE_METRICS_MEMORY_AVAILABLE_PERCENT],
                                 100 * available / total);
    azure_metrics_mem_add_sample(&diag->metrics.data[AZURE_METRICS_MEMORY_USED_PERCENT],
                                 100 * used / total);
    u64 count = diag->metrics.data[0].count;
    if (count == 1) {
        diag->metrics.ts = kern_now(CLOCK_ID_REALTIME);
    } else if (count >= diag->metrics.transfer_interval / diag->metrics.sample_interval) {
        diag->metrics.pending = true;
        azure_metrics_connect(diag);
    }
}

static boolean azure_metrics_table_switch(az_diag diag)
{
    buffer table_name = &diag->metrics.table_name;
    buffer_clear(table_name);
    buffer_write_cstring(table_name, "WADMetrics");
    iso8601_write_interval(diag->metrics.transfer_interval, table_name);
    buffer_write_cstring(table_name, "P10DV2S");
    u64 secs = sec_from_timestamp(diag->metrics.table_switch);
    struct tm tm;
    gmtime_r(&secs, &tm);
    bprintf(table_name, "%d%02d%02d", 1900 + tm.tm_year, 1 + tm.tm_mon, tm.tm_mday);
    if (azure_metrics_table_create(diag, table_name)) {
        diag->metrics.table_switch += seconds(10 * 24 * 60 * 60);
        return true;
    }
    return false;
}

static boolean azure_metrics_add(az_diag diag, buffer b, sstring boundary,
                                 enum azure_metrics_mem kind, struct tm *tm, u64 ticks)
{
    azure_metric metric = &diag->metrics.data[kind];
    u64 average = metric->total / metric->count;
    bprintf(b, "\r\n--%s\r\nContent-Type: application/http\r\n"
               "Content-Transfer-Encoding: binary\r\n\r\n"
               "POST https://%b/%b HTTP/1.1\r\n"
               "Content-Type: application/json\r\n"
               "Accept: application/json;odata=minimalmetadata\r\n"
               "Prefer: return-no-content\r\n"
               "DataServiceVersion: 3.0;\r\n\r\n"
               "{\"PartitionKey\":\"%b\",\"RowKey\":\":002Fbuiltin:002F%s:002F%s__%019ld\","
               "\"CounterName\":\"/builtin/%s/%s\",\"Average\":%ld,\"Count\":%ld,\"Last\":%ld,"
               "\"Minimum\":%ld,\"Maximum\":%ld,\"Total\":%ld,\"DeploymentId\":\"unknown\","
               "\"Host\":\"%b\",\"TIMESTAMP\":\"%d-%02d-%02dT%02d:%02d:%02dZ\"}",
            boundary, &diag->metrics.server, &diag->metrics.table_name, &diag->vm_resource_id,
            metric->category, metric->name, ticks, metric->category, metric->name, average,
            metric->count, metric->last, metric->min, metric->max, metric->total, &diag->vm_name,
            1900 + tm->tm_year, 1 + tm->tm_mon, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec);
    return true;
}

static boolean azure_metrics_post(az_diag diag)
{
    timestamp ts = diag->metrics.ts;
    if ((ts >= diag->metrics.table_switch) && !azure_metrics_table_switch(diag)) {
        msg_err("%s: failed to create table", func_ss);
        return false;
    }
    buffer b = allocate_buffer(diag->h, 1024);
    if (b == INVALID_ADDRESS) {
        msg_err("%s: out of memory", func_ss);
        return false;
    }
    u64 secs = sec_from_timestamp(ts);
    struct tm tm;
    gmtime_r(&secs, &tm);

    /* ticks start from 00:00:00 UTC, January 1, 0001 and advance every 100 nanoseconds */
    const u64 unix_epoch_ticks = 621355968000000000ull; /* 00:00:00 UTC, January 1, 1970 */
    const u64 max_ticks = 3155378975999999999ull;   /* 23:59:59.9999999 UTC, December 31, 9999 */
    u64 ticks = max_ticks - (unix_epoch_ticks + nsec_from_timestamp(ts) / 100);

    sstring batch_boundary = ss("batch_boundary");
    buffer content_type = little_stack_buffer(64);
    bprintf(content_type, "multipart/mixed; boundary=%s", batch_boundary);
    sstring changeset_boundary = ss("changeset_boundary");
    bprintf(b, "--%s\r\nContent-Type: multipart/mixed; boundary=%s\r\n", batch_boundary,
            changeset_boundary);
    for (int i = 0; i < AZURE_METRICS_MEMORY_COUNT; i++)
        if (!azure_metrics_add(diag, b, changeset_boundary, i, &tm, ticks))
            goto err;
    bprintf(b, "\r\n--%s--\r\n--%s--", changeset_boundary, batch_boundary);
    if (!azure_metrics_table_post(diag, ss("$batch"), content_type, b, false))
        goto err;
    azure_metrics_reset(diag);
    return true;
  err:
    deallocate_buffer(b);
    return false;
}

closure_func_basic(connection_handler, input_buffer_handler, azure_metrics_conn_handler,
                   buffer_handler out)
{
    az_diag diag = struct_from_closure(az_diag, metrics.ch);
    input_buffer_handler ibh = INVALID_ADDRESS;
    azdiag_debug("connection to metrics server %s", out ? ss("succeeded") : ss("failed"));
    if (out) {
        diag->metrics.out = out;
        if (azure_metrics_post(diag))
            ibh = (input_buffer_handler)&diag->metrics.ibh;
    }
    if (ibh == INVALID_ADDRESS)
        diag->metrics.pending = false;
    return ibh;
}

closure_func_basic(input_buffer_handler, boolean, azure_metrics_in_handler,
                   buffer data)
{
    az_diag diag = struct_from_closure(az_diag, metrics.ibh);
    if (data) {
        status s = apply(diag->metrics.resp_parser, data);
        if (is_ok(s)) {
            if (!diag->metrics.out)
                return true;
        } else {
            msg_err("%s: failed to parse response: %v", func_ss, s);
            timm_dealloc(s);
            apply(diag->metrics.out, 0);
            return true;
        }
    } else {    /* connection closed */
        diag->metrics.pending = false;
    }
    return false;
}

closure_func_basic(value_handler, void, azure_metrics_value_handler,
                   value v)
{
    az_diag diag = struct_from_closure(az_diag, metrics.vh);
    value start_line = get(v, sym(start_line));
    azdiag_debug("metrics server status %v", start_line);
    u64 status_code = 0;
    if (get_u64(start_line, integer_key(1), &status_code)) {
        int expected_codes[] = {
            202,        /* batch insert accepted */
            201, 409,   /* table created or table already existing */
        };
        int i;
        for (i = 0; i < _countof(expected_codes); i++) {
            if (status_code == expected_codes[i])
                break;
        }
        if (i == _countof(expected_codes)) {
            if (status_code == 403)
                msg_err("Azure: invalid storage account SAS token");
            else
                status_code = 0;
        }
    }
    if (!status_code)
        msg_err("%s: unexpected response %v", func_ss, v);
    apply(diag->metrics.out, 0);
    diag->metrics.out = 0;  /* signal to input buffer handler that connection is closed */
}

int azure_diag_init(tuple cfg)
{
    heap h = heap_locked(get_kernel_heaps());
    az_diag diag = mem_alloc(h, sizeof(*diag), MEM_NOFAIL);
    diag->h = h;
    init_buffer(&diag->vm_name, 0, false, h, 0);
    init_buffer(&diag->vm_resource_id, 0, false, h, 0);
    diag->storage_account = get_string(cfg, sym_this("storage_account"));
    diag->storage_account_sas = get_string(cfg, sym_this("storage_account_sas"));
    boolean config_empty = true;
    tuple metrics = get_tuple(cfg, sym_this("metrics"));
    if (metrics) {
        if (!diag->storage_account || !diag->storage_account_sas) {
            msg_err("Azure diagnostics: missing storage account or SAS token, "
                    "required for metrics");
            return KLIB_INIT_FAILED;
        }
        if (!azure_metric_get_interval(metrics, ss("sample_interval"), 15, 15,
                                       &diag->metrics.sample_interval) ||
            !azure_metric_get_interval(metrics, ss("transfer_interval"), 60, 60,
                                       &diag->metrics.transfer_interval))
            return KLIB_INIT_FAILED;
        azdiag_debug("metrics sample interval %ld seconds, transfer interval %ld seconds, "
                     "storage account %b, SAS token length %ld",
                     sec_from_timestamp(diag->metrics.sample_interval),
                     sec_from_timestamp(diag->metrics.transfer_interval),
                     diag->storage_account, buffer_length(diag->storage_account_sas));
        init_buffer(&diag->metrics.table_name, 0, false, h, 0);

        /* The table where metrics are inserted changes every 10 days; day 0 is January 1, 1601
         * (Windows epoch). */
        const u64 epoch_diff = 11644473600ull;  /* seconds between Windows epoch and Unix epoch */
        u64 secs = epoch_diff + sec_from_timestamp(kern_now(CLOCK_ID_REALTIME));
        u64 days = secs / (24 * 60 * 60);
        days = (days / 10) * 10;
        diag->metrics.table_switch = seconds(days * 24 * 60 * 60 - epoch_diff);

        for (int i = 0; i < AZURE_METRICS_MEMORY_COUNT; i++)
            diag->metrics.data[i].category = ss("memory");
        diag->metrics.data[AZURE_METRICS_MEMORY_AVAILABLE].name = ss("availablememory");
        diag->metrics.data[AZURE_METRICS_MEMORY_USED].name = ss("usedmemory");
        diag->metrics.data[AZURE_METRICS_MEMORY_AVAILABLE_PERCENT].name =
            ss("percentavailablememory");
        diag->metrics.data[AZURE_METRICS_MEMORY_USED_PERCENT].name = ss("percentusedmemory");
        azure_metrics_reset(diag);
        init_buffer(&diag->metrics.server, 0, false, h, 0);
        bprintf(&diag->metrics.server, "%b.table.core.windows.net", diag->storage_account);
        init_timer(&diag->metrics.timer);
        init_closure_func(&diag->metrics.th, timer_handler, azure_metrics_timer_handler);
        init_closure_func(&diag->metrics.ch, connection_handler, azure_metrics_conn_handler);
        init_closure_func(&diag->metrics.ibh, input_buffer_handler, azure_metrics_in_handler);
        value_handler vh = init_closure_func(&diag->metrics.vh, value_handler,
                                             azure_metrics_value_handler);
        diag->metrics.resp_parser = allocate_http_parser(h, vh);
        assert(diag->metrics.resp_parser != INVALID_ADDRESS);
        diag->metrics.pending = false;
        config_empty = false;
    }
    if (!config_empty) {
        azure_ext extension = &diag->extension;
        extension->name = ss("Microsoft.Azure.Diagnostics.LinuxDiagnostic");
        extension->version = ss("3.0.142");
        if (!azure_register_ext(extension)) {
            msg_err("Azure diagnostics: failed to register extension");
            return KLIB_INIT_FAILED;
        }
        azdiag_setup_s setup = mem_alloc(h, sizeof(*setup), MEM_NOFAIL);
        setup->diag = diag;
        setup->retry_backoff = seconds(1);
        init_closure_func(&setup->complete, status_handler, azdiag_setup_complete);
        azdiag_setup(setup);
    }
    return KLIB_INIT_OK;
}
