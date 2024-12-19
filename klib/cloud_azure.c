#include <kernel.h>
#include <lwip.h>
#include <mktime.h>
#include <net_utils.h>
#include <xml.h>

#include "azure.h"

#define AZURE_MS_VERSION    "2015-04-05"

#define AZURE_WIRESERVER_ADDR   ss("168.63.129.16")

typedef struct azure {
    heap h;
    struct buffer ms_version;
    struct buffer goalstate_query;
    closure_struct(value_handler, goalstate_vh);
    struct net_http_req_params goalstate_req_params;
    char container_id[64];
    bytes container_id_len;
    char instance_id[64];
    bytes instance_id_len;
    struct timer report_timer;
    closure_struct(timer_handler, report_th);
    struct buffer goalstate_incarnation;
    struct {
        struct buffer blob_type;
        struct buffer page_write;
        struct buffer content_type;
        struct buffer host;
        struct buffer create_query;
        struct buffer data_query;
        tuple create_req;
        tuple data_req;
        buffer blob;
        struct buffer blob_size;
        struct buffer blob_range;
        struct net_http_req_params params;
        closure_struct(value_handler, vh);
        timestamp last_update;
        boolean valid;
    } status_upload;
    vector extensions;
    struct spinlock lock;
    boolean goalstate_pending;
    boolean goalstate_print_errors;
    boolean provisioned;
} *azure;

typedef struct azure_ready_data {
    azure az;
    struct buffer query;
    struct buffer content_type;
    tuple req;
    closure_struct(value_handler, vh);
} *azure_ready_data;

typedef struct azure_get_ext_data {
    azure az;
    buffer query;
    tuple req;
    closure_struct(value_handler, vh);
} *azure_get_ext_data;

static azure az_agent;

static void azure_report_ready(azure az);

closure_func_basic(timer_handler, void, az_report_th,
                   u64 expiry, u64 overruns)
{
    azure az = struct_from_closure(azure, report_th);
    if ((overruns == timer_disabled) || az->goalstate_pending)
        return;
    status s = net_http_req(&az->goalstate_req_params);
    if (is_ok(s)) {
        az->goalstate_pending = true;
    } else {
        if (az->goalstate_print_errors)
            msg_err("%s error %v", func_ss, s);
        timm_dealloc(s);
    }
    az->goalstate_print_errors = true;
}

static void az_report_status(azure az)
{
    heap h = az->h;
    buffer blob = allocate_buffer(h, KB);
    if (blob == INVALID_ADDRESS) {
        msg_err("%s: out of memory", func_ss);
        return;
    }
    status s;
    u64 seconds = sec_from_timestamp(kern_now(CLOCK_ID_REALTIME));
    struct tm tm;
    gmtime_r(&seconds, &tm);
    bprintf(blob, "{"
        "\"version\": \"1.1\", "
        "\"timestampUTC\": \"%d-%02d-%02dT%02d:%02d:%02dZ\", "
        "\"aggregateStatus\": {"
          "\"guestAgentStatus\": {"
           "\"version\": \"2.10.0.8\", "
            "\"status\": \"Ready\", "
            "\"formattedMessage\": {\"message\": \"Guest Agent is running\", \"lang\": \"en-US\"}"
          "}, "
          "\"handlerAggregateStatus\": [",
          1900 + tm.tm_year, 1 + tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
    azure_ext ext;
    buffer ok_code = alloca_wrap_cstring("0");
    buffer ok_message = alloca_wrap_cstring("Enable succeeded, extension daemon started");
    boolean first = true;
    spin_lock(&az->lock);
    vector_foreach(az->extensions, ext) {
        if (!ext->cfg_seconds)
            continue;
        status s = ext->s;
        gmtime_r(&ext->cfg_seconds, &tm);
        bprintf(blob, "%s{"
              "\"handlerName\": \"%s\", "
              "\"handlerVersion\": \"%s\", "
              "\"status\": \"Ready\", "
              "\"code\": 0, "
              "\"formattedMessage\": {\"message\": \"Plugin enabled\", \"lang\": \"en-US\"}, "
              "\"runtimeSettingsStatus\": {"
                "\"settingsStatus\": {"
                  "\"status\": {"
                    "\"name\": \"%s\", "
                    "\"operation\": \"Enable\", "
                    "\"status\": \"%s\", "
                    "\"code\": \"%b\", "
                    "\"formattedMessage\": {"
                      "\"lang\": \"en-US\", "
                      "\"message\": \"%b\""
                    "}"
                  "}, "
                  "\"version\": 1.0, "
                  "\"timestampUTC\": \"%d-%02d-%02dT%02d:%02d:%02dZ\""
                "}, "
                "\"sequenceNumber\": %d"
              "}"
            "}", first ? sstring_empty() : ss("," ), ext->name, ext->version, ext->name,
                is_ok(s) ? ss("success") : ss("error"), is_ok(s) ? ok_code : get(s, sym(code)),
                is_ok(s) ? ok_message : get(s, sym(result)), 1900 + tm.tm_year, 1 + tm.tm_mon,
                tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, ext->cfg_seqno);
        first = false;
    }
    spin_unlock(&az->lock);
    if (!buffer_write_cstring(blob, "]}}")) {
        s = timm_oom;
        goto done;
    }

    /* Pad the blob until its size is a multiple of 512, as required by the Azure page blob storage
     * API. */
    u64 blob_size = buffer_length(blob);
    u64 padded_size = pad(blob_size, 512);
    while (blob_size++ < padded_size)
        push_u8(blob, ' ');

    buffer_clear(&az->status_upload.blob_size);
    bprintf(&az->status_upload.blob_size, "%ld", padded_size);
    buffer_clear(&az->status_upload.blob_range);
    bprintf(&az->status_upload.blob_range, "bytes=0-%ld", padded_size - 1);
    az->status_upload.blob = blob;
    tuple req = az->status_upload.create_req;
    net_http_req_params req_params = &az->status_upload.params;
    req_params->host = buffer_to_sstring(&az->status_upload.host);
    req_params->req = req;
    req_params->body = 0;
    req_params->resp_handler = (value_handler)&az->status_upload.vh;
    s = net_http_req(req_params);
  done:
    if (!is_ok(s)) {
        msg_err("%s error %v", func_ss, s);
        timm_dealloc(s);
        deallocate_buffer(blob);
    }
}

closure_func_basic(value_handler, void, az_get_ext_vh,
                   value v)
{
    azure_get_ext_data req_data = struct_from_closure(azure_get_ext_data, vh);
    azure az = req_data->az;
    deallocate_buffer(req_data->query);
    deallocate_value(req_data->req);
    deallocate(az->h, req_data, sizeof(*req_data));
    if (!v) {
        msg_err("%s: failed to get response", func_ss);
        return;
    }
    buffer content = get(v, sym(content));
    if (content) {
        struct xml_elem blob;
        if (!xml_get_elem(content, ss("StatusUploadBlob"), &blob))
            goto parse_error;
        bytes offset = sizeof("https://") - 1;
        if (blob.data_len <= offset)
            goto parse_error;
        blob.data_start += offset;
        blob.data_len -= offset;
        void *ptr = runtime_strchr(isstring(buffer_ref(content, blob.data_start), blob.data_len),
                                   '/');
        if (!ptr)
            goto parse_error;
        offset = ptr - buffer_ref(content, blob.data_start);
        buffer_clear(&az->status_upload.host);
        if (!buffer_write(&az->status_upload.host, buffer_ref(content, blob.data_start), offset))
            goto alloc_error;
        blob.data_start += offset;
        blob.data_len -= offset;
        buffer_clear(&az->status_upload.create_query);

        /* replace occurrences of "&amp;" with "&" */
        while ((ptr = runtime_strstr(isstring(buffer_ref(content, blob.data_start), blob.data_len),
                                     ss("&amp;")))) {
            offset = ptr - buffer_ref(content, blob.data_start);
            if (!buffer_write(&az->status_upload.create_query, buffer_ref(content, blob.data_start),
                              offset + 1))
                goto alloc_error;
            offset += sizeof("&amp;") - 1;
            blob.data_start += offset;
            blob.data_len -= offset;
        }
        if ((blob.data_len > 0) &&
            !buffer_write(&az->status_upload.create_query, buffer_ref(content, blob.data_start),
                          blob.data_len))
            goto alloc_error;

        buffer_clear(&az->status_upload.data_query);
        if (!push_buffer(&az->status_upload.data_query, &az->status_upload.create_query) ||
            !buffer_write_cstring(&az->status_upload.data_query, "&comp=page"))
            goto alloc_error;
        struct xml_elem ext_settings;
        if (xml_get_elem(content, ss("PluginSettings"), &ext_settings)) {
            buffer settings = alloca_wrap_buffer(buffer_ref(content, ext_settings.data_start),
                                                 ext_settings.data_len);
            struct xml_elem plugin;
            struct buffer seqno_b;
            while (xml_get_elem(settings, ss("Plugin"), &plugin)) {
                bytes ext_name_start, ext_name_len;
                if (!xml_elem_get_attr(settings, &plugin, ss("name"),
                                       &ext_name_start, &ext_name_len)) {
                    buffer_consume(settings, plugin.start + plugin.len);
                    continue;
                }
                char *ext_name = buffer_ref(settings, ext_name_start);
                buffer_consume(settings, plugin.data_start);
                struct xml_elem rtsettings;
                if (!xml_get_elem(settings, ss("RuntimeSettings"), &rtsettings))
                    goto next;
                bytes seqno_start, seqno_len;
                u64 seqno;
                if (!xml_elem_get_attr(settings, &rtsettings, ss("seqNo"),
                                       &seqno_start, &seqno_len))
                    goto next;
                init_buffer(&seqno_b, seqno_len, true, 0, buffer_ref(settings, seqno_start));
                buffer_produce(&seqno_b, seqno_len);
                if (!parse_int(&seqno_b, 10, &seqno))
                    goto next;
                azure_ext ext;
                spin_lock(&az->lock);
                vector_foreach(az->extensions, ext) {
                    if ((ext_name_len == ext->name.len) &&
                        !runtime_memcmp(ext_name, ext->name.ptr, ext_name_len)) {
                        ext->cfg_seconds = sec_from_timestamp(kern_now(CLOCK_ID_REALTIME));
                        ext->cfg_seqno = seqno;
                        timm_dealloc(ext->s);
                        ext->s = STATUS_OK;
                    }
                }
                spin_unlock(&az->lock);
              next:
                buffer_consume(settings, plugin.len - (plugin.data_start - plugin.start));
            }
        }
        az->status_upload.valid = true;
        az_report_status(az);
        return;
    }
  parse_error:
    msg_err("%s: failed to parse response", func_ss);
    return;
  alloc_error:
    msg_err("%s: out of memory", func_ss);
}

static void az_get_ext_config(azure az)
{
    heap h = az->h;
    status s;
    buffer query = INVALID_ADDRESS;
    tuple req = INVALID_ADDRESS;
    azure_get_ext_data req_data = allocate(h, sizeof(*req_data));
    if (req_data == INVALID_ADDRESS) {
        s = timm_oom;
        goto error;
    }
    req = allocate_tuple();
    if (req == INVALID_ADDRESS) {
        s = timm_oom;
        goto error;
    }
    query = allocate_buffer(az->h, 256);
    if (query == INVALID_ADDRESS) {
        s = timm_oom;
        goto error;
    }
    req_data->az = az;
    struct net_http_req_params req_params;
    req_params.host = AZURE_WIRESERVER_ADDR;
    req_params.port = 80;
    req_params.tls = false;
    req_params.method = HTTP_REQUEST_METHOD_GET;
    bprintf(query, "/machine/%s/%s?comp=config&type=extensionsConfig&incarnation=%b",
            isstring(az->container_id, az->container_id_len),
            isstring(az->instance_id, az->instance_id_len), &az->goalstate_incarnation);
    req_data->query = query;
    set(req, sym_this("url"), query);
    set(req, sym_this("x-ms-version"), &az->ms_version);
    req_data->req = req_params.req = req;
    req_params.body = 0;
    req_params.resp_handler = init_closure_func(&req_data->vh, value_handler, az_get_ext_vh);
    s = net_http_req(&req_params);
    if (is_ok(s))
        return;
  error:
    if (query != INVALID_ADDRESS)
        deallocate_buffer(query);
    if (req != INVALID_ADDRESS)
        deallocate_value(req);
    if (req_data != INVALID_ADDRESS)
        deallocate(h, req_data, sizeof(*req_data));
    if (!is_ok(s)) {
        msg_err("%s error %v", func_ss, s);
        timm_dealloc(s);
    }
}

closure_func_basic(value_handler, void, az_status_upload_vh,
                   value v)
{
    azure az = struct_from_closure(azure, status_upload.vh);
    if (!v) {
        msg_err("%s: failed to get response", func_ss);
        return;
    }
    value start_line = get(v, sym(start_line));
    buffer status_code = get(start_line, integer_key(1));
    if (status_code && !buffer_strcmp(status_code, "201")) {
        tuple req = az->status_upload.data_req;
        net_http_req_params req_params = &az->status_upload.params;
        req_params->req = req;
        req_params->body = az->status_upload.blob;
        req_params->resp_handler = 0;
        status s = net_http_req(req_params);
        if (is_ok(s)) {
            az->status_upload.last_update = kern_now(CLOCK_ID_REALTIME);
        } else {
            msg_err("%s: failed to upload blob page: %v", func_ss, s);
            timm_dealloc(s);
            deallocate_buffer(req_params->body);
        }
    } else {
        msg_err("%s: unexpected response %v", func_ss, v);
    }
}

closure_func_basic(value_handler, void, az_goalstate_vh,
                   value v)
{
    azure az = struct_from_closure(azure, goalstate_vh);
    az->goalstate_pending = false;
    if (!v) {
        msg_err("%s: failed to get response", func_ss);
        return;
    }
    buffer content = get(v, sym(content));
    if (content) {
        struct xml_elem elem;
        if (!xml_get_elem(content, ss("Incarnation"), &elem))
            goto exit;
        boolean new_incarnation =
            (buffer_memcmp(&az->goalstate_incarnation, buffer_ref(content, elem.data_start),
                           elem.data_len) != 0);
        if (new_incarnation) {
            buffer_clear(&az->goalstate_incarnation);
            if (!buffer_write(&az->goalstate_incarnation, buffer_ref(content, elem.data_start),
                              elem.data_len))
                goto exit;
            if (az->container_id_len == 0) {
                if (!xml_get_elem(content, ss("ContainerId"), &elem) ||
                    (elem.data_len > sizeof(az->container_id)))
                        goto exit;
                runtime_memcpy(az->container_id, buffer_ref(content, elem.data_start),
                               elem.data_len);
                az->container_id_len = elem.data_len;
            }
            if (az->instance_id_len == 0) {
                if (!xml_get_elem(content, ss("InstanceId"), &elem) ||
                    (elem.data_len > sizeof(az->instance_id)))
                    goto exit;
                runtime_memcpy(az->instance_id, buffer_ref(content, elem.data_start),
                               elem.data_len);
                az->instance_id_len = elem.data_len;
            }
        }
        if (!az->provisioned)
            azure_report_ready(az);
        if (new_incarnation) {
            az->status_upload.valid = false;
            az_get_ext_config(az);
        } else if (az->status_upload.valid &&
                (kern_now(CLOCK_ID_REALTIME) - az->status_upload.last_update > seconds(60))) {
            az_report_status(az);
        }
        return;
    }
  exit:
    msg_err("%s: failed to parse response %v", func_ss, v);
}

closure_func_basic(value_handler, void, az_ready_vh,
                   value v)
{
    azure_ready_data req_data = struct_from_closure(azure_ready_data, vh);
    azure az = req_data->az;
    deallocate_value(req_data->req);
    deallocate(az->h, req_data, sizeof(*req_data));
    if (v)
        az->provisioned = true;
}

static void azure_report_ready(azure az)
{
    status s;
    heap h = az->h;
    buffer req_body = INVALID_ADDRESS;
    tuple req = INVALID_ADDRESS;
    azure_ready_data req_data = allocate(h, sizeof(*req_data));
    if (req_data == INVALID_ADDRESS) {
        s = timm_oom;
        goto error;
    }
    req = allocate_tuple();
    if (req == INVALID_ADDRESS) {
        s = timm_oom;
        goto error;
    }
    req_body = allocate_buffer(az->h, 512);
    if (req_body == INVALID_ADDRESS) {
        s = timm_oom;
        goto error;
    }
    req_data->az = az;
    struct net_http_req_params req_params;
    req_params.host = AZURE_WIRESERVER_ADDR;
    req_params.port = 80;
    req_params.tls = false;
    req_params.method = HTTP_REQUEST_METHOD_POST;
    buffer_init_from_string(&req_data->query, "/machine?comp=health");
    set(req, sym_this("url"), &req_data->query);
    set(req, sym_this("x-ms-version"), &az->ms_version);
    buffer_init_from_string(&req_data->content_type, "text/xml;charset=utf-8");
    set(req, sym_this("Content-Type"), &req_data->content_type);
    req_data->req = req_params.req = req;
    bprintf(req_body, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
                      "<Health xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
                      " xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">\n"
                      "  <GoalStateIncarnation>%b</GoalStateIncarnation>\n"
                      "  <Container>\n"
                      "    <ContainerId>%s</ContainerId>\n"
                      "    <RoleInstanceList>\n"
                      "      <Role>\n"
                      "        <InstanceId>%s</InstanceId>\n"
                      "        <Health>\n"
                      "          <State>Ready</State>\n"
                      "        </Health>\n"
                      "      </Role>\n"
                      "    </RoleInstanceList>\n"
                      "  </Container>\n"
                      "</Health>\n",
            &az->goalstate_incarnation,
            isstring(az->container_id, az->container_id_len),
            isstring(az->instance_id, az->instance_id_len));
    req_params.body = req_body;
    req_params.resp_handler = init_closure_func(&req_data->vh, value_handler, az_ready_vh);
    s = net_http_req(&req_params);
    if (is_ok(s))
        return;
  error:
    if (req_body != INVALID_ADDRESS)
        deallocate_buffer(req_body);
    if (req != INVALID_ADDRESS)
        deallocate_value(req);
    if (req_data != INVALID_ADDRESS)
        deallocate(h, req_data, sizeof(*req_data));
    if (!is_ok(s)) {
        timm_dealloc(s);
    }
}

static void az_status_upload_init(azure az)
{
    heap h = az->h;
    init_buffer(&az->status_upload.host, 0, false, h, 0);
    init_buffer(&az->status_upload.create_query, 0, false, h, 0);
    init_buffer(&az->status_upload.data_query, 0, false, h, 0);
    init_buffer(&az->status_upload.blob_size, 0, false, h, 0);
    init_buffer(&az->status_upload.blob_range, 0, false, h, 0);

    /* Put Blob request */
    tuple req = allocate_tuple();
    assert(req != INVALID_ADDRESS);
    set(req, sym_this("url"), &az->status_upload.create_query);
    set(req, sym_this("x-ms-version"), &az->ms_version);
    buffer_init_from_string(&az->status_upload.blob_type, "PageBlob");
    set(req, sym_this("x-ms-blob-type"), &az->status_upload.blob_type);
    set(req, sym_this("x-ms-blob-content-length"), &az->status_upload.blob_size);
    az->status_upload.create_req = req;

    /* Put Page request */
    req = allocate_tuple();
    assert(req != INVALID_ADDRESS);
    set(req, sym_this("url"), &az->status_upload.data_query);
    set(req, sym_this("x-ms-version"), &az->ms_version);
    buffer_init_from_string(&az->status_upload.content_type, "application/json");
    set(req, sym_this("Content-Type"), &az->status_upload.content_type);
    buffer_init_from_string(&az->status_upload.page_write, "update");
    set(req, sym_this("x-ms-page-write"), &az->status_upload.page_write);
    set(req, sym_this("x-ms-range"), &az->status_upload.blob_range);
    az->status_upload.data_req = req;

    net_http_req_params params = &az->status_upload.params;
    params->port = 443;
    params->tls = true;
    params->method = HTTP_REQUEST_METHOD_PUT;
    init_closure_func(&az->status_upload.vh, value_handler, az_status_upload_vh);
    az->status_upload.valid = false;
}

boolean azure_cloud_init(heap h)
{
    azure az = allocate(h, sizeof(*az));
    if (az == INVALID_ADDRESS)
        return false;
    az->h = h;
    buffer_init_from_string(&az->ms_version, AZURE_MS_VERSION);
    buffer_init_from_string(&az->goalstate_query, "/machine?comp=goalstate");
    init_buffer(&az->goalstate_incarnation, 0, false, h, 0);
    net_http_req_params params = &az->goalstate_req_params;
    params->host = AZURE_WIRESERVER_ADDR;
    params->port = 80;
    params->tls = false;
    params->method = HTTP_REQUEST_METHOD_GET;
    tuple req = allocate_tuple();
    assert(req != INVALID_ADDRESS);
    set(req, sym_this("url"), &az->goalstate_query);
    set(req, sym_this("x-ms-version"), &az->ms_version);
    params->req = req;
    params->body = 0;
    params->resp_handler = init_closure_func(&az->goalstate_vh, value_handler, az_goalstate_vh);
    az->extensions = allocate_vector(h, 1);
    assert(az->extensions != INVALID_ADDRESS);
    spin_lock_init(&az->lock);
    az->container_id_len = az->instance_id_len = 0;
    az->goalstate_pending = az->provisioned = false;
    /* Do not print error messages if the Azure Wire Server is unreachable just after instance
     * startup (a few seconds may elapse before the network interface acquires a DHCP address). */
    az->goalstate_print_errors = false;
    az_status_upload_init(az);
    init_timer(&az->report_timer);
    register_timer(kernel_timers, &az->report_timer, CLOCK_ID_MONOTONIC, seconds(2), false,
                   seconds(16), init_closure_func(&az->report_th, timer_handler, az_report_th));
    az_agent = az;
    return true;
}

boolean azure_register_ext(azure_ext ext)
{
    if (!az_agent)
        return false;
    ext->cfg_seconds = 0;   /* so that it's not included in status reports */
    ext->s = STATUS_OK;
    spin_lock(&az_agent->lock);
    vector_push(az_agent->extensions, ext);
    spin_unlock(&az_agent->lock);
    return true;
}
