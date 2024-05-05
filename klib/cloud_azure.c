#include <kernel.h>
#include <lwip.h>
#include <net_utils.h>

#define AZURE_MS_VERSION    "2012-11-30"

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
    timestamp report_backoff;
    struct timer report_timer;
    closure_struct(timer_handler, report_ready);
} *azure;

typedef struct azure_ready_data {
    azure az;
    struct buffer query;
    struct buffer content_type;
    tuple req;
    closure_struct(value_handler, vh);
} *azure_ready_data;

static void azure_report_ready(azure az);

closure_func_basic(timer_handler, void, report_ready_func,
                   u64 expiry, u64 overruns)
{
    azure az = struct_from_closure(azure, report_ready);
    if (overruns != timer_disabled)
        azure_report_ready(az);
}

static void azure_report_retry(azure az)
{
    register_timer(kernel_timers, &az->report_timer, CLOCK_ID_MONOTONIC, az->report_backoff, false, 0,
        init_closure_func(&az->report_ready, timer_handler, report_ready_func));
    if (az->report_backoff < seconds(600))
        az->report_backoff <<= 1;
}

closure_func_basic(value_handler, void, az_goalstate_vh,
                   value v)
{
    azure az = struct_from_closure(azure, goalstate_vh);
    if (!v) {
        azure_report_retry(az);
        return;
    }
    buffer content = get(v, sym(content));
    if (content) {
        int index = buffer_strstr(content, ss("<ContainerId>"));
        if (index < 0)
            goto exit;
        buffer_consume(content, index);
        buffer_consume(content, buffer_strchr(content, '>') + 1);
        index = buffer_strchr(content, '<');
        if (index < 0)
            goto exit;
        if (index > sizeof(az->container_id))
            goto exit;
        buffer_read(content, az->container_id, index);
        az->container_id_len = index;
        index = buffer_strstr(content, ss("<InstanceId>"));
        if (index < 0)
            goto exit;
        buffer_consume(content, index);
        buffer_consume(content, buffer_strchr(content, '>') + 1);
        index = buffer_strchr(content, '<');
        if (index < 0)
            goto exit;
        if (index > sizeof(az->instance_id))
            goto exit;
        buffer_read(content, az->instance_id, index);
        az->instance_id_len = index;
        azure_report_ready(az);
        return;
    }
  exit:
    msg_err("failed to parse response %v\n", v);
}

closure_func_basic(value_handler, void, az_ready_vh,
                   value v)
{
    azure_ready_data req_data = struct_from_closure(azure_ready_data, vh);
    azure az = req_data->az;
    deallocate_value(req_data->req);
    deallocate(az->h, req_data, sizeof(*req_data));
    if (!v)
        azure_report_retry(az);
}

static void azure_report_ready(azure az)
{
    status s;
    if (!az->instance_id_len) {
        s = net_http_req(&az->goalstate_req_params);
        goto exit;
    }
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
                      "  <GoalStateIncarnation>1</GoalStateIncarnation>\n"
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
  exit:
    if (!is_ok(s)) {
        timm_dealloc(s);
        azure_report_retry(az);
    }
}

boolean azure_cloud_init(heap h)
{
    azure az = allocate(h, sizeof(*az));
    if (az == INVALID_ADDRESS)
        return false;
    az->h = h;
    buffer_init_from_string(&az->ms_version, AZURE_MS_VERSION);
    buffer_init_from_string(&az->goalstate_query, "/machine?comp=goalstate");
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
    az->container_id_len = az->instance_id_len = 0;
    az->report_backoff = seconds(1);
    init_timer(&az->report_timer);
    azure_report_ready(az);
    return true;
}
