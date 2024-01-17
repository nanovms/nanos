#include <kernel.h>
#include <http.h>
#include <lwip.h>

#define AZURE_MS_VERSION    "2012-11-30"

declare_closure_struct(1, 2, void, report_ready_func,
    struct azure *, az,
    u64, expiry, u64, overruns);

typedef struct azure {
    heap h;
    char container_id[64];
    bytes container_id_len;
    char instance_id[64];
    bytes instance_id_len;
    timestamp report_backoff;
    struct timer report_timer;
    closure_struct(report_ready_func, report_ready);
} *azure;

static void azure_report_ready(azure az);

define_closure_function(1, 2, void, report_ready_func,
                        azure, az,
                        u64, expiry, u64, overruns)
{
    if (overruns != timer_disabled)
        azure_report_ready(bound(az));
}

static void azure_report_retry(azure az)
{
    register_timer(kernel_timers, &az->report_timer, CLOCK_ID_MONOTONIC, az->report_backoff, false, 0,
        init_closure(&az->report_ready, report_ready_func, az));
    if (az->report_backoff < seconds(600))
        az->report_backoff <<= 1;
}

closure_function(2, 1, void, wireserver_parse_resp,
                 azure, az, buffer_handler, out,
                 value, v)
{
    azure az = bound(az);
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
    }
  exit:
    apply(bound(out), 0);
    closure_finish();
}

closure_function(3, 1, boolean, wireserver_get_resp,
                 azure, az, buffer_handler, out, buffer_handler, parser,
                 buffer, data)
{
    if (data) {
        if (apply(bound(parser), data) != STATUS_OK) {
            azure_report_retry(bound(az));
            return true;
        }
    } else {
        closure_finish();
    }
    return false;
}

closure_function(1, 1, input_buffer_handler, wireserver_get_ch,
                 azure, az,
                 buffer_handler, out)
{
    azure az = bound(az);
    value_handler vh = INVALID_ADDRESS;
    buffer_handler parser = INVALID_ADDRESS;
    input_buffer_handler in = INVALID_ADDRESS;
    if (out) {    /* connection succeeded */
        tuple req = allocate_tuple();
        if (req == INVALID_ADDRESS)
            goto exit;
        set(req, sym(url), alloca_wrap_cstring("/machine?comp=goalstate"));
        set(req, sym(Host), alloca_wrap_cstring("168.63.129.16"));
        set(req, sym(x-ms-version), alloca_wrap_cstring(AZURE_MS_VERSION));
        vh = closure(az->h, wireserver_parse_resp, az, out);
        if (vh == INVALID_ADDRESS)
            goto exit;
        buffer_handler parser = allocate_http_parser(az->h, vh);
        if (parser == INVALID_ADDRESS)
            goto exit;
        status s = http_request(az->h, out, HTTP_REQUEST_METHOD_GET, req, 0);
        deallocate_value(req);
        if (is_ok(s))
            in = closure(az->h, wireserver_get_resp, az, out, parser);
        else
            timm_dealloc(s);
    }
  exit:
    closure_finish();
    if (in == INVALID_ADDRESS) {
        if (vh != INVALID_ADDRESS)
            deallocate_closure(vh);
        if (parser != INVALID_ADDRESS)
            apply(parser, 0);
        azure_report_retry(az);
    }
    return in;
}

closure_function(1, 1, boolean, wireserver_post_resp,
                 buffer_handler, out,
                 buffer, data)
{
    if (data) {
        apply(bound(out), 0);
        return true;
    } else {
        closure_finish();
        return false;
    }
}

closure_function(1, 1, input_buffer_handler, wireserver_post_ch,
                 azure, az,
                 buffer_handler, out)
{
    azure az = bound(az);
    input_buffer_handler in = INVALID_ADDRESS;
    if (out) {    /* connection succeeded */
        tuple req = allocate_tuple();
        if (req == INVALID_ADDRESS)
            goto exit;
        buffer b = allocate_buffer(az->h, 512);
        if (b == INVALID_ADDRESS) {
            deallocate_value(req);
            goto exit;
        }
        set(req, sym(url), alloca_wrap_cstring("/machine?comp=health"));
        set(req, sym(Host), alloca_wrap_cstring("168.63.129.16"));
        set(req, sym(x-ms-version), alloca_wrap_cstring(AZURE_MS_VERSION));
        set(req, sym(Content-Type), alloca_wrap_cstring("text/xml;charset=utf-8"));
        bprintf(b, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
                <Health xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\
                xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">\n\
                  <GoalStateIncarnation>1</GoalStateIncarnation>\n\
                  <Container>\n\
                    <ContainerId>%s</ContainerId>\n\
                    <RoleInstanceList>\n\
                      <Role>\n\
                        <InstanceId>%s</InstanceId>\n\
                        <Health>\n\
                          <State>Ready</State>\n\
                        </Health>\n\
                      </Role>\n\
                    </RoleInstanceList>\n\
                  </Container>\n\
                </Health>\n",
                isstring(az->container_id, az->container_id_len),
                isstring(az->instance_id, az->instance_id_len));
        status s = http_request(az->h, out, HTTP_REQUEST_METHOD_POST, req, b);
        deallocate_value(req);
        if (is_ok(s))
            in = closure(az->h, wireserver_post_resp, out);
        else
            timm_dealloc(s);
    }
  exit:
    closure_finish();
    if (in == INVALID_ADDRESS)
        azure_report_retry(az);
    return in;
}


static void azure_report_ready(azure az)
{
    connection_handler ch;
    if (!az->instance_id_len)
        ch = closure(az->h, wireserver_get_ch, az);
    else
        ch = closure(az->h, wireserver_post_ch, az);
    if (ch == INVALID_ADDRESS)
        return;
    ip_addr_t wireserver_addr = IPADDR4_INIT_BYTES(168, 63, 129, 16);
    status s = direct_connect(az->h, &wireserver_addr, 80, ch);
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
    az->container_id_len = az->instance_id_len = 0;
    az->report_backoff = seconds(1);
    init_timer(&az->report_timer);
    azure_report_ready(az);
    return true;
}
