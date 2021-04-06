#include <kernel.h>
#include <http.h>
#include <lwip.h>

#define AZURE_MS_VERSION    "2012-11-30"

declare_closure_struct(1, 1, void, report_ready_func,
    struct azure *, az,
    u64, overruns);

typedef struct azure {
    heap h;
    char container_id[64];
    char instance_id[64];
    timestamp report_backoff;
    closure_struct(report_ready_func, report_ready);
    tuple (*allocate_tuple)(void);
    void (*set)(value z, void *c, void *v);
    void *(*get)(value z, void *c);
    void (*deallocate_tuple)(tuple t);
    void (*destruct_tuple)(tuple t, boolean recursive);
    void (*timm_dealloc)(tuple t);
    symbol (*intern)(string name);
    buffer (*allocate_buffer)(heap h, bytes s);
    boolean (*buffer_read)(buffer b, void *dest, bytes length);
    int (*buffer_strstr)(buffer b, const char *str);
    void (*bprintf)(buffer b, const char *fmt, ...);
    timer (*register_timer)(clock_id id, timestamp val, boolean absolute,
            timestamp interval, timer_handler n);
    status (*direct_connect)(heap h, ip_addr_t *addr, u16 port, connection_handler ch);
    status (*http_request)(heap h, buffer_handler bh, http_method method,
            tuple headers, buffer body);
    buffer_handler (*allocate_http_parser)(heap h, value_handler each);
} *azure;

#undef sym
#define sym(name)   sym_intern(name, az->intern)

static void azure_report_ready(azure az);

define_closure_function(1, 1, void, report_ready_func,
                        azure, az,
                        u64, overruns)
{
    azure_report_ready(bound(az));
}

static void azure_report_retry(azure az)
{
    az->register_timer(CLOCK_ID_MONOTONIC, az->report_backoff, false, 0,
        init_closure(&az->report_ready, report_ready_func, az));
    if (az->report_backoff < seconds(600))
        az->report_backoff <<= 1;
}

closure_function(1, 1, void, wireserver_parse_resp,
                 azure, az,
                 value, v)
{
    azure az = bound(az);
    buffer content = az->get(v, sym(content));
    if (content) {
        int index = az->buffer_strstr(content, "<ContainerId>");
        if (index < 0)
            goto exit;
        buffer_consume(content, index);
        buffer_consume(content, buffer_strchr(content, '>') + 1);
        index = buffer_strchr(content, '<');
        if (index < 0)
            goto exit;
        if (index >= sizeof(az->container_id))
            goto exit;
        az->buffer_read(content, az->container_id, index);
        az->container_id[index] = '\0';
        index = az->buffer_strstr(content, "<InstanceId>");
        if (index < 0)
            goto exit;
        buffer_consume(content, index);
        buffer_consume(content, buffer_strchr(content, '>') + 1);
        index = buffer_strchr(content, '<');
        if (index < 0)
            goto exit;
        if (index >= sizeof(az->instance_id))
            goto exit;
        az->buffer_read(content, az->instance_id, index);
        az->instance_id[index] = '\0';
        azure_report_ready(az);
    }
  exit:
    az->destruct_tuple(v, true);
    closure_finish();
}

closure_function(2, 1, status, wireserver_get_resp,
                 azure, az, buffer_handler, out,
                 buffer, data)
{
    if (data) {
        azure az = bound(az);
        heap h = az->h;
        boolean success = false;
        value_handler vh = closure(h, wireserver_parse_resp, az);
        if (vh != INVALID_ADDRESS) {
            buffer_handler parser = az->allocate_http_parser(h, vh);
            if (parser != INVALID_ADDRESS) {
                apply(parser, data);
                success = true;
            }
        }
        apply(bound(out), 0);
        if (!success)
            azure_report_retry(az);
    } else {
        closure_finish();
    }
    return STATUS_OK;
}

closure_function(1, 1, buffer_handler, wireserver_get_ch,
                 azure, az,
                 buffer_handler, out)
{
    azure az = bound(az);
    buffer_handler in = INVALID_ADDRESS;
    if (out) {    /* connection succeeded */
        tuple req = az->allocate_tuple();
        if (req == INVALID_ADDRESS)
            goto exit;
        az->set(req, sym(url), alloca_wrap_cstring("/machine?comp=goalstate"));
        az->set(req, sym(Host), alloca_wrap_cstring("168.63.129.16"));
        az->set(req, sym(x-ms-version), alloca_wrap_cstring(AZURE_MS_VERSION));
        status s = az->http_request(az->h, out, HTTP_REQUEST_METHOD_GET, req, 0);
        az->deallocate_tuple(req);
        if (is_ok(s))
            in = closure(az->h, wireserver_get_resp, az, out);
        else
            az->timm_dealloc(s);
    }
  exit:
    closure_finish();
    if (in == INVALID_ADDRESS)
        azure_report_retry(az);
    return in;
}

closure_function(1, 1, status, wireserver_post_resp,
                 buffer_handler, out,
                 buffer, data)
{
    if (data)
        apply(bound(out), 0);
    else
        closure_finish();
    return STATUS_OK;
}

closure_function(1, 1, buffer_handler, wireserver_post_ch,
                 azure, az,
                 buffer_handler, out)
{
    azure az = bound(az);
    buffer_handler in = INVALID_ADDRESS;
    if (out) {    /* connection succeeded */
        tuple req = az->allocate_tuple();
        if (req == INVALID_ADDRESS)
            goto exit;
        buffer b = az->allocate_buffer(az->h, 512);
        if (b == INVALID_ADDRESS) {
            az->deallocate_tuple(req);
            goto exit;
        }
        az->set(req, sym(url), alloca_wrap_cstring("/machine?comp=health"));
        az->set(req, sym(Host), alloca_wrap_cstring("168.63.129.16"));
        az->set(req, sym(x-ms-version), alloca_wrap_cstring(AZURE_MS_VERSION));
        az->set(req, sym(Content-Type), alloca_wrap_cstring("text/xml;charset=utf-8"));
        az->bprintf(b, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
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
                </Health>\n", az->container_id, az->instance_id);
        status s = az->http_request(az->h, out, HTTP_REQUEST_METHOD_POST, req, b);
        az->deallocate_tuple(req);
        if (is_ok(s))
            in = closure(az->h, wireserver_post_resp, out);
        else
            az->timm_dealloc(s);
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
    if (!az->instance_id[0])
        ch = closure(az->h, wireserver_get_ch, az);
    else
        ch = closure(az->h, wireserver_post_ch, az);
    if (ch == INVALID_ADDRESS)
        return;
    ip_addr_t wireserver_addr = IPADDR4_INIT_BYTES(168, 63, 129, 16);
    status s = az->direct_connect(az->h, &wireserver_addr, 80, ch);
    if (!is_ok(s)) {
        az->timm_dealloc(s);
        azure_report_retry(az);
    }
}

boolean azure_cloud_init(heap h, klib_get_sym get_sym)
{
    azure az = allocate(h, sizeof(*az));
    if (az == INVALID_ADDRESS)
        return false;
    if (!(az->allocate_tuple = get_sym("allocate_tuple")) ||
            !(az->set = get_sym("set")) ||
            !(az->get = get_sym("get")) ||
            !(az->deallocate_tuple = get_sym("deallocate_tuple")) ||
            !(az->destruct_tuple = get_sym("destruct_tuple")) ||
            !(az->timm_dealloc = get_sym("timm_dealloc")) ||
            !(az->intern = get_sym("intern")) ||
            !(az->allocate_buffer = get_sym("allocate_buffer")) ||
            !(az->buffer_read = get_sym("buffer_read")) ||
            !(az->buffer_strstr = get_sym("buffer_strstr")) ||
            !(az->bprintf = get_sym("bprintf")) ||
            !(az->register_timer = get_sym("kern_register_timer")) ||
            !(az->direct_connect = get_sym("direct_connect")) ||
            !(az->http_request = get_sym("http_request")) ||
            !(az->allocate_http_parser = get_sym("allocate_http_parser"))) {
        deallocate(h, az, sizeof(*az));
        return false;
    }
    az->h = h;
    az->container_id[0] = az->instance_id[0] = '\0';
    az->report_backoff = seconds(1);
    azure_report_ready(az);
    return true;
}
