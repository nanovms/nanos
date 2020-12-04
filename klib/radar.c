#include <kernel.h>
#include <http.h>
#include <lwip.h>

#define RADAR_HOSTNAME  "radar.relayered.net"
#define RADAR_PORT      443

#define RADAR_CA_CERT   "-----BEGIN CERTIFICATE-----\n\
MIIE0DCCA7igAwIBAgIBBzANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UEBhMCVVMx\
EDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNjb3R0c2RhbGUxGjAYBgNVBAoT\
EUdvRGFkZHkuY29tLCBJbmMuMTEwLwYDVQQDEyhHbyBEYWRkeSBSb290IENlcnRp\
ZmljYXRlIEF1dGhvcml0eSAtIEcyMB4XDTExMDUwMzA3MDAwMFoXDTMxMDUwMzA3\
MDAwMFowgbQxCzAJBgNVBAYTAlVTMRAwDgYDVQQIEwdBcml6b25hMRMwEQYDVQQH\
EwpTY290dHNkYWxlMRowGAYDVQQKExFHb0RhZGR5LmNvbSwgSW5jLjEtMCsGA1UE\
CxMkaHR0cDovL2NlcnRzLmdvZGFkZHkuY29tL3JlcG9zaXRvcnkvMTMwMQYDVQQD\
EypHbyBEYWRkeSBTZWN1cmUgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IC0gRzIwggEi\
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC54MsQ1K92vdSTYuswZLiBCGzD\
BNliF44v/z5lz4/OYuY8UhzaFkVLVat4a2ODYpDOD2lsmcgaFItMzEUz6ojcnqOv\
K/6AYZ15V8TPLvQ/MDxdR/yaFrzDN5ZBUY4RS1T4KL7QjL7wMDge87Am+GZHY23e\
cSZHjzhHU9FGHbTj3ADqRay9vHHZqm8A29vNMDp5T19MR/gd71vCxJ1gO7GyQ5HY\
pDNO6rPWJ0+tJYqlxvTV0KaudAVkV4i1RFXULSo6Pvi4vekyCgKUZMQWOlDxSq7n\
eTOvDCAHf+jfBDnCaQJsY1L6d8EbyHSHyLmTGFBUNUtpTrw700kuH9zB0lL7AgMB\
AAGjggEaMIIBFjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNV\
HQ4EFgQUQMK9J47MNIMwojPX+2yz8LQsgM4wHwYDVR0jBBgwFoAUOpqFBxBnKLbv\
9r0FQW4gwZTaD94wNAYIKwYBBQUHAQEEKDAmMCQGCCsGAQUFBzABhhhodHRwOi8v\
b2NzcC5nb2RhZGR5LmNvbS8wNQYDVR0fBC4wLDAqoCigJoYkaHR0cDovL2NybC5n\
b2RhZGR5LmNvbS9nZHJvb3QtZzIuY3JsMEYGA1UdIAQ/MD0wOwYEVR0gADAzMDEG\
CCsGAQUFBwIBFiVodHRwczovL2NlcnRzLmdvZGFkZHkuY29tL3JlcG9zaXRvcnkv\
MA0GCSqGSIb3DQEBCwUAA4IBAQAIfmyTEMg4uJapkEv/oV9PBO9sPpyIBslQj6Zz\
91cxG7685C/b+LrTW+C05+Z5Yg4MotdqY3MxtfWoSKQ7CC2iXZDXtHwlTxFWMMS2\
RJ17LJ3lXubvDGGqv+QqG+6EnriDfcFDzkSnE3ANkR/0yBOtg2DZ2HKocyQetawi\
DsoXiWJYRBuriSUBAA/NxBti21G00w9RKpv0vHP8ds42pM3Z2Czqrpv1KrKQ0U11\
GIo/ikGQI31bS/6kA1ibRrLDYGCD+H1QQc7CoZDDu+8CL9IVVO5EFdkKrqeKM+2x\
LXY2JtwE65/3YR8V3Idv7kaWKK2hJn0KCacuBKONvPi8BDAB\
-----END CERTIFICATE-----"

declare_closure_struct(0, 1, void, boot_timer_func,
    u64, overruns);

static struct telemetry {
    heap h;
    tuple env;
    buffer auth_header;
    s64 boot_id;
    timestamp boot_backoff;
    closure_struct(boot_timer_func, boot_func);
    void (*rprintf)(const char *format, ...);
    tuple (*allocate_tuple)(void);
    void (*table_set)(table z, void *c, void *v);
    void *(*table_find)(table z, void *c);
    void (*deallocate_table)(table t);
    void (*timm_dealloc)(tuple t);
    symbol (*intern)(string name);
    void *(*klib_sym)(klib kl, symbol s);
    buffer (*allocate_buffer)(heap h, bytes s);
    void (*buffer_write)(buffer b, const void *source, bytes length);
    void (*bprintf)(buffer b, const char *fmt, ...);
    timer (*register_timer)(clock_id id, timestamp val, boolean absolute,
            timestamp interval, timer_handler n);
    err_t (*dns_gethostbyname)(const char *hostname, ip_addr_t *addr,
            dns_found_callback found, void *callback_arg);
    status (*http_request)(heap h, buffer_handler bh, http_method method,
            tuple headers, buffer body);
    int (*tls_connect)(ip_addr_t *addr, u16 port, connection_handler ch);
} telemetry;

#undef sym
#define sym(name)   sym_intern(name, telemetry.intern)

#define kfunc(name) telemetry.name

/* To be used with literal strings only */
#define buffer_write_cstring(b, s)  kfunc(buffer_write)(b, s, sizeof(s) - 1)

static void telemetry_boot(void);

static void telemetry_dns_cb(const char *name, const ip_addr_t *ipaddr, void *callback_arg)
{
    connection_handler ch = (connection_handler)callback_arg;
    if (ipaddr) {
        if (telemetry.tls_connect((ip_addr_t *)ipaddr, RADAR_PORT, ch) == 0)
            return;
        else
            kfunc(rprintf)("Radar: failed to connect to server\n");
    } else {
        kfunc(rprintf)("Radar: failed to look up server hostname\n");
    }
    deallocate_closure(ch);
}

static boolean telemetry_req(const char *url, buffer data, buffer_handler bh)
{
    tuple req = kfunc(allocate_tuple)();
    if (req == INVALID_ADDRESS)
        return false;
    kfunc(table_set)(req, sym(url), alloca_wrap_cstring(url));
    kfunc(table_set)(req, sym(Host), alloca_wrap_cstring(RADAR_HOSTNAME));
    kfunc(table_set)(req, sym(Authorization), telemetry.auth_header);
    kfunc(table_set)(req, sym(Content-Type), alloca_wrap_cstring("application/json"));
    status s = kfunc(http_request)(telemetry.h, bh, HTTP_REQUEST_METHOD_POST, req, data);
    kfunc(deallocate_table)(req);
    if (is_ok(s)) {
        return true;
    } else {
        kfunc(timm_dealloc)(s);
        return false;
    }
}

closure_function(1, 1, status, telemetry_recv,
                 buffer_handler, out,
                 buffer, data)
{
    if (data)
        apply(bound(out), 0);   /* close connection */
    else   /* connection closed */
        closure_finish();
    return STATUS_OK;
}

closure_function(2, 1, buffer_handler, telemetry_ch,
                 const char *, url, buffer, data,
                 buffer_handler, out)
{
    buffer data = bound(data);
    buffer_handler in = 0;
    if (out) {
        boolean success = telemetry_req(bound(url), data, out);
        if (success)
            in = closure(telemetry.h, telemetry_recv, out);
        else
            deallocate_buffer(data);
    } else {    /* connection failed */
        deallocate_buffer(data);
    }
    closure_finish();
    return in;
}

boolean telemetry_send(const char *url, buffer data)
{
    connection_handler ch = closure(telemetry.h, telemetry_ch, url, data);
    if (ch == INVALID_ADDRESS)
        return false;
    ip_addr_t radar_addr;
    err_t err = kfunc(dns_gethostbyname)(RADAR_HOSTNAME, &radar_addr, telemetry_dns_cb, ch);
    switch (err) {
    case ERR_OK:
        if (telemetry.tls_connect(&radar_addr, RADAR_PORT, ch) == 0)
            return true;
        break;
    case ERR_INPROGRESS:
        return true;
    }
    deallocate_closure(ch);
    return false;
}

define_closure_function(0, 1, void, boot_timer_func,
                        u64, overruns)
{
    telemetry_boot();
}

static void telemetry_boot(void)
{
    buffer b = kfunc(allocate_buffer)(telemetry.h, 64);
    if (b == INVALID_ADDRESS)
        goto error;
    kfunc(bprintf)(b, "{\"id\":%ld", telemetry.boot_id);
    buffer nanos_ver = kfunc(table_find)(telemetry.env, sym(NANOS_VERSION));
    if (nanos_ver)
        kfunc(bprintf)(b, ",\"nanosVersion\":\"%b\"", nanos_ver);
    buffer ops_ver = kfunc(table_find)(telemetry.env, sym(OPS_VERSION));
    if (ops_ver)
        kfunc(bprintf)(b, ",\"opsVersion\":\"%b\"", ops_ver);
    buffer_write_cstring(b, "}\r\n");
    if (!telemetry_send("/boots/create", b)) {
        deallocate_buffer(b);
        goto error;
    }
    return;
  error:
    kfunc(register_timer)(CLOCK_ID_MONOTONIC, telemetry.boot_backoff, false, 0,
            init_closure(&telemetry.boot_func, boot_timer_func));
    if (telemetry.boot_backoff < seconds(600))
        telemetry.boot_backoff <<= 1;
}

closure_function(0, 2, void, tls_loaded,
                 klib, kl, status, s)
{
    closure_finish();
    if (is_ok(s)) {
        int (*tls_set_cacert)(void *, u64) = kfunc(klib_sym)(kl, sym(tls_set_cacert));
        if (tls_set_cacert(RADAR_CA_CERT, sizeof(RADAR_CA_CERT)) == 0) {
            telemetry.tls_connect = kfunc(klib_sym)(kl, sym(tls_connect));
            telemetry_boot();
        }
    } else {
        kfunc(timm_dealloc)(s);
    }
}

int init(void *md, klib_get_sym get_sym, klib_add_sym add_sym)
{
    telemetry.rprintf = get_sym("rprintf");
    if (!telemetry.rprintf)
        return KLIB_INIT_FAILED;
    void *(*get_kernel_heaps)(void) = get_sym("get_kernel_heaps");
    void *(*get_environment)(void) = get_sym("get_environment");
    u64 (*random_u64)(void) = get_sym("random_u64");
    void (*load_klib)(const char *, klib_handler) = get_sym("load_klib");
    if (!get_kernel_heaps || !get_environment || !random_u64 || !load_klib ||
            !(telemetry.allocate_tuple = get_sym("allocate_tuple")) ||
            !(telemetry.table_set = get_sym("table_set")) ||
            !(telemetry.table_find = get_sym("table_find")) ||
            !(telemetry.deallocate_table = get_sym("deallocate_table")) ||
            !(telemetry.timm_dealloc = get_sym("timm_dealloc")) ||
            !(telemetry.intern = get_sym("intern")) ||
            !(telemetry.klib_sym = get_sym("klib_sym")) ||
            !(telemetry.allocate_buffer = get_sym("allocate_buffer")) ||
            !(telemetry.buffer_write = get_sym("buffer_write")) ||
            !(telemetry.bprintf = get_sym("bprintf")) ||
            !(telemetry.register_timer = get_sym("kern_register_timer")) ||
            !(telemetry.dns_gethostbyname = get_sym("dns_gethostbyname")) ||
            !(telemetry.http_request = get_sym("http_request"))) {
        kfunc(rprintf)("Radar: kernel symbols not found\n");
        return KLIB_INIT_FAILED;
    }
    telemetry.h = heap_general(get_kernel_heaps());
    telemetry.auth_header = kfunc(allocate_buffer)(telemetry.h, 256);
    if (telemetry.auth_header == INVALID_ADDRESS)
        return KLIB_INIT_FAILED;
    klib_handler tls_handler = closure(telemetry.h, tls_loaded);
    if (tls_handler == INVALID_ADDRESS) {
        deallocate_buffer(telemetry.auth_header);
        return KLIB_INIT_FAILED;
    }
    telemetry.env = get_environment();
    kfunc(bprintf)(telemetry.auth_header, "Bearer %b",
            kfunc(table_find)(telemetry.env, sym(RADAR_KEY)));
    telemetry.boot_id = (s64)random_u64();
    telemetry.boot_backoff = seconds(1);
    load_klib("/klib/tls", tls_handler);
    return KLIB_INIT_OK;
}
