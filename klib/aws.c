#include <kernel.h>
#include <aws.h>
#include <http.h>
#include <lwip.h>

#define _RUNTIME_H_ /* guard against double inclusion of runtime.h */
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>

#define AWS_MD_SERVER   IPADDR4_INIT_BYTES(169, 254, 169, 254)

#define AWS_CRED_URI    "/latest/meta-data/iam/security-credentials"
#define AWS_HASH_ALGO   "AWS4-HMAC-SHA256"
#define AWS_REQ         "aws4_request"

closure_function(2, 1, void, aws_metadata_recv,
                 buffer_handler, handler, boolean *, done,
                 value, v)
{
    value resp = get(v, sym(start_line));
    buffer content = 0;
    if (resp) {
        buffer word;
        for (u64 i = 0; (word = get(resp, integer_key(i))); i++)
            if (!buffer_strcmp(word, "OK")) {
                content = get(v, sym(content));
                break;
            }
    }
    apply(bound(handler), content);
    *bound(done) = true;
}

closure_function(5, 1, boolean, aws_metadata_in,
                 heap, h, buffer_handler, handler, buffer_handler, out, buffer_handler, parser, boolean, done,
                 buffer, data)
{
    buffer_handler handler = bound(handler);
    buffer_handler out = bound(out);
    if (data) {
        if (bound(parser) == INVALID_ADDRESS) {
            heap h = bound(h);
            value_handler vh = closure(h, aws_metadata_recv, handler, &bound(done));
            if (vh == INVALID_ADDRESS) {
                msg_err("failed to allocate value handler\n");
                goto error;
            }
            bound(parser) = allocate_http_parser(h, vh);
            if (bound(parser) == INVALID_ADDRESS) {
                msg_err("failed to allocate HTTP parser\n");
                deallocate_closure(vh);
                goto error;
            }
        }
        status s = apply(bound(parser), data);
        if (is_ok(s)) {
            if (bound(done)) {
                apply(out, 0);
                return true;
            } else {
                return false;
            }
        } else {
            msg_err("failed to parse HTTP response: %v\n", s);
            timm_dealloc(s);
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
    apply(handler, 0);
    return true;
}

closure_function(3, 1, input_buffer_handler, aws_metadata_ch,
                 heap, h, sstring, uri, buffer_handler, handler,
                 buffer_handler, out)
{
    heap h = bound(h);
    buffer_handler handler = bound(handler);
    if (!out) {
        msg_err("failed to connect to server\n");
        goto error;
    }
    tuple req = allocate_tuple();
    if (req == INVALID_ADDRESS) {
        msg_err("failed to allocate request\n");
        goto error;
    }
    set(req, sym(url), alloca_wrap_sstring(bound(uri)));
    status s = http_request(h, out, HTTP_REQUEST_METHOD_GET, req, 0);
    deallocate_value(req);
    if (!is_ok(s)) {
        msg_err("failed to send HTTP request: %v\n", s);
        timm_dealloc(s);
        goto error;
    }
    closure_finish();
    return closure(h, aws_metadata_in, h, handler, out, INVALID_ADDRESS, false);
  error:
    closure_finish();
    apply(handler, 0);
    return INVALID_ADDRESS;
}

boolean aws_metadata_available(void)
{
    ip_addr_t md_server = AWS_MD_SERVER;
    struct netif *n = ip_route(&ip_addr_any, &md_server);
    if (n) {
        netif_unref(n);
        return true;
    }
    return false;
}

void aws_metadata_get(heap h, sstring uri, buffer_handler handler)
{
    ip_addr_t md_server = AWS_MD_SERVER;
    connection_handler ch = closure(h, aws_metadata_ch, h, uri, handler);
    if (ch != INVALID_ADDRESS) {
        status s = direct_connect(h, &md_server, 80, ch);
        if (is_ok(s))
            return;
        msg_err("failed to connect to server: %v\n", s);
        timm_dealloc(s);
    } else {
        msg_err("failed to allocate closure\n");
    }
    apply(handler, 0);
}

static boolean aws_cred_parse_item(buffer data, sstring name, buffer value)
{
    int ptr = buffer_strstr(data, name);
    if (ptr < 0)
        goto error;
    buffer_consume(data, ptr);
    ptr = buffer_strchr(data, ':');
    if (ptr < 0)
        goto error;
    buffer_consume(data, ptr);
    int value_start = buffer_strchr(data, '"');
    if (value_start < 0)
        goto error;
    buffer_consume(data, value_start + 1);
    int value_end = buffer_strchr(data, '"');
    if (value_end < 0)
        goto error;
    init_buffer(value, value_end, true, 0, buffer_ref(data, 0));
    buffer_produce(value, value_end);
    data->start = 0;    /* rewind buffer start, so that it can be re-used to parse other items */
    return true;
  error:
    msg_err("parsing of %s failed (%b)\n", name, data);
    return false;
}

closure_function(2, 1, status, aws_cred_parse,
                 buffer, uri, aws_cred_handler, handler,
                 buffer, data)
{
    deallocate_buffer(bound(uri));
    aws_cred_handler handler = bound(handler);
    closure_finish();
    struct aws_cred cred = {
        .access_key = alloca_wrap_buffer(0, 0),
        .secret = alloca_wrap_buffer(0, 0),
        .token = alloca_wrap_buffer(0, 0),
    };
    if (aws_cred_parse_item(data, ss("AccessKeyId"), cred.access_key) &&
        aws_cred_parse_item(data, ss("SecretAccessKey"), cred.secret) &&
        aws_cred_parse_item(data, ss("Token"), cred.token))
        apply(handler, &cred);
    else
        apply(handler, 0);
    return STATUS_OK;
}

closure_function(2, 1, status, aws_iam_role_get,
                 heap, h, aws_cred_handler, handler,
                 buffer, data)
{
    heap h = bound(h);
    aws_cred_handler handler = bound(handler);
    closure_finish();
    if (!data || (buffer_length(data) == 0)) {
        msg_err("no IAM role associated to instance\n");
        goto error;
    }
    buffer uri = wrap_string_cstring(AWS_CRED_URI);
    push_u8(uri, '/');
    if (!push_buffer(uri, data)) {
        msg_err("failed to build URI\n");
        deallocate_buffer(uri);
        goto error;
    }
    buffer_handler cred_parser = closure(h, aws_cred_parse, uri, handler);
    if (cred_parser != INVALID_ADDRESS) {
        aws_metadata_get(h, buffer_to_sstring(uri), cred_parser);
        return STATUS_OK;
    } else {
        msg_err("failed to allocate closure\n");
        deallocate_buffer(uri);
    }
  error:
    apply(handler, 0);
    return STATUS_OK;
}

void aws_cred_get(heap h, aws_cred_handler handler)
{
    buffer_handler role_handler = closure(h, aws_iam_role_get, h, handler);
    if (role_handler != INVALID_ADDRESS) {
        aws_metadata_get(h, ss(AWS_CRED_URI), role_handler);
    } else {
        msg_err("failed to allocate closure\n");
        apply(handler, 0);
    }
}

static boolean aws_hmac(const u8 *key, int key_len, const u8 *data, int data_len, u8 *hmac)
{
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    return mbedtls_md_hmac(md_info, key, key_len, data, data_len, hmac) == 0;
}

static boolean aws_headers_compare(void *a, void *b)
{
    buffer b1 = symbol_string(a), b2 = symbol_string(b);
    bytes len = MIN(buffer_length(b1), buffer_length(b2));
    for (int i = 0 ; i < len; i++) {
        if (byte(b1, i) > byte(b2, i))
            return true;
        else if (byte(b1, i) < byte(b2, i))
            return false;
    }
    return len < buffer_length(b1);
}

closure_function(1, 2, boolean, aws_header_insert,
                 pqueue, pq,
                 value, n, value, v)
{
    if (n != sym(url))
        pqueue_insert(bound(pq), n);
    return true;
}

/* Header names must be lowercase; header values must not have leading or trailing whitespace. */
closure_function(2, 2, boolean, aws_header_add,
                 buffer, dest, boolean, signed_hdr,
                 value, n, value, v)
{
    buffer dest = bound(dest);
    boolean signed_hdr = bound(signed_hdr);
    if (!push_buffer(dest, symbol_string(n)))
        return false;
    if (signed_hdr) {
        push_u8(dest, ';');
    } else {
        push_u8(dest, ':');
        if (!push_buffer(dest, v))
            return false;
        push_u8(dest, '\n');
    }
    return true;
}

static boolean aws_headers_sort(heap h, tuple req, binding_handler handler)
{
    pqueue sorted_headers = allocate_pqueue(h, aws_headers_compare);
    iterate(req, stack_closure(aws_header_insert, sorted_headers));
    boolean result = true;
    symbol hdr_name;
    while ((hdr_name = pqueue_pop(sorted_headers)) != INVALID_ADDRESS) {
        if (!apply(handler, hdr_name, get(req, hdr_name))) {
            result = false;
            break;
        }
    }
    deallocate_pqueue(sorted_headers);
    return result;
}

/* creates a canonical request */
static buffer aws_create_can_req(heap h, sstring method, tuple req, buffer body)
{
    buffer url = get(req, sym(url));
    if (!url)
        return 0;
    buffer can_req = allocate_buffer(h, 512);
    if (can_req == INVALID_ADDRESS)
        return 0;
    if (!buffer_write_sstring(can_req, method))
        goto error;
    push_u8(can_req, '\n');
    int uri_end = buffer_strchr(url, '?');
    if (uri_end < 0)
        uri_end = buffer_length(url);
    if (!buffer_write(can_req, buffer_ref(url, 0), uri_end))
        goto error;
    push_u8(can_req, '\n');
    if ((uri_end < buffer_length(url)) &&
        !buffer_write(can_req, buffer_ref(url, uri_end + 1), buffer_length(url) - uri_end - 1))
        goto error;
    push_u8(can_req, '\n');
    if (!aws_headers_sort(h, req, stack_closure(aws_header_add, can_req, false)))
        goto error;
    push_u8(can_req, '\n');
    if (!aws_headers_sort(h, req, stack_closure(aws_header_add, can_req, true)))
        goto error;

    /* Replace the last ';' character from the signed header list with a newline. */
    *(char *)buffer_ref(can_req, buffer_length(can_req) - 1) = '\n';

    u8 sha[32];
    if (mbedtls_sha256_ret(body ? buffer_ref(body, 0) : 0, body ? buffer_length(body) : 0,
                           sha, 0) < 0)
        goto error;
    for (int i = 0; i < sizeof(sha); i++)
        print_byte(can_req, sha[i]);
    return can_req;
  error:
    deallocate_buffer(can_req);
    return 0;
}

static buffer aws_create_string_to_sign(heap h, sstring region, sstring service,
                                        buffer datetime, buffer can_req)
{
    u8 sha[32];
    if (mbedtls_sha256_ret(buffer_ref(can_req, 0), buffer_length(can_req), sha, 0) < 0)
        return 0;
    buffer string_to_sign = allocate_buffer(h, 256);
    if (string_to_sign == INVALID_ADDRESS)
        return 0;
    if (!buffer_write_cstring(string_to_sign, AWS_HASH_ALGO "\n") ||
        !push_buffer(string_to_sign, datetime))
        goto error;
    push_u8(string_to_sign, '\n');
    buffer cred_scope = little_stack_buffer(64);
    buffer_write(cred_scope, buffer_ref(datetime, 0), 8);   /* date value (YYYYMMDD) */
    push_u8(cred_scope, '/');
    buffer_write_sstring(cred_scope, region);
    push_u8(cred_scope, '/');
    buffer_write_sstring(cred_scope, service);
    buffer_write_cstring(cred_scope, "/" AWS_REQ "\n");
    if (!push_buffer(string_to_sign, cred_scope))
        goto error;
    for (int i = 0; i < sizeof(sha); i++)
        print_byte(string_to_sign, sha[i]);
    return string_to_sign;
  error:
    deallocate_buffer(string_to_sign);
    return 0;
}

static boolean aws_create_signing_key(heap h, sstring region, sstring service,
                                      buffer datetime, sstring secret, u8 *key)
{
    int secret_len = secret.len;
    u8 ext_secret[4 + secret_len];
    runtime_memcpy(ext_secret, "AWS4", 4);
    runtime_memcpy(ext_secret + 4, secret.ptr, secret_len);
    u8 k_date[32], k_region[32], k_service[32];
    if (!aws_hmac(ext_secret, sizeof(ext_secret), buffer_ref(datetime, 0), 8, k_date) ||
        !aws_hmac(k_date, sizeof(k_date), (const u8 *)region.ptr, region.len, k_region) ||
        !aws_hmac(k_region, sizeof(k_region), (const u8 *)service.ptr, service.len,
                  k_service) ||
        !aws_hmac(k_service, sizeof(k_service), (const u8 *)AWS_REQ, sizeof(AWS_REQ) - 1, key))
        return false;
    return true;
}

void aws_req_set_date(tuple req, buffer b)
{
    u64 seconds = sec_from_timestamp(kern_now(CLOCK_ID_REALTIME));
    struct tm tm;
    gmtime_r(&seconds, &tm);
    bprintf(b, "%d%02d%02dT%02d%02d%02dZ", 1900 + tm.tm_year, 1 + tm.tm_mon, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec);
    set(req, sym(x-amz-date), b);
}

buffer aws_req_sign(heap h, sstring region, sstring service, sstring method,
                    tuple req, buffer body, sstring access_key, sstring secret)
{
    buffer datetime = get(req, sym(x-amz-date));
    if (!datetime)
        return 0;
    buffer can_req = aws_create_can_req(h, method, req, body);
    if (!can_req)
        return 0;
    buffer string_to_sign = aws_create_string_to_sign(h, region, service, datetime, can_req);
    deallocate_buffer(can_req);
    if (!string_to_sign)
        return 0;
    buffer auth = 0;
    u8 signing_key[32];
    if (!aws_create_signing_key(h, region, service, datetime, secret, signing_key))
        goto free_string_to_sign;
    u8 signature[32];
    if (!aws_hmac(signing_key, sizeof(signing_key), buffer_ref(string_to_sign, 0),
                  buffer_length(string_to_sign), signature))
        goto free_string_to_sign;
    auth = allocate_buffer(h, 256);
    if (auth == INVALID_ADDRESS) {
        auth = 0;
        goto free_string_to_sign;
    }
    if (!buffer_write_cstring(auth, AWS_HASH_ALGO " Credential=") ||
        !buffer_write_sstring(auth, access_key))
        goto free_auth;
    push_u8(auth, '/');
    if (!buffer_write(auth, buffer_ref(datetime, 0), 8))    /* date value (YYYYMMDD) */
        goto free_auth;
    push_u8(auth, '/');
    if (!buffer_write_sstring(auth, region))
        goto free_auth;
    push_u8(auth, '/');
    if (!buffer_write_sstring(auth, service) ||
        !buffer_write_cstring(auth, "/" AWS_REQ ", SignedHeaders=") ||
        !aws_headers_sort(h, req, stack_closure(aws_header_add, auth, true)))
        goto free_auth;

    /* Replace the last ';' character from the signed header list with a comma. */
    *(char *)buffer_ref(can_req, buffer_length(can_req) - 1) = ',';

    if (!buffer_write_cstring(auth, " Signature="))
        goto free_auth;
    for (int i = 0; i < sizeof(signature); i++)
        print_byte(auth, signature[i]);
    goto free_string_to_sign;
  free_auth:
    deallocate_buffer(auth);
    auth = 0;
  free_string_to_sign:
    deallocate_buffer(string_to_sign);
    return auth;
}
