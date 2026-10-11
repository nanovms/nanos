#include <unix_internal.h>
#include <filesystem.h>
#include <net_utils.h>

#define _RUNTIME_H_ /* guard against double inclusion of runtime.h */
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/oid.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/sha256.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_csr.h>

#ifdef ACME_DEBUG
#define acme_debug(x, ...) do {tprintf(sym(acme), 0, ss(x"\n"), ##__VA_ARGS__);} while(0)
#else
#define acme_debug(x, ...)
#endif

typedef enum {
    ACME_STATE_INIT,
    ACME_STATE_GET_DIRECTORY,
    ACME_STATE_NEW_ACCOUNT,
    ACME_STATE_READY,
    ACME_STATE_ERROR
} acme_state;

typedef enum {
    ACME_CERT_RENEW,
    ACME_CERT_CHALLENGE,
    ACME_CERT_FINALIZE,
    ACME_CERT_ERROR
} acme_cert_state;

typedef struct acme_req {
    sstring url;
    http_method method;
    tuple req;
    sstring nonce;
    void (*send)(struct acme_req *);
    struct buffer content_type;
    buffer body;
    closure_struct(value_handler, resp_handler);
    void *priv;
    struct timer retry_timer;
    closure_struct(timer_handler, retry_timer_handler);
    timestamp retry_backoff;
} *acme_req;

typedef struct acme_nonce_req {
    acme_req req;
    tuple net_req;
    closure_struct(value_handler, resp_handler);
} *acme_nonce_req;

typedef struct acme_cert {
    struct list e;
    sstring cert_chain;
    sstring priv_key;
    vector domains;
    timestamp valid_from;
    timestamp valid_to;
    struct timer renew_timer;
    closure_struct(timer_handler, renew_timer_handler);
    sstring order_url;
    sstring finalize_url;
    sstring cert_url;
    struct list auths;
    acme_cert_state state;
    buffer cert_b;
    fsfile cert_f;
    unsigned char privkey_buf[4096];
    int privkey_len;
    fsfile privkey_f;
    closure_struct(io_status_handler, file_write_complete);
} *acme_cert;

typedef struct acme_auth {
    struct list e;
    acme_cert cert;
    sstring url;
    sstring chall_token;
    sstring chall_url;
    char key_auth[128];
    fsfile chall_f;
    closure_struct(io_status_handler, file_write_complete);
} *acme_auth;

enum acme_resp {
    ACME_RESP_OK,
    ACME_RESP_RETRYING,
    ACME_RESP_ERROR,
};

static struct {
    heap h;
    sstring directory_url;
    sstring new_nonce_url;
    sstring new_account_url;
    sstring new_order_url;
    sstring email;
    struct buffer user_agent;
    sstring nonce;
    struct {
        mbedtls_pk_context pk;
        mbedtls_entropy_context entropy;
        mbedtls_ctr_drbg_context ctr_drbg;
        sstring url;
    } account;
    sstring web_dir;
    int reload_signal;
    struct list certs;
    acme_state state;
    struct spinlock lock;
} acme;

static boolean acme_post_as_get(acme_req req, sstring url);
static void acme_auth_get(acme_req req);
static boolean acme_do_challenge(acme_auth auth);
static void acme_order_finalize(acme_req req);
static void acme_order_get_cert(acme_req req);

static boolean acme_string_new(string src, sstring *dest)
{
    if (!sstring_allocate(acme.h, buffer_length(src), dest))
        return false;
    buffer_read(src, dest->ptr, dest->len);
    return true;
}

static void acme_string_delete(sstring url)
{
    if (!sstring_is_null(url))
        sstring_deallocate(acme.h, url);
}

static void acme_nonce_set(string nonce)
{
    acme_debug("nonce: '%b'", nonce);
    spin_lock(&acme.lock);
    acme_string_delete(acme.nonce);
    acme_string_new(nonce, &acme.nonce);
    spin_unlock(&acme.lock);
}

static sstring acme_nonce_get(void)
{
    sstring nonce;
    spin_lock(&acme.lock);
    nonce = acme.nonce;
    acme.nonce = sstring_null();
    spin_unlock(&acme.lock);
    return nonce;
}

static acme_req acme_req_alloc(void)
{
    acme_req req = allocate(acme.h, sizeof(*req));
    if (req == INVALID_ADDRESS)
        return req;
    req->req = allocate_tuple();
    if (req->req == INVALID_ADDRESS) {
        deallocate(acme.h, req, sizeof(*req));
        return INVALID_ADDRESS;
    }
    req->nonce = sstring_null();
    req->send = 0;
    req->retry_backoff = 0;
    return req;
}

static void acme_req_free(acme_req req)
{
    deallocate_value(req->req);
    acme_string_delete(req->nonce);
    deallocate(acme.h, req, sizeof(*req));
}

closure_func_basic(value_handler, void, acme_nonce_resp,
                   value resp)
{
    acme_nonce_req nonce_req = struct_from_closure(acme_nonce_req, resp_handler);
    acme_req req = nonce_req->req;
    string nonce;
    if (!resp || !(nonce = get(resp, sym(Replay-Nonce))) || !acme_string_new(nonce, &req->nonce))
        msg_err("acme: failed to get nonce");
    deallocate_value(nonce_req->net_req);
    deallocate(acme.h, nonce_req, sizeof(*nonce_req));
    req->send(req);
}

static boolean acme_req_start(acme_req req)
{
    req->nonce = acme_nonce_get();
    if (!sstring_is_null(req->nonce)) {
        req->send(req);
        return true;
    }
    acme_nonce_req nonce_req = allocate(acme.h, sizeof(*nonce_req));
    if (nonce_req == INVALID_ADDRESS)
        goto error;
    tuple net_req = allocate_tuple();
    if (net_req == INVALID_ADDRESS)
        goto err_dealloc_req;
    set(net_req, sym(User-Agent), &acme.user_agent);
    nonce_req->net_req = net_req;
    nonce_req->req = req;
    acme_debug("requesting nonce at %s", acme.new_nonce_url);
    status s = net_http_get(acme.new_nonce_url, net_req,
                            init_closure_func(&nonce_req->resp_handler, value_handler,
                                              acme_nonce_resp));
    if (is_ok(s))
        return true;
    msg_err("acme: failed to request nonce, %v", s);
    timm_dealloc(s);
    deallocate_value(net_req);
  err_dealloc_req:
    deallocate(acme.h, nonce_req, sizeof(*nonce_req));
  error:
    return false;
}

static boolean acme_req_new(void (*send)(struct acme_req *), void *priv)
{
    acme_req req = acme_req_alloc();
    if (req == INVALID_ADDRESS) {
        msg_err("acme: out of memory");
        return false;
    }
    req->send = send;
    req->priv = priv;
    if (!acme_req_start(req)) {
        acme_req_free(req);
        return false;
    }
    return true;
}

static void acme_request(acme_req req)
{
    tuple httq_req = req->req;
    set(httq_req, sym(User-Agent), &acme.user_agent);
    value_handler resp_handler = (value_handler)&req->resp_handler;
    status s;
    if (req->method == HTTP_REQUEST_METHOD_GET) {
        s = net_http_get(req->url, httq_req, resp_handler);
    } else {
        buffer_init_from_string(&req->content_type, "application/jose+json");
        set(req->req, sym(Content-Type), &req->content_type);
        s = net_http_post(req->url, httq_req, req->body, resp_handler);
    }
    if (!is_ok(s)) {
        msg_err("acme: failed to send request, %v", s);
        timm_dealloc(s);
        apply(resp_handler, 0);
    }
}

closure_func_basic(timer_handler, void, acme_retry_timer_handler,
                   u64 expiry, u64 overruns)
{
    acme_request(struct_from_closure(acme_req, retry_timer_handler));
}

static enum acme_resp acme_resp_common(acme_req req, value resp)
{
    if (resp) {
        buffer new_nonce = get(resp, sym(Replay-Nonce));
        if (new_nonce)
            acme_nonce_set(new_nonce);
    }
    if (http_resp_is_ok(resp))
        return ACME_RESP_OK;
    if (!resp) {    /* may be a transient network error */
        if (!req->retry_backoff) {
            init_timer(&req->retry_timer);
            init_closure_func(&req->retry_timer_handler, timer_handler, acme_retry_timer_handler);
            req->retry_backoff = seconds(1);
        } else if (req->retry_backoff < seconds(3600)) {
            req->retry_backoff *= 2;
        }
        register_timer(kernel_timers, &req->retry_timer, CLOCK_ID_MONOTONIC_RAW, req->retry_backoff,
                       false, 0, (timer_handler)&req->retry_timer_handler);
    } else {
        /* Check for a "bad nonce" response, in which case the nonce we just used may have been
         * stale. */
        buffer body = get(resp, sym(content));
        if ((buffer_strstr(body, ss("urn:ietf:params:acme:error:badNonce")) < 0) || !req->send ||
            !acme_req_start(req))
            return ACME_RESP_ERROR;
    }
    return ACME_RESP_RETRYING;
}

closure_func_basic(value_handler, void, acme_account_resp,
                   value resp)
{
    acme_req req = struct_from_closure(acme_req, resp_handler);
    switch (acme_resp_common(req, resp)) {
    case ACME_RESP_RETRYING:
        return;
    case ACME_RESP_OK: {
        buffer url = get(resp, sym_this("Location"));
        if (url && acme_string_new(url, &acme.account.url)) {
            acme_debug("account registered: %s", acme.account.url);
            acme.state = ACME_STATE_READY;
        } else {
            msg_err("acme: failed to get account URL");
            acme.state = ACME_STATE_ERROR;
        }
        break;
    }
    default:
        msg_err("acme: failed to register account");
        acme.state = ACME_STATE_ERROR;
    }
    acme_req_free(req);
}

static boolean acme_jws_encode(acme_req req, buffer payload, sstring url)
{
    if (sstring_is_null(req->nonce))
        return false;
    buffer protected = allocate_buffer(acme.h, 512);
    if (protected == INVALID_ADDRESS)
        return false;
    boolean success = false;
    bprintf(protected, "{\"alg\":\"RS256\",\"nonce\":\"%s\",\"url\":\"%s\",", req->nonce, url);
    if (!sstring_is_null(acme.account.url)) {
        bprintf(protected, "\"kid\":\"%s\"}", acme.account.url);
        success = true;
    } else {
        mbedtls_rsa_context *rsa = mbedtls_pk_rsa(acme.account.pk);
        mbedtls_mpi N, E;
        mbedtls_mpi_init(&N);
        mbedtls_mpi_init(&E);
        if (mbedtls_rsa_export(rsa, &N, 0, 0, 0, &E))
            goto free_mpi;
        size_t n_len = mbedtls_mpi_size(&N);
        size_t e_len = mbedtls_mpi_size(&E);
        unsigned char *n_buf = allocate(acme.h, n_len);
        if (n_buf == INVALID_ADDRESS)
            goto free_mpi;
        unsigned char *e_buf = allocate(acme.h, e_len);
        if (e_buf == INVALID_ADDRESS)
            goto free_n_buf;
        mbedtls_mpi_write_binary(&N, n_buf, n_len);
        mbedtls_mpi_write_binary(&E, e_buf, e_len);
        buffer n_b64 = allocate_buffer(acme.h, n_len * 2);
        if (n_b64 == INVALID_ADDRESS)
            goto free_e_buf;
        buffer e_b64 = allocate_buffer(acme.h, e_len * 2);
        if (e_b64 == INVALID_ADDRESS)
            goto free_n_b64;
        base64url_encode(n_b64, n_buf, n_len);
        base64url_encode(e_b64, e_buf, e_len);
        bprintf(protected, "\"jwk\":{\"kty\":\"RSA\",\"n\":\"%b\",\"e\":\"%b\"}}", n_b64, e_b64);
        success = true;
        deallocate_buffer(e_b64);
      free_n_b64:
        deallocate_buffer(n_b64);
      free_e_buf:
        deallocate(acme.h, e_buf, e_len);
      free_n_buf:
        deallocate(acme.h, n_buf, n_len);
      free_mpi:
        mbedtls_mpi_free(&N);
        mbedtls_mpi_free(&E);
    }
    if (!success)
        goto free_protected;
    success = false;
    buffer protected_b64 = allocate_buffer(acme.h, buffer_length(protected) * 2);
    if (protected_b64 == INVALID_ADDRESS)
        goto free_protected;
    base64url_encode(protected_b64, buffer_ref(protected, 0), buffer_length(protected));
    buffer payload_b64 = allocate_buffer(acme.h, buffer_length(payload) * 2);
    if (payload_b64 == INVALID_ADDRESS)
        goto free_protected_b64;
    base64url_encode(payload_b64, buffer_ref(payload, 0), buffer_length(payload));

    /* Create the signing input: protected_b64 + "." + payload_b64 */
    buffer sig_input = allocate_buffer(acme.h, buffer_length(protected_b64) + 1 +
                                       buffer_length(payload_b64));
    if (sig_input == INVALID_ADDRESS)
        goto free_payload_b64;
    bprintf(sig_input, "%b.%b", protected_b64, payload_b64);

    /* Sign the input */
    unsigned char hash[32];
    mbedtls_sha256(buffer_ref(sig_input, 0), buffer_length(sig_input), hash, 0);
    unsigned char sig[256];
    size_t sig_len = 0;
    mbedtls_pk_sign(&acme.account.pk, MBEDTLS_MD_SHA256, hash, sizeof(hash), sig, &sig_len,
                    mbedtls_ctr_drbg_random, &acme.account.ctr_drbg);
    buffer sig_b64 = allocate_buffer(acme.h, sig_len * 2);
    if (sig_b64 == INVALID_ADDRESS)
        goto free_sig_input;
    base64url_encode(sig_b64, sig, sig_len);

    /* Encapsulate the request payload in a JSON Web Signature (JWS) object */
    req->body = allocate_buffer(acme.h, buffer_length(protected_b64) + buffer_length(payload_b64) +
                                buffer_length(sig_b64) + 50);
    if (req->body != INVALID_ADDRESS) {
        bprintf(req->body, "{\"protected\":\"%b\",\"payload\":\"%b\",\"signature\":\"%b\"}",
                protected_b64, payload_b64, sig_b64);
        success = true;
    }

    deallocate_buffer(sig_b64);
  free_sig_input:
    deallocate_buffer(sig_input);
  free_payload_b64:
    deallocate_buffer(payload_b64);
  free_protected_b64:
    deallocate_buffer(protected_b64);
  free_protected:
    deallocate_buffer(protected);
    return success;
}

static boolean acme_post_as_get(acme_req req, sstring url)
{
    struct buffer payload;
    init_buffer(&payload, 0, false, 0, 0);
    if (!acme_jws_encode(req, &payload, url)) {
        msg_err("acme: failed to encode JWS");
        goto error;
    }
    req->url = url;
    req->method = HTTP_REQUEST_METHOD_POST;
    acme_request(req);
    return true;
  error:
    acme_req_free(req);
    return false;
}

static void acme_account_register(acme_req req)
{
    buffer payload = little_stack_buffer(64 + EMAIL_ADDR_MAX_LEN);
    push_character(payload, '{');
    if (!sstring_is_null(acme.email))
        bprintf(payload, "\"contact\":[\"mailto:%s\"],", acme.email);
    buffer_write_sstring(payload, ss("\"termsOfServiceAgreed\":true}"));
    boolean jws_ok = acme_jws_encode(req, payload, acme.new_account_url);
    if (!jws_ok) {
        msg_err("acme: failed to encode JWS");
        goto error;
    }
    acme_debug("registering account at %s", acme.new_account_url);
    req->url = acme.new_account_url;
    req->method = HTTP_REQUEST_METHOD_POST;
    init_closure_func(&req->resp_handler, value_handler, acme_account_resp);
    acme_request(req);
    return;
  error:
    acme.state = ACME_STATE_ERROR;
    acme_req_free(req);
}

static void acme_account_new(void)
{
    /* Create a public/private key pair */
    mbedtls_pk_init(&acme.account.pk);
    mbedtls_entropy_init(&acme.account.entropy);
    mbedtls_ctr_drbg_init(&acme.account.ctr_drbg);
    if (!mbedtls_ctr_drbg_seed(&acme.account.ctr_drbg, mbedtls_entropy_func, &acme.account.entropy,
                               0, 0) &&
        !mbedtls_pk_setup(&acme.account.pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) &&
        !mbedtls_rsa_gen_key(mbedtls_pk_rsa(acme.account.pk), mbedtls_ctr_drbg_random,
                             &acme.account.ctr_drbg, 2048, 65537) &&
        acme_req_new(acme_account_register, 0)) {
        acme.state = ACME_STATE_NEW_ACCOUNT;
    } else {
        msg_err("acme: failed to create new account");
        mbedtls_pk_free(&acme.account.pk);
        mbedtls_entropy_free(&acme.account.entropy);
        mbedtls_ctr_drbg_free(&acme.account.ctr_drbg);
        acme.state = ACME_STATE_ERROR;
    }
}

closure_func_basic(parse_finish, void, acme_directory_parse,
                   void *v)
{
    tuple directory = v;
    string new_nonce = get_string(directory, sym_this("newNonce"));
    string new_account = get_string(directory, sym_this("newAccount"));
    string new_order = get_string(directory, sym_this("newOrder"));
    if (!new_nonce || !new_account || !new_order) {
        msg_err("acme: missing info in server directory %v", directory);
        acme.state = ACME_STATE_ERROR;
        destruct_value(v, true);
        return;
    }
    acme.new_nonce_url = buffer_to_sstring(new_nonce);
    acme.new_account_url = buffer_to_sstring(new_account);
    acme.new_order_url = buffer_to_sstring(new_order);
    /* Do not deallocate tuple attributes, because the strings above point to those attributes. */
    deallocate_value(v);
}

closure_func_basic(parse_error, void, acme_directory_err,
                   string err)
{
    msg_err("acme: failed to parse server directory: %b", err);
    acme.state = ACME_STATE_ERROR;
}

closure_func_basic(value_handler, void, acme_directory_resp,
                   value resp)
{
    acme_req req = struct_from_closure(acme_req, resp_handler);
    switch (acme_resp_common(req, resp)) {
    case ACME_RESP_RETRYING:
        return;
    case ACME_RESP_OK: {
        parser p = json_parser(acme.h, stack_closure_func(parse_finish, acme_directory_parse),
                               stack_closure_func(parse_error, acme_directory_err));
        if (p == INVALID_ADDRESS) {
            msg_err("acme: out of memory");
            acme.state = ACME_STATE_ERROR;
        } else {
            p = parser_feed(p, get(resp, sym_this("content")));
            p = apply(p, CHARACTER_INVALID);
            json_parser_free(p);
        }
        if (acme.state != ACME_STATE_ERROR)
            acme_account_new();
        break;
    }
    default:
        msg_err("acme: failed to get server directory");
        acme.state = ACME_STATE_ERROR;
    }
    acme_req_free(req);
}

static boolean acme_get_ready(void)
{
    boolean ready;
    spin_lock(&acme.lock);
    switch (acme.state) {
    case ACME_STATE_INIT:
        ready = false;
        acme.state = ACME_STATE_GET_DIRECTORY;
        acme_debug("fetching directory from %s", acme.directory_url);
        acme_req req = acme_req_alloc();
        if (req == INVALID_ADDRESS) {
            msg_err("acme: out of memory");
            acme.state = ACME_STATE_ERROR;
            break;
        }
        req->url = acme.directory_url;
        req->method = HTTP_REQUEST_METHOD_GET;
        init_closure_func(&req->resp_handler, value_handler, acme_directory_resp);
        acme_request(req);
        break;
    case ACME_STATE_READY:
        ready = true;
        break;
    default:
        ready = false;
        break;
    }
    spin_unlock(&acme.lock);
    return ready;
}

static acme_auth acme_auth_new(acme_cert cert, buffer url)
{
    acme_auth auth = allocate(acme.h, sizeof(*auth));
    if (auth != INVALID_ADDRESS) {
        auth->cert = cert;
        if (!acme_string_new(url, &auth->url)) {
            deallocate(acme.h, auth, sizeof(*auth));
            return INVALID_ADDRESS;
        }
        auth->chall_token = sstring_null();
        auth->chall_url = sstring_null();
        list_push_back(&cert->auths, &auth->e);
    }
    return auth;
}

static void acme_auth_delete(acme_auth auth)
{
    acme_string_delete(auth->url);
    acme_string_delete(auth->chall_token);
    acme_string_delete(auth->chall_url);
}

static boolean is_leap_year(int year) {
    if ((year & 3) != 0) {
        return false;
    }
    if ((year % 100) != 0) {
        return true;
    }
    return (year % 400) == 0;
}

static timestamp x509_time_to_timestamp(mbedtls_x509_time *t)
{
    int mon_days[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    u64 days = 0;
    for (int y = 1970; y < t->year; y++) {
        days += 365;
        if (is_leap_year(y))
            days++;
    }
    for (int m = 1; m < t->mon; m++) {
        days += mon_days[m - 1];
        if (m == 2 && is_leap_year(t->year))
            days++;
    }
    days += t->day - 1;
    u64 secs = days * 86400 + t->hour * 3600 + t->min * 60 + t->sec;
    return seconds(secs);
}

static void acme_renew_setup(acme_cert cert)
{
    /* Renew the cert when less than one third of its lifetime remains */
    timestamp renew = cert->valid_to - (cert->valid_to - cert->valid_from) / 3;
    acme_debug("cert at %s valid until %T, will renew at %T", cert->cert_chain, cert->valid_to,
               renew);
    register_timer(kernel_timers, &cert->renew_timer, CLOCK_ID_REALTIME, renew, true, 0,
                   (timer_handler)&cert->renew_timer_handler);
}

static void acme_renew_done(acme_cert cert, boolean success)
{
    acme_string_delete(cert->order_url);
    acme_string_delete(cert->finalize_url);
    acme_string_delete(cert->cert_url);
    list_foreach(&cert->auths, e) {
        acme_auth_delete(struct_from_list(e, acme_auth, e));
    }
    if (success) {
        buffer new_cert = cert->cert_b;
        mbedtls_x509_crt crt;
        mbedtls_x509_crt_init(&crt);
        int ret = mbedtls_x509_crt_parse(&crt, buffer_ref(new_cert, 0), buffer_length(new_cert));
        if (!ret) {
            cert->valid_from = x509_time_to_timestamp(&crt.valid_from);
            cert->valid_to = x509_time_to_timestamp(&crt.valid_to);
            mbedtls_x509_crt_free(&crt);
            if (acme.reload_signal) {
                acme_debug("sending signal %d to reload certificate", acme.reload_signal);
                struct siginfo si;
                zero(&si, sizeof(struct siginfo));
                si.si_signo = acme.reload_signal;
                si.si_code = SI_KERNEL;
                deliver_signal_to_process(unix_process(), &si);
            }
            msg_info("acme: certificate at %s renewed", cert->cert_chain);
            acme_renew_setup(cert);
            cert->state = ACME_CERT_RENEW;
        } else {
            msg_err("acme: failed to parse newly installed certificate (err %d), will not renew",
                    ret);
            success = false;
        }
        deallocate_buffer(new_cert);
    }
    if (!success)
        cert->state = ACME_CERT_ERROR;
}

static void acme_auth_fetch(acme_cert cert, acme_auth auth)
{
    acme_debug("fetching authorization from %s", auth->url);
    if (!acme_req_new(acme_auth_get, auth)) {
        msg_err("acme: cannot fetch authorization: out of memory");
        acme_renew_done(cert, false);
    }
}

closure_function(1, 1, void, acme_order_parse,
                 acme_cert, cert,
                 void *v)
{
    acme_cert cert = bound(cert);
    tuple order = v;
    boolean success = false;
    if (cert->state == ACME_CERT_RENEW) {
        value auths = get(order, sym_this("authorizations"));
        if (!auths || !is_composite(auths)) {
            msg_err("acme: failed to parse authorizations from order");
            goto done;
        }
        value auth_url;
        for (int i = 0; (auth_url = get(auths, integer_key(i))); i++) {
            if (is_string(auth_url)) {
                acme_auth a = acme_auth_new(cert, auth_url);
                if (a == INVALID_ADDRESS) {
                    msg_err("acme: failed to create authorization: out of memory");
                    goto done;
                }
            }
        }
        success = true;
    } else {
        string status_str = get_string(order, sym_this("status"));
        if (!status_str) {
            msg_err("acme: failed to parse order status");
            goto done;
        }
        acme_debug("order status: %b", status_str);
        if (!buffer_strcmp(status_str, "ready")) {
            string finalize = get_string(order, sym_this("finalize"));
            if (!finalize) {
                msg_err("acme: missing finalize URL in ready order");
                goto done;
            }
            if (!acme_string_new(finalize, &cert->finalize_url)) {
                msg_err("acme: failed to allocate finalize URL");
                goto done;
            }
            cert->state = ACME_CERT_FINALIZE;
            acme_debug("finalizing order at %s", cert->finalize_url);
            if (!acme_req_new(acme_order_finalize, cert)) {
                msg_err("acme: failed to create finalize request");
                goto done;
            }
            success = true;
        } else if (!buffer_strcmp(status_str, "pending") ||
                   !buffer_strcmp(status_str, "processing")) {
            /* Poll again after a delay */
            register_timer(kernel_timers, &cert->renew_timer, CLOCK_ID_MONOTONIC_RAW, seconds(5),
                           false, 0, (timer_handler)&cert->renew_timer_handler);
            success = true;
        } else if (!buffer_strcmp(status_str, "valid")) {
            string cert_url = get_string(order, sym_this("certificate"));
            if (!cert_url) {
                msg_err("acme: missing certificate URL in valid order");
                goto done;
            }
            if (!acme_string_new(cert_url, &cert->cert_url)) {
                msg_err("acme: failed to allocate certificate URL");
                goto done;
            }
            acme_debug("retrieving new certificate from %s", cert->cert_url);
            if (!acme_req_new(acme_order_get_cert, cert)) {
                msg_err("acme: failed to create certificate request");
                goto done;
            }
            success = true;
        } else {
            msg_err("acme: order failed with status %b", status_str);
        }
    }
  done:
    destruct_value(v, true);
    closure_finish();
    if (!success)
        acme_renew_done(cert, false);
}

closure_func_basic(parse_error, void, acme_order_err,
                   string err)
{
    msg_err("acme: failed to parse order: %b", err);
}

closure_func_basic(value_handler, void, acme_order_resp,
                   value resp)
{
    acme_req req = struct_from_closure(acme_req, resp_handler);
    acme_cert cert = req->priv;
    switch (acme_resp_common(req, resp)) {
    case ACME_RESP_RETRYING:
        return;
    case ACME_RESP_OK: {
        if (cert->state == ACME_CERT_RENEW) {
            buffer loc = get(resp, sym_this("Location"));
            if (!loc) {
                msg_err("acme: order URL not found");
                acme_renew_done(cert, false);
                break;
            }
            if (!acme_string_new(loc, &cert->order_url)) {
                msg_err("acme: failed to parse order: out of memory");
                acme_renew_done(cert, false);
                break;
            }
        }
        parser p = json_parser(acme.h, closure(acme.h, acme_order_parse, cert),
                               stack_closure_func(parse_error, acme_order_err));
        if (p == INVALID_ADDRESS) {
            msg_err("acme: failed to parse order: out of memory");
            acme_renew_done(cert, false);
            break;
        }
        p = parser_feed(p, get(resp, sym_this("content")));
        p = apply(p, CHARACTER_INVALID);
        json_parser_free(p);
        if (cert->state == ACME_CERT_RENEW) {
            list first = list_get_next(&cert->auths);
            if (first) {
                acme_auth_fetch(cert, struct_from_list(first, acme_auth, e));
            } else {
                msg_err("acme: no authorizations to processs");
                acme_renew_done(cert, false);
            }
        }
        break;
    }
    default:
        msg_err("acme: server error in order response");
        acme_renew_done(cert, false);
    }
    acme_req_free(req);
}

static void acme_order_poll_send(acme_req req)
{
    acme_cert cert = req->priv;
    init_closure_func(&req->resp_handler, value_handler, acme_order_resp);
    acme_post_as_get(req, cert->order_url);
}

static void acme_order_poll(acme_cert cert)
{
    acme_debug("polling order status at %s", cert->order_url);
    if (!acme_req_new(acme_order_poll_send, cert))
        msg_err("acme: failed to create order poll request");
}

static void acme_order_finalize(acme_req req)
{
    acme_cert cert = req->priv;
    buffer payload = allocate_buffer(acme.h, 1024);
    if (payload == INVALID_ADDRESS) {
        msg_err("acme: out of memory");
        goto error;
    }
    mbedtls_pk_context cert_pk;
    mbedtls_pk_init(&cert_pk);
    if (mbedtls_pk_setup(&cert_pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) ||
        mbedtls_rsa_gen_key(mbedtls_pk_rsa(cert_pk),
                            mbedtls_ctr_drbg_random, &acme.account.ctr_drbg, 2048, 65537)) {
        msg_err("acme: failed to generate certificate key pair");
        goto err_pk_free;
    }
    if (mbedtls_pk_write_key_pem(&cert_pk, cert->privkey_buf, sizeof(cert->privkey_buf))) {
        msg_err("acme: failed to write private key PEM");
        goto err_pk_free;
    }
    bytes pk_len = 0;
    while ((pk_len < sizeof(cert->privkey_buf)) && (cert->privkey_buf[pk_len] != '\0'))
        pk_len++;
    cert->privkey_len = pk_len;
    mbedtls_x509write_csr csr;
    mbedtls_x509write_csr_init(&csr);
    mbedtls_x509write_csr_set_md_alg(&csr, MBEDTLS_MD_SHA256);
    mbedtls_x509write_csr_set_key(&csr, &cert_pk);

    /* Add the Common Name (CN) for the first domain */
    string first_dom = vector_get(cert->domains, 0);
    buffer subject = little_stack_buffer(buffer_length(first_dom) + 4);
    bprintf(subject, "CN=%b", first_dom);
    buffer_write_byte(subject, 0);
    mbedtls_x509write_csr_set_subject_name(&csr, buffer_to_sstring(subject));

    /* Add Subject Alternative Names (SAN) extension containing all domains */
    int san_len = 0;
    for (int i = 0; i < vector_length(cert->domains); i++) {
        string dom = vector_get(cert->domains, i);
        san_len += 2 + buffer_length(dom);
    }
    buffer san_buf = allocate_buffer(acme.h, san_len + 3);
    if (san_buf == INVALID_ADDRESS) {
        msg_err("acme: out of memory");
        goto err_csr_free;
    }
    buffer_write_byte(san_buf, 0x30);
    if (san_len < 128) {
        buffer_write_byte(san_buf, san_len);
    } else {
        buffer_write_byte(san_buf, 0x81);
        buffer_write_byte(san_buf, san_len);
    }
    for (int i = 0; i < vector_length(cert->domains); i++) {
        string dom = vector_get(cert->domains, i);
        buffer_write_byte(san_buf, 0x82);
        buffer_write_byte(san_buf, buffer_length(dom));
        buffer_write(san_buf, buffer_ref(dom, 0), buffer_length(dom));
    }
    mbedtls_x509write_csr_set_extension(&csr, MBEDTLS_OID_SUBJECT_ALT_NAME,
                                        MBEDTLS_OID_SIZE(MBEDTLS_OID_SUBJECT_ALT_NAME),
                                        buffer_ref(san_buf, 0), buffer_length(san_buf));
    deallocate_buffer(san_buf);

    unsigned char csr_der[4096];
    int der_len = mbedtls_x509write_csr_der(&csr, csr_der, sizeof(csr_der),
                                            mbedtls_ctr_drbg_random, &acme.account.ctr_drbg);
    if (der_len < 0) {
        msg_err("acme: failed to write CSR DER (err %d)", der_len);
        goto err_csr_free;
    }
    unsigned char *der_ptr = csr_der + sizeof(csr_der) - der_len;
    buffer csr_b64 = little_stack_buffer(der_len * 2);
    base64url_encode(csr_b64, der_ptr, der_len);
    mbedtls_x509write_csr_free(&csr);
    mbedtls_pk_free(&cert_pk);
    buffer_write_sstring(payload, ss("{\"csr\":\""));
    buffer_write(payload, buffer_ref(csr_b64, 0), buffer_length(csr_b64));
    buffer_write_sstring(payload, ss("\"}"));
    if (!acme_jws_encode(req, payload, cert->finalize_url)) {
        msg_err("acme: failed to encode JWS for finalize request");
        goto err_free_buf;
    }
    deallocate_buffer(payload);
    req->url = cert->finalize_url;
    req->method = HTTP_REQUEST_METHOD_POST;
    init_closure_func(&req->resp_handler, value_handler, acme_order_resp);
    acme_request(req);
    return;
  err_csr_free:
    mbedtls_x509write_csr_free(&csr);
  err_pk_free:
    mbedtls_pk_free(&cert_pk);
  err_free_buf:
    deallocate_buffer(payload);
  error:
    acme_req_free(req);
}

closure_func_basic(io_status_handler, void, acme_privkey_write_complete,
                   status s, bytes len)
{
    acme_cert cert = struct_from_closure(acme_cert, file_write_complete);
    fsfile f = cert->privkey_f;
    if (is_ok(s)) {
        acme_debug("private key saved successfully to %s", cert->priv_key);
        acme_renew_done(cert, true);
    } else {
        msg_err("acme: failed to write private key file: %v", s);
        timm_dealloc(s);
        acme_renew_done(cert, false);
    }
    fsfile_release(f);
}

closure_func_basic(io_status_handler, void, acme_cert_write_complete,
                   status s, bytes len)
{
    acme_cert cert = struct_from_closure(acme_cert, file_write_complete);
    fsfile f = cert->cert_f;
    if (is_ok(s)) {
        acme_debug("certificate chain saved successfully to %s", cert->cert_chain);
        filesystem_write_linear(cert->privkey_f, cert->privkey_buf, irangel(0, cert->privkey_len),
                                init_closure_func(&cert->file_write_complete, io_status_handler,
                                                  acme_privkey_write_complete));
    } else {
        msg_err("acme: failed to write certificate chain file: %v", s);
        timm_dealloc(s);
        deallocate_buffer(cert->cert_b);
        fsfile_release(cert->privkey_f);
        acme_renew_done(cert, false);
    }
    fsfile_release(f);
}

closure_func_basic(value_handler, void, acme_cert_download_resp,
                   value resp)
{
    acme_req req = struct_from_closure(acme_req, resp_handler);
    acme_cert cert = req->priv;
    boolean success = false;
    switch (acme_resp_common(req, resp)) {
    case ACME_RESP_RETRYING:
        return;
    case ACME_RESP_OK: {
        buffer body = clone_buffer(acme.h, get(resp, sym(content)));
        if (body == INVALID_ADDRESS) {
            msg_err("acme: out of memory");
            break;
        }
        acme_debug("downloaded certificate chain (%d bytes)", buffer_length(body));
        fsfile f = fsfile_open_or_create(cert->cert_chain, true);
        if (!f) {
            msg_err("acme: failed to open certificate chain file '%s' for writing",
                    cert->cert_chain);
            deallocate_buffer(body);
            break;
        }
        cert->cert_f = f;
        f = fsfile_open_or_create(cert->priv_key, true);
        if (!f) {
            msg_err("acme: failed to open private key file '%s' for writing", cert->priv_key);
            fsfile_release(cert->cert_f);
            deallocate_buffer(body);
            break;
        }
        cert->privkey_f = f;
        cert->cert_b = body;
        init_closure_func(&cert->file_write_complete, io_status_handler, acme_cert_write_complete);
        filesystem_write_linear(cert->cert_f, buffer_ref(body, 0), irangel(0, buffer_length(body)),
                                (io_status_handler)&cert->file_write_complete);
        success = true;
        break;
    }
    default:
        msg_err("acme: failed to download certificate");
    }
    acme_req_free(req);
    if (!success)
        acme_renew_done(cert, false);
}

static void acme_order_get_cert(acme_req req)
{
    acme_cert cert = req->priv;
    init_closure_func(&req->resp_handler, value_handler, acme_cert_download_resp);
    acme_post_as_get(req, cert->cert_url);
}

closure_function(1, 1, void, acme_auth_parse,
                 acme_auth, auth,
                 void *v)
{
    acme_auth auth = bound(auth);
    tuple auth_obj = v;
    value challenges = get(auth_obj, sym_this("challenges"));
    if (challenges && is_composite(challenges)) {
        value chall;
        for (int i = 0; (chall = get(challenges, integer_key(i))); i++) {
            if (!is_tuple(chall))
                continue;
            string type = get_string(chall, sym_this("type"));
            if (!type || buffer_compare_with_sstring(type, ss("http-01")))
                continue;
            string token = get_string(chall, sym_this("token"));
            string url = get_string(chall, sym_this("url"));
            if (!token || !url)
                continue;
            acme_debug("challenge token %b, URL %b", token, url);
            if (sstring_allocate(acme.h, buffer_length(token), &auth->chall_token) &&
                sstring_allocate(acme.h, buffer_length(url), &auth->chall_url)) {
                buffer_read(token, auth->chall_token.ptr, auth->chall_token.len);
                buffer_read(url, auth->chall_url.ptr, auth->chall_url.len);
            } else {
                msg_err("acme: out of memory");
            }
            break;
        }
    }
    destruct_value(v, true);
    closure_finish();
}

closure_func_basic(parse_error, void, acme_auth_err,
                   string err)
{
    msg_err("acme: failed to parse authorization: %b", err);
}

closure_func_basic(value_handler, void, acme_chall_respond_resp,
                   value resp)
{
    acme_req req = struct_from_closure(acme_req, resp_handler);
    acme_auth auth = req->priv;
    switch (acme_resp_common(req, resp)) {
    case ACME_RESP_RETRYING:
        return;
    case ACME_RESP_OK:
        acme_debug("challenge response accepted");
        acme_cert cert = auth->cert;
        list next = auth->e.next;
        if (next == &cert->auths) {
            cert->state = ACME_CERT_CHALLENGE;
            acme_order_poll(cert);
        } else {
            acme_auth_fetch(cert, struct_from_list(next, acme_auth, e));
        }
        break;
    default:
        msg_err("acme: failed to submit challenge response");
        acme_auth_delete(auth);
    }
    acme_req_free(req);
}

static void acme_chall_respond_send(acme_req req)
{
    acme_auth auth = req->priv;
    buffer payload = little_stack_buffer(2);
    buffer_write_sstring(payload, ss("{}"));
    if (!acme_jws_encode(req, payload, auth->chall_url)) {
        msg_err("acme: failed to encode JWS for challenge response");
        acme_auth_delete(auth);
        acme_req_free(req);
        return;
    }
    req->url = auth->chall_url;
    req->method = HTTP_REQUEST_METHOD_POST;
    init_closure_func(&req->resp_handler, value_handler, acme_chall_respond_resp);
    acme_request(req);
}

closure_func_basic(io_status_handler, void, acme_chall_write_complete,
                   status s, bytes len)
{
    acme_auth auth = struct_from_closure(acme_auth, file_write_complete);
    fsfile f = auth->chall_f;
    if (is_ok(s)) {
        acme_debug("challenge ready");
        if (!acme_req_new(acme_chall_respond_send, auth)) {
            msg_err("acme: failed to allocate challenge response request");
            acme_auth_delete(auth);
        }
    } else {
        msg_err("acme: failed to write challenge file: %v", s);
        timm_dealloc(s);
        acme_auth_delete(auth);
    }
    fsfile_release(f);
}

static boolean acme_do_challenge(acme_auth auth)
{
    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(acme.account.pk);
    mbedtls_mpi N, E;
    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&E);
    mbedtls_rsa_export(rsa, &N, 0, 0, 0, &E);
    boolean success = false;
    size_t n_len = mbedtls_mpi_size(&N);
    unsigned char *n_buf = allocate(acme.h, n_len);
    if (n_buf == INVALID_ADDRESS)
        goto mpi_free;
    size_t e_len = mbedtls_mpi_size(&E);
    unsigned char *e_buf = allocate(acme.h, e_len);
    if (e_buf == INVALID_ADDRESS)
        goto n_buf_free;
    mbedtls_mpi_write_binary(&N, n_buf, n_len);
    mbedtls_mpi_write_binary(&E, e_buf, e_len);
    buffer n_b64 = allocate_buffer(acme.h, n_len * 2);
    if (n_b64 == INVALID_ADDRESS)
        goto e_buf_free;
    buffer e_b64 = allocate_buffer(acme.h, e_len * 2);
    if (e_b64 == INVALID_ADDRESS)
        goto n_b64_free;
    base64url_encode(n_b64, n_buf, n_len);
    base64url_encode(e_b64, e_buf, e_len);
    char jwk[512];
    u64 jwk_len = rsnprintf(jwk, sizeof(jwk), "{\"e\":\"%b\",\"kty\":\"RSA\",\"n\":\"%b\"}",
                            e_b64, n_b64);
    unsigned char thumb_hash[32];
    mbedtls_sha256((unsigned char *)jwk, jwk_len, thumb_hash, 0);
    buffer thumb_b64 = little_stack_buffer(64);
    base64url_encode(thumb_b64, thumb_hash, sizeof(thumb_hash));
    u64 key_auth_len = rsnprintf(auth->key_auth, sizeof(auth->key_auth), "%s.%b",
                                 auth->chall_token, thumb_b64);
    buffer challenge_path = little_stack_buffer(PATH_MAX);
    bprintf(challenge_path, "%s/.well-known/acme-challenge/%s", acme.web_dir, auth->chall_token);
    fsfile f = fsfile_open_or_create(buffer_to_sstring(challenge_path), true);
    if (f) {
        auth->chall_f = f;
        filesystem_write_linear(f, auth->key_auth, irangel(0, key_auth_len),
                                init_closure_func(&auth->file_write_complete, io_status_handler,
                                                  acme_chall_write_complete));
        success = true;
    } else {
        msg_err("acme: failed to create challenge file '%b'", challenge_path);
    }
    deallocate_buffer(e_b64);
  n_b64_free:
    deallocate_buffer(n_b64);
  e_buf_free:
    deallocate(acme.h, e_buf, e_len);
  n_buf_free:
    deallocate(acme.h, n_buf, n_len);
  mpi_free:
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&E);
    return success;
}

closure_func_basic(value_handler, void, acme_auth_resp,
                   value resp)
{
    acme_req req = struct_from_closure(acme_req, resp_handler);
    acme_auth auth = req->priv;
    switch (acme_resp_common(req, resp)) {
    case ACME_RESP_RETRYING:
        return;
    case ACME_RESP_OK: {
        parser p = json_parser(acme.h, closure(acme.h, acme_auth_parse, auth),
                               stack_closure_func(parse_error, acme_auth_err));
        if (p == INVALID_ADDRESS) {
            msg_err("acme: failed to parse authorization: out of memory");
            break;
        }
        p = parser_feed(p, get(resp, sym_this("content")));
        p = apply(p, CHARACTER_INVALID);
        json_parser_free(p);
        if (sstring_is_null(auth->chall_token) || sstring_is_null(auth->chall_url)) {
            msg_err("acme: failed to get challenge data");
            break;
        }
        if (!acme_do_challenge(auth)) {
            msg_err("acme: failed to do challenge");
            break;
        }
        goto done;
    }
    default:
        msg_err("acme: server error when getting auth");
    }
    acme_auth_delete(auth);
    acme_renew_done(auth->cert, false);
  done:
    acme_req_free(req);
}

static void acme_auth_get(acme_req req)
{
    acme_auth auth = req->priv;
    init_closure_func(&req->resp_handler, value_handler, acme_auth_resp);
    acme_post_as_get(req, auth->url);
}

static void acme_order(acme_req req)
{
    acme_cert cert = req->priv;
    buffer payload = allocate_buffer(acme.h, 256);
    if (payload == INVALID_ADDRESS) {
        msg_err("acme: out of memory");
        acme_req_free(req);
        return;
    }
    buffer_write_sstring(payload, ss("{\"identifiers\":["));
    for (int i = 0; i < vector_length(cert->domains); i++) {
        string dom = vector_get(cert->domains, i);
        if (i > 0)
            push_character(payload, ',');
        bprintf(payload, "{\"type\":\"dns\",\"value\":\"%b\"}", dom);
    }
    buffer_write_sstring(payload, ss("]}"));
    if (!acme_jws_encode(req, payload, acme.new_order_url)) {
        msg_err("acme: failed to encode JWS for order");
        acme_req_free(req);
    } else {
        req->url = acme.new_order_url;
        req->method = HTTP_REQUEST_METHOD_POST;
        init_closure_func(&req->resp_handler, value_handler, acme_order_resp);
        acme_request(req);
    }
    deallocate_buffer(payload);
}

static void acme_renew(acme_cert cert)
{
    if (!acme_get_ready()) {
        if (acme.state != ACME_STATE_ERROR)
            /* Retry later */
            register_timer(kernel_timers, &cert->renew_timer, CLOCK_ID_MONOTONIC_RAW, seconds(5),
                           false, 0, (timer_handler)&cert->renew_timer_handler);
        else
            msg_err("acme: setup error, cannot renew certificate at %s", cert->cert_chain);
        return;
    }
    acme_debug("starting renewal of certificate at %s", cert->cert_chain);
    if (!acme_req_new(acme_order, cert))
        msg_err("acme: out of memory, cannot renew certificate at %s", cert->cert_chain);
}

closure_func_basic(timer_handler, void, acme_renew_timer_handler,
                   u64 expiry, u64 overruns)
{
    acme_cert cert = struct_from_closure(acme_cert, renew_timer_handler);
    switch (cert->state) {
    case ACME_CERT_RENEW:
        acme_renew(cert);
        break;
    case ACME_CERT_CHALLENGE:
    case ACME_CERT_FINALIZE:
        acme_order_poll(cert);
        break;
    default:    /* should never happen */
        break;
    }
}

static status acme_domain_parse(acme_cert cert, mbedtls_asn1_buf *buf)
{
    u64 fqdn_len = buf->len;
    if (fqdn_len > FQDN_MAX_LEN)
        return timm("result", "acme: invalid domain length %ld", fqdn_len);
    string dom_str = allocate_string(fqdn_len);
    if (dom_str == INVALID_ADDRESS)
        return timm_oom;
    buffer_write(dom_str, buf->p, fqdn_len);
    acme_debug("adding domain %b", dom_str);
    vector_push(cert->domains, dom_str);
    return STATUS_OK;
}

closure_function(2, 1, status, acme_cert_chain_handler,
                 acme_cert, c, status_handler, complete,
                 buffer b)
{
    acme_cert c = bound(c);
    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);
    status s = STATUS_OK;
    int ret = mbedtls_x509_crt_parse(&crt, buffer_ref(b, 0), buffer_length(b));
    if (ret) {
        s = timm("result", "acme: failed to parse cert chain file (err %d)", ret);
        goto done;
    }
    c->valid_from = x509_time_to_timestamp(&crt.valid_from);
    c->valid_to = x509_time_to_timestamp(&crt.valid_to);
    if (vector_length(c->domains) == 0) {
        /* Extract Common Name (CN) */
        mbedtls_asn1_named_data *node = &crt.subject;
        while (node) {
            if (MBEDTLS_OID_CMP(MBEDTLS_OID_AT_CN, &node->oid) == 0) {
                s = acme_domain_parse(c, &node->val);
                if (!is_ok(s))
                    goto done;
                break;
            }
            node = node->next;
        }

        /* Extract Subject Alternative Names (SANs) if available */
        mbedtls_x509_sequence *san = &crt.subject_alt_names;
        while (san) {
            s = acme_domain_parse(c, &san->buf);
            if (!is_ok(s))
                goto done;
            san = san->next;
        }
    }
  done:
    mbedtls_x509_crt_free(&crt);
    deallocate_buffer(b);
    if (is_ok(s)) {
        if (vector_length(c->domains) > 0) {
            spin_lock(&acme.lock);
            list_push_back(&acme.certs, &c->e);
            spin_unlock(&acme.lock);
        } else {
            s = timm("result", "acme: no domains found in certificate chain");
        }
    } else {
        deallocate_vector(c->domains);
        deallocate(acme.h, c, sizeof(*c));
    }
    apply(bound(complete), s);
    closure_finish();
    return s;
}

static void acme_cert_init(value cert, status_handler complete)
{
    status s;
    if (!is_tuple(cert)) {
        s = timm("result", "acme: invalid certificate configuration %v", cert);
        goto done;
    }
    string cert_chain = get_string(cert, sym_this("cert_chain"));
    if (!cert_chain) {
        s = timm("result", "acme: missing or invalid cert chain file path in certificate %v", cert);
        goto done;
    }
    string priv_key = get_string(cert, sym_this("private_key"));
    if (!priv_key) {
        s = timm("result", "acme: missing or invalid private key file path in certificate %v",
                 cert);
        goto done;
    }
    value domains = get(cert, sym_this("domains"));
    acme_cert c = mem_alloc(acme.h, sizeof(*c), MEM_NOFAIL);
    c->cert_chain = buffer_to_sstring(cert_chain);
    c->priv_key = buffer_to_sstring(priv_key);
    c->domains = allocate_vector(acme.h, 1);
    if (c->domains == INVALID_ADDRESS) {
        s = timm_oom;
        goto err_dealloc_cert;
    }
    c->order_url = c->finalize_url = c->cert_url = sstring_null();
    list_init(&c->auths);
    if (domains) {
        if (!is_composite(domains)) {
            s = timm("result", "acme: invalid domains %v", domains);
            goto err_dealloc_doms;
        }
        value dom;
        for (int i = 0; (dom = get(domains, integer_key(i))); i++) {
            if (!is_string(dom) || (buffer_length(dom) > FQDN_MAX_LEN)) {
                s = timm("result", "acme: invalid domain %v", dom);
                goto err_dealloc_doms;
            }
            vector_push(c->domains, dom);
        }
    }
    init_timer(&c->renew_timer);
    init_closure_func(&c->renew_timer_handler, timer_handler, acme_renew_timer_handler);
    c->state = ACME_CERT_RENEW;
    filesystem fs = get_root_fs();
    vector cert_chain_v = split(acme.h, cert_chain, '/');
    tuple cert_chain_t = resolve_path(filesystem_getroot(fs), cert_chain_v);
    split_dealloc(cert_chain_v);
    if (cert_chain_t) {
        buffer_handler bh = closure(acme.h, acme_cert_chain_handler, c, complete);
        if (bh == INVALID_ADDRESS) {
            s = timm_oom;
            goto err_dealloc_doms;
        }
        filesystem_read_entire(fs, cert_chain_t, acme.h, bh, complete);
        return;
    } else {
        if (vector_length(c->domains) == 0) {
            s = timm("result",
                     "acme: no domains specified and missing cert chain file for certificate %v",
                     cert);
            goto err_dealloc_doms;
        }
        /* No certificate found, a new one needs to be generated now */
        c->valid_from = c->valid_to = kern_now(CLOCK_ID_REALTIME);
        spin_lock(&acme.lock);
        list_push_back(&acme.certs, &c->e);
        spin_unlock(&acme.lock);
    }
    s = STATUS_OK;
    goto done;
  err_dealloc_doms:
    deallocate_vector(c->domains);
  err_dealloc_cert:
    deallocate(acme.h, c, sizeof(*c));
  done:
    apply(complete, s);
}

closure_function(1, 1, void, acme_init_complete,
                 status_handler, complete,
                 status s)
{
    status_handler complete = bound(complete);
    if (is_ok(s)) {
        list_foreach(&acme.certs, l) {
            acme_renew_setup(struct_from_list(l, acme_cert, e));
        }
    }
    closure_finish();
    apply(complete, s);
}

int init(status_handler complete)
{
    tuple config = get(get_root_tuple(), sym_this("acme"));
    if (!config)
        return KLIB_INIT_OK;
    string server = get_string(config, sym_this("server"));
    if (!server) {
        msg_err("acme: missing or invalid server in configuration");
        return KLIB_INIT_FAILED;
    }
    acme.directory_url = buffer_to_sstring(server);
    string email = get_string(config, sym_this("email"));
    if (email) {
        if (buffer_length(email) > EMAIL_ADDR_MAX_LEN) {
            msg_err("acme: invalid e-mail address");
            return KLIB_INIT_FAILED;
        }
        acme.email = buffer_to_sstring(email);
    } else {
        acme.email = sstring_null();
    }
    string web_dir = get_string(config, sym_this("web_dir"));
    if (!web_dir) {
        msg_err("acme: missing or invalid web_dir in configuration");
        return KLIB_INIT_FAILED;
    }
    acme.web_dir = buffer_to_sstring(web_dir);
    value reload_action = get(config, sym_this("reload"));
    int reload_signal;
    if (reload_action) {
        if (!is_string(reload_action)) {
            msg_err("acme: invalid reload action %v", reload_action);
            return KLIB_INIT_FAILED;
        }
        if (!buffer_strcmp(reload_action, "SIGHUP")) {
            reload_signal = SIGHUP;
        } else if (!buffer_strcmp(reload_action, "SIGUSR1")) {
                reload_signal = SIGUSR1;
        } else {
            msg_err("acme: invalid reload action '%b'", reload_action);
            return KLIB_INIT_FAILED;
        }
    } else {
        reload_signal = 0;  /* no signal sent to load a renewed certificate */
    }
    acme.reload_signal = reload_signal;
    value certificates = get(config, sym_this("certificates"));
    if (!is_composite(certificates)) {
        msg_err("acme: missing or invalid certificates in configuration");
        return KLIB_INIT_FAILED;
    }
    list_init(&acme.certs);
    acme.h = heap_locked(get_kernel_heaps());
    status_handler init_complete = closure(acme.h, acme_init_complete, complete);
    if (init_complete == INVALID_ADDRESS) {
        msg_err("acme: out of memory");
        return KLIB_INIT_FAILED;
    }
    buffer_init_from_string(&acme.user_agent, "Nanos");
    acme.state = ACME_STATE_INIT;
    acme.nonce = sstring_null();
    spin_lock_init(&acme.lock);
    merge m = allocate_merge(acme.h, init_complete);
    if (m == INVALID_ADDRESS) {
        msg_err("acme: out of memory");
        return KLIB_INIT_FAILED;
    }
    status_handler sh = apply_merge(m);
    value cert;
    for (int i = 0; (cert = get(certificates, integer_key(i))); i++)
        acme_cert_init(cert, apply_merge(m));
    apply(sh, STATUS_OK);
    return KLIB_INIT_IN_PROGRESS;
}
