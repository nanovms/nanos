#include <kernel.h>
#include <lwip.h>

#define _RUNTIME_H_ /* guard against double inclusion of runtime.h */
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ssl.h>

typedef struct tls_conn {
    mbedtls_ssl_context ssl;
    closure_struct(connection_handler, ch);
    closure_struct(input_buffer_handler, in);
    buffer_handler out;
    connection_handler app_ch;
    input_buffer_handler app_in;
    closure_struct(buffer_handler, app_out);
    buffer incoming, outgoing;
    enum {
        tls_handshake,
        tls_open,
        tls_closing,
    } state;
    struct refcount refcount;
    closure_struct(thunk, free);
} *tls_conn;

static struct {
    mbedtls_ssl_config conf;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_x509_crt cacert;
    heap h;
} tls;

static void tls_close(tls_conn conn)
{
    if (conn->app_in) {
        input_buffer_handler app_in = conn->app_in;
        conn->app_in = 0;
        apply(app_in, 0);   /* notify connection shutdown to application layer */
    } else if (conn->app_ch) {
        connection_handler app_ch = conn->app_ch;
        conn->app_ch = 0;
        apply(app_ch, 0);   /* notify connection failure to application layer */
    }
    if (conn->out) {
        buffer_handler out = conn->out;
        conn->out = 0;
        apply(out, 0);  /* close underlying TCP connection */
    } else {
        refcount_release(&conn->refcount);
    }
}

static int tls_send(void *ctx, const unsigned char *buf, size_t len)
{
    tls_conn conn = ctx;
    if (!conn->out)
        return MBEDTLS_ERR_SSL_CONN_EOF;
    buffer b = wrap_buffer(tls.h, (void *)buf, len);
    if (b == INVALID_ADDRESS)
        return MBEDTLS_ERR_SSL_ALLOC_FAILED;
    status s = apply(conn->out, b);
    if (!is_ok(s)) {
        timm_dealloc(s);
        deallocate_buffer(b);
        return MBEDTLS_ERR_SSL_ALLOC_FAILED;
    }
    return len;
}

static int tls_recv(void *ctx, unsigned char *buf, size_t len)
{
    tls_conn conn = ctx;
    if (!conn->incoming || (buffer_length(conn->incoming) == 0))
        return MBEDTLS_ERR_SSL_WANT_READ;
    len = MIN(buffer_length(conn->incoming), len);
    runtime_memcpy(buf, buffer_ref(conn->incoming, 0), len);
    buffer_consume(conn->incoming, len);
    return len;
}

static int tls_out_internal(tls_conn conn, buffer b)
{
    if (!b)
        b = conn->outgoing;
    u64 len = buffer_length(b);
    int ret = 0;
    while (len > 0) {
        ret = mbedtls_ssl_write(&conn->ssl, buffer_ref(b, 0), len);
        if (ret <= 0) {
            if ((ret == MBEDTLS_ERR_SSL_WANT_READ) || (ret == MBEDTLS_ERR_SSL_WANT_WRITE)) {
                ret = 0;
            } else if (ret < 0) {
                tls_close(conn);
                deallocate_buffer(b);
                return -1;
            }
            break;
        }
        buffer_consume(b, ret);
        len -= ret;
    }
    if (len == 0) {
        deallocate_buffer(b);
        if (b == conn->outgoing)
            conn->outgoing = 0;
    } else {
        conn->outgoing = b;
    }
    return ret;
}

closure_func_basic(buffer_handler, status, tls_out_handler,
                   buffer b)
{
    tls_conn conn = struct_from_closure(tls_conn, app_out);
    if (b) {
        tls_out_internal(conn, b);
    } else {    /* application requested connection shutdown */
        int ret = mbedtls_ssl_close_notify(&conn->ssl);
        if ((ret == MBEDTLS_ERR_SSL_WANT_READ) || (ret == MBEDTLS_ERR_SSL_WANT_WRITE))
            conn->state = tls_closing;
        else
            tls_close(conn);
    }
    return STATUS_OK;
}

closure_func_basic(input_buffer_handler, boolean, tls_in_handler,
                   buffer b)
{
    tls_conn conn = struct_from_closure(tls_conn, in);
    refcount_reserve(&conn->refcount);
    if (!b) {   /* underlying TCP connection closed */
        conn->out = 0;
        goto conn_close;
    }
    conn->incoming = b;
    int ret;
    switch (conn->state) {
    case tls_handshake:
        ret = mbedtls_ssl_handshake(&conn->ssl);
        if (ret == 0) {
            conn->state = tls_open;
            conn->app_in = apply(conn->app_ch, init_closure_func(&conn->app_out, buffer_handler,
                                                                 tls_out_handler));
            conn->app_ch = 0;   /* so that it is not invoked when the connection is closed */
            if (conn->app_in == INVALID_ADDRESS)    /* application-level error */
                goto conn_close;
        } else if ((ret != MBEDTLS_ERR_SSL_WANT_READ) && (ret != MBEDTLS_ERR_SSL_WANT_WRITE)) {
            goto conn_close;
        }
        break;
    case tls_open:
        b = little_stack_buffer(2 * KB);
        do {
            ret = mbedtls_ssl_read(&conn->ssl, buffer_ref(b, 0), b->length);
            if (ret > 0) {
                buffer_produce(b, ret);
                if (conn->app_in) {
                    if (apply(conn->app_in, b))
                        break;  /* application requested connection shutdown */
                }
                buffer_clear(b);
            } else if ((ret != MBEDTLS_ERR_SSL_WANT_READ) && (ret != MBEDTLS_ERR_SSL_WANT_WRITE)) {
                if (MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
                    break;
                goto conn_close;
            }
            if (conn->outgoing && (tls_out_internal(conn, 0) < 0))
                /* An error happened and the connection has been closed. */
                break;
        } while ((ret > 0) && conn->app_in);
        break;
    case tls_closing:
        ret = mbedtls_ssl_close_notify(&conn->ssl);
        if ((ret != MBEDTLS_ERR_SSL_WANT_READ) && (ret != MBEDTLS_ERR_SSL_WANT_WRITE))
            goto conn_close;
        break;
    }
    conn->incoming = 0;
    boolean conn_closed = conn->out == 0;
    refcount_release(&conn->refcount);
    return conn_closed;
  conn_close:
    refcount_release(&conn->refcount);
    tls_close(conn);
    return true;
}

closure_func_basic(connection_handler, input_buffer_handler, tls_conn_handler,
                   buffer_handler out)
{
    tls_conn conn = struct_from_closure(tls_conn, ch);
    conn->out = out;
    if (!out)   /* TCP connection failed */
        goto conn_close;
    input_buffer_handler in = init_closure_func(&conn->in, input_buffer_handler, tls_in_handler);
    mbedtls_ssl_set_bio(&conn->ssl, conn, tls_send, tls_recv, NULL);
    conn->state = tls_handshake;
    int ret = mbedtls_ssl_handshake(&conn->ssl);
    if ((ret != 0) && (ret != MBEDTLS_ERR_SSL_WANT_READ) && (ret != MBEDTLS_ERR_SSL_WANT_WRITE))
        goto conn_close;
    return in;
  conn_close:
    tls_close(conn);
    return 0;
}

closure_func_basic(thunk, void, tls_conn_free)
{
    tls_conn conn = struct_from_field(closure_self(), tls_conn, free);
    mbedtls_ssl_free(&conn->ssl);
    deallocate(tls.h, conn, sizeof(*conn));
}

int tls_set_cacert(void *cert, u64 len)
{
    mbedtls_x509_crt_init(&tls.cacert);
    int ret = mbedtls_x509_crt_parse(&tls.cacert, cert, len);
    if (ret < 0) {
        msg_err("%s: cannot parse certificate (%d)", func_ss, ret);
        return ret;
    }
    mbedtls_ssl_conf_ca_chain(&tls.conf, &tls.cacert, NULL);
    mbedtls_ssl_conf_authmode(&tls.conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    return ret;
}

int tls_connect(ip_addr_t *addr, u16 port, connection_handler ch)
{
    tls_conn conn = allocate(tls.h, sizeof(*conn));
    if (conn == INVALID_ADDRESS)
        return -1;
    mbedtls_ssl_init(&conn->ssl);
    int ret = mbedtls_ssl_setup(&conn->ssl, &tls.conf);
    if (ret) {
        msg_err("%s: cannot set up SSL context", func_ss);
        goto err_ssl_setup;
    }
    conn->app_ch = ch;
    conn->app_in = 0;
    conn->incoming = conn->outgoing = 0;
    init_refcount(&conn->refcount, 1, init_closure_func(&conn->free, thunk, tls_conn_free));
    status s = direct_connect(tls.h, addr, port,
                              init_closure_func(&conn->ch, connection_handler, tls_conn_handler));
    if (!is_ok(s)) {
        timm_dealloc(s);
        ret = -1;
        goto err_connect;
    }
    return 0;
  err_connect:
    mbedtls_ssl_free(&conn->ssl);
  err_ssl_setup:
    deallocate(tls.h, conn, sizeof(*conn));
    return ret;
}

int init(status_handler complete)
{
    tls.h = heap_malloc();
    mbedtls_ssl_config_init(&tls.conf);
    mbedtls_ctr_drbg_init(&tls.ctr_drbg);
    mbedtls_entropy_init(&tls.entropy);
    if (mbedtls_ctr_drbg_seed(&tls.ctr_drbg, mbedtls_entropy_func, &tls.entropy, 0, 0)) {
        msg_err("TLS init: cannot seed entropy source");
        return KLIB_INIT_FAILED;
    }
    mbedtls_ssl_config_defaults(&tls.conf, MBEDTLS_SSL_IS_CLIENT,
        MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_conf_authmode(&tls.conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&tls.conf, mbedtls_ctr_drbg_random, &tls.ctr_drbg);
    return KLIB_INIT_OK;
}

void mbedtls_platform_zeroize( void *buf, size_t len )
{
    zero(buf, len);
}

void *mbedtls_calloc(size_t n, size_t s)
{
    size_t total = n * s;
    void *p = allocate(tls.h, total);
    if (p != INVALID_ADDRESS) {
        runtime_memset(p, 0, total);
        return p;
    } else {
        return 0;
    }
}

void mbedtls_free(void *x)
{
    if (x)
        deallocate(tls.h, x, -1ull);
}

int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen)
{
    *olen = random_buffer(alloca_wrap_buffer(output, len));
    return 0;
}

struct tm *mbedtls_platform_gmtime_r(const mbedtls_time_t *tt, struct tm *tm_buf)
{
    return gmtime_r((u64 *)tt, tm_buf);
}

/* gcc will sometimes generate a call to mem* functions. On an aarch64
   build with gcc 8.3.0, mbedtls_sha256_clone generates a call to
   memcpy. There doesn't appear to be some universal flag to disable
   this behavior, so use a wrapper... */

#undef memcpy /* lwIP */
void *memcpy(void *dst, const void *src, u64 n)
{
    runtime_memcpy(dst, src, n);
    return dst;
}
