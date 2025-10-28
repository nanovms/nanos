#include <kernel.h>
#include <lwip.h>
#include "net_utils.h"

#define _RUNTIME_H_ /* guard against double inclusion of runtime.h */
#include <mbedtls/base64.h>

#define METADATA_SERVER_ADDR    ss("169.254.169.254")

/* Retry configuration: 5 retries at 3 second intervals = 15 seconds maximum wait */
#define MAX_NETWORK_RETRIES     5
#define RETRY_INTERVAL_SECONDS  3

#ifdef USERDATA_ENV_DEBUG
#define userdata_env_debug(fmt, ...)   tprintf(sym(userdata_env), 0, ss(fmt "\n"), ##__VA_ARGS__)
#else
#define userdata_env_debug(fmt, ...)
#endif

/* Cloud provider types */
enum cloud_provider {
    PROVIDER_AWS,
    PROVIDER_GCP,
    PROVIDER_AZURE,
    PROVIDER_DIGITALOCEAN,
    PROVIDER_OPENSTACK,
    PROVIDER_HETZNER,
    PROVIDER_MAX,
    PROVIDER_UNKNOWN
};

/* Provider detection/fetch configuration */
struct provider_config {
    sstring name;
    sstring detect_path;
    sstring detect_header_name;
    sstring detect_header_value;
    http_method detect_method;
    sstring userdata_path;
    sstring userdata_header_name;
    sstring userdata_header_value;
    boolean needs_base64_decode;
    boolean needs_token;  /* for AWS IMDSv2 */
};

static const struct provider_config providers[] = {
    [PROVIDER_AWS] = {
        .name = ss_static_init("AWS"),
        .detect_path = ss_static_init("/latest/api/token"),
        .detect_header_name = ss_static_init("X-aws-ec2-metadata-token-ttl-seconds"),
        .detect_header_value = ss_static_init("21600"),
        .detect_method = HTTP_REQUEST_METHOD_PUT,
        .userdata_path = ss_static_init("/latest/user-data"),
        .userdata_header_name = ss_static_init("X-aws-ec2-metadata-token"),
        .userdata_header_value = sstring_null_init,  /* filled with token */
        .needs_base64_decode = false,
        .needs_token = true,
    },
    [PROVIDER_GCP] = {
        .name = ss_static_init("GCP"),
        .detect_path = ss_static_init("/computeMetadata/v1/"),
        .detect_header_name = ss_static_init("Metadata-Flavor"),
        .detect_header_value = ss_static_init("Google"),
        .detect_method = HTTP_REQUEST_METHOD_GET,
        .userdata_path = ss_static_init("/computeMetadata/v1/instance/attributes/user-data"),
        .userdata_header_name = ss_static_init("Metadata-Flavor"),
        .userdata_header_value = ss_static_init("Google"),
        .needs_base64_decode = false,
        .needs_token = false,
    },
    [PROVIDER_AZURE] = {
        .name = ss_static_init("Azure"),
        .detect_path = ss_static_init("/metadata/instance?api-version=2021-01-01"),
        .detect_header_name = ss_static_init("Metadata"),
        .detect_header_value = ss_static_init("true"),
        .detect_method = HTTP_REQUEST_METHOD_GET,
        .userdata_path = ss_static_init("/metadata/instance/compute/userData?api-version=2021-01-01&format=text"),
        .userdata_header_name = ss_static_init("Metadata"),
        .userdata_header_value = ss_static_init("true"),
        .needs_base64_decode = true,
        .needs_token = false,
    },
    [PROVIDER_DIGITALOCEAN] = {
        .name = ss_static_init("DigitalOcean"),
        .detect_path = ss_static_init("/metadata/v1/id"),
        .detect_header_name = sstring_null_init,
        .detect_header_value = sstring_null_init,
        .detect_method = HTTP_REQUEST_METHOD_GET,
        .userdata_path = ss_static_init("/metadata/v1/user-data"),
        .userdata_header_name = sstring_null_init,
        .userdata_header_value = sstring_null_init,
        .needs_base64_decode = true,
        .needs_token = false,
    },
    [PROVIDER_OPENSTACK] = {
        .name = ss_static_init("OpenStack"),
        .detect_path = ss_static_init("/openstack/latest/"),
        .detect_header_name = sstring_null_init,
        .detect_header_value = sstring_null_init,
        .detect_method = HTTP_REQUEST_METHOD_GET,
        .userdata_path = ss_static_init("/openstack/latest/user-data"),
        .userdata_header_name = sstring_null_init,
        .userdata_header_value = sstring_null_init,
        .needs_base64_decode = false,
        .needs_token = false,
    },
    [PROVIDER_HETZNER] = {
        .name = ss_static_init("Hetzner"),
        .detect_path = ss_static_init("/hetzner/v1/metadata"),
        .detect_header_name = sstring_null_init,
        .detect_header_value = sstring_null_init,
        .detect_method = HTTP_REQUEST_METHOD_GET,
        .userdata_path = ss_static_init("/hetzner/v1/userdata"),
        .userdata_header_name = sstring_null_init,
        .userdata_header_value = sstring_null_init,
        .needs_base64_decode = false,
        .needs_token = false,
    },
};

typedef struct userdata_env {
    heap h;
    status_handler complete;
    enum cloud_provider current_provider;
    buffer aws_token;  /* for AWS IMDSv2 */
    boolean detecting;
    boolean started;  /* true after first provider attempt */
    int retry_count;
    closure_struct(value_handler, userdata_vh);
    closure_struct(value_handler, detect_vh);
} *userdata_env;

static userdata_env ue;

/* Forward declarations */
static void try_next_provider(void);
static void fetch_userdata(enum cloud_provider provider);
static boolean metadata_server_reachable(void);

/* Parse a line for VARNAME=value format and set environment variable */
static void parse_and_set_env_line(buffer line)
{
    if (buffer_length(line) == 0)
        return;

    /* Skip comments and blank lines */
    char first = byte(line, 0);
    if (first == '#' || first == '\n' || first == '\r')
        return;

    int eq_pos = buffer_strchr(line, '=');
    if (eq_pos <= 0)
        return;  /* no equals sign or it's at the start */

    /* Extract variable name */
    buffer name_buf = allocate_buffer(ue->h, eq_pos);
    if (name_buf == INVALID_ADDRESS)
        return;

    buffer_write(name_buf, buffer_ref(line, 0), eq_pos);

    /* Extract value (rest of line after '=') */
    int value_len = buffer_length(line) - eq_pos - 1;

    /* Trim trailing newline/carriage return */
    while (value_len > 0) {
        char last = byte(line, eq_pos + value_len);
        if (last == '\n' || last == '\r')
            value_len--;
        else
            break;
    }

    if (value_len > 0) {
        buffer value_buf = allocate_buffer(ue->h, value_len);
        if (value_buf != INVALID_ADDRESS) {
            buffer_write(value_buf, buffer_ref(line, eq_pos + 1), value_len);

            /* Set environment variable */
            symbol var_sym = intern(name_buf);
            set(get_environment(), var_sym, value_buf);

            userdata_env_debug("Set environment variable: %b=%b", name_buf, value_buf);
        }
    }

    deallocate_buffer(name_buf);
}

/* Parse userdata content for environment variables */
static void parse_userdata(buffer content)
{
    if (!content || buffer_length(content) == 0)
        return;

    buffer line = allocate_buffer(ue->h, 512);
    if (line == INVALID_ADDRESS)
        return;

    bytes offset = 0;
    bytes content_len = buffer_length(content);

    while (offset < content_len) {
        buffer_clear(line);

        /* Read until newline */
        while (offset < content_len) {
            char c = byte(content, offset++);
            push_u8(line, c);
            if (c == '\n')
                break;
        }

        parse_and_set_env_line(line);
    }

    deallocate_buffer(line);
}

/* Decode base64 content (for Azure) */
static buffer decode_base64(buffer encoded)
{
    if (!encoded || buffer_length(encoded) == 0)
        return 0;

    /* Calculate required output size */
    bytes encoded_len = buffer_length(encoded);
    bytes decoded_len = (encoded_len * 3) / 4 + 4;  /* upper bound */

    buffer decoded = allocate_buffer(ue->h, decoded_len);
    if (decoded == INVALID_ADDRESS)
        return 0;

    size_t actual_len;
    int ret = mbedtls_base64_decode(buffer_ref(decoded, 0), decoded_len,
                                     &actual_len,
                                     buffer_ref(encoded, 0), encoded_len);

    if (ret == 0) {
        buffer_produce(decoded, actual_len);
        return decoded;
    } else {
        deallocate_buffer(decoded);
        return 0;
    }
}

closure_func_basic(value_handler, void, userdata_vh,
                   value v)
{
    if (!v) {
        msg_err("userdata_env: failed to fetch userdata");
        try_next_provider();
        return;
    }

    value start_line = get(v, sym(start_line));
    buffer status_code = get(start_line, integer_key(1));

    if (!status_code || buffer_length(status_code) < 1 || byte(status_code, 0) != '2') {
        /* Not a 2xx response, try next provider */
        userdata_env_debug("Non-2xx response from %s: %v",
                          providers[ue->current_provider].name, start_line);
        try_next_provider();
        return;
    }

    buffer content = get(v, sym_this("content"));
    if (!content || buffer_length(content) == 0) {
        userdata_env_debug("Empty userdata from %s", providers[ue->current_provider].name);
        /* Empty userdata is OK, just complete */
        apply(ue->complete, STATUS_OK);
        return;
    }

    /* Decode base64 if needed (Azure) */
    buffer decoded = content;
    if (providers[ue->current_provider].needs_base64_decode) {
        decoded = decode_base64(content);
        if (!decoded) {
            msg_err("userdata_env: failed to decode base64 userdata");
            try_next_provider();
            return;
        }
    }

    userdata_env_debug("Got userdata from %s, parsing environment variables",
                      providers[ue->current_provider].name);

    /* Parse and set environment variables */
    parse_userdata(decoded);

    if (decoded != content)
        deallocate_buffer(decoded);

    /* Success! */
    apply(ue->complete, STATUS_OK);
}

closure_func_basic(value_handler, void, detect_vh,
                   value v)
{
    if (!v) {
        try_next_provider();
        return;
    }

    value start_line = get(v, sym(start_line));
    buffer status_code = get(start_line, integer_key(1));

    if (status_code && buffer_length(status_code) >= 1 && byte(status_code, 0) == '2') {
        /* Detected! */
        userdata_env_debug("Detected cloud provider: %s", providers[ue->current_provider].name);

        /* Set PROVIDER environment variable for debugging */
        sstring provider_name = providers[ue->current_provider].name;
        buffer provider_buf = allocate_buffer(ue->h, provider_name.len);
        if (provider_buf != INVALID_ADDRESS) {
            buffer_write_sstring(provider_buf, provider_name);
            set(get_environment(), sym(USERDATA_ENV_PROVIDER), provider_buf);
            userdata_env_debug("Set PROVIDER=%s", provider_name);
        }

        /* For AWS, save the token for userdata fetch */
        if (providers[ue->current_provider].needs_token) {
            buffer token = get(v, sym_this("content"));
            if (token) {
                ue->aws_token = clone_buffer(ue->h, token);
                if (ue->aws_token == INVALID_ADDRESS) {
                    msg_err("userdata_env: failed to allocate AWS token buffer");
                    apply(ue->complete, STATUS_OK);
                    return;
                }
            }
        }

        /* Now fetch userdata */
        ue->detecting = false;
        fetch_userdata(ue->current_provider);
    } else {
        /* Detection failed, try next */
        try_next_provider();
    }
}

static void fetch_userdata(enum cloud_provider provider)
{
    const struct provider_config *cfg = &providers[provider];

    struct net_http_req_params params;
    params.host = METADATA_SERVER_ADDR;
    params.port = 80;
    params.tls = false;
    params.method = HTTP_REQUEST_METHOD_GET;

    tuple req = allocate_tuple();
    if (req == INVALID_ADDRESS) {
        msg_err("userdata_env: failed to allocate request tuple");
        apply(ue->complete, STATUS_OK);
        return;
    }

    /* Set URL */
    buffer url = allocate_buffer(ue->h, 128);
    if (url == INVALID_ADDRESS) {
        deallocate_value(req);
        msg_err("userdata_env: failed to allocate URL buffer");
        apply(ue->complete, STATUS_OK);
        return;
    }
    buffer_write_sstring(url, cfg->userdata_path);
    set(req, sym(url), url);

    /* Set provider-specific header if needed */
    if (!sstring_is_null(cfg->userdata_header_name)) {
        buffer header_val;

        /* For AWS, use the token we fetched */
        if (cfg->needs_token && ue->aws_token) {
            header_val = ue->aws_token;
        } else {
            header_val = allocate_buffer(ue->h, cfg->userdata_header_value.len);
            if (header_val == INVALID_ADDRESS) {
                deallocate_value(req);
                msg_err("userdata_env: failed to allocate header buffer");
                apply(ue->complete, STATUS_OK);
                return;
            }
            buffer_write_sstring(header_val, cfg->userdata_header_value);
        }

        symbol header_sym = intern(alloca_wrap_sstring(cfg->userdata_header_name));
        set(req, header_sym, header_val);
    }

    params.req = req;
    params.body = 0;
    params.resp_handler = init_closure_func(&ue->userdata_vh, value_handler, userdata_vh);

    status s = net_http_req(&params);
    if (!is_ok(s)) {
        msg_err("userdata_env: HTTP request failed: %v", s);
        timm_dealloc(s);
        deallocate_value(req);
        apply(ue->complete, STATUS_OK);
    }
}

static void try_provider(enum cloud_provider provider)
{
    const struct provider_config *cfg = &providers[provider];

    ue->current_provider = provider;
    ue->detecting = true;

    userdata_env_debug("Trying provider: %s", cfg->name);

    struct net_http_req_params params;
    params.host = METADATA_SERVER_ADDR;
    params.port = 80;
    params.tls = false;
    params.method = cfg->detect_method;

    tuple req = allocate_tuple();
    if (req == INVALID_ADDRESS) {
        msg_err("userdata_env: failed to allocate request tuple");
        try_next_provider();
        return;
    }

    /* Set URL */
    buffer url = allocate_buffer(ue->h, 128);
    if (url == INVALID_ADDRESS) {
        deallocate_value(req);
        msg_err("userdata_env: failed to allocate URL buffer");
        try_next_provider();
        return;
    }
    buffer_write_sstring(url, cfg->detect_path);
    set(req, sym(url), url);

    /* Set provider-specific header if needed */
    if (!sstring_is_null(cfg->detect_header_name)) {
        buffer header_val = allocate_buffer(ue->h, cfg->detect_header_value.len);
        if (header_val == INVALID_ADDRESS) {
            deallocate_value(req);
            msg_err("userdata_env: failed to allocate header buffer");
            try_next_provider();
            return;
        }
        buffer_write_sstring(header_val, cfg->detect_header_value);

        symbol header_sym = intern(alloca_wrap_sstring(cfg->detect_header_name));
        set(req, header_sym, header_val);
    }

    params.req = req;
    params.body = 0;
    params.resp_handler = init_closure_func(&ue->detect_vh, value_handler, detect_vh);

    status s = net_http_req(&params);
    if (!is_ok(s)) {
        userdata_env_debug("Detection request failed for %s: %v", cfg->name, s);
        timm_dealloc(s);
        deallocate_value(req);
        try_next_provider();
    }
}

static void try_next_provider(void)
{
    if (!ue->started) {
        /* First provider attempt */
        ue->started = true;
        ue->current_provider = PROVIDER_AWS;
        try_provider(ue->current_provider);
    } else if (ue->current_provider < PROVIDER_MAX - 1) {
        /* Try next provider */
        ue->current_provider++;
        try_provider(ue->current_provider);
    } else {
        /* Exhausted all providers */
        userdata_env_debug("No cloud provider detected or no userdata available");
        apply(ue->complete, STATUS_OK);
    }
}

closure_function(1, 2, void, retry_detection,
                 struct timer, timer,
                 u64 expiry, u64 overruns)
{
    if (overruns == timer_disabled)
        return;

    ue->retry_count++;

    if (ue->retry_count > MAX_NETWORK_RETRIES) {
        userdata_env_debug("Max retries (%d) reached, network not available", MAX_NETWORK_RETRIES);
        apply(ue->complete, STATUS_OK);
        closure_finish();
        return;
    }

    userdata_env_debug("Retry %d/%d: checking if network is available",
                      ue->retry_count, MAX_NETWORK_RETRIES);

    /* Check if metadata server is reachable now */
    if (!metadata_server_reachable()) {
        userdata_env_debug("Metadata server still not reachable, scheduling retry %d",
                          ue->retry_count + 1);

        /* Schedule another retry */
        struct timer retry_timer = {0};
        init_timer(&retry_timer);
        timer_handler th = closure(ue->h, retry_detection, retry_timer);
        if (th != INVALID_ADDRESS) {
            register_timer(kernel_timers, &closure_member(retry_detection, th, timer),
                          CLOCK_ID_MONOTONIC, seconds(RETRY_INTERVAL_SECONDS), false, 0, th);
            closure_finish();
            return;
        }

        /* Failed to allocate timer, give up */
        userdata_env_debug("Failed to schedule retry, giving up");
        apply(ue->complete, STATUS_OK);
        closure_finish();
        return;
    }

    userdata_env_debug("Network is now available, starting cloud provider detection");
    /* started flag is already false, try_next_provider will handle initialization */
    try_next_provider();

    closure_finish();
}

static boolean metadata_server_reachable(void)
{
    ip_addr_t addr;
    if (!ipaddr_aton(METADATA_SERVER_ADDR, &addr))
        return false;

    struct netif *n = ip_route(&ip_addr_any, &addr);
    if (n) {
        netif_unref(n);
        return true;
    }
    return false;
}

int init(status_handler complete)
{
    /* Allocate our global state */
    heap h = heap_locked(get_kernel_heaps());
    ue = allocate(h, sizeof(*ue));
    if (ue == INVALID_ADDRESS)
        return KLIB_INIT_FAILED;

    zero(ue, sizeof(*ue));
    ue->h = h;
    ue->complete = complete;
    ue->current_provider = 0;
    ue->aws_token = 0;
    ue->retry_count = 0;
    ue->started = false;

    /* Check if metadata server is reachable */
    if (!metadata_server_reachable()) {
        userdata_env_debug("Metadata server not reachable, will retry up to %d times (every %d seconds)",
                          MAX_NETWORK_RETRIES, RETRY_INTERVAL_SECONDS);

        /* Schedule retry (network might not be ready yet) */
        struct timer retry_timer = {0};
        init_timer(&retry_timer);
        timer_handler th = closure(h, retry_detection, retry_timer);
        if (th == INVALID_ADDRESS) {
            deallocate(h, ue, sizeof(*ue));
            return KLIB_INIT_FAILED;
        }

        register_timer(kernel_timers, &closure_member(retry_detection, th, timer),
                      CLOCK_ID_MONOTONIC, seconds(RETRY_INTERVAL_SECONDS), false, 0, th);

        return KLIB_INIT_IN_PROGRESS;
    }

    /* Start provider detection */
    try_next_provider();

    return KLIB_INIT_IN_PROGRESS;
}
