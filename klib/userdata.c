#include <unix_internal.h>
#include <filesystem.h>
#include <lwip.h>
#include "net_utils.h"

#define _RUNTIME_H_ /* guard against double inclusion of runtime.h */
#include <mbedtls/base64.h>

#define METADATA_SERVER_ADDR    ss("169.254.169.254")

/* Retry configuration: 5 retries at 3 second intervals = 15 seconds maximum wait */
#define MAX_NETWORK_RETRIES     5
#define RETRY_INTERVAL_SECONDS  3

#ifdef USERDATA_DEBUG
#define userdata_debug(fmt, ...)   tprintf(sym(userdata), 0, ss(fmt "\n"), ##__VA_ARGS__)
#else
#define userdata_debug(fmt, ...)
#endif

/* Cloud provider types */
enum cloud_provider {
    PROVIDER_AWS,
    PROVIDER_GCP,
    PROVIDER_AZURE,
    PROVIDER_DIGITALOCEAN,
    PROVIDER_OPENSTACK,
    PROVIDER_HETZNER,
    PROVIDER_MAX
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

typedef struct userdata {
    heap h;
    status_handler complete;
    enum cloud_provider current_provider;
    buffer token;  /* for IMDSv2 */
    boolean started;  /* true after first provider attempt */
    int retry_count;
    buffer save_file_path;  /* path to save raw userdata if configured */
    struct timer retry_timer;
    closure_struct(value_handler, userdata_vh);
    closure_struct(value_handler, detect_vh);
    closure_struct(timer_handler, retry_th);
} *userdata;

static userdata ue;

/* Forward declarations */
static void try_next_provider(void);
static void fetch_userdata(enum cloud_provider provider);
static boolean metadata_server_reachable(void);

/* Parse a line for VARNAME=value format and set environment variable */
static void parse_and_set_env_line(sstring line)
{
    if (line.len == 0)
        return;

    /* Skip comments and blank lines */
    char first = line.ptr[0];
    if (first == '#' || first == '\n' || first == '\r')
        return;

    char *eq_ptr = runtime_strchr(line, '=');
    if (!eq_ptr || (eq_ptr == 0))
        return;  /* no equals sign or it's at the start */

    /* Extract value (rest of line after '=') */
    int value_len = line.ptr + line.len - eq_ptr - 1;

    /* Trim trailing newline/carriage return */
    while (value_len > 0) {
        char last = *(eq_ptr + value_len);
        if (last == '\n' || last == '\r')
            value_len--;
        else
            break;
    }

    if (value_len > 0) {
        buffer value_buf = allocate_buffer(ue->h, value_len);
        if (value_buf != INVALID_ADDRESS) {
            buffer_write(value_buf, eq_ptr + 1, value_len);

            /* Set environment variable using sstring approach */
            sstring name_ss = isstring(line.ptr, eq_ptr - line.ptr);
            symbol var_sym = sym_sstring(name_ss);
            set(get_environment(), var_sym, value_buf);

            userdata_debug("Set environment variable: %s=%b", name_ss, value_buf);
        }
    }
}

/* Parse userdata content for environment variables */
static void parse_userdata(buffer content)
{
    if (!content || buffer_length(content) == 0)
        return;

    bytes offset = 0;
    bytes content_len = buffer_length(content);

    while (offset < content_len) {
        bytes line_start = offset;;

        /* Read until newline */
        while (offset < content_len) {
            char c = byte(content, offset++);
            if (c == '\n')
                break;
        }

        parse_and_set_env_line(isstring(buffer_ref(content, line_start), offset - line_start));
    }
}

/* Decode base64 content (e.g. for Azure) */
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

static void userdata_complete(status s)
{
    apply(ue->complete, s);
    deallocate(ue->h, ue, sizeof(*ue));
}

/* Completion handler for file write operation */
closure_function(2, 2, void, userdata_write_complete,
                 fsfile, f, buffer, write_buf,
                 status s, bytes len)
{
    deallocate_buffer(bound(write_buf));
    fsfile_release(bound(f));
    userdata_complete(s);
    closure_finish();
}

closure_func_basic(value_handler, void, userdata_vh,
                   value v)
{
    if (!v) {
        msg_err("userdata: failed to fetch userdata");
        try_next_provider();
        return;
    }

    value start_line = get(v, sym(start_line));
    buffer status_code = get(start_line, integer_key(1));

    if (!status_code || buffer_length(status_code) < 1 || byte(status_code, 0) != '2') {
        /* Not a 2xx response, try next provider */
        userdata_debug("Non-2xx response from %s: %v",
                       providers[ue->current_provider].name, start_line);
        try_next_provider();
        return;
    }

    buffer content = get(v, sym_this("content"));
    if (!content || buffer_length(content) == 0) {
        userdata_debug("Empty userdata from %s", providers[ue->current_provider].name);
        /* Empty userdata is OK, just complete */
        userdata_complete(STATUS_OK);
        return;
    }

    /* Decode base64 if needed (Azure) */
    buffer decoded = content;
    if (providers[ue->current_provider].needs_base64_decode) {
        decoded = decode_base64(content);
        if (!decoded) {
            msg_err("userdata: failed to decode base64 userdata");
            try_next_provider();
            return;
        }
    }

    /* Check if we should save to file or parse environment variables */
    if (ue->save_file_path) {
        /* Save to file mode */
        userdata_debug("Saving userdata from %s to file: %b",
                          providers[ue->current_provider].name, ue->save_file_path);

        fsfile f = fsfile_open_or_create(buffer_to_sstring(ue->save_file_path), true);
        if (!f) {
            userdata_debug("Failed to open file: %b", ue->save_file_path);
            status s = timm("result", "userdata: failed to open file %b", ue->save_file_path);
            if (decoded != content)
                deallocate_buffer(decoded);
            userdata_complete(s);
            return;
        }
        buffer write_buf = clone_buffer(ue->h, decoded);

        /* Clean up decoded buffer after cloning */
        if (decoded != content)
            deallocate_buffer(decoded);

        if (write_buf == INVALID_ADDRESS) {
            userdata_debug("Failed to clone buffer");
            status s = timm("result", "userdata: failed to clone buffer");
            fsfile_release(f);
            userdata_complete(s);
            return;
        }

        /* Get buffer data and length */
        void *buf_ptr = buffer_ref(write_buf, 0);
        bytes len = buffer_length(write_buf);

        io_status_handler io_sh = closure(ue->h, userdata_write_complete, f, write_buf);
        if (io_sh == INVALID_ADDRESS) {
            userdata_debug("Failed to allocate completion handler");
            deallocate_buffer(write_buf);
            fsfile_release(f);
            userdata_complete(timm("result", "failed to allocate completion handler"));
            return;
        }

        /* Write userdata to file */
        userdata_debug("Writing %d bytes to %b", len, ue->save_file_path);
        filesystem_write_linear(f, buf_ptr, irangel(0, len), io_sh);

        /* Cleanup handled by async completion handler */
        return;
    } else {
        /* Parse environment variables mode */
        userdata_debug("Got userdata from %s, parsing environment variables",
                          providers[ue->current_provider].name);

        parse_userdata(decoded);

        if (decoded != content)
            deallocate_buffer(decoded);

        /* Success! */
        userdata_complete(STATUS_OK);
    }
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
        userdata_debug("Detected cloud provider: %s", providers[ue->current_provider].name);

        /* Set USERDATA_PROVIDER environment variable */
        sstring provider_name = providers[ue->current_provider].name;
        buffer provider_buf = allocate_buffer(ue->h, provider_name.len);
        if (provider_buf != INVALID_ADDRESS) {
            buffer_write_sstring(provider_buf, provider_name);
            set(get_environment(), sym(USERDATA_PROVIDER), provider_buf);
            userdata_debug("Set USERDATA_PROVIDER=%s", provider_name);
        }

        /* For AWS, save the token for userdata fetch */
        if (providers[ue->current_provider].needs_token) {
            buffer token = get(v, sym_this("content"));
            if (token) {
                ue->token = clone_buffer(ue->h, token);
                if (ue->token == INVALID_ADDRESS) {
                    msg_err("userdata: failed to allocate token buffer");
                    userdata_complete(timm_oom);
                    return;
                }
            }
        }

        /* Now fetch userdata */
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
        msg_err("userdata: failed to allocate request tuple");
        userdata_complete(timm_oom);
        return;
    }

    /* Set URL */
    buffer url = allocate_buffer(ue->h, 128);
    if (url == INVALID_ADDRESS) {
        deallocate_value(req);
        msg_err("userdata: failed to allocate URL buffer");
        userdata_complete(timm_oom);
        return;
    }
    buffer_write_sstring(url, cfg->userdata_path);
    set(req, sym(url), url);

    /* Set provider-specific header if needed */
    if (!sstring_is_null(cfg->userdata_header_name)) {
        buffer header_val;

        /* For AWS, use the token we fetched */
        if (cfg->needs_token && ue->token) {
            header_val = ue->token;
        } else {
            header_val = allocate_buffer(ue->h, cfg->userdata_header_value.len);
            if (header_val == INVALID_ADDRESS) {
                deallocate_value(req);
                msg_err("userdata: failed to allocate header buffer");
                userdata_complete(timm_oom);
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
        msg_err("userdata: HTTP request failed: %v", s);
        timm_dealloc(s);
        deallocate_value(req);
        userdata_complete(STATUS_OK);
    }
}

static void try_provider(enum cloud_provider provider)
{
    const struct provider_config *cfg = &providers[provider];

    ue->current_provider = provider;

    userdata_debug("Trying provider: %s", cfg->name);

    struct net_http_req_params params;
    params.host = METADATA_SERVER_ADDR;
    params.port = 80;
    params.tls = false;
    params.method = cfg->detect_method;

    tuple req = allocate_tuple();
    if (req == INVALID_ADDRESS) {
        msg_err("userdata: failed to allocate request tuple");
        try_next_provider();
        return;
    }

    /* Set URL */
    buffer url = allocate_buffer(ue->h, 128);
    if (url == INVALID_ADDRESS) {
        deallocate_value(req);
        msg_err("userdata: failed to allocate URL buffer");
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
            msg_err("userdata: failed to allocate header buffer");
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
        userdata_debug("Detection request failed for %s: %v", cfg->name, s);
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
        userdata_debug("No cloud provider detected or no userdata available");
        userdata_complete(STATUS_OK);
    }
}

closure_func_basic(timer_handler, void, retry_detection,
                   u64 expiry, u64 overruns)
{
    userdata ue = struct_from_field(closure_self(), userdata, retry_th);

    if (overruns == timer_disabled)
        return;

    ue->retry_count++;

    if (ue->retry_count > MAX_NETWORK_RETRIES) {
        userdata_debug("Max retries (%d) reached, network not available", MAX_NETWORK_RETRIES);
        userdata_complete(STATUS_OK);
        return;
    }

    userdata_debug("Retry %d/%d: checking if network is available",
                   ue->retry_count, MAX_NETWORK_RETRIES);

    /* Check if metadata server is reachable now */
    if (!metadata_server_reachable()) {
        userdata_debug("Metadata server still not reachable, scheduling retry %d",
                       ue->retry_count + 1);

        /* Schedule another retry using existing timer */
        register_timer(kernel_timers, &ue->retry_timer, CLOCK_ID_MONOTONIC,
                      seconds(RETRY_INTERVAL_SECONDS), false, 0,
                      (timer_handler)&ue->retry_th);
        return;
    }

    userdata_debug("Network is now available, starting cloud provider detection");
    /* started flag is already false, try_next_provider will handle initialization */
    try_next_provider();
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
    /* Set up heap */
    heap h = heap_locked(get_kernel_heaps());
    /* Allocate our global state */
    ue = allocate(h, sizeof(*ue));
    if (ue == INVALID_ADDRESS)
        return KLIB_INIT_FAILED;

    zero(ue, sizeof(*ue));
    ue->h = h;
    ue->complete = complete;
    init_timer(&ue->retry_timer);
    init_closure_func(&ue->retry_th, timer_handler, retry_detection);

    /* Retrieve configuration parameters */
    tuple config = get(get_root_tuple(), sym(userdata));
    if (config && is_tuple(config)) {
        buffer save_to = get(config, sym(save_to_file));
        if (save_to && is_string(save_to) && buffer_length(save_to) > 0) {
            ue->save_file_path = save_to;
            userdata_debug("save_to_file configured: %b", save_to);
        }
    }

    /* Check if metadata server is reachable */
    if (!metadata_server_reachable()) {
        userdata_debug("Metadata server not reachable, will retry up to %d times (every %d seconds)",
                       MAX_NETWORK_RETRIES, RETRY_INTERVAL_SECONDS);

        /* Schedule retry (network might not be ready yet) */
        register_timer(kernel_timers, &ue->retry_timer, CLOCK_ID_MONOTONIC,
                       seconds(RETRY_INTERVAL_SECONDS), false, 0,
                       (timer_handler)&ue->retry_th);

        return KLIB_INIT_IN_PROGRESS;
    }

    /* Start provider detection */
    try_next_provider();

    return KLIB_INIT_IN_PROGRESS;
}
