#include <kernel.h>
#include <lwip.h>

#define NTP_SERVER_DEFAULT  "pool.ntp.org"
#define NTP_PORT_DEFAULT    123

#define NTP_EPOCH_DELTA 2208988800ul    /* Number of seconds between 1900 and 1970 */

#define NTP_QUERY_INTERVAL_DEFAULT  (10 * seconds(60))
#define NTP_QUERY_INTERVAL_MAX      (5120 * seconds(60))

#define NTP_QUERY_ATTEMPTS  8

#define NTP_MAX_SLEW_RATE   ((1ll << CLOCK_CALIBR_BITS) / 2000) /* 500 PPM */

struct ntp_ts {
    u32 seconds;
    u32 fraction;
};

struct ntp_packet {
    u8 mode:3;
    u8 vn:3;
    u8 li:2;
    u8 stratum;
    u8 poll;
    u8 precision;
    u32 root_delay;
    u32 root_dispersion;
    u32 reference_id;
    struct ntp_ts reference_ts;
    struct ntp_ts originate_ts;
    struct ntp_ts receive_ts;
    struct ntp_ts transmit_ts;
} __attribute((packed));

declare_closure_struct(0, 1, void, ntp_query_func,
    u64, overruns);

static struct {
    char server_addr[256];
    u16 server_port;
    struct udp_pcb *pcb;
    timer query_timer;
    closure_struct(ntp_query_func, query_func);
    boolean query_ongoing;
    timestamp query_interval;
    int query_errors;
    timestamp last_raw;
    void (*rprintf)(const char *format, ...);
    timer (*register_timer)(clock_id id, timestamp val, boolean absolute, timestamp interval,
            timer_handler n);
    err_t (*dns_gethostbyname)(const char *hostname, ip_addr_t *addr,
            dns_found_callback found, void *callback_arg);
    struct pbuf *(*pbuf_alloc)(pbuf_layer layer, u16_t length, pbuf_type type);
    u8 (*pbuf_free)(struct pbuf *p);
    err_t(*udp_sendto)(struct udp_pcb *pcb, struct pbuf *p,
            const ip_addr_t *dst_ip, u16_t dst_port);
    void (*runtime_memset)(u8 *a, u8 b, bytes len);
    timestamp (*now)(clock_id id);
    void (*clock_adjust)(timestamp now, s64 temp_cal, timestamp sync_complete, s64 cal);
} ntp;

/* Calculates a division between a 128-bit value and a 64-bit value and returns a 64-bit quotient.
 * If the quotient does not fit in 64 bits, -1ull is returned.
 * Only one 64-bit division is executed, thus the result may not be as accurate as it could be.
 */
static u64 div128_64(u128 dividend, u64 divisor)
{
    if (dividend == 0)
        return 0;
    if (divisor == 0)
        return -1ull;
    u64 dividend_msb = (dividend >> 64) ? (64 + msb(dividend >> 64)) : msb(dividend);
    if (dividend_msb <= 63)
        return ((u64)dividend) / divisor;
    u64 shift = dividend_msb - 63;
    u64 div = ((u64)(dividend >> shift)) / divisor;
    if (msb(div) >= 64 - shift)
        return -1ull;
    return (div << shift);
}

static void timestamp_to_ntptime(timestamp t, struct ntp_ts *ntptime)
{
    ntptime->seconds = PP_HTONL(NTP_EPOCH_DELTA + sec_from_timestamp(t));
    ntptime->fraction = PP_HTONL((u32)t);
}

static timestamp ntptime_to_timestamp(struct ntp_ts *ntptime)
{
    return (seconds(PP_NTOHL(ntptime->seconds) - NTP_EPOCH_DELTA) + PP_NTOHL(ntptime->fraction));
}

static s64 ntptime_diff(struct ntp_ts *t1, struct ntp_ts *t2)
{
    return (seconds(PP_NTOHL(t1->seconds) - PP_NTOHL(t2->seconds)) +
            PP_NTOHL(t1->fraction) - PP_NTOHL(t2->fraction));
}

static void ntp_query_complete(boolean success)
{
    if (success) {
        ntp.query_errors = 0;
        ntp.query_interval = NTP_QUERY_INTERVAL_DEFAULT;
    } else  if ((++ntp.query_errors > NTP_QUERY_ATTEMPTS) &&
            (ntp.query_interval < NTP_QUERY_INTERVAL_MAX)) {
        ntp.query_interval *= 2;
    }
    if (ntp.query_timer == INVALID_ADDRESS)
        ntp.query_timer = ntp.register_timer(CLOCK_ID_MONOTONIC_RAW, ntp.query_interval, false, 0,
            (timer_handler)&ntp.query_func);
}

static void ntp_query(const ip_addr_t *server_addr)
{
    struct pbuf *p = ntp.pbuf_alloc(PBUF_TRANSPORT, sizeof(struct ntp_packet), PBUF_RAM);
    if (p == 0)
        return;
    struct ntp_packet *pkt = p->payload;
    ntp.runtime_memset(p->payload, 0, sizeof(*pkt));
    pkt->vn = 3;    /* NTP version number */
    pkt->mode = 3;  /* client mode */
    timestamp_to_ntptime(ntp.now(CLOCK_ID_REALTIME), &pkt->transmit_ts);
    err_t err = ntp.udp_sendto(ntp.pcb, p, server_addr, ntp.server_port);
    if (err != ERR_OK) {
        ntp.rprintf("%s: failed to send request: %d\n", __func__, err);
        ntp_query_complete(false);
    }
    ntp.pbuf_free(p);
    ntp.query_ongoing = true;
    if (ntp.query_timer == INVALID_ADDRESS)
        ntp.query_timer = ntp.register_timer(CLOCK_ID_MONOTONIC_RAW, ntp.query_interval, false, 0,
            (timer_handler)&ntp.query_func);
}

static void ntp_input(void *z, struct udp_pcb *pcb, struct pbuf *p,
                      const ip_addr_t *addr, u16 port)
{
    ntp.query_ongoing = false;
    struct ntp_packet *pkt = p->payload;
    boolean success;
    if (p->len != sizeof(*pkt)) {
        ntp.rprintf("%s: invalid response length %d\n", __func__, p->len);
        success = false;
        goto done;
    }
    timestamp wallclock_now = ntp.now(CLOCK_ID_REALTIME);
    timestamp origin = ntptime_to_timestamp(&pkt->originate_ts);
    /* round trip delay */
    timestamp rtd = wallclock_now - origin - ntptime_diff(&pkt->transmit_ts, &pkt->receive_ts);
    s64 offset = ntptime_to_timestamp(&pkt->transmit_ts) - wallclock_now + rtd / 2;
    u128 offset_calibr = ((u128)((offset >= 0) ? offset : -offset)) << CLOCK_CALIBR_BITS;
    s64 temp_cal, cal;
    timestamp raw = ntp.now(CLOCK_ID_MONOTONIC_RAW);

    /* Apply maximum slew rate until local time is synchronized with NTP time. */
    timestamp sync_complete;
    if (offset == 0) {
        temp_cal = 0;
        sync_complete = raw;
    } else {
        timestamp sync_time = div128_64(offset_calibr, NTP_MAX_SLEW_RATE);
        if (sync_time == -1ull) {
            ntp.rprintf("%s: time offset too large, ignoring\n", __func__);
            success = false;
            goto done;
        }
        temp_cal = NTP_MAX_SLEW_RATE;
        sync_complete = raw + sync_time;
        if (offset < 0)
            temp_cal = -temp_cal;
    }

    /* If at least 2 samples have been received from the NTP server, calculate a calibration value
     * to be applied after the local time is synchronized with the NTP time. */
    raw -= rtd / 2;
    if ((ntp.last_raw != 0) && (raw > ntp.last_raw)) {
        cal = (s64)div128_64(offset_calibr, raw - ntp.last_raw);
        if ((cal < 0) || (cal > NTP_MAX_SLEW_RATE))
            cal = NTP_MAX_SLEW_RATE;
        if (offset < 0)
            cal = -cal;
    } else {
        cal = 0;
    }
    ntp.last_raw = raw;

    ntp.clock_adjust(wallclock_now + offset, temp_cal, sync_complete, cal);
    success = true;
  done:
    ntp_query_complete(success);
    ntp.pbuf_free(p);
}

static void ntp_dns_cb(const char *name, const ip_addr_t *ipaddr, void *callback_arg)
{
    if (ipaddr) {
        ntp_query(ipaddr);
    } else {
        ntp.rprintf("%s: failed to resolve hostname %s\n", __func__, name);
        ntp_query_complete(false);
    }
}

define_closure_function(0, 1, void, ntp_query_func,
                        u64, overruns)
{
    ntp.query_timer = INVALID_ADDRESS;
    if (ntp.query_ongoing) {
        ntp.rprintf("NTP: failed to receive server response\n", __func__);
        ntp_query_complete(false);
    }
    ip_addr_t server_addr;
    err_t err = ntp.dns_gethostbyname(ntp.server_addr, &server_addr, ntp_dns_cb, 0);
    if (err == ERR_OK)
        ntp_query(&server_addr);
    else if (err != ERR_INPROGRESS) {
        ntp.rprintf("%s: failed to resolve hostname: %d\n", __func__, err);
        ntp_query_complete(false);
    }
}

int init(void *md, klib_get_sym get_sym, klib_add_sym add_sym)
{
    ntp.rprintf = get_sym("rprintf");
    if (!ntp.rprintf)
        return KLIB_INIT_FAILED;
    tuple (*get_root_tuple)(void) = get_sym("get_root_tuple");
    symbol (*intern)(string name) = get_sym("intern");
    void *(*table_find)(table z, void *c) = get_sym("table_find");
    void (*memcopy)(void *a, const void *b, unsigned long len) = get_sym("runtime_memcpy");
    struct udp_pcb *(*udp_new)(void) = get_sym("udp_new");
    void (*udp_recv)(struct udp_pcb *pcb, udp_recv_fn recv, void *recv_arg) = get_sym("udp_recv");
    if (!get_root_tuple || !intern || !table_find || !memcopy || !udp_new || !udp_recv ||
            !(ntp.register_timer = get_sym("kern_register_timer")) ||
            !(ntp.dns_gethostbyname = get_sym("dns_gethostbyname")) ||
            !(ntp.pbuf_alloc = get_sym("pbuf_alloc")) || !(ntp.pbuf_free = get_sym("pbuf_free")) ||
            !(ntp.udp_sendto = get_sym("udp_sendto")) ||
            !(ntp.runtime_memset = get_sym("runtime_memset")) ||
            !(ntp.now = get_sym("now")) || !(ntp.clock_adjust = get_sym("clock_adjust"))) {
        ntp.rprintf("NTP: kernel symbols not found\n");
        return KLIB_INIT_FAILED;
    }
    tuple root = get_root_tuple();
    if (!root) {
        ntp.rprintf("NTP: failed to get root tuple\n");
        return KLIB_INIT_FAILED;
    }
    buffer server_addr = table_find(root, sym_intern(ntp_address, intern));
    if (server_addr) {
        bytes len = buffer_length(server_addr);
        if (len >= sizeof(ntp.server_addr)) {
            ntp.rprintf("NTP: invalid server address\n");
            return KLIB_INIT_FAILED;
        }
        memcopy(ntp.server_addr, buffer_ref(server_addr, 0), len);
        ntp.server_addr[len] = '\0';
    } else {
        memcopy(ntp.server_addr, NTP_SERVER_DEFAULT, sizeof(NTP_SERVER_DEFAULT));
    }
    value server_port = table_find(root, sym_intern(ntp_port, intern));
    if (server_port) {
        u64 port;
        if (!u64_from_value(server_port, &port) || (port > U16_MAX)) {
            ntp.rprintf("NTP: invalid server port\n");
            return KLIB_INIT_FAILED;
        }
        ntp.server_port = port;
    } else {
        ntp.server_port = NTP_PORT_DEFAULT;
    }
    ntp.pcb = udp_new();
    if (!ntp.pcb) {
        ntp.rprintf("NTP: failed to create PCB\n");
        return KLIB_INIT_FAILED;
    }
    udp_recv(ntp.pcb, ntp_input, 0);
    init_closure(&ntp.query_func, ntp_query_func);
    ntp.query_interval = NTP_QUERY_INTERVAL_DEFAULT;
    ntp.query_timer = ntp.register_timer(CLOCK_ID_MONOTONIC_RAW, seconds(5), false, 0,
        (timer_handler)&ntp.query_func);
    return KLIB_INIT_OK;
}
