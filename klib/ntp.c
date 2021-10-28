#include <kernel.h>
#include <lwip.h>

#define NTP_SERVER_DEFAULT  "pool.ntp.org"
#define NTP_PORT_DEFAULT    123

#define NTP_EPOCH_DELTA 2208988800ul    /* Number of seconds between 1900 and 1970 */

#define NTP_QUERY_INTERVAL_MIN  4   /* 16 seconds */
#define NTP_QUERY_INTERVAL_MAX  17  /* 36.4 hours */

#define NTP_QUERY_ATTEMPTS  8

#define NTP_JIGGLE_THRESHOLD    30

#define NTP_MAX_SLEW_RATE   ((1ll << CLOCK_CALIBR_BITS) / 2000) /* 500 PPM */

#define NTP_RESET_THRESHOLD_MIN 60  /* 60 seconds */

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

declare_closure_struct(0, 2, void, ntp_query_func,
                       u64, expiry, u64, overruns);

static struct {
    char server_addr[256];
    u16 server_port;
    struct udp_pcb *pcb;
    struct timer query_timer;
    closure_struct(ntp_query_func, query_func);
    boolean query_ongoing;
    u64 reset_threshold;

    /* interval values expressed as bit order of number of seconds */
    int pollmin, pollmax;
    int query_interval;

    int query_errors;
    timestamp last_raw;
    u64 last_offset;
    int jiggle_counter;
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

static void ntp_schedule_query(void)
{
    if (!timer_is_active(&ntp.query_timer))
        register_timer(kernel_timers, &ntp.query_timer, CLOCK_ID_MONOTONIC_RAW,
            seconds(U64_FROM_BIT(ntp.query_interval)), false, 0, (timer_handler)&ntp.query_func);
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
    } else  if ((++ntp.query_errors > NTP_QUERY_ATTEMPTS) &&
            (ntp.query_interval < ntp.pollmax)) {
        ntp.query_interval++;
    }
    ntp_schedule_query();
}

static void ntp_query(const ip_addr_t *server_addr, boolean lwip_locked)
{
    if (!lwip_locked)
        lwip_lock();
    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, sizeof(struct ntp_packet), PBUF_RAM);
    if (!lwip_locked)
        lwip_unlock();
    if (p == 0)
        return;
    struct ntp_packet *pkt = p->payload;
    runtime_memset(p->payload, 0, sizeof(*pkt));
    pkt->vn = 3;    /* NTP version number */
    pkt->mode = 3;  /* client mode */
    struct ntp_ts t;
    timestamp_to_ntptime(kern_now(CLOCK_ID_REALTIME), &t);
    runtime_memcpy(&pkt->transmit_ts, &t, sizeof(t));
    if (!lwip_locked)
        lwip_lock();
    err_t err = udp_sendto(ntp.pcb, p, server_addr, ntp.server_port);
    if (err != ERR_OK) {
        rprintf("%s: failed to send request: %d\n", __func__, err);
        ntp_query_complete(false);
    }
    pbuf_free(p);
    if (!lwip_locked)
        lwip_unlock();
    ntp.query_ongoing = true;
    ntp_schedule_query();
}

/* called with lwIP lock held */
static void ntp_input(void *z, struct udp_pcb *pcb, struct pbuf *p,
                      const ip_addr_t *addr, u16 port)
{
    ntp.query_ongoing = false;
    struct ntp_packet *pkt = p->payload;
    boolean success;
    if (p->len != sizeof(*pkt)) {
        rprintf("%s: invalid response length %d\n", __func__, p->len);
        success = false;
        goto done;
    }
    timestamp wallclock_now = kern_now(CLOCK_ID_REALTIME);
    struct ntp_ts t1, t2;
    runtime_memcpy(&t1, &pkt->originate_ts, sizeof(t1));
    timestamp origin = ntptime_to_timestamp(&t1);
    /* round trip delay */
    runtime_memcpy(&t1, &pkt->transmit_ts, sizeof(t1));
    runtime_memcpy(&t2, &pkt->receive_ts, sizeof(t2));
    timestamp rtd = wallclock_now - origin - ntptime_diff(&t1, &t2);
    s64 offset = ntptime_to_timestamp(&t1) - wallclock_now + rtd / 2;
    if (ntp.reset_threshold > 0 &&
            sec_from_timestamp(offset < 0 ? -offset : offset) > ntp.reset_threshold) {
        clock_reset_rtc(wallclock_now + offset);
        ntp.last_offset = 0;
        ntp.last_raw = 0;
        success = true;
        goto done;
    }
    u128 offset_calibr = ((u128)ABS(offset)) << CLOCK_CALIBR_BITS;
    s64 temp_cal, cal;
    timestamp raw = kern_now(CLOCK_ID_MONOTONIC_RAW);

    /* Apply maximum slew rate until local time is synchronized with NTP time. */
    timestamp sync_complete;
    if (offset == 0) {
        temp_cal = 0;
        sync_complete = raw;
    } else {
        timestamp sync_time = div128_64(offset_calibr, NTP_MAX_SLEW_RATE);
        if (sync_time == -1ull) {
            rprintf("%s: time offset too large, ignoring\n", __func__);
            success = false;
            goto done;
        }
        temp_cal = NTP_MAX_SLEW_RATE;
        sync_complete = raw + sync_time;
        if (offset < 0)
            temp_cal = -temp_cal;
    }

    /* If at least 2 samples have been received from the NTP server, calculate a calibration value
     * to be applied after the local time is synchronized with the NTP time, and possibly adjust the
     * query interval based on the clock jitter. */
    raw -= rtd / 2;
    if ((ntp.last_raw != 0) && (raw > ntp.last_raw)) {
        cal = (s64)div128_64(offset_calibr, raw - ntp.last_raw);
        if ((cal < 0) || (cal > NTP_MAX_SLEW_RATE))
            cal = NTP_MAX_SLEW_RATE;
        if (offset < 0)
            cal = -cal;
        s64 jitter = offset - ntp.last_offset;
        if (ABS(offset) < ABS(jitter) * 4) {
            ntp.jiggle_counter += ntp.query_interval;
            if ((ntp.jiggle_counter > NTP_JIGGLE_THRESHOLD) && (ntp.query_interval < ntp.pollmax)) {
                ntp.query_interval++;
                ntp.jiggle_counter = 0;
            }
        } else {
            ntp.jiggle_counter -= 2 * ntp.query_interval;
            if ((ntp.jiggle_counter < -NTP_JIGGLE_THRESHOLD) && (ntp.query_interval > ntp.pollmin)) {
                ntp.query_interval--;
                ntp.jiggle_counter = 0;
            }
        }
    } else {
        cal = 0;
    }
    ntp.last_raw = raw;
    ntp.last_offset = offset;

    clock_adjust(wallclock_now + offset, temp_cal, sync_complete, cal);
    success = true;
  done:
    ntp_query_complete(success);
    pbuf_free(p);
}

static void ntp_dns_cb(const char *name, const ip_addr_t *ipaddr, void *callback_arg)
{
    if (ipaddr) {
        ntp_query(ipaddr, true);
    } else {
        rprintf("%s: failed to resolve hostname %s\n", __func__, name);
        ntp_query_complete(false);
    }
}

define_closure_function(0, 2, void, ntp_query_func,
                        u64, expiry, u64, overruns)
{
    if (overruns == timer_disabled)
        return;
    if (ntp.query_ongoing) {
        rprintf("NTP: failed to receive server response\n", __func__);
        ntp_query_complete(false);
    }
    ip_addr_t server_addr;
    lwip_lock();
    err_t err = dns_gethostbyname(ntp.server_addr, &server_addr, ntp_dns_cb, 0);
    lwip_unlock();
    if (err == ERR_OK)
        ntp_query(&server_addr, false);
    else if (err != ERR_INPROGRESS) {
        rprintf("%s: failed to resolve hostname: %d\n", __func__, err);
        ntp_query_complete(false);
    }
}

int init(status_handler complete)
{
    tuple root = get_root_tuple();
    if (!root) {
        rprintf("NTP: failed to get root tuple\n");
        return KLIB_INIT_FAILED;
    }
    buffer server_addr = get(root, sym_intern(ntp_address, intern));
    if (server_addr) {
        bytes len = buffer_length(server_addr);
        if (len >= sizeof(ntp.server_addr)) {
            rprintf("NTP: invalid server address\n");
            return KLIB_INIT_FAILED;
        }
        runtime_memcpy(ntp.server_addr, buffer_ref(server_addr, 0), len);
        ntp.server_addr[len] = '\0';
    } else {
        runtime_memcpy(ntp.server_addr, NTP_SERVER_DEFAULT, sizeof(NTP_SERVER_DEFAULT));
    }
    value server_port = get(root, sym_intern(ntp_port, intern));
    if (server_port) {
        u64 port;
        if (!u64_from_value(server_port, &port) || (port > U16_MAX)) {
            rprintf("NTP: invalid server port\n");
            return KLIB_INIT_FAILED;
        }
        ntp.server_port = port;
    } else {
        ntp.server_port = NTP_PORT_DEFAULT;
    }
    ntp.pollmin = 6;
    ntp.pollmax = 10;
    value pollmin = get(root, sym_intern(ntp_poll_min, intern));
    if (pollmin) {
        u64 interval;
        if (!u64_from_value(pollmin, &interval) || (interval < NTP_QUERY_INTERVAL_MIN) ||
                (interval > NTP_QUERY_INTERVAL_MAX)) {
            rprintf("NTP: invalid minimum poll interval\n");
            return KLIB_INIT_FAILED;
        }
        ntp.pollmin = interval;
        if (interval > ntp.pollmax)
            ntp.pollmax = interval;
    }
    value pollmax = get(root, sym_intern(ntp_poll_max, intern));
    if (pollmax) {
        u64 interval;
        if (!u64_from_value(pollmax, &interval) || (interval < NTP_QUERY_INTERVAL_MIN) ||
                (interval > NTP_QUERY_INTERVAL_MAX)) {
            rprintf("NTP: invalid maximum poll interval\n");
            return KLIB_INIT_FAILED;
        }
        ntp.pollmax = interval;
        if (interval < ntp.pollmin) {
            if (pollmin) {
                rprintf("NTP: maximum poll interval smaller than minimum poll interval\n");
                return KLIB_INIT_FAILED;
            }
            ntp.pollmin = interval;
        }
    }
    ntp.reset_threshold = 0;
    value reset_thresh = get(root, sym_intern(ntp_reset_threshold, intern));
    if (reset_thresh) {
        u64 thresh;
        if (!u64_from_value(reset_thresh, &thresh) || (thresh > 0 && thresh < NTP_RESET_THRESHOLD_MIN)) {
            rprintf("NTP: invalid reset threshold\n");
            return KLIB_INIT_FAILED;
        }
        ntp.reset_threshold = thresh;
    }
    lwip_lock();
    ntp.pcb = udp_new();
    if (!ntp.pcb) {
        lwip_unlock();
        rprintf("NTP: failed to create PCB\n");
        return KLIB_INIT_FAILED;
    }
    udp_recv(ntp.pcb, ntp_input, 0);
    lwip_unlock();
    init_closure(&ntp.query_func, ntp_query_func);
    ntp.query_interval = ntp.pollmin;
    ntp.jiggle_counter = 0;
    init_timer(&ntp.query_timer);
    register_timer(kernel_timers, &ntp.query_timer, CLOCK_ID_MONOTONIC_RAW, seconds(5), false, 0,
        (timer_handler)&ntp.query_func);
    return KLIB_INIT_OK;
}
