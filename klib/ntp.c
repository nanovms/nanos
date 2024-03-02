#include <kernel.h>
#include <lwip.h>

//#define NTP_DEBUG
#ifdef NTP_DEBUG
#define ntp_debug(x, ...) do {tprintf(sym(ntp), 0, ss(x), ##__VA_ARGS__);} while(0)
#else
#define ntp_debug(x, ...)
#endif

#define NTP_SERVER_DEFAULT  "pool.ntp.org"
#define NTP_PORT_DEFAULT    123

#define NTP_EPOCH_DELTA 2208988800ul    /* Number of seconds between 1900 and 1970 */

#define NTP_QUERY_INTERVAL_MIN  4   /* 16 seconds */
#define NTP_QUERY_INTERVAL_MAX  17  /* 36.4 hours */

#define NTP_QUERY_ATTEMPTS  8

#define NTP_JIGGLE_THRESHOLD    30

#define NTP_RESET_THRESHOLD_MIN 1 /* seconds*/
#define NTP_MAX_SLEW_LIMIT 500000ll /* ppm */
#define NTP_MAX_FREQ_LIMIT 100000ll /* ppm */

#define PPM_SCALE(x) (((s64)(x)<<CLOCK_FP_BITS) / 1000000ll)
#define fpmax (~(1ull<<63))

#define DEFAULT_MAX_FREQ_PPM 25000
#define DEFAULT_MAX_SLEW_PPM 83333
#define MAX_BAD_REGRESSIONS 5
#define MAX_SAMPLES 30
#define MIN_SAMPLES 4
#define get_sample(i) (ntp.samples + ((MAX_SAMPLES + (ntp.sample_index - ntp.nsamples) + i) % MAX_SAMPLES))

#define MAX_DISPERSION seconds(16)
#define MIN_SLEW_DURATION seconds(1)
#define MAX_SLEW_DURATION seconds(10000)
#define MIN_OFFSET_CORRECTION nanoseconds(1)

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

struct ntp_sample {
    timestamp time;
    s64 offset;
    s64 offset_orig;
    s64 rtd;
    u64 root_delay;
    u64 root_dispersion;
    u64 peer_delay;
    u64 peer_dispersion;
};

typedef struct ntp_server {
    sstring addr;
    u16 port;
    ip_addr_t ip_addr;
    struct ntp_ts last_transmit_time;
    struct ntp_ts last_originate_time;
} *ntp_server;

static struct {
    boolean ptp_clock;
    vector servers;
    int current_server;
    struct udp_pcb *pcb;
    struct timer query_timer;
    struct timer slew_timer;
    struct timer raw_update_timer;
    timer_handler query_func;
    closure_struct(timer_handler, slew_complete_func);
    closure_struct(timer_handler, raw_update_func);
    boolean query_ongoing;
    u64 reset_threshold;

    /* interval values expressed as bit order of number of seconds */
    int pollmin, pollmax;
    int query_interval;

    int query_errors;
    int jiggle_counter;
    int bad_regressions;
    struct ntp_sample samples[MAX_SAMPLES];
    int nsamples;
    int sample_index;
    timestamp slew_start;
    s64 offset;                 /* negative means ahead of reference clock */
    s64 base_freq;              /* negative means faster than reference clock */
    s64 slew_freq;
    s64 offset_sd;
    s64 skew;
    s64 max_corr_freq;
    s64 max_base_freq;
    timestamp resp_time;
    int no_resp_warn_time;  /* expressed in minutes */
    struct spinlock lock;
} ntp;

#define ntp_lock()      spin_lock(&ntp.lock)
#define ntp_unlock()    spin_unlock(&ntp.lock)

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
    ntp_lock();
    if (!timer_is_active(&ntp.query_timer))
        register_timer(kernel_timers, &ntp.query_timer, CLOCK_ID_MONOTONIC,
            seconds(U64_FROM_BIT(ntp.query_interval)), false, 0, ntp.query_func);
    ntp_unlock();
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
    if (ntp.current_server >= 0) {
        if (success)
            ntp.query_errors = 0;
        else if ((++ntp.query_errors > NTP_QUERY_ATTEMPTS) && (ntp.query_interval < ntp.pollmax))
            ntp.query_interval++;
    }
    ntp_schedule_query();
}

static void ntp_reset_state(void)
{
    ntp.query_interval = ntp.pollmin;
    ntp.jiggle_counter = 0;
    ntp.sample_index = 0;
    ntp.nsamples = 0;
    ntp.bad_regressions = 0;
    ntp.offset = 0;
    ntp.slew_freq = 0;
    ntp.slew_start = 0;
    ntp.base_freq = 0;
    ntp.skew = milliseconds(2);
    runtime_memset((void *)ntp.samples, 0, sizeof(ntp.samples));
    ntp_lock();
    ntp.current_server = -1;
    ntp_unlock();
    ntp.resp_time = kern_now(CLOCK_ID_MONOTONIC_RAW);
    ntp.no_resp_warn_time = U64_FROM_BIT(ntp.query_interval) * NTP_QUERY_ATTEMPTS / 60;
}

/* Converts pair of whole and fractional integer values to 64-bit fixed point */
static inline s64 i2fp(s32 w, u32 f)
{
    boolean neg = false;
    if (w < 0) {
        neg = true;
        w = -w;
    }
    s64 r = ((s64)w) << CLOCK_FP_BITS;
    int n = 1;
    s32 fn = f;
    while (1) {
        if (fn == 0)
            break;
        fn /= 10;
        n *= 10;
    }
    r |= (((s64)f) << CLOCK_FP_BITS) / n;
    if (neg)
        r = -r;
    return r;
}

/* Signed fixed point multiplication without loss of significant bits */
static s64 fpmul(s64 a, s64 b)
{
    boolean neg = false;
    if ((a < 0 || b < 0) && (!(a < 0 && b < 0)))
        neg = true;
    if (a < 0)
        a = -a;
    if (b < 0)
        b = -b;
    u128 p = ((u128)a) * b;
    p >>= CLOCK_FP_BITS;
    s64 pp = (s64)p;
    if (neg)
        pp = -pp;
    return pp;
}

/* Signed fixed point division */
static inline s64 fpdiv(s64 dividend, s64 divisor)
{
    boolean neg = false;
    if ((dividend < 0 || divisor < 0) &&
            !(dividend < 0 && divisor < 0))
        neg = true;
    if (dividend < 0)
        dividend = -dividend;
    if (divisor < 0)
        divisor = -divisor;
    u128 d = ((u128)dividend) << CLOCK_FP_BITS;
    s64 q = div128_64(d, divisor);
    if (q == -1) {
        msg_err("%f / %f quotient out of range at %p!\n", dividend, divisor, __builtin_return_address(0));
        q = fpmax;
    }
    if (neg)
        q = -q;
    return q;
}

/* Fixed point square root */
static s64 fpsqrt(s64 a)
{
    s64 r = a;
    s64 b = 1ull<<62;
    s64 q = 0;
    while (b > 0x40) {
        s64 t = q + b;
        if (r >= t) {
            r -= t;
            q = t + b;
        }
        r <<= 1;
        b >>= 1;
    }
    q >>= 16;
    return q;
}

static inline s64 fpclamp(s64 v, s64 min, s64 max)
{
    if (v < min)
        v = min;
    else if (v > max)
        v = max;
    return v;
}

/* compensates current time for in-progress slewing */
static timestamp slew_compensate(timestamp raw)
{
    return raw + (ntp.offset - fpmul(ntp.slew_freq, raw - ntp.slew_start));
}

static void ntp_query(ntp_server server)
{
    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, sizeof(struct ntp_packet), PBUF_RAM);
    if (p == 0)
        return;
    struct ntp_packet *pkt = p->payload;
    runtime_memset(p->payload, 0, sizeof(*pkt));
    pkt->vn = 3;    /* NTP version number */
    pkt->mode = 3;  /* client mode */
    struct ntp_ts t;
    timestamp_to_ntptime(slew_compensate(kern_now(CLOCK_ID_REALTIME)), &t);
    runtime_memcpy(&pkt->transmit_ts, &t, sizeof(t));
    runtime_memcpy(&server->last_originate_time, &t, sizeof(t));
    err_t err = udp_sendto(ntp.pcb, p, &server->ip_addr, server->port);
    if (err != ERR_OK) {
        msg_err("failed to send request: %d\n", err);
        ntp_query_complete(false);
    }
    pbuf_free(p);
    ntp.query_ongoing = true;
    ntp_schedule_query();
}

/* Convert 32-bit ntp fixed point to nanos 64-bit fixed point */
static s64 ntp_fixed_conv(u32 t)
{
    return ((u64)PP_NTOHL(t)) << (CLOCK_FP_BITS - 16);
}

/* Weighted least squares linear regression  */
static boolean regression(s64 *est_offset, s64 *est_freq, s64 *offset_sd, s64 *skew)
{
    int n = ntp.nsamples;
    s64 x[MAX_SAMPLES];
    s64 y[MAX_SAMPLES];
    s64 w[MAX_SAMPLES];

    assert(n >= MIN_SAMPLES);

    /* Prepare data and calculate weights */
    struct ntp_sample *last_sample = get_sample(ntp.nsamples - 1);
    s64 lasttime = last_sample->time;
    s64 peer_distances[MAX_SAMPLES];
    s64 mean_dist = 0, min_dist = fpmax;
    for (int i = 0; i < n; i++) {
        struct ntp_sample *s = get_sample(i);
        x[i] = s->time - lasttime;
        y[i] = s->offset;
        /* peer distance is request trip time plus error estimate */
        peer_distances[i] = fpmul(s->peer_delay, i2fp(0,5)) + s->peer_dispersion;
        mean_dist += peer_distances[i];
        if (peer_distances[i] < min_dist)
            min_dist = peer_distances[i];
    }
    /* Samples with smaller peer distance are weighed more */
    mean_dist = fpdiv(mean_dist, i2fp(n, 0));
    if (mean_dist == fpmax)
        return false;
    s64 sd = mean_dist - min_dist;
    if (sd > min_dist || sd <= 0)
        sd = min_dist;
    for (int i = 0; i < n; i++) {
      s64 sd_weight = fpdiv(peer_distances[i] - min_dist, sd);
      if (sd_weight == fpmax)
        return false;
      sd_weight += i2fp(1,0);
      w[i] = fpmul(sd_weight, sd_weight);
    }

    /* Calculate regression terms */
    s64 Xsum = 0, Ysum = 0, Wsum = 0;
    for (int i = 0; i < n; i++) {
        s64 tx = fpdiv(x[i], w[i]);
        s64 ty = fpdiv(y[i], w[i]);
        s64 tw = fpdiv(i2fp(1, 0), w[i]);
        if (tx == fpmax || ty == fpmax || tw == fpmax)
            return false;
        Xsum += tx;
        Ysum += ty;
        Wsum += tw;
    }
    s64 Xbar = fpdiv(Xsum, Wsum);
    s64 Ybar = fpdiv(Ysum, Wsum);
    if (Xbar == fpmax || Ybar == fpmax)
        return false;
    s64 Xss = 0, XYdevsum = 0;
    for (int i = 0; i < n; i++) {
        s64 xdev = x[i] - Xbar;
        s64 t = fpdiv(fpmul(xdev, y[i] - Ybar), w[i]);
        s64 u = fpdiv(fpmul(xdev, xdev), w[i]);
        if (t == fpmax || u == fpmax)
            return false;
        XYdevsum += t;
        Xss += u;
    }
    s64 b1 = fpdiv(XYdevsum, Xss);          /* est slope */
    s64 b0 = Ybar - fpmul(b1, Xbar);        /* est offset */
    s64 sigsq = 0;
    if (b1 == fpmax)
        return false;
    /* Calculate error sum of squares */
    for (int i = 0; i < n; i++) {
        s64 r = y[i] - b0 - fpmul(b1, x[i]);
        s64 t = fpdiv(fpmul(r, r), w[i]);
        if (t == fpmax)
            return false;
        sigsq += t;
    }
    /* Calculate mean square error */
    sigsq = fpdiv(sigsq, i2fp(n - 2, 0));
    /* Calculate standard error terms */
    s64 seb1 = fpdiv(fpsqrt(sigsq), fpsqrt(Xss));
    if (sigsq == fpmax || seb1 == fpmax)
        return false;
    s64 tmp = fpmul(seb1, Xbar);
    s64 seb0 = fpdiv(sigsq, Wsum) + fpmul(tmp, tmp);
    if (seb0 == fpmax)
        return false;
    seb0 = fpsqrt(seb0);
    *est_offset = b0;
    *est_freq = b1;
    *offset_sd = seb0;
    /* naively scale freq error inversely proportional to number of data points */
    *skew = fpmul(seb1, i2fp(4 + (256>>(n - MIN_SAMPLES)), 0));
    return true;
}

static void insert_sample(timestamp t, s64 off, s64 pdelay, s64 pdisp, s64 rdelay, s64 rdisp)
{
    struct ntp_sample *s = ntp.samples + ntp.sample_index;
    s->time = t;
    s->offset = off;
    s->offset_orig = off;
    s->root_delay = rdelay;
    s->root_dispersion = rdisp;
    s->peer_delay = pdelay;
    s->peer_dispersion = pdisp;
    ntp_debug("insert %d: %T, off=%f, rtd=%f, jit=%f\n", ntp.sample_index, t, off, 
        pdelay, off - s[ntp.sample_index == 0 ? MAX_SAMPLES - 1 : -1].offset);
    ntp.sample_index = (ntp.sample_index + 1) % MAX_SAMPLES;
    if (ntp.nsamples < MAX_SAMPLES)
        ntp.nsamples++;
}

static void stop_slew()
{
    remove_timer(kernel_timers, &ntp.slew_timer, 0);
    ntp.slew_freq = 0;
    clock_set_slew(ntp.slew_freq, 0, 0);
}

static void start_slew()
{
    /* Remove any existing slew */
    remove_timer(kernel_timers, &ntp.slew_timer, 0);

    timestamp here = kern_now(CLOCK_ID_REALTIME);

    /* Adjust offset and rtc with accumulated slew */
    s64 duration = fpclamp((s64)here - (s64)ntp.slew_start, 0, fpmax);
    s64 slew_adj = fpmul(ntp.slew_freq, duration);
    ntp.offset -= slew_adj;
    clock_step_rtc(slew_adj);

    /* Estimate slew rate based on adjusting an offset_sd-sized offset in
     * 1.5 * query interval seconds. The correction duration is inversely
     * proportional to the size of the offset */
    s64 rate = fpmul(fpmul(i2fp(1,5), U64_FROM_BIT(ntp.query_interval)), ntp.offset_sd);
    duration = fpclamp(fpdiv(rate, ABS(ntp.offset)),
        MIN_SLEW_DURATION, fpmax);

    /* Calculate frequency correction needed to slew offset in duration */
    ntp.slew_freq = fpclamp(fpdiv(ntp.offset, duration),
        -ntp.max_corr_freq, ntp.max_corr_freq);

    /* Calculate actual slew duration. Use the maximum duration if the slew
     * is close to zero or signs don't match, from e.g. a precision error */
    if (ABS(ntp.offset) < MIN_OFFSET_CORRECTION ||
        (ntp.offset < 0 && ntp.slew_freq > 0) ||
        (ntp.offset > 0 && ntp.slew_freq < 0)) {
        duration = MAX_SLEW_DURATION;
    } else {
        duration = fpclamp(fpdiv(ntp.offset, ntp.slew_freq),
            MIN_SLEW_DURATION, MAX_SLEW_DURATION);
    }

    /* Start slew */
    ntp.slew_start = here;
    clock_set_slew(ntp.slew_freq, here, duration);
    register_timer(kernel_timers, &ntp.slew_timer, CLOCK_ID_MONOTONIC, duration,
        false, 0, (timer_handler)&ntp.slew_complete_func);
}

closure_func_basic(timer_handler, void, ntp_slew_complete_func,
                   u64 expiry, u64 overruns)
{
    if (overruns == timer_disabled)
        return;
    start_slew();
}

static s64 get_log_precision(s8 lp)
{
    s64 p = 1ll << CLOCK_FP_BITS;
    if (lp < 0)
        p >>= -lp;
    else
        p <<= lp;
    return p;
}

static boolean chrony_new_sample(timestamp t, s64 off, s64 pdelay, s64 pdisp, s64 rdelay, s64 rdisp)
{
    insert_sample(t, off, pdelay, pdisp, rdelay, rdisp);
    if (ntp.nsamples < MIN_SAMPLES)
        return true;
    s64 est_off, est_freq, sd, skew;
    if (!regression(&est_off, &est_freq, &sd, &skew)) {
        msg_err("regression computation failed\n");
        if (++ntp.bad_regressions == MAX_BAD_REGRESSIONS)
            goto badlimit;
        return false;
    }
    /* if the frequency is out of range then assume bad data or misbehaving clock and clamp */
    if (ABS(ntp.base_freq + est_freq) > ntp.max_base_freq) {
        msg_err("freq out of range: %f limit=%f\n", ABS(ntp.base_freq + est_freq), ntp.max_base_freq);
        /* if too many bad regressions in a row, then toss everything and start over */
        if (++ntp.bad_regressions == MAX_BAD_REGRESSIONS) {
badlimit:
            msg_err("too many bad regressions; starting over\n");
            stop_slew();
            ntp_reset_state();
            clock_set_freq(0);
            return false;
        }
        /* otherwise, clamp frequency, use packet offset for now */
        est_freq = fpclamp(est_freq, -ntp.max_base_freq, ntp.max_base_freq);
        est_off = off;
    } else {
        ntp.bad_regressions = 0;
    }
    ntp.offset_sd = sd;
    ntp.skew = skew;

    timestamp here = kern_now(CLOCK_ID_REALTIME);
    /* get old compensated time before changes for statistics update later */
    timestamp here_comp = slew_compensate(here);
    /* adjust offset with time elapsed since packet reception with new frequency */
    here += (s64)ntp.offset - fpmul(ntp.slew_freq, here - ntp.slew_start);
    s64 elapsed = (s64)here - (s64)t;
    s64 adjoff = est_off + fpmul(elapsed, est_freq);

    /* The regression calculates incremental frequency and offset changes */
    ntp.base_freq += est_freq;
    ntp.offset += adjoff;
    ntp_debug("packet offset=%f est_offset(total)=%f(%f) est_freq(total)=%f(%f) offset_sd=%f skew=%f\n",
              off, adjoff, ntp.offset, est_freq, ntp.base_freq, ntp.offset_sd, ntp.skew);
    clock_set_freq(ntp.base_freq);

    s64 step_offset = 0;
    if (ntp.offset > ntp.reset_threshold || ntp.offset < -ntp.reset_threshold) {
        clock_step_rtc(ntp.offset);
        step_offset = ntp.offset;
        adjoff = 0;
        ntp.offset = 0;
    } else {
        start_slew();
    }
    /* Update existing statistics to reflect frequency and offset changes */
    for (int i = 0; i < ntp.nsamples; i++) {
        struct ntp_sample *s = get_sample(i);
        s64 dt = fpmul((here_comp - s->time), est_freq) - adjoff;
        s->time += dt + step_offset;
        s->offset += dt - step_offset;
    }
    /* Check how closely we're tracking the server and update poll time */
    s64 jitter = off - est_off;
    if (ABS(jitter) < fpmul(ntp.offset_sd, i2fp(1,5))) {
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
    return true;
}

closure_func_basic(timer_handler, void, ptp_query_func,
                   u64 expiry, u64 overruns)
{
    if (overruns == timer_disabled)
        return;
    timestamp ts = apply(ptp_clock_now);
    boolean success;
    if (ts) {
        s64 dispersion = get_log_precision(PTP_CLOCK_PRECISION);
        success = chrony_new_sample(ts, ts - slew_compensate(kern_now(CLOCK_ID_REALTIME)),
                                    0, dispersion, 0, dispersion);
    } else {
        success = false;
    }
    ntp_query_complete(success);
}

/* some sanity checks from RFC5905 */
static boolean sanity_checks(ntp_server server, struct ntp_packet *p)
{
    int tssz = sizeof(struct ntp_ts);
    struct ntp_ts zerots = {0};
    /* Check for duplicate packet */
    if (runtime_memcmp(&p->transmit_ts, &server->last_transmit_time, tssz) == 0)
        return false;
    runtime_memcpy(&server->last_transmit_time, &p->transmit_ts, tssz);
    /* Check packet matches our last transmit time */
    if (runtime_memcmp(&p->originate_ts, &server->last_originate_time, tssz) != 0)
        return false;
    runtime_memset((void *)&server->last_originate_time, 0, tssz);
    /* Check all timestamps are non-zero */
    if (runtime_memcmp(&p->originate_ts, &zerots, tssz) == 0 ||
        runtime_memcmp(&p->receive_ts, &zerots, tssz) == 0 ||
        runtime_memcmp(&p->transmit_ts, &zerots, tssz) == 0)
        return false;
    /* Check for sane root delay */
    if (ntp_fixed_conv(p->root_delay) / 2 + ntp_fixed_conv(p->root_dispersion) >= MAX_DISPERSION)
        return false;
    return true;
}

/* called with lwIP lock held */
static void ntp_input(void *z, struct udp_pcb *pcb, struct pbuf *p,
                      struct ip_globals *ip_data, u16 port)
{
    ntp.query_ongoing = false;
    struct ntp_packet *pkt = p->payload;
    boolean success;
    if (p->len != sizeof(*pkt)) {
        msg_err("invalid response length %d\n", p->len);
        success = false;
        goto done;
    }
    const ip_addr_t *addr = &ip_data->current_iphdr_src;
    ntp_lock();
    if (ntp.current_server >= 0) {
        ntp_server server = vector_get(ntp.servers, ntp.current_server);
        ntp_unlock();
        if (!ip_addr_cmp(addr, &server->ip_addr)) {
            ntp_debug("received packet is not from current server, discarding\n");
            goto exit;
        }
        if (!sanity_checks(server, pkt)) {
            msg_err("packet sanity checks failed; discarded\n");
            success = false;
            goto done;
        }
    } else {
        ntp_server server = 0;
        ntp_server s;
        vector_foreach(ntp.servers, s) {
            if (ip_addr_cmp(addr, &s->ip_addr)) {
                if (sanity_checks(s, pkt)) {
                    ntp_debug("selecting %s as current server\n", s->addr);
                    ntp.current_server = _i;
                    server = s;
                }
                break;
            }
        }
        ntp_unlock();
        if (!server)
            goto exit;
    }
    ntp.resp_time = kern_now(CLOCK_ID_MONOTONIC_RAW);
    timestamp wallclock_now = slew_compensate(kern_now(CLOCK_ID_REALTIME));
    struct ntp_ts t1, t2;
    runtime_memcpy(&t1, &pkt->originate_ts, sizeof(t1));
    timestamp origin = ntptime_to_timestamp(&t1);
    /* round trip delay */
    runtime_memcpy(&t1, &pkt->transmit_ts, sizeof(t1));
    runtime_memcpy(&t2, &pkt->receive_ts, sizeof(t2));
    /* calculate sample time as in the middle of local send and receive times */
    s64 local_diff = wallclock_now - origin;
    timestamp local_avg = origin + local_diff / 2;
    /* calculate local error */
    s64 disp = get_log_precision(pkt->precision) + fpmul(ntp.skew, ABS(local_diff));
    /* calculate worst-case round trip delay by including frequency error */
    s64 delay = local_diff - fpmul(ntptime_diff(&t1, &t2), i2fp(1,0) + (ntp.base_freq - ntp.skew));
    if (delay <= 0)
        delay = nanoseconds(1);
    s64 offset = (s64)ntptime_to_timestamp(&t1) - (s64)wallclock_now + delay / 2;

    s64 root_delay = ntp_fixed_conv(pkt->root_delay);
    s64 root_disp = ntp_fixed_conv(pkt->root_dispersion);
    success = chrony_new_sample(local_avg, offset, delay, disp, delay + root_delay,
                                disp + root_disp);
  done:
    ntp_query_complete(success);
  exit:
    pbuf_free(p);
}

static void ntp_dns_cb(sstring name, const ip_addr_t *ipaddr, void *callback_arg)
{
    if (ipaddr) {
        ntp_server server = callback_arg;
        server->ip_addr = *ipaddr;
        ntp_query(server);
    } else {
        msg_err("failed to resolve hostname %s\n", name);
        ntp_query_complete(false);
    }
}

static boolean ntp_resolve_and_query(ntp_server server)
{
    err_t err = dns_gethostbyname(server->addr, &server->ip_addr, ntp_dns_cb, server);
    if (err == ERR_OK) {
        ntp_query(server);
    } else if (err != ERR_INPROGRESS) {
        msg_err("failed to resolve hostname %s: %d\n", server->addr, err);
        return false;
    }
    return true;
}

closure_func_basic(timer_handler, void, ntp_query_func,
                   u64 expiry, u64 overruns)
{
    if (overruns == timer_disabled)
        return;
    if (ntp.query_ongoing) {
        if ((ntp.current_server < 0) || (ntp.query_errors >= NTP_QUERY_ATTEMPTS)) {
            timestamp t = kern_now(CLOCK_ID_MONOTONIC_RAW) - ntp.resp_time;
            if (t >= seconds(ntp.no_resp_warn_time * 60)) {
                rprintf("NTP: failed to receive any valid server response in the past %d minutes\n",
                        ntp.no_resp_warn_time);
                if (ntp.no_resp_warn_time <= 30)
                    ntp.no_resp_warn_time <<= 1;
                else
                    ntp.no_resp_warn_time = 60 * (1 + ntp.no_resp_warn_time / 60);
            }
        }
        ntp_query_complete(false);
    } else {
        ntp.no_resp_warn_time = U64_FROM_BIT(ntp.query_interval) * NTP_QUERY_ATTEMPTS / 60;
    }
    int current_server = ntp.current_server;
    boolean success;
    if (current_server >= 0) {
        success = ntp_resolve_and_query(vector_get(ntp.servers, current_server));
    } else {
      success = false;
      ntp_server server;
      vector_foreach(ntp.servers, server) {
          success |= ntp_resolve_and_query(server);
      }
    }
    if (!success)
        ntp_query_complete(false);
}

/* Periodically update last raw to avoid numeric errors from big intervals */
closure_func_basic(timer_handler, void, ntp_raw_update_func,
                   u64 expiry, u64 overruns)
{
    if (overruns == timer_disabled)
        return;
    clock_update_last_raw(kern_now(CLOCK_ID_MONOTONIC_RAW));
    register_timer(kernel_timers, &ntp.raw_update_timer, CLOCK_ID_MONOTONIC, seconds(CLOCK_RAW_UPDATE_SECONDS + 1), false, 0,
        (timer_handler)&ntp.raw_update_func);
}

static void ntp_server_add(heap h, buffer addr, u16 port)
{
    ntp_debug("adding server %b (port %d)\n", addr, port);
    ntp_server server = allocate(h, sizeof(*server));
    assert(server != INVALID_ADDRESS);
    server->addr = buffer_to_sstring(addr);
    server->port = port;
    vector_push(ntp.servers, server);
}

static boolean ntp_server_parse(heap h, buffer server)
{
    if (buffer_length(server) == 0)
        return false;
    buffer addr = 0;
    u16 port;
    int separator;
    if (byte(server, 0) == '[') {   /* numeric IPv6 address */
        int addr_end = buffer_strchr(server, ']');
        if (addr_end < 0)
            return false;
        if (addr_end == buffer_length(server) - 1) {
            separator = -1;
        } else {
            if ((addr_end < buffer_length(server) - 2) && (byte(server, addr_end + 1) == ':'))
                separator = addr_end + 1;
            else
                return false;
        }
        addr = alloca_wrap_buffer(buffer_ref(server, 1), addr_end - 1);
    } else {
        separator = buffer_strchr(server, ':');
        if ((separator == 0) || (separator == buffer_length(server) - 1))
            return false;
    }
    if (separator > 0) {
        buffer port_buf = alloca_wrap_buffer(buffer_ref(server, separator + 1),
                                             buffer_length(server) - separator - 1);
        u64 val;
        if (!u64_from_value(port_buf, &val) || (val > U16_MAX))
            return false;
        if (!addr)
            addr = alloca_wrap_buffer(buffer_ref(server, 0), separator);
        port = val;
    } else {
        if (!addr)
            addr = server;
        port = NTP_PORT_DEFAULT;
    }
    ntp_server_add(h, addr, port);
    return true;
}

int init(status_handler complete)
{
    tuple root = get_root_tuple();
    if (!root) {
        rprintf("NTP: failed to get root tuple\n");
        return KLIB_INIT_FAILED;
    }
    heap h = heap_locked(get_kernel_heaps());
    value chrony = get(root, sym_this("chrony"));
    if (chrony) {
        if (is_tuple(chrony)) {
            value refclock = get(chrony, sym_this("refclock"));
            if (refclock) {
                boolean refclock_ok = is_string(refclock);
                if (refclock_ok) {
                    if (!buffer_strcmp(refclock, "ptp")) {
                        if (ptp_clock_now)
                            ntp.ptp_clock = true;
                        else
                            rprintf("chrony: PTP clock not available, using NTP\n");
                    } else {
                        refclock_ok = false;
                    }
                }
                if (!refclock_ok) {
                    rprintf("chrony: invalid refclock %v\n", refclock);
                    return KLIB_INIT_FAILED;
                }
            }
        } else  {
            rprintf("chrony: invalid configuration %v\n", chrony);
            return KLIB_INIT_FAILED;
        }
    }
    value servers = get(root, sym(ntp_servers));
    int server_count;
    if (servers) {
        server_count = is_tuple(servers) ? tuple_count(servers) :
            is_vector(servers) ? vector_length(servers) : 0;
        if (server_count == 0) {
            servers = 0;
            server_count = 1;
        }
    } else  {
        server_count = 1;
    }
    if (!ntp.ptp_clock) {
        ntp.servers = allocate_vector(h, server_count);
        assert(ntp.servers != INVALID_ADDRESS);
        if (servers) {
            string server;
            for (int i = 0; (server = get_string(servers, integer_key(i))); i++) {
                if (!ntp_server_parse(h, server)) {
                    rprintf("NTP: invalid server '%b'\n", server);
                    return KLIB_INIT_FAILED;
                }
            }
            if (vector_length(ntp.servers) == 0) {
                rprintf("NTP: invalid servers %v\n", servers);
                return KLIB_INIT_FAILED;
            }
        } else {
            ntp_server_add(h, alloca_wrap_cstring(NTP_SERVER_DEFAULT), NTP_PORT_DEFAULT);
        }
    }
    ntp.pollmin = 4;
    ntp.pollmax = 10;
    value pollmin = get(root, sym(ntp_poll_min));
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
    value pollmax = get(root, sym(ntp_poll_max));
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
    value reset_thresh = get(root, sym(ntp_reset_threshold));
    if (reset_thresh) {
        u64 thresh;
        if (!u64_from_value(reset_thresh, &thresh) || (thresh > 0 && thresh < NTP_RESET_THRESHOLD_MIN)) {
            rprintf("NTP: invalid reset threshold\n");
            return KLIB_INIT_FAILED;
        }
        ntp.reset_threshold = seconds(thresh);
    }
    ntp.max_corr_freq = PPM_SCALE(DEFAULT_MAX_SLEW_PPM);
    value corr_freq = get(root, sym(ntp_max_slew_ppm));
    if (corr_freq) {
        u64 ppm;
        if (!u64_from_value(corr_freq, &ppm) || (ppm > 0 && ppm < NTP_MAX_SLEW_LIMIT)) {
            rprintf("NTP: invalid max slew frequency\n");
            return KLIB_INIT_FAILED;
        }
        ntp.max_corr_freq = PPM_SCALE(ppm);
    }
    ntp.max_base_freq = PPM_SCALE(DEFAULT_MAX_FREQ_PPM);
    value base_freq = get(root, sym(ntp_max_freq_ppm));
    if (base_freq) {
        u64 ppm;
        if (!u64_from_value(base_freq, &ppm) || (ppm > 0 && ppm < NTP_MAX_FREQ_LIMIT)) {
            rprintf("NTP: invalid max base frequency\n");
            return KLIB_INIT_FAILED;
        }
        ntp.max_base_freq = PPM_SCALE(ppm);
    }
    if (ntp.ptp_clock) {
        ntp.query_func = closure_func(h, timer_handler, ptp_query_func);
    } else {
        ntp.pcb = udp_new_ip_type(IPADDR_TYPE_ANY);
        if (!ntp.pcb) {
            rprintf("NTP: failed to create PCB\n");
            return KLIB_INIT_FAILED;
        }
        udp_recv(ntp.pcb, ntp_input, 0);
        ntp.query_func = closure_func(h, timer_handler, ntp_query_func);
    }
    assert(ntp.query_func != INVALID_ADDRESS);
    init_closure_func(&ntp.slew_complete_func, timer_handler, ntp_slew_complete_func);
    init_closure_func(&ntp.raw_update_func, timer_handler, ntp_raw_update_func);
    spin_lock_init(&ntp.lock);
    ntp_reset_state();
    runtime_memset((void *)ntp.samples, 0, sizeof(ntp.samples));
    init_timer(&ntp.query_timer);
    init_timer(&ntp.slew_timer);
    register_timer(kernel_timers, &ntp.query_timer, CLOCK_ID_MONOTONIC_RAW, seconds(5), false, 0,
                   ntp.query_func);
    register_timer(kernel_timers, &ntp.raw_update_timer, CLOCK_ID_MONOTONIC, seconds(CLOCK_RAW_UPDATE_SECONDS), false, 0,
        (timer_handler)&ntp.raw_update_func);
    return KLIB_INIT_OK;
}
