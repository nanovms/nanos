/* Number of fractional bits in fixed-point clock values. */
#define CLOCK_FP_BITS   32
#define CLOCK_RAW_UPDATE_SECONDS 30ull

/* these need to map to linux values */
typedef enum {
    CLOCK_ID_REALTIME = 0,
    CLOCK_ID_MONOTONIC,
    CLOCK_ID_PROCESS_CPUTIME_ID, /* not used for system, included */
    CLOCK_ID_THREAD_CPUTIME_ID,  /* for parity with unix world */
    CLOCK_ID_MONOTONIC_RAW,
    CLOCK_ID_REALTIME_COARSE,
    CLOCK_ID_MONOTONIC_COARSE,
    CLOCK_ID_BOOTTIME,
    CLOCK_ID_REALTIME_ALARM,
    CLOCK_ID_BOOTTIME_ALARM,
} clock_id;

/* these are used for exporting vdso to userspace */
typedef enum {
    VDSO_CLOCK_SYSCALL = 0,
    VDSO_CLOCK_HPET,
    VDSO_CLOCK_TSC_STABLE,
    VDSO_CLOCK_PVCLOCK,
    VDSO_CLOCK_NRCLOCKS
} vdso_clock_id;

closure_type(clock_now, timestamp);
extern clock_now platform_monotonic_now;

#define PTP_CLOCK_PRECISION -9  /* expressed in seconds as power of two */

extern clock_now ptp_clock_now;

#if defined(KERNEL) || defined(BUILD_VDSO)
#include <vdso.h>
#define __vdso_dat (&(VVAR_REF(vdso_dat)))

static inline s64 clock_freq_adjust(s64 interval)
{
    return (interval * __vdso_dat->base_freq) >> CLOCK_FP_BITS;
}

static inline s64 clock_phase_adjust(timestamp raw, s64 interval)
{
    timestamp start = raw - interval;
    timestamp end = raw;
    if (__vdso_dat->slew_start > start)
        start = __vdso_dat->slew_start;
    if (raw > __vdso_dat->slew_end)
        end = __vdso_dat->slew_end;
    if (raw < start)
        return 0;
    interval = end - start;

    return __vdso_dat->slew_freq * interval >> CLOCK_FP_BITS;
}

void clock_set_freq(s64 freq);
void clock_set_slew(s64 slewfreq, timestamp start, u64 duration);
void clock_step_rtc(s64 step);
void clock_update_last_raw(timestamp t);
#endif

static inline timestamp now(clock_id id)
{
    if (!platform_monotonic_now)
        return -1ull;
    timestamp t;

#if defined(KERNEL) || defined(BUILD_VDSO)
    u64 gen;
    do {
        gen = __vdso_dat->vdso_gen & ~1ull;
        s64 last_raw = __vdso_dat->last_raw;
        read_barrier();
#endif
        t = apply(platform_monotonic_now);
#if defined(KERNEL) || defined(BUILD_VDSO)
        if (id == CLOCK_ID_MONOTONIC_RAW)
            return t;
        assert(t >= last_raw);
        s64 interval = t - last_raw;
        t += clock_freq_adjust(interval);
        if (t < last_raw) {
            msg_err("%s error: t(%T) < last_raw(%T) after freq adjust (%f)",
                    func_ss, t, last_raw, __vdso_dat->base_freq);
            t = last_raw;
        }
        switch (id) {
        case CLOCK_ID_REALTIME:
        case CLOCK_ID_REALTIME_COARSE:
            t += clock_phase_adjust(t, interval);
            t += __vdso_dat->rtc_offset;
            break;
        default:
            break;
        }
        read_barrier();
    } while (gen != __vdso_dat->vdso_gen);
#endif

    return t;
}

static inline timestamp uptime(void)
{
    return now(CLOCK_ID_BOOTTIME);
}

u64 rtc_gettimeofday(void);
void rtc_settimeofday(u64 seconds);

#if defined(KERNEL) || defined(BUILD_VDSO)
static inline void reset_clock_vdso_dat()
{
    __vdso_dat->last_raw = 0;
    __vdso_dat->base_freq = 0;
    __vdso_dat->slew_freq = 0;
    __vdso_dat->slew_start = 0;
    __vdso_dat->slew_end = 0;
    __vdso_dat->vdso_gen = 0;
}
#endif

static inline void register_platform_clock_now(clock_now cn, vdso_clock_id id, timestamp rtc_offset)
{
    platform_monotonic_now = cn;
#if defined(KERNEL) || defined(BUILD_VDSO)
    __vdso_dat->clock_src = id;
    if (!rtc_offset) {
        u64 rt = rtc_gettimeofday();
        if (rt)
            rtc_offset = (rt << 32) - apply(platform_monotonic_now);
    }
    __vdso_dat->rtc_offset = rtc_offset;
    reset_clock_vdso_dat();
#endif
}

void clock_reset_rtc(timestamp wallclock_now);
#if defined(KERNEL) || defined(BUILD_VDSO)
#undef __vdso_dat
#endif

#define THOUSAND         (1000ull)
#define MILLION          (1000000ull)
#define BILLION          (1000000000ull)
#define TRILLION         (1000000000000ull)
#define QUADRILLION      (1000000000000000ull)
#define TIMESTAMP_SECOND (1ull << 32)

// danger - truncation, should always be subsec

static inline timestamp seconds(u64 n)
{
    return n * TIMESTAMP_SECOND;
}

#define TIMESTAMP_CONV_FN(name, factor)                         \
    static inline timestamp name(u64 n)                         \
    {                                                           \
        if (n == 0)                                             \
            return 0;                                           \
        u64 sec = n / factor;                                   \
        n -= sec * factor;                                      \
        return seconds(sec) + (seconds(n) / factor) + 1;        \
    }

#define TIMESTAMP_CONV_FN_2(name, factor)       \
    static inline timestamp name(u64 n)         \
    {                                           \
        if (n == 0)                             \
            return 0;                           \
        return n / (factor >> 32) + 1;          \
    }

TIMESTAMP_CONV_FN(milliseconds, THOUSAND)
TIMESTAMP_CONV_FN(microseconds, MILLION)
TIMESTAMP_CONV_FN(nanoseconds, BILLION)
TIMESTAMP_CONV_FN_2(picoseconds, TRILLION)
TIMESTAMP_CONV_FN_2(femtoseconds, QUADRILLION)

static inline timestamp truncate_seconds(timestamp t)
{
    return t & MASK(32);
}

static inline u64 sec_from_timestamp(timestamp t)
{
    return t / TIMESTAMP_SECOND;
}

static inline u64 nsec_from_timestamp(timestamp t)
{
    u64 sec = sec_from_timestamp(t);
    return (sec * BILLION) +
        ((truncate_seconds(t) * BILLION) / TIMESTAMP_SECOND);
}

static inline u64 usec_from_timestamp(timestamp t)
{
    u64 sec = sec_from_timestamp(t);
    return (sec * MILLION) +
        ((truncate_seconds(t) * MILLION) / TIMESTAMP_SECOND);
}

static inline u64 msec_from_timestamp(timestamp t)
{
    u64 sec = sec_from_timestamp(t);
    return (sec * THOUSAND) +
        ((truncate_seconds(t) * THOUSAND) / TIMESTAMP_SECOND);
}
