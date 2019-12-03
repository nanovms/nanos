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

typedef closure_type(clock_now, timestamp);

extern timestamp rtc_offset;
extern clock_now platform_monotonic_now;

static inline timestamp now(clock_id id)
{
    switch (id) {
    case CLOCK_ID_MONOTONIC:
    case CLOCK_ID_MONOTONIC_RAW:
    case CLOCK_ID_MONOTONIC_COARSE:
    case CLOCK_ID_BOOTTIME:
        return apply(platform_monotonic_now);
    case CLOCK_ID_REALTIME:
    case CLOCK_ID_REALTIME_COARSE:
        return apply(platform_monotonic_now) + rtc_offset;
    default:
        halt("now: unsupported clock id %d\n", id);
    }
}

static inline timestamp uptime(void)
{
    return now(CLOCK_ID_BOOTTIME);
}

static inline void register_platform_clock_now(clock_now cn)
{
    platform_monotonic_now = cn;
}

u64 rtc_gettimeofday(void);
