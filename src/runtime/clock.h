/* Number of fractional bits in fixed-point clock calibration value. */
#define CLOCK_CALIBR_BITS   32

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

typedef closure_type(clock_now, timestamp);
extern clock_now platform_monotonic_now;

#if defined(STAGE3) || defined(BUILD_VDSO)
#include <vdso.h>
#define __vdso_dat (&(VVAR_REF(vdso_dat)))

static inline u64
_rdtscp(void)
{
    u32 a, d;
    asm volatile("rdtscp" : "=a" (a), "=d" (d) :: "%rcx");
    return (((u64)a) | (((u64)d) << 32));
}

static inline u64
_rdtsc(void)
{
    u32 a, d;
    asm volatile("rdtsc" : "=a" (a), "=d" (d));
    return (((u64)a) | (((u64)d) << 32));
}

static inline u64
rdtsc(void)
{
    if (__vdso_dat->platform_has_rdtscp)
        return _rdtscp();
    return _rdtsc();
}

static inline u64
rdtsc_ordered(void)
{
    if (__vdso_dat->platform_has_rdtscp)
        return _rdtscp();

    /* Now both AMD and Intel has lfence  */
    __asm __volatile("lfence" : : : "memory");
    return _rdtsc();
}

static inline u64
rdtsc_precise(void)
{
    if (__vdso_dat->platform_has_rdtscp)
        return _rdtscp();

    asm volatile("cpuid" ::: "%rax", "%rbx", "%rcx", "%rdx"); /* serialize execution */
    return _rdtsc();
}

static inline s64 clock_calculate_drift(timestamp interval, s64 cal)
{
    if (cal >= 0)
        return ((interval * cal) >> CLOCK_CALIBR_BITS);
    else
        return -((interval * -cal) >> CLOCK_CALIBR_BITS);
}

static inline s64 clock_get_drift(timestamp raw)
{
    if (!__vdso_dat->temp_cal && !__vdso_dat->cal)
        return 0;
    s64 drift = __vdso_dat->last_drift;
    if (raw > __vdso_dat->sync_complete) {
        if (__vdso_dat->last_raw > __vdso_dat->sync_complete) {
            drift += clock_calculate_drift(raw - __vdso_dat->last_raw, __vdso_dat->cal);
        } else {
            drift += clock_calculate_drift(__vdso_dat->sync_complete - __vdso_dat->last_raw,
                __vdso_dat->temp_cal);
            drift += clock_calculate_drift(raw - __vdso_dat->sync_complete, __vdso_dat->cal);
        }
    } else {
        drift += clock_calculate_drift(raw - __vdso_dat->last_raw, __vdso_dat->temp_cal);
    }
    return drift;
}

static inline s64 clock_update_drift(timestamp raw)
{
    s64 drift = clock_get_drift(raw);
    __vdso_dat->last_drift = drift;
    __vdso_dat->last_raw = raw;
    return drift;
}
#endif

/* This is all kernel-only below here */
static inline timestamp now(clock_id id)
{
    timestamp t = apply(platform_monotonic_now);

#if defined(STAGE3) || defined(BUILD_VDSO)
    if (id == CLOCK_ID_MONOTONIC_RAW)
        return t;
    t += clock_update_drift(t);
    switch (id) {
    case CLOCK_ID_REALTIME:
    case CLOCK_ID_REALTIME_COARSE:
        t += __vdso_dat->rtc_offset;
        break;
    default:
        break;
    }
#endif

    return t;
}

static inline timestamp uptime(void)
{
    return now(CLOCK_ID_BOOTTIME);
}

u64 rtc_gettimeofday(void);
void rtc_settimeofday(u64 seconds);

static inline void register_platform_clock_now(clock_now cn, vdso_clock_id id)
{
    platform_monotonic_now = cn;
#if defined(STAGE3) || defined(BUILD_VDSO)
    __vdso_dat->clock_src = id;
    __vdso_dat->rtc_offset = (rtc_gettimeofday() << 32) - apply(cn);
    __vdso_dat->temp_cal = __vdso_dat->cal = 0;
    __vdso_dat->sync_complete = 0;
    __vdso_dat->last_raw = __vdso_dat->last_drift = 0;
#endif
}

void clock_adjust(timestamp wallclock_now, s64 temp_cal, timestamp sync_complete, s64 cal);

#if defined(STAGE3) || defined(BUILD_VDSO)
#undef __vdso_dat
#endif
