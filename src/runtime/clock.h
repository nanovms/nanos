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

#if defined(KERNEL) || defined(BUILD_VDSO)
#include "vdso.h"
#endif
#define __vdso_dat (&(VVAR_REF(vdso_dat)))

/* This is all kernel-only below here */
static inline timestamp now(clock_id id)
{
#if defined(KERNEL) || defined(BUILD_VDSO)
    u64 rtc_offset = __vdso_dat->rtc_offset;
#else
    u64 rtc_offset = 0;
#endif
    if (!platform_monotonic_now)
        return 0;

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
        return 0;
    }
}

static inline timestamp uptime(void)
{
    return now(CLOCK_ID_BOOTTIME);
}

#if defined(KERNEL) || defined(BUILD_VDSO)
static inline void register_platform_clock_now(clock_now cn, vdso_clock_id id)
{
    platform_monotonic_now = cn;
    __vdso_dat->clock_src = id;
}
#undef __vdso_dat
#endif

u64 rtc_gettimeofday(void);
