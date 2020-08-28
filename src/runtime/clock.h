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
#endif

/* This is all kernel-only below here */
static inline timestamp now(clock_id id)
{
#if defined(STAGE3) || defined(BUILD_VDSO)
    u64 rtc_offset = __vdso_dat->rtc_offset;
#else
    u64 rtc_offset = 0;
#endif

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

static inline void register_platform_clock_now(clock_now cn, vdso_clock_id id)
{
    platform_monotonic_now = cn;
#if defined(STAGE3) || defined(BUILD_VDSO)
    __vdso_dat->clock_src = id;
#endif
}

#if defined(STAGE3) || defined(BUILD_VDSO)
#undef __vdso_dat
#endif

u64 rtc_gettimeofday(void);
