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

extern timestamp rtc_offset;
extern clock_now platform_monotonic_now;

timestamp now(clock_id id);
timestamp uptime(void);
void register_platform_clock_now(clock_now cn, vdso_clock_id);
u64 rtc_gettimeofday(void);
