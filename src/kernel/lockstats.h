#define MAX_TRACE_DEPTH 8
#define LOCK_TYPE_SPIN 0
#define LOCK_TYPE_MUTEX 1

typedef struct lock_block {
    u64 lock_trace[MAX_TRACE_DEPTH];
    u64 lock_address;
    int type;               /* lock type */
    u64 hash;
} *lock_block;

typedef struct lock_stats {
    struct lock_block lock; /* lock information */
    u64 acq;                /* number of acquisitions */
    u64 cont;               /* number of contended acquisitions */
    u64 tries;              /* number of lock tries when not acquired */
    u64 spins_total;        /* number of spins to acquire (when waiting) */
    u64 spins_max;          /* max spins to acquire (when waiting) */
    u64 spins_min;          /* min spins to acquire (when waiting) */
    u64 hold_time_total;    /* total time (cycles) holding lock */
    u64 hold_time_max;      /* max time holding lock */
    u64 hold_time_min;      /* min time holding lock */
    u64 sleep_time_total;   /* time spent sleeping for lock */

} *lock_stats;

void lockstats_init(kernel_heaps kh);

#ifdef __x86_64__
static inline u64 lockstats_rdtscp(void)
{
    u32 a, d;
    if (platform_has_precise_clocksource())
        asm volatile("rdtscp" : "=a" (a), "=d" (d) :: "%rcx");
    else
        asm volatile("rdtsc" : "=a" (a), "=d" (d) :: "%rcx");
    return (((u64)a) | (((u64)d) << 32));
}

#define lockstats_timestamp() lockstats_rdtscp()
#else
#define lockstats_timestamp() (nsec_from_timestamp(now(CLOCK_ID_MONOTONIC)))
#endif

#define LOCKSTATS_RECORD_LOCK(L, A, N, S)                       \
            if (record_lock_stats) {                               \
                if (A) L.acq_time = lockstats_timestamp();         \
                lockstats_record(&L, A, N, S);     \
            }

#define LOCKSTATS_RECORD_UNLOCK(L) \
    if (record_lock_stats) { lockstats_record_unlock(&L, lockstats_timestamp() - L.acq_time); }

extern boolean record_lock_stats;

lock_stats get_lockstats_block(lockstats_lock ll, boolean islocking);

static inline void lockstats_record(lockstats_lock ll, boolean acq, u64 spins, u64 sleeps)
{
    if (!record_lock_stats)
        return;
    lock_stats stats = get_lockstats_block(ll, true);
    if (!stats)
        return;
    if (!acq) {
        stats->tries++;
        return;
    }
    stats->acq++;
    if (spins > 0) {
        stats->spins_total += spins;
        if (spins > stats->spins_max)
            stats->spins_max = spins;
        if (spins < stats->spins_min)
            stats->spins_min = spins;
        stats->sleep_time_total += sleeps;
        stats->cont++;
    }
    ll->trace_hash = stats->lock.hash;
}

static inline void lockstats_record_unlock(lockstats_lock ll, u64 holdtm)
{
    lock_stats stats = get_lockstats_block(ll, false);
    /* XXX unlocks on a cpu that has never first locked this hash will be dropped */
    if (!stats)
        return;

    ll->trace_hash = 0;
    /* discard giant hold times resulting from enabling profiling while lock was being held */
    if (holdtm > 10*BILLION)
        return;
    stats->hold_time_total += holdtm;
    if (holdtm > stats->hold_time_max)
        stats->hold_time_max = holdtm;
    if (holdtm < stats->hold_time_min)
        stats->hold_time_min = holdtm;
}
