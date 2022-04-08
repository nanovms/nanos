#define LOCK_TYPE_SPIN 0
#define LOCK_TYPE_MUTEX 1

typedef struct lockstats_lock {
    int type;
    u64 acq_time;
    u64 trace_hash;
} *lockstats_lock;
