typedef struct lockstats_lock {
    int type;
    u64 acq_time;
    u64 trace_hash;
} *lockstats_lock;
