typedef struct mutex {
    u64 spin_iterations;
    context turn;
    void *mcs_tail;             /* cpuinfo */
    struct spinlock waiters_lock;
    struct list waiters;
    u64 mcs_spinouts;           /* stats */
    u64 acquire_spinouts;
#ifdef LOCK_STATS
    struct lockstats_lock s;
#endif
} *mutex;

boolean mutex_try_lock(mutex ql);

void mutex_lock(mutex ql);

void mutex_unlock(mutex ql);

#define mutex_is_acquired(m)    ((m)->turn == get_current_context(current_cpu()))

mutex allocate_mutex(heap h, u64 spin_iterations);
