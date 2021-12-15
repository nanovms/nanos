typedef struct mutex {
    u32 count;
    context turn;
    u64 spin_iterations;
    queue waiters;
} *mutex;

boolean mutex_try_lock(mutex ql);

void mutex_lock(mutex ql);

void mutex_unlock(mutex ql);

mutex allocate_mutex(heap h, u64 depth, u64 spin_iterations);
