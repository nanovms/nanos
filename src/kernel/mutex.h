typedef struct mutex {
    u64 spin_iterations;
    context turn;
    context waiters_tail;
} *mutex;

boolean mutex_try_lock(mutex ql);

void mutex_lock(mutex ql);

void mutex_unlock(mutex ql);

#define mutex_is_acquired(m)    ((m)->turn == get_current_context(current_cpu()))

mutex allocate_mutex(heap h, u64 depth, u64 spin_iterations);
