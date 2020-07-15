static inline void compiler_barrier(void)
{
    asm volatile("" ::: "memory");
}

static inline void write_barrier(void)
{
    asm volatile("sfence" ::: "memory");
}

static inline void read_barrier(void)
{
    asm volatile("lfence" ::: "memory");
}

static inline void memory_barrier(void)
{
    asm volatile("mfence" ::: "memory");
}

static inline word fetch_and_add(word *variable, word value)
{
    asm volatile("lock; xadd %0, %1" : "+r" (value), "+m" (*variable) :: "memory", "cc");
    return value;
}

static inline void atomic_set_bit(u64 *target, u64 bit)
{
    asm volatile("lock btsq %1, %0": "+m"(*target): "r"(bit) : "memory");
}

static inline void atomic_clear_bit(u64 *target, u64 bit)
{
    asm volatile("lock btrq %1, %0": "+m"(*target):"r"(bit) : "memory");
}

static inline u64 fetch_and_add_64(u64 *target, u64 num)
{
    return __sync_fetch_and_add(target, num);
}

static inline void kern_pause(void)
{
    asm volatile("pause");
}
