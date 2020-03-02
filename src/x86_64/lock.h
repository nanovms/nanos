typedef struct spinlock {
    u64 w;
} *spinlock;

static inline boolean spin_try(spinlock l) {
    u64 tmp = 1;
    /* Is it worth the compare and branch to skip a pause? */
    asm volatile("lock xchg %0, %1; cmp $1, %1; jne 1f; pause; 1:" : "+m"(*&l->w), "+r"(tmp) :: "memory");
    return tmp == 0 ? true:false;
}

static inline void spin_lock(spinlock l) {
    u64 tmp = 1;
    asm volatile("1: lock xchg %0, %1; cmp $1, %1; jne 2f; pause; jmp 1b; 2:" : "+m"(*&l->w), "+r"(tmp) :: "memory");
}

static inline void spin_unlock(spinlock l) {
    compiler_barrier();
    *(volatile u64 *)&l->w = 0;
}

static inline u64 spin_lock_irq(spinlock l)
{
    u64 flags = read_flags();
    disable_interrupts();
    spin_lock(l);
    return flags;
}

static inline void spin_unlock_irq(spinlock l, u64 flags)
{
    spin_unlock(l);
    irq_restore(flags);
}

static inline void spin_lock_init(spinlock l)
{
    *&l->w = 0;
}
