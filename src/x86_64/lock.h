static inline boolean spin_try(u64 *loc) {
    u64 tmp = 1;
    /* Is it the compare and branch to skip a pause? */
    asm volatile("lock xchg %0, %1; cmp $1, %1; jne 1f; pause; 1:" : "+m"(*loc), "+r"(tmp) :: "memory");
    return tmp == 0 ? true:false;
}

static inline void spin_lock(u64 *loc) {
    u64 tmp = 1;
    asm volatile("1: lock xchg %0, %1; cmp $1, %1; jne 2f; pause; jmp 1b; 2:" : "+m"(*loc), "+r"(tmp) :: "memory");
}

static inline void spin_unlock(u64 *loc) {
    compiler_barrier();
    *(volatile u64 *)loc = 0;
}

static inline u64 spin_lock_irq(u64 *loc)
{
    u64 flags = read_flags();
    disable_interrupts();
    spin_lock(loc);
    return flags;
}

static inline void spin_unlock_irq(u64 *loc, u64 flags)
{
    spin_unlock(loc);
    irq_restore(flags);
}

static inline void spin_lock_init(u64 *loc)
{
    *loc = 0;
}
