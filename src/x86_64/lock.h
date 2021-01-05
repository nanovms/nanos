/* struct spinlock defined in machine.h */

#if defined(KERNEL) && defined(SMP_ENABLE)
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

static inline void spin_rlock(rw_spinlock l) {
    while (1) {
        fetch_and_add(&l->readers, 1);
        if (!l->l.w)
            return;
        fetch_and_add(&l->readers, -1);
        kern_pause();
    }
}

static inline void spin_runlock(rw_spinlock l) {
    fetch_and_add(&l->readers, -1);
}

static inline void spin_wlock(rw_spinlock l) {
    spin_lock(&l->l);
    while (l->readers)
        kern_pause();
}

static inline void spin_wunlock(rw_spinlock l) {
    spin_unlock(&l->l);
}

#else
#ifdef SPIN_LOCK_DEBUG_NOSMP
static inline boolean spin_try(spinlock l)
{
    if (l->w)
        return false;
    l->w = 1;
    return true;
}

static inline void spin_lock(spinlock l)
{
    assert(l->w == 0);
    l->w = 1;
}

static inline void spin_unlock(spinlock l)
{
    assert(l->w == 1);
    l->w = 0;
}

static inline void spin_rlock(rw_spinlock l) {
    assert(l->l.w == 0);
    assert(l->readers == 0);
    l->readers++;
}

static inline void spin_runlock(rw_spinlock l) {
    assert(l->readers == 1);
    assert(l->l.w == 0);
    l->readers--;
}

static inline void spin_wlock(rw_spinlock l) {
    assert(l->readers == 0);
    spin_lock(&l->l);
}

static inline void spin_wunlock(rw_spinlock l) {
    assert(l->readers == 0);
    spin_unlock(&l->l);
}
#else
#define spin_try(x) (true)
#define spin_lock(x) ((void)x)
#define spin_unlock(x) ((void)x)
#define spin_wlock(x) ((void)x)
#define spin_wunlock(x) ((void)x)
#define spin_rlock(x) ((void)x)
#define spin_runlock(x) ((void)x)
#endif
#endif

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

static inline u64 spin_wlock_irq(rw_spinlock l)
{
    u64 flags = read_flags();
    disable_interrupts();
    spin_wlock(l);
    return flags;
}

static inline void spin_wunlock_irq(rw_spinlock l, u64 flags)
{
    spin_wunlock(l);
    irq_restore(flags);
}

static inline u64 spin_rlock_irq(rw_spinlock l)
{
    u64 flags = read_flags();
    disable_interrupts();
    spin_rlock(l);
    return flags;
}

static inline void spin_runlock_irq(rw_spinlock l, u64 flags)
{
    spin_runlock(l);
    irq_restore(flags);
}

static inline void spin_lock_init(spinlock l)
{
    l->w = 0;
}

static inline void spin_rw_lock_init(rw_spinlock l)
{
    spin_lock_init(&l->l);
    l->readers = 0;
}
