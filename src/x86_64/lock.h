/* struct spinlock defined in machine.h */

#if defined(KERNEL) && defined(SMP_ENABLE)

#ifdef LOCK_STATS
#include <lockstats.h>
#endif

static inline boolean spin_try(spinlock l) {
    u64 tmp = 1;
    /* Is it worth the compare and branch to skip a pause? */
    asm volatile("lock xchg %0, %1; cmp $1, %1; jne 1f; pause; 1:" : "+m"(*&l->w), "+r"(tmp) :: "memory");

#ifdef LOCK_STATS
    LOCKSTATS_RECORD_LOCK(l->s, tmp == 0, 0, 0);
#endif
    return tmp == 0 ? true:false;
}

static inline void spin_lock(spinlock l) {
    u64 tmp = 1;
#ifdef LOCK_STATS
    u64 spins = 0;
    asm volatile("1: cmp %0, %1; jne 2f; pause; inc %2; jmp 1b; 2: lock xchg %0, %1; cmp $1, %1; je 1b" :
                 "+m"(*&l->w), "+r"(tmp), "+r"(spins) :: "memory");
    LOCKSTATS_RECORD_LOCK(l->s, true, spins, 0);
#else
    asm volatile("1: cmp %0, %1; jne 2f; pause; jmp 1b; 2: lock xchg %0, %1; cmp $1, %1; je 1b" :
                 "+m"(*&l->w), "+r"(tmp) :: "memory");
#endif
}

static inline void spin_unlock(spinlock l) {
#ifdef LOCK_STATS
    LOCKSTATS_RECORD_UNLOCK(l->s);
#endif
    compiler_barrier();
    *(volatile u64 *)&l->w = 0;
}

static inline void spin_rlock(rw_spinlock l) {
    while (1) {
        if (l->l.w) {
            kern_pause();
            continue;
        }
        fetch_and_add(&l->readers, 1);
        if (!l->l.w)
            return;
        fetch_and_add(&l->readers, -1);
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
u64 get_program_counter(void);

/* TODO undo this if/when we add klib relocations */
#ifdef KLIB
#define lock_assert(x) ((void)(x))
#else
#define lock_assert(x) assert(x)
#endif

static inline boolean spin_try(spinlock l)
{
    if (l->w)
        return false;
#ifndef KLIB
    l->w = get_program_counter();
#else
    l->w = 1;
#endif
    return true;
}

static inline void spin_lock(spinlock l)
{
#ifndef KLIB
    if (l->w != 0) {
        print_frame_trace_from_here();
        halt("spin_lock: lock %p already locked by 0x%lx\n", l, l->w);
    }
    l->w = get_program_counter();
#else
    l->w = 1;
#endif
}

static inline void spin_unlock(spinlock l)
{
    lock_assert(l->w != 1);
    l->w = 0;
}

static inline void spin_rlock(rw_spinlock l) {
    lock_assert(l->l.w == 0);
    lock_assert(l->readers == 0);
    l->readers++;
}

static inline void spin_runlock(rw_spinlock l) {
    lock_assert(l->readers == 1);
    lock_assert(l->l.w == 0);
    l->readers--;
}

static inline void spin_wlock(rw_spinlock l) {
    lock_assert(l->readers == 0);
    spin_lock(&l->l);
}

static inline void spin_wunlock(rw_spinlock l) {
    lock_assert(l->readers == 0);
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
#ifdef LOCK_STATS
    l->s.type = LOCK_TYPE_SPIN;
    l->s.acq_time = 0;
    l->s.trace_hash = 0;
#endif
}

static inline void spin_rw_lock_init(rw_spinlock l)
{
    spin_lock_init(&l->l);
    l->readers = 0;
}
