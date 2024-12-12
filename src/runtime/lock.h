#ifdef LOCK_STATS
#include <lockstats_struct.h>
#endif

typedef struct spinlock {
    word w;
#ifdef LOCK_STATS
    struct lockstats_lock s;
#endif
} *spinlock;

typedef struct rw_spinlock {
    struct spinlock l;
    word readers;
} *rw_spinlock;

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

#if defined(KERNEL) && defined(SMP_ENABLE)
static inline boolean spin_try(spinlock l)
{
    boolean success = compare_and_swap_64(&l->w, 0, 1);
#ifdef LOCK_STATS
    LOCKSTATS_RECORD_LOCK(l->s, success, 0, 0);
#endif
    return success;
}

static inline void spin_lock(spinlock l)
{
    volatile u64 *p = (volatile u64 *)&l->w;
#ifdef LOCK_STATS
    u64 spins = 0;
    while (*p || !compare_and_swap_64(&l->w, 0, 1)) {
        spins++;
        kern_pause();
    }
    LOCKSTATS_RECORD_LOCK(l->s, true, spins, 0);
#else
    while (*p || !compare_and_swap_64(&l->w, 0, 1))
        kern_pause();
#endif
}

static inline void spin_unlock(spinlock l)
{
#ifdef LOCK_STATS
    LOCKSTATS_RECORD_UNLOCK(l->s);
#endif
    compiler_barrier();
    *(volatile u64 *)&l->w = 0;
}

static inline boolean spin_tryrlock(rw_spinlock l)
{
    if (*(volatile word *)&l->l.w)
        return false;
    fetch_and_add(&l->readers, 1);
    if (!*(volatile word *)&l->l.w)
        return true;
    fetch_and_add(&l->readers, -1);
    return false;
}

static inline void spin_rlock(rw_spinlock l)
{
    while (1) {
        if (*(volatile word *)&l->l.w) {
            kern_pause();
            continue;
        }
        fetch_and_add(&l->readers, 1);
        if (!*(volatile word *)&l->l.w)
            return;
        fetch_and_add(&l->readers, -1);
    }
}

static inline void spin_runlock(rw_spinlock l)
{
    fetch_and_add(&l->readers, -1);
}

static inline boolean spin_trywlock(rw_spinlock l)
{
    if (*(volatile word *)&l->readers || !spin_try(&l->l))
        return false;
    if (!*(volatile word *)&l->readers)
        return true;
    spin_unlock(&l->l);
    return false;
}

static inline void spin_wlock(rw_spinlock l)
{
    spin_lock(&l->l);
    while (*(volatile word *)&l->readers)
        kern_pause();
}

static inline void spin_wunlock(rw_spinlock l)
{
    spin_unlock(&l->l);
}
#else
#ifdef SPIN_LOCK_DEBUG_NOSMP
u64 get_program_counter(void);

static inline boolean spin_try(spinlock l)
{
    if (l->w)
        return false;
    l->w = get_program_counter();
    return true;
}

static inline void spin_lock(spinlock l)
{
    if (l->w != 0) {
        print_frame_trace_from_here();
        halt("spin_lock: lock %p already locked by 0x%lx\n", l, l->w);
    }
    l->w = get_program_counter();
}

static inline void spin_unlock(spinlock l)
{
    assert(l->w != 1);
    l->w = 0;
}

static inline boolean spin_tryrlock(rw_spinlock l)
{
    if (l->l.w)
        return false;
    l->readers++;
    return true;
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

static inline boolean spin_trywlock(rw_spinlock l)
{
    if (l->readers || l->l.w)
        return false;
    assert(spin_try(&l->l));
    return true;
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
#define spin_trywlock(x) (true)
#define spin_wlock(x) ((void)x)
#define spin_wunlock(x) ((void)x)
#define spin_tryrlock(x) (true)
#define spin_rlock(x) ((void)x)
#define spin_runlock(x) ((void)x)
#endif
#endif
