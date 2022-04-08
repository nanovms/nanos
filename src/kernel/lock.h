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
