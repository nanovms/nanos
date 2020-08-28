typedef struct spinlock {
    word w;
} *spinlock;

#define spin_try(x) (true)
#define spin_lock(x) ((void)x)
#define spin_unlock(x) ((void)x)

static inline u64 spin_lock_irq(spinlock l)
{
    u64 flags = irq_disable_save();
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
