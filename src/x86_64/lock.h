static inline void spin_lock(u64 *loc) {
    u64 tmp;
    // no pause!?
    __asm__ ("spin:lock xchg %0, %1; test %1, 1; jne spin":"=m"(*loc),"=r"(tmp));
}

static inline void spin_unlock(u64 *loc) {
    *loc = 0;
}
