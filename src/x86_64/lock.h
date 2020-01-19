static inline boolean spin_try(u64 *loc) {
    u64 tmp;
    // no pause!?
    __asm__ ("lock xchg %0, %1":"=m"(*loc),"=r"(tmp));
    return tmp == 0 ? true:false;
}

static inline void spin_lock(u64 *loc) {
    u64 tmp = 1;
    // no pause!?
    __asm__ ("__spin:lock xchg %0, %1; test %1, 1; jne __spin":"=m"(*loc),"=r"(tmp));
}

static inline void spin_unlock(u64 *loc) {
    *loc = 0;
}
