#ifndef _ATOMIC_H_
#define _ATOMIC_H_

#define MPLOCKED        "lock ; "

/*
 * Atomically add the value of v to the integer pointed to by p and return
 * the previous value of *p.
 */
static __inline u32
atomic_fetchadd32(volatile u32 *p, u32 v)
{

    __asm __volatile(
    "   lock ;              "
    "   xaddl   %0,%1 ;     "
    "# atomic_fetchadd_int"
    : "+r" (v),         /* 0 */
      "+m" (*p)         /* 1 */
    : : "cc");
    return (v);
}

static __inline int
atomic_testandset32(volatile u32 *p, u32 v)
{
        u8 res;

#ifdef __GCC_ASM_FLAG_OUTPUTS__
        __asm __volatile(
        "       " MPLOCKED "            "
        "       btsl    %2,%1 ;         "
        "# atomic_testandset_int"
        : "=@ccc" (res),                /* 0 */
          "+m" (*p)                     /* 1 */
        : "Ir" (v & 0x1f)               /* 2 */
        : "cc");
#else
        __asm __volatile(
        "       " MPLOCKED "            "
        "       btsl    %2,%1 ;         "
        "       sbb     %0,%0 ;         "
        "# atomic_testandset_int"
        : "=r" (res),                   /* 0 */
          "+m" (*p)                     /* 1 */
        : "Ir" (v & 0x1f)               /* 2 */
        : "cc");
#endif
        return (res);
}

static __inline u64
atomic_swap64(volatile u64 *p, u64 v)
{

        __asm __volatile(
        "       xchgq   %1,%0 ;         "
        "# atomic_swap_long"
        : "+r" (v),                     /* 0 */
          "+m" (*p));                   /* 1 */
        return (v);
}

static __inline int
atomic_testandclear64(volatile u64 *p, u32 v)
{
    unsigned char res;

#ifdef __GCC_ASM_FLAG_OUTPUTS__
    __asm __volatile(
    "   " MPLOCKED "        "
    "   btrq    %2,%1 ;     "
    "# atomic_testandclear64"
    : "=@ccc" (res),        /* 0 */
      "+m" (*p)         /* 1 */
    : "Jr" ((u64)(v & 0x3f)) /* 2 */
    : "cc");
#else
    __asm __volatile(
    "   " MPLOCKED "        "
    "   btrq    %2,%1 ;     "
    "   sbb     %0,%0 ;     "
    "# atomic_testandclear64"
    : "=r" (res),        /* 0 */
      "+m" (*p)         /* 1 */
    : "Jr" ((u64)(v & 0x3f)) /* 2 */
    : "cc");
#endif
    return (res);
}

//atomic_set_*
#define ATOMIC_ASM(NAME, SIZE, OP, CONS, V)             \
static __inline void                                    \
atomic_##NAME##SIZE(volatile u##SIZE *p, u##SIZE v)\
{                                                       \
        __asm __volatile(MPLOCKED OP                    \
        : "+m" (*p)                                     \
        : CONS (V)                                      \
        : "cc");                                        \
}

ATOMIC_ASM(set,      64,  "orq %1,%0",   "er",  v);

ATOMIC_ASM(set,      32,   "orl %1,%0",   "ir",  v);
ATOMIC_ASM(clear,    32,   "andl %1,%0",  "ir", ~v);
ATOMIC_ASM(add,      32,   "addl %1,%0",  "ir",  v);
ATOMIC_ASM(subtract, 32,   "subl %1,%0",  "ir",  v);

/*
 * Atomic compare and set, used by the mutex functions.
 *
 * cmpset:
 *      if (*dst == expect)
 *              *dst = src
 *
 * fcmpset:
 *      if (*dst == *expect)
 *              *dst = src
 *      else
 *              *expect = *dst
 *
 * Returns 0 on failure, non-zero on success.
 */
#ifdef __GCC_ASM_FLAG_OUTPUTS__
#define ATOMIC_CMPSET(SIZE)                             \
static __inline int                                     \
atomic_cmpset##SIZE(volatile u##SIZE *dst, u##SIZE expect, u##SIZE src) \
{                                                       \
        u8 res;                                     \
                                                        \
        __asm __volatile(                               \
        "       " MPLOCKED "            "               \
        "       cmpxchg %3,%1 ; "                       \
        "# atomic_cmpset_" #SIZE "      "               \
        : "=@cce" (res),                /* 0 */         \
          "+m" (*dst),                  /* 1 */         \
          "+a" (expect)                 /* 2 */         \
        : "r" (src)                     /* 3 */         \
        : "memory", "cc");                              \
        return (res);                                   \
}
#else
#define ATOMIC_CMPSET(SIZE)                             \
static __inline int                                     \
atomic_cmpset##SIZE(volatile u##SIZE *dst, u##SIZE expect, u##SIZE src) \
{                                                       \
        int res;                                        \
        __asm __volatile(                               \
        "       " MPLOCKED "            "               \
        "       cmpxchg %3,%1 ; "                       \
        "       lahf ; "                                \
        "       andq $0x4000,%%rax ; "                  \
        "# atomic_cmpset_" #SIZE "      "               \
        : "=a" (res),                   /* 0 */         \
          "+m" (*dst),                  /* 1 */         \
          "+a" (expect)                 /* 2 */         \
        : "r" (src)                     /* 3 */         \
        : "memory", "cc");                              \
        return (res);                                   \
}
#endif

ATOMIC_CMPSET(32);

#endif //_ATOMIC_H_
