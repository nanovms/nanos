typedef unsigned char u8;
typedef signed char s8;
typedef unsigned short u16;
typedef signed short s16;
typedef unsigned int u32;
typedef signed int s32;
typedef unsigned long long u64;
typedef signed long long s64;
typedef __uint128_t u128;

typedef u64 word;
typedef u64 bytes;

#define U16_MAX 0xFFFF
#define S16_MAX ((s16)(U16_MAX >> 1))
#define S16_MIN (-S16_MAX - 1)

#define U32_MAX (~0u)
#define S32_MAX ((s32)(U32_MAX >> 1))
#define S32_MIN (-S32_MAX - 1)

#define U64_MAX (~0ull)
#define S64_MAX ((s64)(U64_MAX >> 1))
#define S64_MIN (-S64_MAX - 1)

#define USER_VA_TAG_OFFSET 56
#define USER_VA_TAG_WIDTH  8

/* XXX move to generic */
#define pointer_from_u64(__a) ((void *)(__a))
#define u64_from_pointer(__a) ((u64)(__a))
#define field_from_u64(u, f) (((u) >> f ## _SHIFT) & MASK(f ## _BITS))
#define clear_field(u, f) ((u) & ~(MASK(f ## _BITS) << f ## _SHIFT))
#define u64_from_field(f, v) (((v) & MASK(f ## _BITS)) << f ## _SHIFT)
#define mask_and_set_field(u, f, v) (clear_field(u, f) | u64_from_field(f, v))

#define DIV(__x, __by, __q, __r) \
    do { asm("divu %0, %2, %3; remu %1, %2, %3" :           \
             "=&r"(__q), "=r"(__r) : "r"(__x), "r"(__by)); } while(0)

/* These are defined as functions to avoid multiple evaluation of x. */
static inline __attribute__((always_inline)) u16
__bswap16(u16 _x)
{
    return (u16)(_x << 8 | _x >> 8);
}

static inline __attribute__((always_inline)) u32
__bswap32(u32 _x)
{
    return ((u32)__bswap16(_x & 0xffff) << 16) | __bswap16(_x >> 16);
}

static inline __attribute__((always_inline)) u64
__bswap64(u64 _x)
{
    return ((u64)__bswap32(_x & 0xffffffff) << 32) | __bswap32(_x >> 32);
}

#ifndef htobe16
#define htobe16(x) __bswap16(x)
#endif
#ifndef be16toh
#define be16toh(x) __bswap16(x)
#endif
#ifndef htole16
#define htole16(x) (x)
#endif
#ifndef le16toh
#define le16toh(x) (x)
#endif

#ifndef htobe32
#define htobe32(x) __bswap32(x)
#endif
#ifndef be32toh
#define be32toh(x) __bswap32(x)
#endif
#ifndef htole32
#define htole32(x) (x)
#endif
#ifndef le32toh
#define le32toh(x) (x)
#endif

#ifndef htobe64
#define htobe64(x) __bswap64(x)
#endif
#ifndef be64toh
#define be64toh(x) __bswap64(x)
#endif
#ifndef htole64
#define htole64(x) (x)
#endif
#ifndef le64toh
#define le64toh(x) (x)
#endif

typedef void *value;
typedef u8 value_tag;

#ifdef KERNEL
#define KMEM_BASE        0xffff800000000000ull
#define USER_LIMIT       0x0000800000000000ull  /* 4-level page tables -> 48-bit addresses */
#define VA_TAG_BASE      KMEM_BASE
#define VA_TAG_OFFSET    38
#define VA_TAG_WIDTH     8

static inline __attribute__((always_inline)) value tag(void *v, value_tag t) {
    return pointer_from_u64(VA_TAG_BASE | (((u64)t) << VA_TAG_OFFSET) |
                            u64_from_pointer(v));
}

static inline __attribute__((always_inline)) value_tag tagof(value v) {
    return (u64_from_pointer(v) >> VA_TAG_OFFSET) & ((1ull << VA_TAG_WIDTH) - 1);
}

#else

static inline void *tag(void *v, u8 tval)
{
    *((u8 *)v-1) = tval;
    return v;
}

static inline u8 tagof(void *v)
{
    return *((u8 *)v-1);
}

#endif

/* returns -1 if x == 0, caller must check */
static inline __attribute__((always_inline)) u64 msb(u64 x)
{
    /* XXX risc-v currently lacks bit manip extension */
    if (x == 0)
        return -1ull;
    for (int i = 63; i >= 0; i--)
        if ((x>>i) & 1)
            return i;
    return -1ull;
}

static inline __attribute__((always_inline)) u64 lsb(u64 x)
{
    /* XXX risc-v currently lacks bit manip extension */
    if (x == 0)
        return -1ull;
    for (int i = 0; i < 64; i++)
        if ((x>>i) & 1)
            return i;
    return -1ull;
}

static inline __attribute__((always_inline)) void compiler_barrier(void)
{
    asm volatile("" ::: "memory");
}

static inline __attribute__((always_inline)) void write_barrier(void)
{
    asm volatile("fence w,w" ::: "memory");
}

static inline __attribute__((always_inline)) void read_barrier(void)
{
    asm volatile("fence r,r" ::: "memory");
}

static inline __attribute__((always_inline)) void memory_barrier(void)
{
    asm volatile("fence.tso" ::: "memory");
}

static inline __attribute__((always_inline)) u8 atomic_test_and_set_bit(u64 *target, u64 bit)
{
    /* XXX no bit manip operations yet */
    u64 mask = 1ull << bit;
    u64 w = *target;
    *target = w | mask;
    return (w & mask) != 0;
}

static inline __attribute__((always_inline)) u8 atomic_test_and_clear_bit(u64 *target, u64 bit)
{
    /* XXX no bit manip operations yet */
    u64 mask = 1ull << bit;
    u64 w = *target;
    *target = w & ~mask;
    return (w & mask) != 0;
}

static inline __attribute__((always_inline)) void atomic_set_bit(u64 *target, u64 bit)
{
    atomic_test_and_set_bit(target, bit);
}

static inline __attribute__((always_inline)) void atomic_clear_bit(u64 *target, u64 bit)
{
    atomic_test_and_clear_bit(target, bit);
}

static inline __attribute__((always_inline)) word fetch_and_add(word *target, word num)
{
    return __sync_fetch_and_add(target, num);
}

#define mk_atomic_swap(bits) \
    static inline __attribute__((always_inline)) u ## bits atomic_swap_ ## bits(u ## bits *variable, u ## bits value) \
    { return __atomic_exchange_n(variable, value, __ATOMIC_SEQ_CST); }

mk_atomic_swap(32)
mk_atomic_swap(64)

#define mk_fake_atomic_swap(bits) \
    static inline __attribute__((always_inline)) u ## bits atomic_swap_ ## bits(u ## bits *variable, u ## bits value) \
    { u ## bits v = *variable; *variable = value; return v; }

/* non-atomic stand-ins */
mk_fake_atomic_swap(8)
mk_fake_atomic_swap(16)

static inline __attribute__((always_inline)) u8 compare_and_swap_64(u64 *p, u64 old, u64 new)
{
    return __atomic_compare_exchange_8(p, &old, new, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
}

static inline __attribute__((always_inline)) u8 compare_and_swap_32(u32 *p, u32 old, u32 new)
{
    return __atomic_compare_exchange_4(p, &old, new, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
}

static inline __attribute__((always_inline)) u8 compare_and_swap_8(u8 *p, u8 old, u8 new)
{
    /* XXX no byte size swap builtin */
    if (*p != old)
        return 0;
    *p = new;
    return 1;
}

static inline __attribute__((always_inline)) void kern_pause(void)
{
    //asm volatile("pause" ::: "memory"); // XXX need Zihintpause extension support
}

/* XXX used in vdso, but is rdcycle right for that? */
/* XXX make names generic */
#if defined(KERNEL) || defined(BUILD_VDSO)
static inline __attribute__((always_inline)) u64 rdtsc(void)
{
    // XXX vdso
    u64 vct;
    asm volatile("rdcycle %0" : "=r"(vct));
    return vct;
}

// XXX adhere to ordering semantics
static inline __attribute__((always_inline)) u64 rdtsc_ordered(void)
{
    // XXX vdso
    u64 vct;
    asm volatile("rdcycle %0" : "=r"(vct));
    return vct;
}

static inline __attribute__((always_inline)) u64 rdtsc_precise(void)
{
    // XXX vdso
    u64 vct;
    asm volatile("rdcycle %0" : "=r"(vct));
    return vct;
}
#endif

