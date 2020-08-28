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
    do { asm("udiv %0, %2, %3; msub %1, %0, %3, %2" :           \
             "=&r"(__q), "=r"(__r) : "r"(__x), "r"(__by)); } while(0)

#if 0
#define ROL(__x, __b)\
     ({\
        __asm__("rolq %1, %0": "=g"(__x): "i" (__b));\
        __x;\
     })
#endif
  
/* These are defined as functions to avoid multiple evaluation of x. */
static inline u16
__bswap16(u16 _x)
{
    return (u16)(_x << 8 | _x >> 8);
}

static inline u32
__bswap32(u32 _x)
{
    return ((u32)__bswap16(_x & 0xffff) << 16) | __bswap16(_x >> 16);
}

static inline u64
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

#define USER_LIMIT  0x0008000000000000ull
#define KMEM_BASE   0xffff000000000000ull
#define KMEM_LIMIT  0xffffffff00000000ull

#ifdef KERNEL
#define VA_TAG_BASE   KMEM_BASE
#define VA_TAG_OFFSET 56
#define VA_TAG_WIDTH  8
#else
#define VA_TAG_BASE   0
#define VA_TAG_OFFSET USER_VA_TAG_OFFSET
#define VA_TAG_WIDTH  USER_VA_TAG_WIDTH
#endif

static inline void *tag(void* v, u64 tval) {
    return pointer_from_u64(VA_TAG_BASE | (tval << VA_TAG_OFFSET) | u64_from_pointer(v));
}

static inline u16 tagof(void* v) {
    return (u64_from_pointer(v) >> VA_TAG_OFFSET) & ((1ull << VA_TAG_WIDTH) - 1);
}

#define valueof(__x) (__x)
/* returns -1 if x == 0, caller must check */
static inline u64 msb(u64 x)
{
    return x ? 63 - __builtin_clzll(x) : -1ull;
}

static inline u64 lsb(u64 x)
{
    return ((s64)__builtin_ffsll(x)) - 1;
}


static inline void compiler_barrier(void)
{
}

static inline void write_barrier(void)
{
}

static inline void read_barrier(void)
{
}

static inline void memory_barrier(void)
{
}

static inline void atomic_set_bit(u64 *target, u64 bit)
{
//    asm volatile("lock btsq %1, %0": "+m"(*target): "r"(bit) : "memory");
}

static inline void atomic_clear_bit(u64 *target, u64 bit)
{
//    asm volatile("lock btrq %1, %0": "+m"(*target):"r"(bit) : "memory");
}

static inline word fetch_and_add(word *target, word num)
{
    return __sync_fetch_and_add(target, num);
}

static inline u64 fetch_and_add_64(u64 *target, u64 num)
{
    return __sync_fetch_and_add(target, num);
}

static inline void kern_pause(void)
{
  // XXX
}
