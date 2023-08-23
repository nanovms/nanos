typedef unsigned char u8;
typedef char s8;
typedef unsigned short u16;
typedef short s16;
typedef unsigned int u32;
typedef int s32;
typedef unsigned long long u64;
typedef long long s64;
typedef __uint128_t u128;

typedef u64 word;
typedef s64 sword;
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

#define IMM_UINT_MAX (1ull << (64 - 2 /* encoding */ - 1 /* no sign */))
#define IMM_UINT_MIN (0)
#define IMM_SINT_MAX ((s64)IMM_UINT_MAX)
#define IMM_SINT_MIN (((s64)(1ull << 63)) >> 2) /* sign extend */

typedef void *value;
typedef u8 value_tag;

#define pointer_from_u64(__a) ((void *)(__a))
#define u64_from_pointer(__a) ((u64)(__a))

#define field_from_u64(u, f) (((u) >> f ## _SHIFT) & MASK(f ## _BITS))

#define DIV(__x, __by, __q, __r){		\
     register u64 a asm("rax");\
     register u64 d asm("rdx");\
     register u64 c asm("rcx");\
     a = __x;\
     c = __by;\
     d = 0;\
     asm("divq %%rcx":"=r"(a), "=r"(d): "r"(a),"r"(d),"r"(c));\
     __q = a;\
     __r = d;\
 }

#define ROL(__x, __b)\
     ({\
        __asm__("rolq %1, %0": "=g"(__x): "i" (__b));\
        __x;\
     })

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

/* returns -1 if x == 0, caller must check */
static inline u64 msb(u64 x)
{
    return x ? 63 - __builtin_clzll(x) : -1ull;
}

static inline u64 lsb(u64 x)
{
    return ((s64)__builtin_ffsll(x)) - 1;
}
