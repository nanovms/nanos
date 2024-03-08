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

/* returns -1 if x == 0, caller must check */
static inline u64 msb(u64 x)
{
    return x ? 63 - __builtin_clzll(x) : -1ull;
}

static inline u64 lsb(u64 x)
{
    return ((s64)__builtin_ffsll(x)) - 1;
}
