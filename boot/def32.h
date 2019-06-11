typedef unsigned char u8;
typedef char s8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef long long s64;
typedef u32 bytes;

// not sure if we keep word, sizeof(word) == sizeof(void **), so I guess its uintptr_t
typedef u32 word;

#define pointer_from_u64(__a) ((void *)(u32)(__a))
#define u64_from_pointer(__a) ((u64)(u32)(__a))
#define physical_from_virtual(__x) u64_from_pointer(__x)

// a super sad hack to allow us to write to the bss in elf.c as
// phy instead of virt
#define vpzero(__v, __p, __s) zero(pointer_from_u64(__p), __s)

static inline void *tag(void *v, u16 tval)
{
    *((u8 *)v-1) = tval;
    return v;
}

static inline u16 tagof(void *v)
{
    return *((u8 *)v-1);
}

static inline void *valueof(void *v)
{
    return v;
}

#define DIV(__x, __by, __q, __r)\
 {\
     register u32 a asm("eax");\
     register u32 b asm("ebx");\
     register u32 c asm("ecx");\
     register u32 d asm("edx");\
     a = __x>>32;\
     b = x;\
     c = __by;\
     d = 0;\
     asm("div %%ecx":"=r"(a), "=r"(d): "r"(a),"r"(d),"r"(c));\
     asm("xchg %%ebx, %%eax": "=r"(a),"=r"(b): "r"(a),"r"(b));\
     asm("div %%ecx":"=r"(a), "=r"(d): "r"(a),"r"(d),"r"(c)); \
     __q = a|(((u64)b)<<32);                                  \
     __r = d;\
 }

/* 64bit rol */
#define ROL(__x, __b) __rolq(__x, __b)

static inline u64 __rolq(u64 x, int b)
{
    b &= 63;
    return (x << b) | (x >> (-b & 63));
}

/* returns -1 if x == 0, caller must check */
static inline u64 msb(u64 x)
{
    /* gcc docs state __builtin_clz for 0 val is undefined, so check */
    unsigned int high = x >> 32;
    if (high) {
	return 63 - __builtin_clz(high);
    } else {
	unsigned int low = x & 0xffffffff;
	return low ? 31 - __builtin_clz(low) : -1ull;
    }
}

static inline void print_stack_from_here()
{
    // empty for now
}
