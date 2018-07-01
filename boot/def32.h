#include <predef.h>

#define BITS32
typedef unsigned char u8;
typedef char s8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef long long s64;

#define pointer_from_u64(__a) ((void *)(u32)(__a))
#define u64_from_pointer(__a) ((u64)(u32)(__a))
#define physical_from_virtual(__x) u64_from_pointer(__x)

// a super sad hack to allow us to write to the bss in elf.c as
// phy instead of virt
#define vpzero(__v, __p, __s) zero(pointer_from_u64(__p), __s)

static inline void *tag(void *v, u16 tval)
{
    return pointer_from_u64(tval|u64_from_pointer(v));
}

static inline u16 tagof(void *v)
{
    return u64_from_pointer(v)&3;
}

static inline void *valueof(void *v)
{
    return pointer_from_u64(u64_from_pointer(v)&0xfffffffc);
}

#define DIV(__x, __by, __q, __r)\
 {\
     register int a asm("eax");\
     register int d asm("edx");\
     register int c asm("ecx");\
     a = __x;\
     c = __by;\
     d = 0;\
     asm("div %ecx");\
     __q = a;\
     __r = d;\
 }

void print_number(buffer s, u64 x, int base, int pad);
static inline void format_pointer(buffer dest, buffer fmt, vlist a)
{
    u64 x = varg(a, u64);
    print_number(dest, x, 10, 8);
}
