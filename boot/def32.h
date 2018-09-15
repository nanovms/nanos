#define BITS32
typedef unsigned char u8;
typedef char s8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef long long s64;

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
    return *(u8 *)v-1;
}

static inline void *valueof(void *v)
{
    return v;
}

#define DIV(__x, __by, __q, __r)\
 {\
     volatile register unsigned int a asm("eax");\
     volatile register unsigned int b asm("ebx");\
     volatile register unsigned int c asm("ecx");\
     volatile register unsigned int d asm("edx");\
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

void print_number(buffer s, u64 x, int base, int pad);
static inline void format_pointer(buffer dest, buffer fmt, vlist *a)
{
    u64 x = varg(*a, u32);
    print_number(dest, x, 16, 8);
}

static void format_number(buffer dest, buffer fmt, vlist *a)
{
    // ehh - move to def
    u64 x = varg(*a, u32);
    print_number(dest, x, 10, 1);
}

