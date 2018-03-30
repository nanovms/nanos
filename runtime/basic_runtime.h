typedef unsigned char u8;
typedef char s8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef long long s64;
typedef u8 boolean;

#define true (1)
#define false (0)

typedef u64 bytes;

typedef u64 time;

extern void console(char *x);

extern void serial_out(char c);

void print_u64(u64 s);

typedef u8 character;

static inline void runtime_memcpy(void *a, void *b, bytes len)
{
    for (int i = 0; i < len; i++) ((u8 *)a)[i] = ((u8 *)b)[i];
}

static inline int runtime_strlen(char *a)
{
    int i = 0;
    for (char *z = a; *a; a++, i++);
    return i;
}

#define pad(__x, __s) ((((__x) - 1) & (~((__s) - 1))) + (__s))

#define MASK(x) ((1ull<<x)-1)

#ifndef pointer_from_u64
#define pointer_from_u64(__a) ((void *)(__a))
#endif
#ifndef u64_from_pointer
#define u64_from_pointer(__a) ((u64)(__a))
#endif

typedef struct buffer *buffer;

static inline void zero(void *x, bytes length)
{
    u64 *start = pointer_from_u64(pad(u64_from_pointer(x), 8));
    u64 first = u64_from_pointer((void *)start - x);
    if (first > length) first = length;
    u64 aligned = (length - first) >>3;
    u8 *end = (u8 *)(start + first+aligned);
    u64 final = length - aligned*8 - first;

    for (int i =0; i < first; i++) *(u8 *)(x + i) = 0;
    // rep, movent
    for (int i =0; i < aligned; i++) start[i] = 0;
    for (int i =0; i < final; i++) end[i] = 0;        
}
#if 0
static inline void zero(void *x, bytes length)
{
#ifdef STAGE2
    console ("zero: ");
    print_u64(u64_from_pointer(x));
    console (" ");
    print_u64(length);
    console ("\n");
#endif    
    for (int i = 0; i < length; i++)
        ((u8 *)x)[i] = 0;
}
#endif

#include <heap/heap.h>
#include <buffer.h>

// inline bsf
#define log2(__x) ( __x)

typedef void *status;

#define STATUS_OK ((void *)0)

static inline status status_nomem() {return (void *)1;}

static inline boolean is_ok(status s)
{
    return s == ((void *)0);
}

static inline status allocate_status(char *format, ...)
{
}

extern heap general;
typedef unsigned long size_t;

typedef u64 physical;

physical vtop(void *x);

#define cprintf(...)

// belongs in the kernel
#define PAGELOG 12
#define PAGESIZE (1<<PAGELOG)
#ifndef physical_from_virtual
physical physical_from_virtual(void *x);
#endif    
void map(u64 virtual, physical p, int length, heap h);

#define INVALID_PHYSICAL ((u64)0xffffffffffffffff)


#define varg __builtin_va_arg
#define vlist __builtin_va_list
#define vstart __builtin_va_start
#define vend __builtin_va_end
    

#define INVALID_ADDRESS ((void *)0xffffffffffffffffull)

heap zero_wrap(heap meta, heap parent);

boolean validate_virtual(void *base, u64 length);

#ifndef vpzero
// a super sad hack to allow us to write to the bss in elf.c as
// phy instead of virt
#define vpzero(__p, __v, __y) zero(pointer_from_u64(__v), __y)
#endif
