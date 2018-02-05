typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef long long s64;
typedef u8 boolean;

#define true (1)
#define false (0)

typedef u64 bytes;

typedef char *string;

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

#define MASK(x) ((1<<x)-1)


#ifndef pointer_from_u64
#define pointer_from_u64(__a) ((void *)(__a))
#endif
#ifndef u64_from_pointer
#define u64_from_pointer(__a) ((u64)(__a))
#endif


#include <heap/heap.h>

// inline bsf
#define log2(__x) ( __x)

typedef void *status;
status allocate_status(char *format, ...);

extern heap general;
typedef unsigned long size_t;

typedef u64 physical;

physical vtop(void *x);

// fc is boot sig
#define cprintf(...)

#include <elf64.h>

#define PAGELOG 12
#define PAGESIZE (1<<PAGELOG)
#ifndef physical_from_virtual
physical physical_from_virtual(void *x);
#endif    
void map(u64 virtual, physical p, int length, heap h);

#define PHYSICAL_INVALID ((u64)0xffffffffffffffff)

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

#define varg __builtin_va_arg
#define vlist __builtin_va_list
#define vstart __builtin_va_start
#define vend __builtin_va_end

typedef struct buffer *buffer;
#include <buffer.h>
#include <table.h>
#include <vector.h>
    
void debug(buffer);

extern void vbprintf(buffer s, buffer fmt, vlist ap);
static inline void rprintf(char *format, ...)
{
    // fix alloca buffer support
    char t[1024];
    vlist a;
    struct buffer b;
    b.start = 0;
    b.end = 0;    
    b.contents = t;
    b.length = sizeof(t);
    
    struct buffer f;
    f.start = 0;
    f.contents = format;
    f.end = runtime_strlen(format);
    
    vstart(a, format);
    vbprintf(&b, &f, a);
    debug(&b);
}

#define INVALID_ADDRESS ((void *)0xffffffffffffffffull)

void *load_elf(void *base, u64 offset, heap pages, heap bss);
#include <storage.h>
#include <closure.h>
#include <closure_templates.h>
