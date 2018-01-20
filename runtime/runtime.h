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


// worst possible
static inline void runtime_memcpy(void *a, void *b, bytes len)
{
    for (int i = 0; i < len; i++) ((u8 *)a)[i] = ((u8 *)b)[i];
}

static inline int runtime_strlen(char *a)
{
    int i = 0;
    for (char *z = a; *a; a, i++);
    return i;
}


/*
 * WARNING: these inserts seem to be very fragile wrt actually
 *          referring to the correct value by the right register
 */
#define mov_to_cr(__x, __y) __asm__("mov %0,%%"__x: :"r"(__y):);
#define mov_from_cr(__x, __y) __asm__("mov %%"__x", %0":"=r"(__y):);

#define pad(__x, __s) ((((__x) - 1) & (~((__s) - 1))) + (__s))

#define MASK(x) ((1<<x)-1)


#include <io.h>
#include <heap/heap.h>

extern heap general;
extern heap contiguous;

// inline bsf
#define log2(__x) ( __x)

typedef void *status;
status allocate_status(char *format, ...);

extern heap general;
typedef unsigned long size_t;
extern void *memset(void *a, int val, unsigned long length);

typedef u64 physical;

physical vtop(void *x);

static inline void enable_interrupts()
{
    asm ("sti");
}

static inline void disable_interrupts()
{
    asm ("cli");
}

// defined in stage1...pass this through entry stack
#define ABSOLUTION ((u32 *)0x7de8)
#define MEMORY_MAX  ((u32 *)0x7df2) 
#define START_ADDRESS  ((u32 *)0x7df6)

// fc is boot sig
#define cprintf(...)
#define apply(__h, ...) ((__h->f)(__h->a))


typedef struct handler {
    void (*f)(void *);
    void *a;
} *handler;
    
static inline handler allocate_handler(heap h, void (*f)(void *), void *a)
{
    handler r = allocate(h, sizeof(struct handler));
    r->f = f;
    r->a = a;
    return(r);
}

void register_interrupt(int vector, handler h);
void msi_map_vector(int slot, int vector);
u8 allocate_msi(handler h);

extern void *pagebase;
extern u64 *ptalloc();

#include <disk.h>
#include <elf64.h>

#ifndef pointer_from_u64
#define pointer_from_u64(__a) ((void *)(__a))
#endif
#ifndef u64_from_pointer
#define u64_from_pointer(__a) ((u64)(__a))
#endif

#include <region.h>

#define PAGELOG 12
#define PAGESIZE (1<<PAGELOG)
#ifndef physical_from_virtual
physical physical_from_virtual(void *x);
#endif    
void map(u64 virtual, physical p, int length, heap h);

#define LSTAR 0xC0000082

#define FRAME_RAX 0
#define FRAME_SYSCALL 0
#define FRAME_RBX 1
#define FRAME_RCX 2
#define FRAME_RDX 3
#define FRAME_RBP 4
#define FRAME_RSP 5
#define FRAME_RSI 6
#define FRAME_RDI 7
#define FRAME_R8 8
#define FRAME_R9 9 
#define FRAME_R10 10
#define FRAME_R11 11
#define FRAME_R12 12
#define FRAME_R13 13
#define FRAME_R14 14
#define FRAME_R15 15
#define FRAME_VECTOR 16
#define FRAME_RIP 17
#define FRAME_FLAGS 18

#define PHYSICAL_INVALID ((u64)0xffffffffffffffff)

//#define runtime_memcpy __builtin_memcpy
//#define runtime_memset __builtin_memset

static inline void runtime_memset(void *x, u8 val, bytes length)
{
    for (int i =0; i < length; i++) *(u8 *)(x + i) = val;  
}

typedef struct buffer *buffer;
#include <buffer.h>
#include <table.h>
#include <vector.h>


buffer create_index(heap h, int buckets);
void index_set(buffer index, buffer key, buffer value);
