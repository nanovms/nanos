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

static inline physical vtophys(void *v)
{
    return (unsigned long)v;
}

static inline void enable_interrupts()
{
    asm ("sti");
}

static inline void disable_interrupts()
{
    asm ("cli");
}

// defined in stage1...pass this through entry stack
#define MEMORY_MAX  ((u32 *)0x7df2) 
#define START_ADDRESS  ((u32 *)0x7df6)
// not really used
#define IDT_ADDRESS  ((u32 *)0x7dfa)

// fc is boot sig
#define cprintf(...)
#define apply(__h, ...) ((__h->f)(__h->a))

#include <page.h>

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
