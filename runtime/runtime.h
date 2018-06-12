
typedef u8 boolean;
typedef u32 character;

#define true (1)
#define false (0)

typedef u64 bytes;

typedef u64 time;

extern void console(char *x);

extern void serial_out(char c);

void print_u64(u64 s);

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

#ifndef MIN
#define MIN(x, y) ((x) < (y)? (x):(y))
#endif
#ifndef MAX
#define MAX(x, y) ((x) > (y)? (x):(y))
#endif

typedef struct buffer *buffer;
#if 0
// this...seems to have a fault (?).. it may be the interrupt
// machinery
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
#endif
static inline void zero(void *x, bytes length)
{
    for (int i = 0; i < length; i++)
        ((u8 *)x)[i] = 0;
}

#include <heap/heap.h>
#include <buffer.h>

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

heap wrap_freelist(heap meta, heap parent, bytes size);
typedef unsigned long size_t;
typedef u64 physical;

physical vtop(void *x);

#define cprintf(...)

// used by stage2/stage3, not process
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

void sha256(buffer dest, buffer source);

#define varg __builtin_va_arg
#define vlist __builtin_va_list
#define vstart __builtin_va_start
#define vend __builtin_va_end

#define alloca __builtin_alloca

typedef struct buffer *buffer;
typedef struct buffer *string;

void format_number(buffer s, u64 x, int base, int pad);

#include <table.h>
#include <text.h>
#include <vector.h>

typedef buffer string;

buffer aprintf(heap h, char *fmt, ...);
void debug(buffer);
void format_number(buffer s, u64 x, int base, int pad);
extern void vbprintf(buffer s, buffer fmt, vlist ap);
void bprintf(buffer b, char *fmt, ...);

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

static inline boolean compare_bytes(void *a, void *b, bytes len)
{
    for (int i = 0; i < len ; i++) {
        if (((u8 *)a)[i] != ((u8 *)b)[i])
            return false;
    }
    return true;
}

// try not to go crazy here
#define tag_symbol (1ull)
#define tag_tuple (2ull)
#define tag_string (3ull)

#include <symbol.h>

typedef table node;
#include <storage.h>
typedef table tuple;
#include <closure.h>
#include <closure_templates.h>
typedef closure_type(buffer_handler, void, buffer);
typedef closure_type(thunk, void);
#include <pqueue.h>
#include <timer.h>


// break out platform - move into the implicit include
#include <x86_64.h>

// just take a buffer or a tuple?
extern void halt(char *format, ...);

// should be  (parser, parser, character)
typedef closure_type(parser, void *, character);
// textual? semantic
typedef closure_type(parse_error, void, buffer);
typedef closure_type(parse_finish, void, void *);
parser tuple_parser(heap h, parse_finish c, parse_error err);
parser parser_feed (parser p, buffer b);
u64 random_u64();
void init_tuples(heap theap);
void print_tuple(buffer b, tuple t);

typedef struct signature {
    u64 s[4];
} *signature;
    
void *deserialize_tuple(heap h, tuple dictionary, buffer source);
void serialize_tuple(tuple dictionary, buffer dest, tuple t);
#include <rtrie.h>
