#pragma once
#include <uniboot.h>
typedef u8 boolean;
typedef u32 character;

#define true 1
#define false 0
#define infinity (-1ull)
#define INVALID_PHYSICAL ((u64)infinity)
#define INVALID_ADDRESS ((void *)infinity)

typedef u64 timestamp;

extern void console(char *x);
void print_u64(u64 s);

extern void halt(char *format, ...) __attribute__((noreturn));
extern void vm_exit(u8 code) __attribute__((noreturn));

// make into no-op for production
#ifdef NO_ASSERT
#define assert(x) do { if((x)) { } } while(0)
#else
#define assert(x) \
    do { if(!(x)) halt("assertion %s failed in " __FILE__ ": %s() on line %d; halt\n", \
		       #x, __func__, __LINE__); } while(0)
#endif

static inline void runtime_memcpy(void *a, const void *b, bytes len)
{
    for (int i = 0; i < len; i++) ((u8 *)a)[i] = ((u8 *)b)[i];
}

static inline void runtime_memset(u8 *a, u8 b, bytes len)
{
    for (int i = 0; i < len; i++) ((u8 *)a)[i] = b;
}

static inline int runtime_memcmp(const void *a, const void *b, bytes len)
{
    for (int i = 0; i < len; i++) {
        int res = ((signed char *) a)[i] - ((signed char *) b)[i];
        if (res != 0)
            return res;
    }
    return 0;
}

static inline int runtime_strlen(const char *a)
{
    int i = 0;
    const char *z;
    for (z = a; *a; a++, i++);
    return i;
}

#define pad(__x, __s) ((((__x) - 1) & (~((__s) - 1))) + (__s))

#define find_order(x) ((x) > 1 ? msb((x) - 1) + 1 : 0)

#define U64_FROM_BIT(x) (1ull<<(x))
#define MASK(x) (U64_FROM_BIT(x)-1)

#ifndef MIN
#define MIN(x, y) ((x) < (y)? (x):(y))
#endif
#ifndef MAX
#define MAX(x, y) ((x) > (y)? (x):(y))
#endif

#define offsetof(__t, __e) u64_from_pointer(&((__t)0)->__e)

#define check_flags_and_clear(x, f) ({boolean match = ((x) & (f)) != 0; (x) &= ~(f); match;})

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

typedef struct heap *heap;
#include <table.h>
#include <heap/heap.h>
#include <kernel_heaps.h>

// transient is supposed to be cleaned up when we can guarantee that
// its out of scope - so we argue its ok to make it global. however
// there isn't a very good definition of what the lifetime of it is.
// transient objects shouldnt be shared.
extern heap transient;

#include <buffer.h>

typedef u64 physical;

physical vtop(void *x);

// used by stage2/stage3, not process
#define PAGELOG 12
#define PAGESIZE U64_FROM_BIT(PAGELOG)
#define PAGELOG_2M 21
#define PAGESIZE_2M U64_FROM_BIT(PAGELOG_2M)
#ifndef physical_from_virtual
physical physical_from_virtual(void *x);
#endif

heap zero_wrap(heap meta, heap parent);

boolean validate_virtual(void *base, u64 length);

void sha256(buffer dest, buffer source);

#define stack_allocate __builtin_alloca

typedef struct buffer *buffer;

void print_number(buffer s, u64 x, int base, int pad);

#include <text.h>
#include <vector.h>

void debug(buffer);
#include <format.h>

/* XXX: Note that printing function names will reveal our internals to
   some degree. All the logging stuff needs more time in the oven. */

#define msg_err(fmt, ...) rprintf("%s error: " fmt, __func__,   \
				  ##__VA_ARGS__)

#ifdef ENABLE_MSG_WARN
#define msg_warn(fmt, ...) rprintf("%s warning: " fmt, __func__,   \
				  ##__VA_ARGS__)
#else
#define msg_warn(fmt, ...)
#endif

#ifdef ENABLE_MSG_DEBUG
#define msg_debug(fmt, ...) rprintf("%s debug: " fmt, __func__, \
				    ##__VA_ARGS__)
#else
#define msg_debug(fmt, ...)
#endif

static inline boolean compare_bytes(void *a, void *b, bytes len)
{
    for (int i = 0; i < len ; i++) {
        if (((u8 *)a)[i] != ((u8 *)b)[i])
            return false;
    }
    return true;
}

// value is a pointer that we can meaningfully inquire about the type of 
typedef void *value;

// try not to go crazy here
#define tag_unknown (0ull)
#define tag_symbol (1ull)
#define tag_tuple (2ull)
#define tag_string (3ull)
#define tag_buffer_promise (4ull) //?

#include <symbol.h>

#include <closure.h>
#include <closure_templates.h>

typedef closure_type(thunk, void);

#include <list.h>
#include <bitmap.h>
#include <status.h>
#include <pqueue.h>
#include <timer.h>
#include <tuple.h>
#include <range.h>

typedef closure_type(buffer_handler, void, buffer);
typedef closure_type(block_io, void, void *, range, status_handler);

// break out platform - move into the implicit include
#include <x86_64.h>

// should be  (parser, parser, character)
typedef closure_type(parser, void *, character);
// change to status_handler
typedef closure_type(parse_error, void, buffer);
typedef closure_type(parse_finish, void, void *);
parser tuple_parser(heap h, parse_finish c, parse_error err);
parser parser_feed (parser p, buffer b);
u64 random_u64();

typedef struct signature {
    u64 s[4];
} *signature;

void init_runtime(kernel_heaps kh);
heap allocate_tagged_region(kernel_heaps kh, u64 tag);
typedef closure_type(buffer_promise, void, buffer_handler);

extern thunk ignore;
extern status_handler ignore_status;

#include <metadata.h>

#define KB 1024
#define MB (KB*KB)
#define GB (KB*MB)

// fix transient - also should be legit to use the space between end and length w/o penalty
#define cstring(__b) ({buffer n = little_stack_buffer(512); push_buffer(n, __b); push_u8(n, 0); n->contents;})

extern heap transient;

typedef struct merge *merge;

merge allocate_merge(heap h, status_handler completion);
status_handler apply_merge(merge m);
