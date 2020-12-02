#include <predef.h>
#include <config.h>
#include <machine.h>
#include <attributes.h>
#if !defined(BOOT) && !defined(STAGE3) && !defined(KLIB)
#include <unix_process_runtime.h>
#endif

typedef u8 boolean;
typedef u32 character;
typedef u64 timestamp;

#define true 1
#define false 0
#define infinity (-1ull)
#define INVALID_PHYSICAL ((u64)infinity)
#define INVALID_ADDRESS ((void *)infinity)

#define PAGELOG 12
#define PAGESIZE U64_FROM_BIT(PAGELOG)
#define PAGELOG_2M 21
#define PAGESIZE_2M U64_FROM_BIT(PAGELOG_2M)

#define KB 1024
#define MB (KB*KB)
#define GB (KB*MB)

#define UUID_LEN    16

void console_write(const char *s, bytes count);

void print_u64(u64 s);

void halt(char *format, ...) __attribute__((noreturn));
void kernel_shutdown(int status) __attribute__((noreturn));
void vm_exit(u8 code) __attribute__((noreturn));
void print_stack_from_here();

// make into no-op for production
#ifdef NO_ASSERT
#define assert(x) do { if((x)) { } } while(0)
#else
#define assert(x)                                   \
    do {                                            \
        if (!(x)) {                                 \
            print_stack_from_here();                \
            halt("assertion " #x " failed in " __FILE__ ": %s() on line %d; halt\n", __func__, __LINE__); \
        }                                           \
    } while(0)
#endif

#define build_assert(x) _Static_assert((x), "build assertion failure")

void runtime_memcpy(void *a, const void *b, bytes len);

void runtime_memset(u8 *a, u8 b, bytes len);

int runtime_memcmp(const void *a, const void *b, bytes len);

static inline int runtime_strlen(const char *a)
{
    int i = 0;
    for (; *a; a++, i++);
    return i;
}

static inline void console(const char *s)
{
    console_write(s, runtime_strlen(s));
}

#define pad(__x, __s) ((((__x) - 1) & (~((__s) - 1))) + (__s))

#define find_order(x) ((x) > 1 ? msb((x) - 1) + 1 : 0)

#define U64_FROM_BIT(x) (1ull<<(x))
#define MASK(x) (U64_FROM_BIT(x)-1)

#define __compare(x, y, op) ({ typeof(x) __x = (x); typeof(y) __y = (y); (__x op __y ? __x : __y);})

#define MIN(x, y) __compare((x), (y), <)
#define MAX(x, y) __compare((x), (y), >)

#define offsetof(__t, __e) u64_from_pointer(&((__t)0)->__e)

#define check_flags_and_clear(x, f) ({boolean match = ((x) & (f)) != 0; (x) &= ~(f); match;})

static inline void zero(void *x, bytes length)
{
    runtime_memset(x, 0, length);
}

typedef struct heap *heap;
#include <table.h>
#include <heap/heap.h>

// transient is supposed to be cleaned up when we can guarantee that
// its out of scope - so we argue its ok to make it global. however
// there isn't a very good definition of what the lifetime of it is.
// transient objects shouldnt be shared.
extern heap transient;

#include <buffer.h>

typedef u64 physical;

physical vtop(void *x);

// used by stage2/stage3, not process

heap zero_wrap(heap meta, heap parent);

boolean validate_virtual(void *base, u64 length);

void sha256(buffer dest, buffer source);

#define stack_allocate __builtin_alloca

typedef struct buffer *buffer;

void print_number(buffer s, u64 x, int base, int pad);

#include <text.h>
#include <vector.h>
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

// value is a pointer that we can meaningfully inquire about the type of 
typedef void *value;

// try not to go crazy here
#define tag_unknown (0ull)
#define tag_symbol (1ull)
#define tag_tuple (2ull)
#define tag_string (3ull)
#define tag_buffer_promise (4ull) //?
#define tag_max (5ull)

#include <symbol.h>

/* closures, used everywhere, including in data structures */
#include <closure.h>
#include <closure_templates.h>
typedef closure_type(thunk, void);

/* data structures */
#include <list.h>
#include <bitmap.h>
#include <tuple.h>
#include <status.h>
#include <pqueue.h>
#include <rbtree.h>
#include <range.h>
#include <queue.h>
#include <refcount.h>

/* heaps that depend on above structures */
#include <heap/id.h>

/* clocksource and timer facilities */
#include <clock.h>
#include <timer.h>

void kernel_shutdown_ex(status_handler completion) __attribute__((noreturn));

typedef closure_type(buffer_handler, status, buffer);
typedef closure_type(connection_handler, buffer_handler, buffer_handler);
typedef closure_type(io_status_handler, void, status, bytes);
typedef closure_type(block_io, void, void *, range, status_handler);

#include <sg.h>

// should be  (parser, parser, character)
typedef closure_type(parser, void *, character);
// change to status_handler
typedef closure_type(parse_error, void, buffer);
typedef closure_type(parse_finish, void, void *);
parser tuple_parser(heap h, parse_finish c, parse_error err);
parser value_parser(heap h, parse_finish c, parse_error err);
parser parser_feed (parser p, buffer b);

// RNG
void init_random();
u64 random_u64();
u64 random_buffer(buffer b);

typedef struct signature {
    u64 s[4];
} *signature;

void init_runtime(heap general, heap safe);

extern thunk ignore;
extern status_handler ignore_status;
extern value null_value;

#include <metadata.h>

#define cstring(b, t) ({buffer_clear(t); push_buffer((t), (b)); push_u8((t), 0); (char*)(t)->contents;})

typedef struct merge *merge;

merge allocate_merge(heap h, status_handler completion);
status_handler apply_merge(merge m);

void __stack_chk_guard_init();

#define _countof(a) (sizeof(a) / sizeof(*(a)))

#ifdef KERNEL
typedef struct export_sym {
    const char *name;
    void *v;
} *export_sym;

#define KLIB_EXPORT_RENAME(sym, name)                                      \
    static const char * __attribute__((section(".klib_symtab.strs")))      \
        __attribute__((used)) _klib_sym_str_ ##sym = #name;                \
    static struct export_sym __attribute__((section(".klib_symtab.syms"))) \
        __attribute__((used)) _klib_export_sym_ ##sym = (struct export_sym){#name, (sym)};
#define KLIB_EXPORT(sym)    KLIB_EXPORT_RENAME(sym, sym)
#else
#define KLIB_EXPORT(x)
#define KLIB_EXPORT_RENAME(x, y)
#endif
