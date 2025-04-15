#include <predef.h>
#include <config.h>

/* Value tags

   A value is a pointer or immediate whose type can be meaningfully inquired.

   The tag is not necessarily the value type. For instance, a tuple may be one
   of a number of tags (tag_table_tuple, tag_function_tuple). Rather, the tag
   steers us toward the correct access methods.

   We practically have 8 bits to work with for x86_64 and aarch64, but try to
   be conservative in allocating these.
*/

#define tag_unknown        (0ull) /* untyped */
#define tag_string         (1ull) /* buffer of utf-encoded characters */
#define tag_symbol         (2ull) /* struct symbol */
#define tag_table_tuple    (3ull) /* table-based tuple */
#define tag_function_tuple (4ull) /* backed tuple; struct function_tuple */
#define tag_vector         (5ull) /* struct vector */
#define tag_integer        (6ull)
#define tag_max            (7ull)

#include <machine.h>
#include <attributes.h>

typedef u8 boolean;
typedef u32 character;
typedef u64 timestamp;

#define compare_and_swap_boolean compare_and_swap_8
#define atomic_swap_boolean atomic_swap_8

#define true 1
#define false 0
#define infinity (-1ull)
#define INVALID_PHYSICAL ((u64)infinity)
#define INVALID_ADDRESS ((void *)infinity)

#define PAGELOG_2M 21
#define PAGESIZE_2M U64_FROM_BIT(PAGELOG_2M)

#define KB 1024
#define MB (KB*KB)
#define GB (KB*MB)

#define UUID_LEN    16

void console_write(const char *s, bytes count);

void print_u64(u64 s);

#include <sstring.h>

#define VM_EXIT_SIGNAL(x) (x)
#define VM_EXIT_GDB 0x7d
#define VM_EXIT_FAULT 0x7e
#define VM_EXIT_HALT 0x7f

#define halt(fmt, ...) halt_with_code(VM_EXIT_HALT, ss(fmt), ##__VA_ARGS__)
void halt_with_code(u8 code, sstring format, ...) __attribute__((noreturn));
void kernel_shutdown(int status) __attribute__((noreturn));
void vm_exit(u8 code) __attribute__((noreturn));
void vm_shutdown(u8 code) __attribute__((noreturn));
void vm_reset(void) __attribute__((noreturn));
void print_frame_trace_from_here();

// make into no-op for production
#ifdef NO_ASSERT
#define assert(x) do { if((x)) { } } while(0)
#else
#define assert(x)                                   \
    do {                                            \
        if (!(x)) {                                 \
            __label__ __here;                       \
            print_frame_trace_from_here();          \
            __here: halt("assertion " #x " failed at %s:%d (IP %p) in %s()\n",  \
                         file_ss, __LINE__, &&__here, func_ss);                 \
        }                                           \
    } while(0)
#endif

#define build_assert(x) _Static_assert((x), "build assertion failure")

#define string_literal(s)           (char []){s}
#define assert_string_literal(s)    (void)string_literal(s)

void runtime_memcpy(void *a, const void *b, bytes len);

void runtime_memset(u8 *a, u8 b, bytes len);

int runtime_memcmp(const void *a, const void *b, bytes len);
void *runtime_memchr(const void *a, int c, bytes len);

void rput_sstring(sstring s);
#define rputs(s)    rput_sstring(ss(s))

static inline void console_sstring(sstring s)
{
    console_write(s.ptr, s.len);
}
#define console(s)  console_sstring(ss(s))

#define pad(__x, __s) ((((__x) - 1) & (~((__s) - 1))) + (__s))

#define find_order(x) ((x) > 1 ? msb((x) - 1) + 1 : 0)

#define U32_FROM_BIT(x) (1ul<<(x))
#define U64_FROM_BIT(x) (1ull<<(x))
#define MASK32(x) (U32_FROM_BIT(x)-1)
#define MASK(x) (U64_FROM_BIT(x)-1)

#define __compare(x, y, op) ({ typeof(x) __x = (x); typeof(y) __y = (y); (__x op __y ? __x : __y);})

#define MIN(x, y) __compare((x), (y), <)
#define MAX(x, y) __compare((x), (y), >)

#define ABS(x) (((x) >= 0) ? (x) : -(x))

#define offsetof(__t, __e) u64_from_pointer(&((__t)0)->__e)

#define check_flags_and_clear(x, f) ({boolean match = ((x) & (f)) != 0; (x) &= ~(f); match;})

static inline void zero(void *x, bytes length)
{
    runtime_memset(x, 0, length);
}

static inline void touch_memory(const void *x, bytes length)
{
    u64 addr = u64_from_pointer(x);
    volatile u8 *bp = pointer_from_u64(addr & ~PAGEMASK),
        *end = pointer_from_u64(pad((addr + length), PAGESIZE));
    while (bp < end) {
        (void)*bp;
        bp += PAGESIZE;
    }
    memory_barrier();
}

typedef struct heap *heap;
#include <table.h>
#include <heap/heap.h>

#define MEM_ZERO        U32_FROM_BIT(0)
#define MEM_NOWAIT      U32_FROM_BIT(1)
#define MEM_NOFAIL      U32_FROM_BIT(2)

void *mem_alloc(heap h, bytes size, u32 flags);

#define mem_alloc_u64(h, s, f)  u64_from_pointer(mem_alloc(h, s, f))

// transient is supposed to be cleaned up when we can guarantee that
// its out of scope - so we argue its ok to make it global. however
// there isn't a very good definition of what the lifetime of it is.
// transient objects shouldnt be shared.
extern heap transient;

#if defined(BOOT)
#include <boot.h>
#endif
#include <buffer.h>
#include <ringbuf.h>

typedef u64 physical;

physical vtop(void *x);

// used by stage2/stage3, not process

heap zero_wrap(heap meta, heap parent);

boolean validate_virtual(void *base, u64 length);
boolean validate_virtual_writable(void *base, u64 length);

void sha256(buffer dest, buffer source);

#define stack_allocate __builtin_alloca

typedef struct buffer *buffer;

void print_number(buffer s, u64 x, int base, int pad, boolean upper);
void print_signed_number(buffer s, s64 x, int base, int pad, boolean upper);

typedef struct flush_entry *flush_entry;

#include <text.h>
#include <vector.h>
#include <format.h>

#ifdef KERNEL

enum log_level {
    LOG_ALWAYS = -1,
    LOG_ERR,
    LOG_WARN,
    LOG_INFO,
};

#define msg_print(fmt, ...) log_printf(LOG_ALWAYS, ss(fmt), ##__VA_ARGS__)
#define msg_err(fmt, ...)   log_printf(LOG_ERR, ss(fmt), ##__VA_ARGS__)
#define msg_warn(fmt, ...)  log_printf(LOG_WARN, ss(fmt), ##__VA_ARGS__)
#define msg_info(fmt, ...)  log_printf(LOG_INFO, ss(fmt), ##__VA_ARGS__)

void log_printf(enum log_level level, sstring fmt, ...);

#else

#define msg_err(fmt, ...)   rprintf(fmt "\n", ##__VA_ARGS__)

#ifdef ENABLE_MSG_WARN
#define msg_warn(fmt, ...)  rprintf(fmt "\n", ##__VA_ARGS__)
#else
#define msg_warn(fmt, ...)
#endif

#endif

#ifdef ENABLE_MSG_DEBUG
#define msg_debug(fmt, ...) rprintf("%s debug: " fmt, func_ss,  \
				    ##__VA_ARGS__)
#else
#define msg_debug(fmt, ...)
#endif

#include <symbol.h>

/* closures, used everywhere, including in data structures */
#include <closure.h>
#include <closure_templates.h>
closure_type(thunk, void);

/* data structures */
#include <list.h>
#include <bitmap.h>
#include <tuple.h>
#include <runtime_string.h>
#include <status.h>
#include <pqueue.h>
#include <rbtree.h>
#include <range.h>
#include <queue.h>
#include <refcount.h>

/* heaps that depend on above structures */
#include <heap/id.h>
#include <heap/page.h>

/* clocksource and timer facilities */
#include <clock.h>
#include <timer.h>

closure_type(buffer_handler, status, buffer b);
closure_type(input_buffer_handler, boolean, buffer b);
closure_type(connection_handler, input_buffer_handler, buffer_handler out);
closure_type(value_handler, void, value v);
closure_type(io_status_handler, void, status s, bytes len);
closure_type(block_io, void, void *buf, range r, status_handler complete);

struct storage_req;
closure_type(storage_req_handler, void, struct storage_req *req);
closure_type(storage_attach, void, storage_req_handler h, u64 size, int attach_id);

#include <sg.h>

void print_value(buffer dest, value v, tuple attrs);

// should be  (parser, parser, character)
closure_type(parser, void *, character c);
// change to status_handler
closure_type(parse_error, void, string err);
closure_type(parse_finish, void, void *v);
parser tuple_parser(heap h, parse_finish c, parse_error err);
parser value_parser(heap h, parse_finish c, parse_error err);
parser json_parser(heap h, parse_finish c, parse_error err);
void json_parser_free(parser p);
parser parser_feed (parser p, buffer b);

/* RNG */
void init_random(heap h);
u64 hw_get_seed(void);
extern bytes (*preferred_get_seed)(void *seed, bytes len);
void get_seed_complete(void *seed, bytes len);

u64 random_early_u64(void);
u64 random_u64(void);
u64 random_buffer(buffer b);
void random_buffer_aborted(void);
void random_reseed(void);

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

#define struct_from_field(l, s, f) ((s)pointer_from_u64(u64_from_pointer(l) - offsetof(s, f)))

struct context;
typedef struct context *context;

#if defined(KERNEL) || defined(BOOT)
/* This is really kernel-specific, but closures require these definitions at a
   low-level, and runtime code built at kernel level doesn't always include kernel.h. */
#include <frame.h>
#include <context.h>
#endif

/* XXX type safety, possibly tag */
static inline void deallocate_closure(void *p)
{
    struct _closure_common *c = p + sizeof(void *); /* skip __apply */
    void *x = pointer_from_u64(c->ctx & ~CLOSURE_COMMON_CTX_FLAGS_MASK);
    if ((c->ctx & CLOSURE_COMMON_CTX_DEALLOC_ON_FINISH) == 0)
        return;
    heap h =
#ifdef KERNEL
        (c->ctx & CLOSURE_COMMON_CTX_IS_CONTEXT) ? ((context)x)->transient_heap :
#endif
        x;
    if (h && c->size > 0)
        deallocate(h, p, c->size);
}

#define closure_finish() do { deallocate_closure(__self); __self = 0; } while(0)

#if !defined(BOOT) && !defined(KERNEL)
#include <unix_process_runtime.h>
#endif
