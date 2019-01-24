#include <runtime.h>

void initialize_buffer();

static inline CLOSURE_0_0(ignore_body, void);
static inline void ignore_body(){}
thunk ignore;
status_handler ignore_status;


// doesn't really belong here
static char *hex_digits="0123456789abcdef";

void print_number(buffer s, u64 x, int base, int pad)
{
    if ((x > 0) || (pad > 0)) {
        u64 q, r;
        DIV(x, base, q, r);
        print_number(s, q, base, pad - 1);
        push_u8(s, hex_digits[r]);
    }
}

static inline void format_number(buffer dest, buffer fmt, vlist *a)
{
    s64 x = varg(*a, s64);
    if (x < 0) {                /* emit sign & two's complement */
        push_u8(dest, '-');
        x = -x;
    }
    print_number(dest, x, 10, 1);
}

static void format_buffer(buffer dest, buffer fmt, vlist *ap)
{
    push_buffer(dest, varg(*ap, buffer));
}

#ifndef BITS32    
static void format_character(buffer dest, buffer fmt, vlist *a)
{
    character x = varg(*a, character);
    push_character(dest, x);
}
#endif

static void format_u64(buffer dest, buffer fmt, vlist *a)
{
    u64 x = varg(*a, u64);
    print_number(dest, x, 16, 1);
}

static void format_spaces(buffer dest, buffer fmt, vlist *a)
{
    u64 n = varg(*a, u64);
    for (int i = 0; i < n; i++) push_u8(dest, ' ');
}


// maybe the same?
heap errheap;
heap transient;

// init linker sets would clean up the platform dependency, if you link
// with it, it gets initialized
void init_runtime(kernel_heaps kh)
{
    // environment specific
    heap h = transient = heap_general(kh);
    register_format('p', format_pointer);
    init_tuples(allocate_tagged_region(kh, tag_tuple));
    init_symbols(allocate_tagged_region(kh, tag_symbol), h);
    ignore = closure(h, ignore_body);
    ignore_status = (void*)ignore;
    errheap = h;
    register_format('P', format_u64);    // for 32 bit
    register_format('d', format_number);
    register_format('b', format_buffer);
    register_format('n', format_spaces);    
    // fix
#ifndef BITS32    
    initialize_timers(kh);
    register_format('c', format_character);
#endif
}

