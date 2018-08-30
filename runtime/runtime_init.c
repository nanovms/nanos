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


static void format_buffer(buffer dest, buffer fmt, vlist *ap)
{
    push_buffer(dest, varg(*ap, buffer));
}

static void format_character(buffer dest, buffer fmt, vlist *a)
{
    character x = varg(*a, character);
    push_character(dest, x);
}

static void format_u64(buffer dest, buffer fmt, vlist *a)
{
    u64 x = varg(*a, u64);
    print_number(dest, x, 16, 1);
}


// maybe the same?
heap errheap;
heap transient;

// init linker sets would clean up the platform dependency, if you link
// with it, it gets initialized
void init_runtime(heap h)
{
    // environment specific
    transient = h;
    register_format('p', format_pointer);
    init_tuples(allocate_tagged_region(h, tag_tuple), allocate_tagged_region(h, tag_tuple_handler));
    init_symbols(allocate_tagged_region(h, tag_symbol), h);
    ignore = closure(h, ignore_body);
    ignore_status = (void*)ignore;
    errheap = h;
    register_format('P', format_u64);    // for 32 bit
    register_format('d', format_number);
    register_format('b', format_buffer);
    // fix
#ifndef BITS32    
    initialize_timers(h);
    register_format('c', format_character);
#endif
}

