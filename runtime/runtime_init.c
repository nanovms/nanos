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


static void format_buffer(buffer dest, buffer fmt, vlist ap)
{
    push_buffer(dest, varg(ap, buffer));
}

static void format_character(buffer dest, buffer fmt, vlist a)
{
    character x = varg(a, character);
    push_character(dest, x);
}

static void format_number(buffer dest, buffer fmt, vlist a)
{
    u64 x = varg(a, u64);
    print_number(dest, x, 10, 1);
}

static void format_hex_buffer(buffer dest, buffer fmt, vlist a)
{
    buffer b= varg(a, buffer);
    print_hex_buffer(dest, b);
}


heap errheap;

// init linker sets would clean up the platform dependency, if you link
// with it, it gets initialized
void init_runtime(heap h)
{
    init_tuples(allocate_tagged_region(h, tag_tuple));
    init_symbols(allocate_tagged_region(h, tag_symbol));
    ignore = closure(h, ignore_body);
    ignore_status = (void*)ignore;
    errheap = h;
    register_format('p', format_pointer);
    
    // fix
#ifndef BITS32    
    initialize_timers(h);
    register_format('b', format_buffer);
    register_format('c', format_character);
    register_format('d', format_number);

    register_format('X', format_hex_buffer);    
#endif        
}

