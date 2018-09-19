#include <runtime.h>

void initialize_buffer();

static inline CLOSURE_0_0(ignore_body, void);
static inline void ignore_body(){}
thunk ignore;
status_handler ignore_status;

static char *hex_digit="0123456789abcdef";

void print_byte(buffer s, u8 f)
{
    push_u8(s, hex_digit[f >> 4]);
    push_u8(s, hex_digit[f & 15]);
}

void print_hex_buffer(buffer s, buffer b)
{
    int len = buffer_length(b);
    int wlen = 4;
    int rowlen = wlen * 4;
    boolean first = true;

    for (int i = 0 ; i<len ; i+= 1) {
        if (!(i % rowlen)) {
            if (!first) push_u8(s, '\n');
            first = false;
            print_byte(s, i>>24);
            print_byte(s, i>>16);
            print_byte(s, i>>8);
            print_byte(s, i);
            push_u8(s, ':');
        }
        if (!(i % wlen)) push_u8 (s, ' ');
        print_byte(s, *(u8 *)buffer_ref(b, i));
    }
    // better handling of empty buffer
    push_u8(s, '\n');
}

void print_tuple(buffer b, tuple z)
{
    table t = valueof(z);
    boolean sub = false;
    entry e = valueof(t->entries[0]);
            
    bprintf(b, "(");
    table_foreach(t, n, v) {
        if (sub) {
            push_character(b, ' ');
        }
        bprintf(b, "%b:", symbol_string((symbol)n));
        // xxx print value
        if (tagof(v) == tag_tuple) {
            print_tuple(b, v);
        } else {
            bprintf(b, "%b", v);
        }
        sub = true;
    }
    bprintf(b, ")");
}

static void format_tuple(buffer dest, buffer fmt, vlist *v)
{
    print_tuple(dest, varg(*v, tuple));
}

static void format_value(buffer dest, buffer fmt, vlist *v)
{
    value x = varg(*v, value);
    switch(tagof(x)) {
    case tag_tuple:
        print_tuple(dest, (tuple)x);
        break;
   case tag_symbol:
       bprintf(dest, "%b", symbol_string((symbol)x));
       break;        
    default:
        {
            buffer b = (buffer)x;
            if (buffer_length(b) > 20) {
                bprintf(dest, "{buffer %d}", buffer_length(b));
            } else bprintf(dest, "%b", b);
        }
        break;
    }
}


static void format_cstring(buffer dest, buffer fmt, vlist *a)
{
    char *c = varg(*a, char *);
    if (!c) c = (char *)"(null)";
    int len = runtime_strlen(c);
    buffer_write(dest, c, len);    
}

static void format_hex_buffer(buffer dest, buffer fmt, vlist *a)
{
    buffer b= varg(*a, buffer);
    print_hex_buffer(dest, b);
}

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

static void format_spaces(buffer dest, buffer fmt, vlist *a)
{
    u64 n = varg(*a, u64);
    for (int i = 0; i < n; i++) push_u8(dest, ' ');
}


// maybe the same?
heap errheap;
heap transient;

extern  void format_symbol(buffer dest, buffer fmt, vlist *a);
    
// init linker sets would clean up the platform dependency, if you link
// with it, it gets initialized
void init_runtime(heap h)
{
    // environment specific
    transient = h;
    register_format('p', format_pointer);
    init_tuples(allocate_tagged_region(h, tag_tuple));
    init_symbols(allocate_tagged_region(h, tag_symbol), h);
    ignore = closure(h, ignore_body);
    ignore_status = (void*)ignore;
    errheap = h;
    register_format('P', format_u64);    // for 32 bit
    register_format('d', format_number);
    register_format('b', format_buffer);
    register_format('t', format_tuple);
    register_format('v', format_value);
    register_format('s', format_cstring);
    register_format('X', format_hex_buffer);
    register_format('S', format_symbol);
    register_format('n', format_spaces);    
    // fix
#ifndef BITS32    
    initialize_timers(h);
    register_format('c', format_character);
#endif
}

