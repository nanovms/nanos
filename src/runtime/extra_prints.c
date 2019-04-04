#include <runtime.h>


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
        push_u8(s, ' ');
    }
    // better handling of empty buffer
    push_u8(s, '\n');
}

/* just a little tool for debugging */
void print_csum_buffer(buffer s, buffer b)
{
    u64 csum = 0;
    for (int i = 0; i < buffer_length(b); i++)
        csum += *(u8*)buffer_ref(b, i);
    bprintf(s, "%lx", csum);
}

void print_tuple(buffer b, tuple z)
{
    table t = valueof(z);
    boolean sub = false;
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

static void format_tuple(buffer dest, struct formatter_state *s, vlist *v)
{
    print_tuple(dest, varg(*v, tuple));
}

static void format_value(buffer dest, struct formatter_state *s, vlist *v)
{
    buffer b;
    value x = varg(*v, value);
    if (!x) {
        bprintf(dest, "(none)");
        return;
    }

    switch(tagof(x)) {
    case tag_tuple:
        print_tuple(dest, (tuple)x);
        break;
    case tag_symbol:
        bprintf(dest, "%b", symbol_string((symbol)x));
        break;
    default:
        b = (buffer)x;
        if (buffer_length(b) > 20)
            bprintf(dest, "{buffer %d}", buffer_length(b));
        else
            bprintf(dest, "%b", b);
    }
}

static void format_hex_buffer(buffer dest, struct formatter_state *s, vlist *a)
{
    buffer b = varg(*a, buffer);
    print_hex_buffer(dest, b);
}

static void format_csum_buffer(buffer dest, struct formatter_state *s, vlist *a)
{
    buffer b = varg(*a, buffer);
    print_csum_buffer(dest, b);
}

static void format_timestamp(buffer dest, struct formatter_state *s, vlist *a)
{
    timestamp t = varg(*a, timestamp);
#ifdef BOOT
    print_number(dest, t, 10, 0);
#else
    print_timestamp(dest, t);
#endif
}

static void format_range(buffer dest, struct formatter_state *s, vlist *a)
{
    range r = varg(*a, range);
    bprintf(dest, "[%ld %ld)", r.start, r.end);
}

void init_extra_prints()
{
    register_format('t', format_tuple, 0);
    register_format('v', format_value, 0);
    register_format('X', format_hex_buffer, 0);
    register_format('T', format_timestamp, 0);
    register_format('R', format_range, 0);
    register_format('C', format_csum_buffer, 0);
}
