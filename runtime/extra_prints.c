#include <runtime.h>

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


void init_extra_prints()
{
    register_format('t', format_tuple);
    register_format('v', format_value);
    register_format('s', format_cstring);    
}

