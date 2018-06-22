#include <runtime.h>


static formatter formatters[96];

void register_format(character c, formatter f)
{
    if ((c > 32) && (c < 128)) formatters[c-32] = f;
}


void vbprintf(buffer d, buffer fmt, vlist ap)
{
    character i;
    int state = 0;

    foreach_character(i, fmt) {
        if (state == 1)  {
            if ((i > 32) && (i < 128) && formatters[i]) {
                formatters[i-32](d, fmt, ap);
            } else {
                char header[] = "[invalid format %";
                buffer_write(d, header, sizeof(header)-1);
                push_character(d, i);
                push_u8(d, ']');                
            }
            state = 0;
        } else {           
            if ((state == 0) && (i == '%')) {
                state = 1;
            } else {
                push_character(d, i);
            }
        }
    }
}


buffer aprintf(heap h, char *fmt, ...)
{
    buffer b = allocate_buffer(h, 80);
    vlist ap;
    buffer f = alloca_wrap_buffer(fmt, runtime_strlen(fmt));
    vstart (ap, fmt);
    vbprintf(b, f, ap);
    vend(ap);
    return(b);
}

void bbprintf(buffer b, buffer fmt, ...)
{
    vlist ap;
    vstart(ap, fmt);
    vbprintf(b, fmt, ap);
    vend(ap);
}

void bprintf(buffer b, char *fmt, ...)
{
    vlist ap;
    buffer f = alloca_wrap_buffer(fmt, runtime_strlen(fmt));
    vstart (ap, fmt);
    vbprintf(b, f, ap);
    vend(ap);
}
