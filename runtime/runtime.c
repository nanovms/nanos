#include <runtime.h>

char hex[]="0123456789abcdef";

void print_u64(u64 s)
{
    for (int x = 60; x >= 0; x -= 4)
        serial_out(hex[(s >> x)&0xf]);
}

void console(char *x)
{
    for (char *i = x; *i; i++) 
        serial_out(*i);
}
