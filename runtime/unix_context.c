#include <runtime.h>
#include <unistd.h>

void debug(buffer b)
{
    write(2, b->contents, buffer_length(b));
}

void print_u64(u64 x)
{
}

void console(char *x)
{
}

time now()
{
}
