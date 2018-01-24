#include <runtime.h>
#include <unistd.h>

void debug(buffer b)
{
    write(2, b->contents, buffer_length(b));
}
