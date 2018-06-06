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

void notreally(heap h, u64 z, bytes length)
{
}




static u64 malloc_alloc(heap h, bytes s)
{
    return (u64)malloc(s);
}

heap malloc_allocator()
{    
    struct heap h;
    h.alloc = malloc_alloc;
    h.dealloc = notreally;
}

