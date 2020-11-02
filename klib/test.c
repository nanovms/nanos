#include <klib.h>

#define INVALID_ADDRESS ((void*)-1ull)
static int foo(int x)
{
    return x + 123;
}

int init(void *md, klib_add_sym add_sym)
{
    add_sym(md, "foo", foo);
    add_sym(md, "bar", (void*)0);
    return KLIB_INIT_OK;
}
