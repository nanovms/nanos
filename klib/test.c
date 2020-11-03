#include <klib.h>

#define INVALID_ADDRESS ((void*)-1ull)

#define Z_LEN 1024

int y = 123;
unsigned long z[Z_LEN];

static int foo(int x)
{
    z[0] = x; /* bss write */
    return z[0] + y; /* test data */
}

int init(void *md, klib_add_sym add_sym)
{
    /* test that bss is clear */
    for (int i = 0; i < Z_LEN; i++)
        if (z[i] != 0)
            return KLIB_INIT_FAILED;

    add_sym(md, "foo", foo);
    add_sym(md, "bar", (void*)0);
    return KLIB_INIT_OK;
}
