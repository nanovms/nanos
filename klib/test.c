#include <klib.h>

#define Z_LEN 1024

int y = 123;
unsigned long z[Z_LEN];

static int foo(int x)
{
    z[0] = x; /* bss write */
    return z[0] + y; /* test data */
}

void (*memset)(void *a, unsigned char b, unsigned long len);

int init(void *md, klib_get_sym get_sym, klib_add_sym add_sym)
{
    /* test that bss is clear */
    for (int i = 0; i < Z_LEN; i++)
        if (z[i] != 0)
            return KLIB_INIT_FAILED;

    add_sym(md, "foo", foo);
    add_sym(md, "bar", (void*)0);

    memset = get_sym("runtime_memset");
    if (!memset)
        return KLIB_INIT_FAILED;

    unsigned long a = -1ull;
    memset(&a, 0, sizeof(unsigned long));
    return a == 0 ? KLIB_INIT_OK : KLIB_INIT_FAILED;
}
