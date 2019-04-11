#include <stdio.h>
#include <stdlib.h>

void foo(void)
{
    printf("foo\n");
}

int main(int argc, char * argv[])
{
    unsigned long * p = (unsigned long *)&foo;
    printf("before write to exec page (addr = 0x%p)\n", p);
    *p = 0x0;
    printf("after write; should not see this\n");
    return EXIT_SUCCESS;
}
