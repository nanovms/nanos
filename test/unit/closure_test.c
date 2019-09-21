#include <runtime.h>
#include <stdlib.h>

void _apply_dealloc(void)
{
    struct _closure_common *c;
    asm volatile("pop %0" : "=r" (c));
    rprintf("dealloc %p\n", c);
    deallocate(c->h, c, c->size);
}

static CLOSURE_0_0(test0, void);
void test0(void)
{
    rprintf("test0\n");
    return_without_dealloc;
}

int main(int argc, char **argv)
{
    heap h = init_process_runtime();
    thunk t = closure(h, test0);
    rprintf("closure alloc %p\n", t);
    apply(t);
    rprintf("end\n");
}
