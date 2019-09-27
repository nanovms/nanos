#include <runtime.h>
#include <stdlib.h>

define_closure(0, 0, u64, test0)
{
    rprintf("test0\n");
    return 0xdeadbeef;
}

define_closure(0, 0, void, test1)
{
    rprintf("test1, self = %p\n", __self);
}

typedef closure_type(footype, u64);

int main(int argc, char **argv)
{
    heap h = init_process_runtime();
    rprintf("runtime heap %p\n", h);
    footype f = closure(h, test0);
    rprintf("closure alloc %p\n", f);
    assert(apply(f) == 0xdeadbeef);
    thunk t = closure(h, test1);
    rprintf("test1 %p\n", t);
    apply(t);
    rprintf("end\n");
}
