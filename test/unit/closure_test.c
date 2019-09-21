#include <runtime.h>
#include <stdlib.h>

/* this would exist within the runtime environment */
void _apply_dealloc(void)
{
    void *p;
    asm volatile("pop %0" : "=r" (p));
    struct _closure_common *c = p + sizeof(void*);
    rprintf("p %p, dealloc h %p, c %p, size %d\n", p, c->h, c, c->size);
    deallocate(c->h, p, c->size);
}

static CLOSURE_0_0(test0, u64);
u64 test0(void)
{
    rprintf("test0\n");
    u64 rv = 0xdeadbeef;
    closure_return_nodealloc rv;
}

static CLOSURE_0_0(test1, void);
void test1(void)
{
    void *self;
    asm volatile("mov 8(%%rsp), %0" : "=r"(self));
    rprintf("test1, self = %p\n", self);
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
