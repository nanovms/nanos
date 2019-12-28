#include <runtime.h>

heap vector_heap;

// these two should be asynchronous? dont you think?
static value vget(value m, symbol b)
{
    return 0;
}

static u64 velements(value m)
{
    return 0;
}

static void vset(value m, symbol b, value v)
{
}


static void vvformat(buffer b, value m)
{
    push_buffer(b, m);
}

// static CLOSURE_2_0(seach, void, buffer, each);
static void veach(buffer b, each n)
{
    rprintf("actually calling seah\n");
    // self close
}

static void viterate(heap h, value v, each e)
{
    buffer in = (buffer)v;
    buffer b = wrap_buffer(h, in->contents, buffer_length(in));
    // allocate working buffer to record offset, and reclaim..on h i guess
    rprintf("actually calling titerate\n");
    veach(b, e);
}

static struct methods _vm = {vget, vset, viterate, vvformat, velements};

void init_vector(heap h)
{
    vector_heap = h;
    tagmethods[tag_vector] = &_vm;
}
