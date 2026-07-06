#include <runtime.h>

BSS_RO_AFTER_INIT static heap vheap;

vector allocate_tagged_vector(int length)
{
    return allocate_vector(vheap, length);
}

void init_vectors(heap h, heap init)
{
    vheap = h;
}

boolean vector_init(vector v, heap h, int len)
{
    bytes s = len * sizeof(void *);
    void *contents = allocate(h, s);
    if (contents == INVALID_ADDRESS)
        return false;
    init_buffer(v, s, false, h, contents);
    return true;
}

void vector_deinit(vector v)
{
    deallocate(v->h, v->contents, v->length);
}
