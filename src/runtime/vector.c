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
