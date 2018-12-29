#include <runtime.h>

buffer allocate_buffer(heap h, bytes s)
{
    buffer b = allocate(h, sizeof(struct buffer));
    b->start = 0;
    b->end = 0;
    b->length = s;
    b->wrapped = false;
    b->h = h;
    // two allocations to remove the deallocate ambiguity, otherwise
    // we'd prefer to do it in one
    b->contents = allocate(h, s);
    return(b);
}


void buffer_prepend(buffer b,
                      void *body,
                      bytes length)
{
    if (b->start < length) {
        buffer new = allocate_buffer(b->h, buffer_length(b) + length);
        buffer_write(new, body, length);
        buffer_write(new, buffer_ref(b, 0), buffer_length(b));
    } else {
        b->start -= length;
        runtime_memcpy(buffer_ref(b, b->start), body, length);
    }
}


void buffer_append(buffer b,
                     void *body,
                     bytes length)
{
    buffer_extend(b, length);
    buffer_write(b, body, length);
}
