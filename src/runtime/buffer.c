#include <runtime.h>

buffer allocate_buffer(heap h, bytes s)
{
    buffer b = allocate(h, sizeof(struct buffer));
    b->start = 0;
    b->end = 0;
    b->length = s;
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

void __buffer_extend(buffer b, bytes len)
{
    // xxx - pad to pagesize
    if (b->length < (b->end + len)) {
        int oldlen = b->length;
        b->length = 2*((b->end-b->start)+len);
        void *new =  allocate(b->h, b->length);
        runtime_memcpy(new, b->contents + b->start, (b->end-b->start));
        deallocate(b->h, b->contents, oldlen);
        b->end = b->end - b->start;
        b->start = 0;
        b->contents = new;
    }
}

extern int __fs_ready;
void buffer_extend(buffer b, bytes len)
{
    if (__fs_ready && b->length < (b->end + len)) {
        int oldlen = b->length;
        int newlen = 2*((b->end-b->start)+len);
        rprintf("buffer @ %p is extended from %d to %d\n", oldlen, newlen);
        print_stack_from_here();
    }
    __buffer_extend(b, len);
}
