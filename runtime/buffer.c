#include <runtime.h>

static char *hex_digit="0123456789abcdef";
void print_byte(buffer s, u8 f)
{
    push_character(s, hex_digit[f >> 4]);
    push_character(s, hex_digit[f & 15]);
}

void print_hex_buffer(buffer s, buffer b)
{
    int len = buffer_length(b);
    int wlen = 32;
    int rowlen = wlen * 4;
    boolean first = true;

    for (int i = 0 ; i<len ; i+= 8) {
        if (!(i % rowlen)) {
            if (!first) push_character(s, '\n');
            first = false;
            print_byte(s, i>>24);
            print_byte(s, i>>16);
            print_byte(s, i>>8);
            print_byte(s, i);
            push_character(s, ':');
        }
        if (!(i % wlen)) push_character (s, ' ');
        print_byte(s, *(u8 *)buffer_ref(b, i));
    }
    // better handling of empty buffer
    push_character(s, '\n');
}

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
