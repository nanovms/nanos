#include <runtime.h>

static void ringbuf_write_at(ringbuf b, bytes dest_offset, const void *src, bytes len)
{
    void *dest = b->contents + (dest_offset & (b->length - 1));
    bytes avail = MIN(len, b->contents + b->length - dest);
    runtime_memcpy(dest, src, avail);
    if (avail < len)
        runtime_memcpy(b->contents, src + avail, len - avail);
}

boolean ringbuf_read(ringbuf b, void *dest, bytes len)
{
    if (!ringbuf_peek(b, dest, len))
        return false;
    ringbuf_consume(b, len);
    return true;
}

boolean ringbuf_peek(ringbuf b, void *dest, bytes len)
{
    if (buffer_length(b) < len)
        return false;
    void *start = b->contents + (b->start & (b->length - 1));
    bytes avail = MIN(len, b->contents + b->length - start);
    runtime_memcpy(dest, start, avail);
    if (avail < len)
        runtime_memcpy(dest + avail, b->contents, len - avail);
    return true;
}

boolean ringbuf_write(ringbuf b, const void *src, bytes len)
{
    if (!ringbuf_extend(b, len))
        return false;
    ringbuf_write_at(b, b->end, src, len);
    ringbuf_produce(b, len);
    return true;
}

boolean ringbuf_memset(ringbuf b, u8 c, bytes len)
{
    if (!ringbuf_extend(b, len))
        return false;
    void *end = b->contents + (b->end & (b->length - 1));
    bytes avail = MIN(len, b->contents + b->length - end);
    runtime_memset(end, c, avail);
    if (avail < len)
        runtime_memset(b->contents, c, len - avail);
    ringbuf_produce(b, len);
    return true;
}

/* Overwrites `len` bytes of buffer contents starting at `offset`; does not change the buffer
 * length.
 */
void ringbuf_overwrite(ringbuf b, bytes offset, const void *src, bytes len)
{
    ringbuf_write_at(b, b->start + offset, src, len);
}

boolean ringbuf_extend(ringbuf b, bytes len)
{
    if (ringbuf_space(b) < len) {
        bytes new_len;
        if (len <= b->length)
            new_len = 2 * b->length;
        else
            new_len = U64_FROM_BIT(find_order(len) + 1);
        return (ringbuf_set_capacity(b, new_len) == new_len);
    }
    return true;
}

bytes ringbuf_set_capacity(ringbuf b, bytes len)
{
    if (len < buffer_length(b))
        len = buffer_length(b);

    /* ensure that length is a power of 2 */
    len = U64_FROM_BIT(find_order(len));

    if (len != b->length) {
        void *new = allocate(b->h, len);
        if (new == INVALID_ADDRESS)
            return b->length;
        ringbuf_peek(b, new, buffer_length(b));
        deallocate(b->h, b->contents, b->length);
        b->length = len;
        b->end = b->end - b->start;
        b->start = 0;
        b->contents = new;
    }
    return len;
}
