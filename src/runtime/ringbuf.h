typedef buffer ringbuf;

static inline ringbuf allocate_ringbuf(heap h, bytes len)
{
    /* ensure that length is a power of 2 */
    return allocate_buffer(h, U64_FROM_BIT(find_order(len)));
}

#define ringbuf_length      buffer_length
#define ringbuf_ref         buffer_ref
#define deallocate_ringbuf  deallocate_buffer

boolean ringbuf_read(ringbuf b, void *dest, bytes len);
boolean ringbuf_peek(ringbuf b, void *dest, bytes len);
boolean ringbuf_write(ringbuf b, const void *src, bytes len);
boolean ringbuf_memset(ringbuf b, u8 c, bytes len);

void ringbuf_overwrite(ringbuf b, bytes offset, const void *src, bytes len);

static inline void ringbuf_produce(ringbuf b, bytes len)
{
    b->end += len;
}

static inline void ringbuf_consume(ringbuf b, bytes len)
{
    b->start += len;
}

static inline void ringbuf_unconsume(ringbuf b, bytes len)
{
    b->start -= len;
}

static inline bytes ringbuf_space(ringbuf b)
{
    return b->length - buffer_length(b);
}

boolean ringbuf_extend(ringbuf b, bytes len);
bytes ringbuf_set_capacity(ringbuf b, bytes len);
