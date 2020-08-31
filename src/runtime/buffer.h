// consider -
//   adding a stride
//   going back to using bit offsets
struct buffer {
    bytes start;
    bytes end;
    bytes length;
    boolean wrapped;
    heap h;
    void *contents;
};

static inline void *buffer_ref(buffer b, bytes offset)
{
    // alignment?
    return((void *)b->contents + (b->start + offset));
}

// out of bounds
static inline char peek_char(buffer b)
{
    return(*(char *)buffer_ref(b, 0));
}

#define alloca_wrap_buffer(__b, __l) ({                         \
            buffer b = stack_allocate(sizeof(struct buffer));   \
            b->contents = (void *) (__b);                       \
            b->end = b->length = (__l);                         \
            b->start  = 0;                                      \
            b->wrapped = true;                                  \
            b->h = 0;                                           \
            b;                                                  \
        })

#define alloca_wrap_cstring(__x) alloca_wrap_buffer((__x), runtime_strlen(__x))

#define alloca_wrap(__z) alloca_wrap_buffer(buffer_ref((__z), 0), buffer_length(__z))

#define byte(__b, __i) *(u8 *)((__b)->contents + (__b)->start + (__i))

static inline void buffer_clear(buffer b)
{
    b->start = b->end = 0; 
}

static inline void buffer_consume(buffer b, bytes s)
{
    b->start += s; 
}

static inline void buffer_produce(buffer b, bytes s)
{
    b->end += s; 
}

static inline bytes buffer_length(buffer b)
{
    return b->end - b->start;
} 

static inline boolean buffer_is_wrapped(buffer b)
{
    return b->wrapped;
}

static inline bytes buffer_set_capacity(buffer b, bytes len)
{
    assert(!buffer_is_wrapped(b));  /* wrapped buffers can't be resized */
    if (len < b->end - b->start)
        len = b->end - b->start;
    if (len != b->length) {
        void *new = allocate(b->h, len);
        if (new == INVALID_ADDRESS)
            return b->length;
        runtime_memcpy(new, b->contents + b->start, b->end - b->start);
        deallocate(b->h, b->contents, b->length);
        b->length = len;
        b->end = b->end - b->start;
        b->start = 0;
        b->contents = new;
    }
    return len;
}

static inline boolean buffer_extend(buffer b, bytes len)
{
    // xxx - pad to pagesize
    if (b->length < (b->end + len)) {
        bytes new_len = 2 * (b->end - b->start + len);
        return (buffer_set_capacity(b, new_len) == new_len);
    }
    return true;
}

static inline boolean extend_total(buffer b, int offset)
{
    if (offset > b->end) {
        if (!buffer_extend(b, offset - b->end))
            return false;
        // shouldn't need to in all cases - this is to preserve
        // the idea of the vector as a mapping - we need a reliable
        // sigleton to denote an empty slot
        zero(b->contents + b->end, offset - b->end);
        b->end = offset;
    }
    return true;
}

static inline buffer wrap_buffer(heap h,
                                 void *body,
                                 bytes length)
{
    buffer new = allocate(h, sizeof(struct buffer));
    assert(new != INVALID_ADDRESS);
    new->contents = body;
    new->start = 0;
    new->h = h;
    new->end = length;
    new->length = length;
    new->wrapped = true;
    return(new);
}

static inline void unwrap_buffer(heap h, buffer b)
{
    deallocate(h, b, sizeof(struct buffer));
}

static inline buffer wrap_buffer_cstring(heap h, char *x)
{
    return wrap_buffer(h, x, runtime_strlen(x));
}

buffer allocate_buffer(heap h, bytes length);


static inline void buffer_write(buffer b, const void *source, bytes length)
{
    buffer_extend(b, length);
    runtime_memcpy(buffer_ref(b, buffer_length(b)), source, length);
    buffer_produce(b, length);
}

static inline void buffer_write_cstring(buffer b, const char *x)
{
    return buffer_write(b, x, runtime_strlen(x));
}

static inline boolean buffer_read(buffer b, void *dest, bytes length)
{
    if (buffer_length(b) < length) return(false);
    runtime_memcpy(dest, buffer_ref(b, 0), length);
    buffer_consume(b, length);
    return(true);
}

static inline void push_buffer(buffer d, buffer s)
{
    buffer_write(d, buffer_ref(s, 0), buffer_length(s));
}

static inline buffer clone_buffer(heap h, buffer b)
{
    buffer new = allocate_buffer(h, buffer_length(b));
    if (new == INVALID_ADDRESS)
        return new;
    push_buffer(new, b);
    return new;
}

void buffer_append(buffer b,
                   const void *body,
                   bytes length);

static inline buffer buffer_cstring(heap h, const char *x)
{
    int len = runtime_strlen(x);
    buffer b = allocate_buffer(h, len);
    buffer_append(b, x, len);
    return b;
}

// little endian variants
#define WRITE_BE(bits)                                          \
    static inline void buffer_write_be##bits(buffer b, u64 x)   \
    {                                                           \
        u64 k = (x);                                            \
        int len = bits>>3;                                      \
        buffer_extend((b), len);                                \
        u8 *n = buffer_ref((b), (b)->end);                      \
        for (int i = len-1; i >= 0; i--) {                      \
            n[i] = k & 0xff;                                    \
            k >>= 8;                                            \
        }                                                       \
        b->end += len;                                          \
    }

#define READ_BE(bits)                                   \
    static inline u64 buffer_read_be##bits(buffer b)    \
    {                                                   \
        u64 k = 0;                                      \
        int len = bits>>3;                              \
        u8 *n = buffer_ref((b), 0);                     \
        for (int i = 0; i < len; i++) {                 \
            k = (k << 8) | (*n++);                      \
        }                                               \
        (b)->start +=len;                               \
        return(k);                                      \
    }

WRITE_BE(64)
WRITE_BE(32)
WRITE_BE(16)
READ_BE(64)
READ_BE(32)
READ_BE(16)

static inline void buffer_write_le64(buffer b, u64 v)
{
    buffer_extend(b, sizeof(u64));
    *(u64 *)(b->contents + b->end) = v;
    b->end += sizeof(u64);
}

// end of buffer?
static inline u64 buffer_read_byte(buffer b)
{
    if (!buffer_length(b)) return -1;
    u64 r = *(u8 *)buffer_ref(b, 0);
    b->start += 1;
    return(r);
}

static inline void buffer_write_byte(buffer b, u8 x)
{
    buffer_extend(b, 1);                                  
    *(u8 *)buffer_ref(b, buffer_length(b)) = x;
    b->end += 1;
}

static inline buffer sub_buffer(heap h, 
                                buffer b,
                                bytes start,
                                bytes length)
{
    // copy?
    return(wrap_buffer(h, b->contents+(b->start+start), length));
}

void print_hex_buffer(buffer s, buffer b);

void print_byte(buffer b, u8 f);

void print_uuid(buffer b, u8 *uuid);

static inline void deallocate_buffer(buffer b)
{
    heap h = b->h;
    if (!b->wrapped)
        deallocate(h, b->contents, b->length);
    deallocate(h, b, sizeof(struct buffer));
}

static inline void copy_descriptor(buffer d, buffer s)
{
    d->contents = s->contents;
    d->start = s->start;
    d->end = s->end;
    d->length = s->length;
    d->wrapped = s->wrapped;
}

static inline boolean buffer_compare(void *za, void *zb)
{
    buffer a = za;
    buffer b = zb;
    int len = buffer_length(a);
    if (len != buffer_length(b)) return false;
    for (int i = 0 ; i < len; i++) {
        if (byte(a, i) != byte(b, i))
            return false;
    }
    return true;
}

static inline boolean buffer_compare_with_cstring(buffer b, const char *x)
{
    int len = buffer_length(b);
    for (int i = 0; i < len; i++) {
        if (byte(b, i) != x[i])
            return false;
        if (x[i] == '\0')       /* must terminate */
            return i == len - 1;
    }
    return x[len] == '\0';
}

static inline int buffer_memcmp(buffer b, void *mem, bytes n)
{
    bytes len = buffer_length(b);
    int ret = runtime_memcmp(buffer_ref(b, 0), mem, MIN(len, n));
    if (ret)
        return ret;
    else if (len < n)
        return -1;
    else
        return 0;
}

/* Can only be used with literal strings. */
#define buffer_strcmp(b, str)   ({  \
    int res = buffer_memcmp(b, str, sizeof(str) - 1);   \
    if (!res && buffer_length(b) >= sizeof(str))    \
        res = 1;    \
    res;    \
})

static inline int buffer_strchr(buffer b, int c)
{
    bytes len = buffer_length(b);
    for (bytes i = 0; i < len; i++) {
        if (byte(b, i) == c)
            return i;
    }
    return -1;
}

// the ascii subset..utf8 me
#define foreach_character(__i, __c, __s)                                \
    for (u32 __i = 0, __c, __limit = buffer_length(__s);                \
         __c = *(u8 *)buffer_ref((__s), (__i)), (__i) < __limit;        \
         (__i)++)
             

/* Beware: such allocations on the stack persist until the calling
   function returns to its caller, not necessarily at the end of the
   block. Therefore, avoid using little_stack_buffer within loops or
   in any case where it could blow the stack. */
#define little_stack_buffer(__length)                                   \
    ({                                                                  \
        buffer __b = stack_allocate(sizeof(struct buffer));             \
        __b->contents = stack_allocate(__length);                       \
        __b->start = 0;                                                 \
        __b->end = 0;                                                   \
        __b->length = (__length);                                       \
        __b->wrapped = true; /* it's not wrapped, but we don't want a resize */ \
        __b;                                                            \
    })

    
#define staticbuffer(__n) ({                    \
            static struct buffer b;             \
            b.contents = (__n);                 \
            b.start = 0;                        \
            b.end = sizeof(__n) -1;             \
            &b;})

static inline u8 pop_u8(buffer b)
{
    // bounds
    u8 x = *(u8 *)buffer_ref(b, 0);
    b->start++;
    return (x);
}

static inline void push_u8(buffer b, u8 x)
{
    buffer_extend(b, 1);
    *(u8 *)buffer_ref(b, buffer_length(b)) = x;
    b->end++;
}

static inline u32 buffer_read_le32(buffer b)
{
    // bounds
    u32 x = *(u32 *)buffer_ref(b, 0);
    b->start+=sizeof(u32);
    return (x);
}

static inline void buffer_write_le32(buffer b, u32 x)
{
    buffer_extend(b, sizeof(u32));
    *(u32 *)buffer_ref(b, buffer_length(b)) = x;
    b->end+=sizeof(u32);
}

static inline void push_varint(buffer b, u64 x)
{
    int last = 0;
    u8 tmp[10];               /* max (pad(64, 7) / 7) 7-bit strides */
    tmp[0] = x & 0x7f;
    x >>= 7;
    while (x) {
        tmp[++last] = 0x80 | (x & 0x7f);
        x >>= 7;
    }
    for (int i = last; i >= 0; i--)
        push_u8(b, tmp[i]);
}

static inline u64 pop_varint(buffer b)
{
    u64 out = 0;
    u64 m;
    do {
        m = pop_u8(b);
        out = (out << 7) | (m & MASK(7));
    } while (m & 0x80);
    return out;
}

static inline key fnv64(void *z)
{
    buffer b = z;
    u64 hash = 0xcbf29ce484222325;
    u64 fnv_prime = 1099511628211;
    for (int i = 0; i < buffer_length(b); i++) {
        hash ^= byte(b, i);
        hash *= fnv_prime;
    }
    return hash;
}

static inline void buffer_print(buffer b)
{
    // should probably use foreach_character() once it supports UTF-8 properly
    console_write(buffer_ref(b, 0), buffer_length(b));
}
