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

#define buffer_assert(x) assert(x)

/* ascii string helpers */
#define isupper(a) (((u8)(a)-(u8)'A') < 26)
#define tolower(a) (isupper(a) ? ((a) | 0x20) : (a))

static inline void init_buffer(buffer b, bytes s, boolean wrapped, heap h, void *contents)
{
    b->start = 0;
    b->end = 0;
    b->length = s;
    b->wrapped = wrapped;
    b->h = h;
    b->contents = contents;
}

static inline void *buffer_ref(buffer b, bytes offset)
{
    buffer_assert(b->start + offset <= b->length);
    // alignment?
    return((void *)b->contents + (b->start + offset));
}

static inline bytes buffer_length(buffer b)
{
    return b->end - b->start;
}

static inline void *buffer_end(buffer b)
{
    return b->contents + b->end;
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

#define alloca_wrap_sstring(s)  ({          \
    sstring __s = s;                        \
    alloca_wrap_buffer(__s.ptr, __s.len);   \
})

#define alloca_wrap_cstring(__x) alloca_wrap_sstring(ss(__x))

#define alloca_wrap(__z) alloca_wrap_buffer(buffer_ref((__z), 0), buffer_length(__z))

#define byte(__b, __i) *(u8 *)((__b)->contents + (__b)->start + (__i))

static inline sstring buffer_to_sstring(buffer b)
{
    return isstring(buffer_ref(b, 0), buffer_length(b));
}

#define buffer_to_cstring(__b) ({                           \
            bytes len = buffer_length(__b);                 \
            char *str = stack_allocate(len + 1);            \
            runtime_memcpy(str, buffer_ref(__b, 0), len);   \
            str[len] = '\0';                                \
            str;                                            \
        })

static inline void buffer_clear(buffer b)
{
    b->start = b->end = 0;
}

static inline void buffer_consume(buffer b, bytes s)
{
    buffer_assert(b->start + s <= b->end);
    buffer_assert(b->end <= b->length);
    b->start += s;
}

static inline void buffer_produce(buffer b, bytes s)
{
    buffer_assert(b->start <= b->end);
    buffer_assert(b->end + s <= b->length);
    b->end += s;
}

static inline bytes buffer_space(buffer b)
{
    return b->length - b->end;
}

static inline boolean buffer_is_wrapped(buffer b)
{
    return b->wrapped;
}

static inline bytes buffer_set_capacity(buffer b, bytes len)
{
    if (buffer_is_wrapped(b))   /* wrapped buffers can't be resized */
        return b->length;
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
        if (new_len > b->length) {
            return (buffer_set_capacity(b, new_len) == new_len);
        } else {
            /* no need to resize, move current contents to the beginning of the allocated memory */
            runtime_memcpy(b->contents, b->contents + b->start, b->end - b->start);
            b->end -= b->start;
            b->start = 0;
        }
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
    if (new == INVALID_ADDRESS)
        return new;
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

buffer allocate_buffer(heap h, bytes length);


static inline boolean buffer_write(buffer b, const void *source, bytes length)
{
    if (!buffer_extend(b, length))
        return false;
    runtime_memcpy(buffer_ref(b, buffer_length(b)), source, length);
    buffer_produce(b, length);
    return true;
}

static inline boolean buffer_write_sstring(buffer b, sstring s)
{
    return buffer_write(b, s.ptr, s.len);
}

#define buffer_write_cstring(b, x)  buffer_write_sstring(b, ss(x))

static inline boolean buffer_read(buffer b, void *dest, bytes length)
{
    if (buffer_length(b) < length) return(false);
    runtime_memcpy(dest, buffer_ref(b, 0), length);
    buffer_consume(b, length);
    return(true);
}

static inline bytes buffer_read_at(buffer b, bytes offset, void *dest, bytes length)
{
    bytes available = buffer_length(b);
    if (available <= offset)
        return 0;
    length = MIN(length, available - offset);
    runtime_memcpy(dest, buffer_ref(b, offset), length);
    return length;
}

static inline boolean push_buffer(buffer d, buffer s)
{
    return buffer_write(d, buffer_ref(s, 0), buffer_length(s));
}

static inline buffer clone_buffer(heap h, buffer b)
{
    buffer new = allocate_buffer(h, buffer_length(b));
    if (new == INVALID_ADDRESS)
        return new;
    buffer_assert(push_buffer(new, b));
    return new;
}

boolean buffer_append(buffer b,
                   const void *body,
                   bytes length);

#define BUF_WRITE_ENDIAN(_bits, _endian)                                        \
    static inline boolean buffer_write_##_endian##_bits(buffer b, u##_bits x)   \
    {                                                                           \
        int len = _bits >> 3;                                                   \
        if (!buffer_extend(b, len))                                             \
            return false;                                                       \
        u##_bits *p = b->contents + b->end;                                     \
        *p = hto##_endian##_bits(x);                                            \
        b->end += len;                                                          \
        return true;                                                            \
    }

#define BUF_READ_ENDIAN(_bits, _endian)                             \
    static inline u##_bits buffer_read_##_endian##_bits(buffer b)   \
    {                                                               \
        int len = _bits >> 3;                                       \
        u##_bits *p = b->contents + b->start;                       \
        b->start += len;                                            \
        return _endian##_bits##toh(*p);                             \
    }

BUF_WRITE_ENDIAN(16, le)
BUF_WRITE_ENDIAN(32, le)
BUF_WRITE_ENDIAN(64, le)
BUF_READ_ENDIAN(16, le)
BUF_READ_ENDIAN(32, le)
BUF_READ_ENDIAN(64, le)

BUF_WRITE_ENDIAN(16, be)
BUF_WRITE_ENDIAN(32, be)
BUF_WRITE_ENDIAN(64, be)
BUF_READ_ENDIAN(16, be)
BUF_READ_ENDIAN(32, be)
BUF_READ_ENDIAN(64, be)

// end of buffer?
static inline u64 buffer_read_byte(buffer b)
{
    if (!buffer_length(b)) return -1;
    u64 r = *(u8 *)buffer_ref(b, 0);
    b->start += 1;
    return(r);
}

static inline boolean buffer_write_byte(buffer b, u8 x)
{
    if (!buffer_extend(b, 1))
        return false;
    *(u8 *)buffer_ref(b, buffer_length(b)) = x;
    b->end += 1;
    return true;
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

static inline boolean buffer_lt(buffer a, buffer b)
{
    int alen = buffer_length(a);
    int blen = buffer_length(b);
    for (int i = 0; i < blen; i++) {
        if (i >= alen ||
            byte(a, i) < byte(b, i))
            return true;
        if (byte(a, i) > byte(b, i))
            return false;
    }
    return false;
}

int buffer_compare_with_sstring(buffer b, sstring x);
int buffer_compare_with_sstring_ci(buffer b, sstring x);

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
#define buffer_strcmp(b, str)       buffer_compare_with_sstring(b, ss(str))
#define buffer_strcasecmp(b, str)   buffer_compare_with_sstring_ci(b, ss(str))

static inline int buffer_strchr(buffer b, int c)
{
    bytes len = buffer_length(b);
    for (bytes i = 0; i < len; i++) {
        if (byte(b, i) == c)
            return i;
    }
    return -1;
}

static inline int buffer_strrchr(buffer b, int c)
{
    for (s64 len = buffer_length(b) - 1; len >= 0; len--) {
        if (byte(b, len) == c)
            return len;
    }
    return -1;
}

int buffer_strstr(buffer b, sstring str);

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
        ((u8 *)__b->contents)[0] = 0; /* quiet uninitialized warning */ \
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
    buffer_assert(b->start + 1 <= b->end);
    buffer_assert(b->end <= b->length);
    // bounds
    u8 x = *(u8 *)buffer_ref(b, 0);
    b->start++;
    return (x);
}

static inline void push_u8(buffer b, u8 x)
{
    buffer_assert(buffer_extend(b, 1));
    buffer_assert(b->start <= b->end);
    buffer_assert(b->end < b->length);
    *(u8 *)buffer_ref(b, buffer_length(b)) = x;
    b->end++;
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

void buffer_print(buffer b);

/* modifies the original buffer, buffer must be a string */
static inline buffer buffer_basename(buffer b)
{
    int p;

    if (buffer_length(b) <= 1)
        return b;
    if ((p = buffer_strrchr(b, '/')) != -1) {
        if (p == buffer_length(b) - 1) {
            b->end--;
            if ((p = buffer_strrchr(b, '/')) == -1 || buffer_length(b) == 1)
                return b;
        }
        buffer_consume(b, p + 1);
    }
    return b;
}
