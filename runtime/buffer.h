
// consider -
//   adding a stride
//   going back to using bit offsets
struct buffer {
    bytes start;
    bytes end;
    bytes length;
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

#define alloca_wrap_buffer(__b, __l) ({           \
  buffer b = __builtin_alloca(sizeof(struct buffer));   \
  b->contents =(void *) __b;                  \
  b->end = b->length = __l;\
  b->start  =0 ;\
  b->h = 0;\
  b;\
  })

#define alloca_wrap(__z) alloca_wrap_buffer(buffer_ref(__z, 0), buffer_length(__z))

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
    return(b->end - b->start);
} 

static inline void buffer_extend(buffer b, bytes len)
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

static inline void extend_total(buffer b, int offset)
{
    if (offset > b->end) {
        buffer_extend(b, offset - b->end);
        // shouldn't need to in all cases - this is to preserve
        // the idea of the vector as a mapping - we need a reliable
        // sigleton to denote an empty slot
        zero(b->contents + b->end, offset - b->end);
        b->end = offset;
    }
}


static inline buffer wrap_buffer(heap h,
                                 void *body,
                                 bytes length)
{
    buffer new = allocate(h, sizeof(struct buffer));
    new->contents = body;
    new->start = 0;
    new->end = length;
    new->length = length;
    return(new);
}

buffer allocate_buffer(heap h, bytes length);


static inline void buffer_write(buffer b, void *source, bytes length)
{
    buffer_extend(b, length);
    runtime_memcpy(buffer_ref(b, b->end-b->start), source, length);
    buffer_produce(b, length);
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


void buffer_copy(buffer dest, bytes doff,
                 buffer source, bytes soff,
                 bytes length);

void buffer_write(buffer b, void *source, bytes length);
boolean buffer_read(buffer b, void *dest, bytes length);

void buffer_append(buffer b,
                   void *body,
                   bytes length);

void buffer_prepend(buffer b,
                      void *body,
                      bytes length);

// little endian variants
#define WRITE_BE(bits)\
   static inline void buffer_write_be##bits(buffer b, u64 x)   \
  {                                                            \
      u64 k = x;                                               \
      int len = bits>>3;                                       \
      buffer_extend(b, len);                                   \
      u8 *n = buffer_ref(b, b->end);                                 \
      for (int i = len-1; i >= 0; i--) {                       \
          n[i] = k & 0xff;                                     \
          k >>= 8;                                             \
      }                                                        \
      b->end += len;                                           \
  }

#define READ_BE(bits)                                            \
    static inline u64 buffer_read_be##bits(buffer b)             \
    {                                                            \
        u64 k = 0;                                               \
        int len = bits>>3;                                       \
        u8 *n = buffer_ref(b, 0);                                      \
        for (int i = 0; i < len; i++) {                          \
            k = (k << 8) | (*n++);                               \
        }                                                        \
        b->start +=len;                                          \
        return(k);                                               \
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

static inline void deallocate_buffer(buffer b)
{
    heap h = b->h;
    deallocate(h, b->contents, b->length);
    deallocate(h, b, sizeof(struct buffer));
}

static inline void copy_descriptor(buffer d, buffer s)
{
    d->contents = s->contents;
    d->start = s->start;
    d->end = s->end;
    d->length = s->length;                    
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


// the ascii subset..utf8 me
#define foreach_character(__i, __s)                          \
    for (u32 __x = 0, __i, __limit = buffer_length(__s);   \
         __i = *(u8 *)buffer_ref(__s, __x), __x<__limit;    \
         __x++)
             

// alternate stack, real heap, say no to alloca
#define little_stack_buffer(__length)\
    ({\
    buffer __b = stack_allocate(sizeof(struct buffer));\
    __b->contents = stack_allocate(__length);\
    __b->start = 0;\
    __b->end = 0;\
    __b->length = __length;\
    __b;\
   })

    
#define staticbuffer(__n) ({ \
    static struct buffer b;\
    b.contents = __n;\
    b.start = 0;\
    b.end = sizeof(__n) -1;\
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
    *(u8 *)buffer_ref(b, b->end) = x;
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
    *(u32 *)buffer_ref(b, b->end) = x;
    b->end+=sizeof(u32);
}

static inline void push_varint(buffer b, u64 p)
{
    u64 k = p;
    while (k > 127) {
        push_u8(b, 0x80 | (k&MASK(7)));
        k >>= 7;
    }
    push_u8(b, k);
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

