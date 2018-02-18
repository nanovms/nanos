
struct buffer {
    bytes start;
    bytes end;
    bytes length;
    heap h;
    void *contents;
};


#define alloca_wrap_buffer(__b, __l) ({           \
  buffer b = alloca(sizeof(struct buffer));   \
  b->contents =(void *) __b;                  \
  b->end = b->length = __l;\
  b->start  =0 ;\
  b->h = 0;\
  b;\
  })


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

static inline void *buffer_ref(buffer b, bytes offset)
{
    // alignment?
    return((void *)b->contents + (b->start + offset));
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
        // shouldn't need to 
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


static inline buffer push_buffer(buffer d, buffer s)
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

void buffer_read_field(buffer b,
                       bytes offset, 
                       void *dest,
                       bytes length);

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
    *(u64 *)buffer_ref(b, b->end) = v;
    b->end += sizeof(u64);
}

static inline u64 buffer_read_byte(buffer b)
{
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

static void push_character(buffer b, character x)
{
    buffer_extend(b, 1);
    *(u8 *)(b->contents + b->end) = x;
    b->end ++ ;
}

static inline boolean buffer_compare(void *za, void *zb)
{
    buffer a = za;
    buffer b = zb;
    int len = buffer_length(a);
    if (len != buffer_length(b)) return false;
    for (int i = 0 ; i < len; i++) 
        if (byte(a, i) != byte(b, i))
            return false;
    return true;
}


// the ascii subset..utf8 me
#define foreach_character(__i, __s)                          \
    for (u32 __x = 0, __i, __limit = buffer_length(__s);   \
         __i = *(u8 *)buffer_ref(__s, __x), __x<__limit;    \
         __x++)
             

#define little_stack_buffer(__name, __length)    \
    unsigned char __name##__contents[__length];\
    struct buffer __name_##_buffer;\
    buffer __name = &__name_##_buffer;\
    __name->contents = __name##__contents;\
    __name->start = 0;\
    __name->end = 0;\
    __name->length = __length;

    
#define staticbuffer(__n) ({ \
    static struct buffer b;\
    b.contents = __n;\
    b.start = 0;\
    b.end = sizeof(__n) -1;\
    &b;})


