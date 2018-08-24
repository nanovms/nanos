
typedef buffer vector;

static inline void *vector_get(vector v, int offset)
{
    void *res;
    bytes base = v->start + offset * sizeof(void *);
    if ((base + sizeof(void *)) > v->end)
        // should be INVALID_VIRTUAL (? )
        return 0;
    
    runtime_memcpy(&res, v->contents + base, sizeof(void *));
    return res;
}

static inline void vector_set(vector v, int offset, void *value)
{
    extend_total(v, (offset + 1) *sizeof(void *));
    runtime_memcpy(v->contents + offset * sizeof(void*), &value, sizeof(void *));
}

static inline int vector_length(vector v)
{
    return buffer_length(v)/sizeof(void *);
}

static inline vector allocate_vector(heap h, int length)
{
    return allocate_buffer(h, length * sizeof (void *));
}

static void vector_push(vector v, void *i)
{
    buffer_extend(v, sizeof(void *));
    runtime_memcpy(v->contents + v->end, &i, sizeof(void *));
    v->end += sizeof(void *);
}

static void *vector_peek(vector v)
{
    if ((v->end - v->start) < sizeof(void *))
        return 0;
    return *(void **)(v->contents + v->start);
}

static void *vector_pop(vector v)
{
    if ((v->end - v->start) < sizeof(void *))
        return 0;
    
    void *res;
    runtime_memcpy(&res, v->contents + v->start, sizeof(void *));
    v->start += sizeof(void *);
    return res;
}

static inline vector split(heap h, buffer source, char divider)
{
    vector result = allocate_vector(h, 10);
    buffer each = allocate_buffer(h, 10);
    foreach_character(i, source) {
        if (i == divider)  {
            vector_push(result, each);
            each = allocate_buffer(h, 10);
        } else {
            push_character(each, i);
        }
    }
    if (buffer_length(each) > 0)  vector_push(result, each);
    return result;
}

static inline buffer join(heap h, vector source, char between)
{
    buffer out = allocate_buffer(h, 100);
    for (int i = 0; i < vector_length(source); i++){
        if (i) push_character(out, between);
        push_buffer(out, vector_get(source, i));
    }
    return out;
}

#define vector_foreach(__v, __i) for(u32 _i = 0, _len = vector_length(__v); _i< _len && (__i = vector_get(__v, _i), 1); _i++)

static inline void bitvector_set(buffer b, int position)
{
    extend_total(b, pad(position, 8)>>3);
    ((u8 *)b->contents)[position>>3] |= (1<<(position & 7));
}

static inline vector build_vector_internal(heap h, ...)
{
    vlist ap;
    vstart(ap, h);
    u64 x;
    vector v = allocate_vector(h, 10);
    while (x = varg(ap, u64), x != INVALID_PHYSICAL) {
        vector_push(v, pointer_from_u64(x));
    }
    return v;
}

#define build_vector(_h, ...) build_vector_internal(_h, __VA_ARGS__, INVALID_PHYSICAL)                       
