typedef buffer vector;

static inline void *vector_get(vector v, int offset)
{
    bytes boffset = offset * sizeof(void *);
    if (offset < 0 || boffset + sizeof(void *) > buffer_length(v))
        return 0;

    return *(void **)buffer_ref(v, boffset);
}

static inline boolean vector_set(vector v, int offset, void *value)
{
    if (!extend_total(v, (offset + 1) * sizeof(void *)))
        return false;
    ((void **)(v->contents + v->start))[offset] = value;
    return true;
}

static inline int vector_length(vector v)
{
    return buffer_length(v)/sizeof(void *);
}

static inline void vector_clear(vector v)
{
    v->start = v->end = 0;
}

static inline void *vector_delete(vector v, int offset)
{
    void *res;
    bytes base = v->start + offset * sizeof(void *);
    if ((base + sizeof(void *)) > v->end) {
        return 0;
    }
    runtime_memcpy(&res, v->contents + base, sizeof(void *));
    int len = vector_length(v);
    for (; offset < len - 1; offset++) {
        base = v->start + offset * sizeof(void *);
        runtime_memcpy(v->contents + base, v->contents + base + sizeof(void *),
                sizeof(void *));
    }
    v->end -= sizeof(void *);
    return res;
}

static inline int vector_delete_range(vector v, int start, int end)
{
    bytes start_offset = v->start + start * sizeof(void *);
    bytes end_offset = v->start + end * sizeof(void *);
    end_offset = MIN(end_offset, v->end);
    if (end_offset <= start_offset)
        return 0;
    if (end_offset < v->end)
        runtime_memcpy(v->contents + start_offset, v->contents + end_offset, v->end - end_offset);
    v->end -= end_offset - start_offset;
    return (end_offset - start_offset) / sizeof(void *);
}

static inline vector allocate_vector(heap h, int length)
{
    return allocate_buffer(h, length * sizeof (void *));
}

static inline void deallocate_vector(vector v)
{
    deallocate_buffer((buffer)v);
}

static inline void vector_push(vector v, void *i)
{
    assert(buffer_extend(v, sizeof(void *)));
    *((void **)(v->contents + v->end)) = i;
    v->end += sizeof(void *);
}

static inline void *vector_peek(vector v)
{
    if ((v->end - v->start) < sizeof(void *))
        return 0;
    return *(void **)(v->contents + v->end - sizeof(void *));
}

static inline void *vector_pop(vector v)
{
    if ((v->end - v->start) < sizeof(void *))
        return 0;

    v->end -= sizeof(void *);
    return *((void **)(v->contents + v->end));
}

static inline void vector_consume(vector v, int n)
{
    buffer_consume(v, n * sizeof(void *));
}

static inline vector split(heap h, buffer source, char divider)
{
    vector result = allocate_vector(h, 10);
    buffer each = allocate_buffer(h, 10);
    foreach_character(_, i, source) {
        if (i == divider)  {
            vector_push(result, each);
            each = allocate_buffer(h, 10);
        } else {
            push_character(each, i);
        }
    }
    if (buffer_length(each) > 0)
        vector_push(result, each);
    else
        deallocate_buffer(each);
    return result;
}

static inline buffer join(heap h, vector source, char between)
{
    buffer out = allocate_buffer(h, 100);
    for (int i = 0; i < vector_length(source); i++){
        if (i) push_character(out, between);
        assert(push_buffer(out, vector_get(source, i)));
    }
    return out;
}

#define vector_foreach(__v, __i) for(u32 _i = 0, _len = vector_length(__v); _i< _len && (__i = vector_get(__v, _i), 1); _i++)

static inline void split_dealloc(vector v)
{
    buffer b;
    vector_foreach(v, b) {
        deallocate_buffer(b);
    }
    deallocate_vector(v);
}

static inline void bitvector_set(buffer b, int position)
{
    assert(extend_total(b, pad(position, 8)>>3));
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

void init_vectors(heap h, heap init);

vector allocate_tagged_vector(int length);

