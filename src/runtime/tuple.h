union tuple;
typedef union tuple *tuple;

closure_type(tuple_generator, tuple);
closure_type(tuple_get, value, value k);
closure_type(tuple_set, void, value k, value v);
closure_type(binding_handler, boolean, value k, value v);
closure_type(tuple_iterate, boolean, binding_handler h);

typedef struct function_tuple {
    tuple_get g;
    tuple_set s;
    tuple_iterate i;
} *function_tuple;

union tuple {
    struct table t;
    struct function_tuple f;
};

value get(value e, value a);
void set(value e, value a, value v);
boolean iterate(value e, binding_handler h);

void init_integers(heap iheap);
void init_tuples(heap theap);
int tuple_count(tuple t);
symbol tuple_get_symbol(tuple t, value v);
tuple allocate_tuple();
tuple clone_tuple(tuple t);
void destruct_value(value v, boolean recursive);
void deallocate_value(value t);

void encode_tuple(buffer dest, table dictionary, tuple t, u64 *total);

// h is for the bodies, the space for symbols and tuples are both implicit
void *decode_value(heap h, table dictionary, buffer source, u64 *total,
                   u64 *obsolete, boolean old_encoding);
void encode_eav(buffer dest, table dictionary, tuple e, symbol a, value v,
                u64 *obsolete);

value indirect_integer_from_u64(u64 n);
value indirect_integer_from_s64(s64 n);

static inline boolean is_tuple(value v)
{
    value_tag tag = tagof(v);
    return tag == tag_table_tuple || tag == tag_function_tuple;
}

static inline boolean is_symbol(value v)
{
    return tagof(v) == tag_symbol;
}

/* need to allow untyped buffers until we drop support for old encodings */
static inline boolean is_string(value v)
{
    return tagof(v) == tag_string || tagof(v) == tag_unknown;
}

static inline boolean is_vector(value v)
{
    return tagof(v) == tag_vector;
}

static inline boolean is_untyped(value v)
{
    return tagof(v) == tag_unknown;
}

static inline boolean is_integer(value v)
{
    return tagof(v) == tag_integer;
}

boolean is_composite(value v);

/* we're lax about typing here as these are sometimes used on alloca-wrapped buffers */
static inline boolean u64_from_value(value v, u64 *result)
{
    if (is_immediate_integer(v)) {
        *result = u64_from_tagged_immediate(v);
        return true;
    }
    if (!(is_string(v) || is_integer(v)))
        return false;
    return parse_int(alloca_wrap((buffer)v), 10, result);
}

static inline boolean s64_from_value(value v, s64 *result)
{
    if (is_immediate_integer(v)) {
        *result = s64_from_tagged_immediate(v);
        return true;
    }
    if (!(is_string(v) || is_integer(v)))
        return false;
    return parse_signed_int(alloca_wrap((buffer)v), 10, result);
}

static inline boolean is_signed_integer_value(value v)
{
    if (is_immediate_integer(v))
        return s64_from_tagged_immediate(v) < 0;
    if (!(is_string(v) || is_integer(v)))
        return false;
    return is_signed_int_string((buffer)v);
}

static inline value value_from_u64(u64 n)
{
    if (n > IMM_UINT_MAX)
        return indirect_integer_from_u64(n);
    return tagged_immediate_unsigned(n);
}

static inline value value_from_s64(s64 n)
{
    if (n > IMM_SINT_MAX || n < IMM_SINT_MIN)
        return indirect_integer_from_s64(n);
    return tagged_immediate_signed(n);
}

static inline value integer_key(u64 n)
{
    return value_from_u64(n);
}

static inline value value_rewrite_u64(value v, u64 n)
{
    if (is_immediate_integer(v))
        return tagged_immediate_unsigned(n);
    assert(is_string(v) || is_integer(v));
    buffer_clear((buffer)v);
    print_number((buffer)v, n, 10, 0, false);
    return v;
}

static inline value value_rewrite_s64(value v, s64 n)
{
    if (is_immediate_integer(v))
        return tagged_immediate_signed(n);
    assert(is_string(v) || is_integer(v));
    buffer_clear((buffer)v);
    print_signed_number((buffer)v, n, 10, 0, false);
    return v;
}

/* XXX questionable part of interface */
static inline tuple find_or_allocate_tuple(tuple t, symbol s)
{
    value v = get(t, s);
    assert(v != INVALID_ADDRESS);
    if (!v)
        return allocate_tuple();
    assert(is_tuple(v));
    return (tuple)v;
}

/* get and validate that result is a tuple type */
static inline tuple get_tuple(value e, symbol a)
{
    value v = get(e, a);
    return (v && is_tuple(v)) ? v : 0;
}

/* get and validate that result is a vector type */
static inline vector get_vector(value e, symbol a)
{
    value v = get(e, a);
    return (v && is_vector(v)) ? v : 0;
}

/* TODO - change to validate string tag type */
static inline string get_string(value e, symbol a)
{
    value v = get(e, a);
    return (v && is_string(v)) ? v : 0;
}

static inline boolean get_u64(value e, symbol a, u64 *result)
{
    value v = get(e, a);
    if (!v)
        return false;
    return u64_from_value(v, result);
}

/* really just for parser output */
static inline boolean is_null_string(value v)
{
    return is_string(v) && buffer_length(v) == 0;
}

static inline symbol sym_from_attribute(value a)
{
    if (is_symbol(a))
        return a;
    u64 x;
    if (u64_from_value(a, &x))
        return intern_u64(x);
    return 0;
}

static inline boolean u64_from_attribute(value a, u64 *x)
{
    /* must check if immediate first; if so, tagof not valid boot targets */
    if (is_immediate_integer(a))
        return u64_from_value(a, x);
    if (is_symbol(a) || is_integer(a))
        return parse_int(alloca_wrap(symbol_string(a)), 10, x);
    return false;
}
