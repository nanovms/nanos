#include <runtime.h>

//#define TUPLE_DEBUG
#if defined(TUPLE_DEBUG)
#define tuple_debug(x, ...) do { rprintf("TUPLE: " x, ##__VA_ARGS__); } while(0)
#else
#define tuple_debug(x, ...)
#endif

BSS_RO_AFTER_INIT tuple timm_oom;

BSS_RO_AFTER_INIT static heap theap;
BSS_RO_AFTER_INIT static heap iheap;

#define type_buffer  0          /* untyped storage */
#define type_tuple   1
#define type_vector  2
#define type_integer 3
#define type_string  4

#define immediate 1
#define reference 0

const sstring tag_names[tag_max] = {
    ss_static_init("unknown"),
    ss_static_init("string"),
    ss_static_init("symbol"),
    ss_static_init("table-backed tuple"),
    ss_static_init("function-backed tuple"),
    ss_static_init("vector"),
    ss_static_init("integer"),
};

static inline void validate_tag_type(sstring fn, value v, u16 tag)
{
    if (tag >= tag_max)
        halt("%s: value %p has invalid tag type %d\n", fn, v, tag);
}

value indirect_integer_from_u64(u64 n)
{
    buffer result = allocate_buffer(iheap, 10);
    print_number(result, n, 10, 0, false);
    return (value)result;
}

value indirect_integer_from_s64(s64 n)
{
    buffer result = allocate_buffer(iheap, 10);
    print_signed_number(result, n, 10, 0, false);
    return (value)result;
}

value get(value e, value a)
{
    u16 tag = tagof(e);
    tuple t = (tuple)e;
    validate_tag_type(func_ss, e, tag);

    switch (tag) {
    case tag_table_tuple:
        return (a = sym_from_attribute(a)) ? table_find(&t->t, a) : 0;
    case tag_function_tuple:
        return apply(t->f.g, a);
    case tag_vector: {
        u64 i;
        if (u64_from_attribute(a, &i))
            return vector_get((vector)e, i);
        return 0;
    }
    default:
        halt("cannot get from %s value (e %p, a %p)\n", tag_names[tag], e, a);
    }
}

void set(value e, value a, value v)
{
    u16 tag = tagof(e);
    tuple t = (tuple)e;
    validate_tag_type(func_ss, e, tag);

    switch (tag) {
    case tag_table_tuple:
        assert(a = sym_from_attribute(a));
        table_set(&t->t, a, v);
        break;
    case tag_function_tuple:
        apply(t->f.s, a, v);
        break;
    case tag_vector: {
        u64 i;
        assert(u64_from_attribute(a, &i));
        vector_set((vector)e, i, v);
        break;
    }
    default:
        halt("cannot set on %s value (e %p, a %p, v %p)\n", tag_names[tag], e, a, v);
    }
}

boolean iterate(value e, binding_handler h)
{
    u16 tag = tagof(e);
    tuple t = (tuple)e;
    validate_tag_type(func_ss, e, tag);
    switch (tag) {
    case tag_table_tuple:
        table_foreach(&t->t, a, v) {
            if (!apply(h, a, v))
                return false;
        }
        return true;
    case tag_function_tuple:
        return apply(t->f.i, h);
    case tag_vector: {
        for (int i = 0; i < vector_length((vector)e); i++) {
            value v = vector_get((vector)e, i);
            if (!apply(h, integer_key(i), v))
                return false;
        }
        return true;
    }
    default:
        halt("cannot iterate on %s value (e %p, h %p)\n", tag_names[tag], e, h);
    }
}

boolean is_composite(value v)
{
    switch (tagof(v)) {
    case tag_table_tuple:
    case tag_function_tuple:
    case tag_vector:
        return true;
    default:
        return false;
    }
}

closure_function(1, 2, boolean, tuple_count_each,
                 int *, count,
                 value s, value v)
{
    assert(is_symbol(s));
    (*bound(count))++;
    return true;
}

int tuple_count(tuple t)
{
    u16 tag = tagof(t);
    int count = 0;
    switch (tag) {
    case tag_table_tuple:
        return t->t.count;
    case tag_function_tuple:
        apply(t->f.i, stack_closure(tuple_count_each, &count));
        return count;
    default:
        halt("%s: t %p is not a tuple (tag %d)\n", func_ss, t, tag);
    }
}

closure_function(2, 2, boolean, tuple_get_symbol_each,
                 value, val, symbol *, sym,
                 value s, value v)
{
    if (v != bound(val))
        return true;
    *bound(sym) = s;
    return false;
}

symbol tuple_get_symbol(tuple t, value v)
{
    symbol sym = 0;
    iterate(t, stack_closure(tuple_get_symbol_each, v, &sym));
    return sym;
}

static inline void drecord(table dictionary, void *x)
{
    u64 count = dictionary->count + 1;
    tuple_debug("drecord: dict %p, index 0x%lx <-> x %p\n", dictionary, count, x);
    table_set(dictionary, pointer_from_u64(count), x);
}

static inline void srecord(table dictionary, void *x)
{
    u64 count = dictionary->count + 1;
    tuple_debug("srecord: dict %p, x %p -> index 0x%lx\n", dictionary, x, count);
    table_set(dictionary, x, pointer_from_u64(count));
}

// decode dictionary can really be a vector
// region?
tuple allocate_tuple(void)
{
    return (tuple)allocate_table(theap, key_from_symbol, pointer_equal);
}

closure_function(1, 2, boolean, clone_tuple_each,
                 tuple, clone,
                 value s, value v)
{
    if (!is_immediate(v) && (v != null_value)) {
        value_tag tag = tagof(v);
        switch (tag) {
        case tag_symbol:
            break;
        case tag_table_tuple:
            v = clone_tuple(v);
            break;
        case tag_function_tuple:
            break;
        default:
            v = clone_buffer(((buffer)v)->h, v);
        }
        if (v == INVALID_ADDRESS)
            return false;
    }
    set(bound(clone), s, v);
    return true;
}

tuple clone_tuple(tuple t)
{
    tuple clone = allocate_tuple();
    if (clone != INVALID_ADDRESS) {
        if (!iterate(t, stack_closure(clone_tuple_each, clone))) {
            destruct_value(clone, true);
            clone = INVALID_ADDRESS;
        }
    }
    return clone;
}

closure_function(2, 2, boolean, destruct_value_each,
                 value, v, boolean, recursive,
                 value s, value v)
{
    if (is_composite(v)) {
        if (bound(recursive))
            destruct_value(v, true);
    } else if (v != null_value) {
        deallocate_value(v);
    }
    return true;
}

void destruct_value(value v, boolean recursive)
{
    if (is_composite(v))
        iterate(v, stack_closure(destruct_value_each, v, recursive));
    deallocate_value(v);
}

tuple timm_clone(tuple t)
{
    if ((t == STATUS_OK) || (t == timm_oom))
        return t;
    t = clone_tuple(t);
    return (t != INVALID_ADDRESS) ? t : timm_oom;
}

closure_function(1, 2, boolean, timm_dealloc_each,
                 tuple, t,
                 value s, value v)
{
    if (tagof(v) == tag_string)
        deallocate_string((string)v);
    else
        timm_dealloc((tuple)v);
    return true;
}

void timm_dealloc(tuple t)
{
    if ((t != STATUS_OK) && (t != timm_oom)) {
        iterate(t, stack_closure(timm_dealloc_each, t));
        deallocate_table(&t->t);
    }
}

// header: immediate(1)
//         type(3) (1 if old_encoding)
//         varint encoded unsigned
// no error path
static u64 pop_header(buffer f, boolean *imm, u8 *type, boolean old_encoding)
{
    u8 a = pop_u8(f);
    tuple_debug("pop %x\n", a);
    *imm = a>>7;
    *type = old_encoding ? ((a>>6) & 1) : ((a>>4) & 0x7);
    
    u64 len = a & (old_encoding ? 0x1f : 0x7);
    if (a & (old_encoding ? (1<<5) : (1<<3))) {
        do {
            a = pop_u8(f);
            tuple_debug("pop %x extra\n", a);
            len = (len<<7) | (a & 0x7f);
        } while(a & 0x80);
    }
    tuple_debug("header: %s type %d len %lx\n", (*imm) ? ss("immediate") : ss("reference"),
                *type, len);
    return len;
}

static void push_header(buffer b, boolean imm, u8 type, u64 length)
{
    // is msb off by one?
    int bits = msb(length) + 1;
    int words = 0;
    // (imm type ext) 
    if (bits > 3)
        words = ((bits - 3) + (7 - 1)) / 7;
    assert(buffer_extend(b, words + 1));

    tuple_debug("push header: %s type %d length:0x%lx bits:%d words:%d\n",
                imm ? ss("immediate") : ss("reference"), type, length, bits, words);
    assert(type < 8);
    u8 first = (imm << 7) | (type << 4) | (((words)?1:0)<<3) | (length >> (words * 7));
    tuple_debug("push %x\n", first);
    push_u8(b, first);

    int i = words;
    while (i-- > 0) {
        u8 v = ((length >> (i * 7)) & 0x7f) | (i ? 0x80 : 0);
        tuple_debug("push %x extra\n", v);
        push_u8(b, v);
    }
}

static void set_new_value(value e, value a, heap h, table dictionary, buffer source, u64 *total, u64 *obsolete, boolean old_encoding)
{
    tuple_debug("%s: e %p, a %v\n", func_ss, e, a);
    value nv = decode_value(h, dictionary, source, total, obsolete, old_encoding);
    if (obsolete) {
        value old_v = get(e, a);
        if (old_v) {
            (*obsolete)++;
            if (!nv)
                (*obsolete)++;
        }
    }
    set(e, a, nv);
    if (total)
        (*total)++;
}

/* TODO: proper error handling for tuple decoding; a corrupt encoding shouldn't halt() */

static value pop_indirect_value(table dictionary, buffer source)
{
    value v;
    u64 e = pop_varint(source);
    v = table_find(dictionary, pointer_from_u64(e));
    if (!v)
        halt("indirect value not found: 0x%lx, offset %d\n", e, source->start);
    tuple_debug("decode_value: indirect 0x%lx -> 0x%lx\n", e, u64_from_pointer(v));
    return v;
}

// h is for buffer values, copy them out
// would be nice to merge into a tuple dest, but it changes the loop and makes
// it weird in the reference case
value decode_value(heap h, table dictionary, buffer source, u64 *total,
                   u64 *obsolete, boolean old_encoding)
{
    u8 type;
    boolean imm;
    u64 len = pop_header(source, &imm, &type, old_encoding);
    tuple_debug("%s: type %d, imm %d, len %d\n", func_ss, type, imm, len);

    if (type == type_tuple) {
        tuple t;
    
        if (imm == immediate) {
            t = allocate_tuple();
            tuple_debug("decode_value: immediate, alloced tuple %v\n", t);
            drecord(dictionary, t);
        } else {
            t = pop_indirect_value(dictionary, source);
        }

        for (int i = 0; i < len ; i++) {
            u8 nametype;
            // nametype is always buffer. can we use that bit?
            u64 nlen = pop_header(source, &imm, &nametype, old_encoding);
            symbol s;
            if (imm) {
                buffer n = wrap_buffer(transient, buffer_ref(source, 0), nlen);
                s = intern(n);
                drecord(dictionary, s);
                source->start += nlen;                                
            } else {
                s = table_find(dictionary, pointer_from_u64(nlen));
                if (!s)
                    halt("indirect symbol not found: 0x%lx, offset %d\n", nlen, source->start);
            }
            set_new_value(t, s, h, dictionary, source, total, obsolete, old_encoding);
        }
        tuple_debug("decode_value: decoded tuple %v\n", t);
        return t;
    } else if (type == type_vector) {
        vector v;
        if (imm == immediate) {
            v = allocate_tagged_vector(len);
            assert(v != INVALID_ADDRESS);
            tuple_debug("decode_value: immediate, alloced vector %p\n", v);
            drecord(dictionary, v);
        } else {
            v = pop_indirect_value(dictionary, source);
        }
        for (int i = 0; i < len; i++)
            set_new_value(v, integer_key(i), h, dictionary, source, total, obsolete,
                          old_encoding);
        tuple_debug("decode_value: decoded vector %v\n", v);
        return v;
    } else if (type == type_integer) {
        boolean neg = len > 0;
        assert(imm == immediate);
        u64 n = pop_varint(source);
        tuple_debug("decode_value: decoded integer %s%lu\n", neg ? ss("-") : sstring_empty(), n);
        if (neg)
            return value_from_s64(-(s64)n);
        else
            return value_from_u64(n);
    } else if (type == type_string) {
        if (len == 0)
            return 0;
        string s;
        if (imm == immediate) {
            s = allocate_string(len);
            assert(buffer_write(s, buffer_ref(source, 0), len));
            source->start += len;
        } else {
            s = table_find(dictionary, pointer_from_u64(len));
            // XXX not halt - fix error handling
            if (!s)
                halt("indirect string not found: 0x%lx, offset %d\n", len, source->start);
        }
        return s;
    } else {
        if (len == 0)
            return 0;
        buffer b;
        if (imm == immediate) {
            if (len == 1 && *(u8*)buffer_ref(source, 0) == '\0') {
                source->start++;
                return null_value;
            }
            if (!old_encoding)
                msg_warn("%s: untyped buffer, len %ld, offset %d: %B", func_ss,
                        len, source->start, alloca_wrap_buffer(buffer_ref(source, 0), len));

            /* address a long-standing bug in bootloaders; untyped buffers must be tagged */
            b = allocate_buffer(
#ifdef BOOT
                boot_buffer_heap,
#else
                h,
#endif
                len);
            assert(buffer_write(b, buffer_ref(source, 0), len));
            source->start += len;
        } else {
            b = table_find(dictionary, pointer_from_u64(len));
            if (!b) halt("indirect buffer not found: 0x%lx, offset %d\n", len, source->start);
        }
        tuple_debug("decode_value: %s buffer %p (%b)\n",
                    imm == immediate ? ss("immediate") : ss("indirect"), b, b);
        return b;
    }
}

void encode_symbol(buffer dest, table dictionary, symbol s)
{
    u64 ind;
    if ((ind = u64_from_pointer(table_find(dictionary, s)))) {
        push_header(dest, reference, type_buffer, ind);
    } else {
        buffer sb = symbol_string(s);
        push_header(dest, immediate, type_buffer, buffer_length(sb));
        assert(push_buffer(dest, sb));
        srecord(dictionary, s);
    }
}

static void encode_string(buffer dest, string s)
{
    push_header(dest, immediate, type_string, buffer_length(s));
    assert(push_buffer(dest, s));
}

static void encode_tuple_internal(buffer dest, table dictionary, tuple t, u64 *total, table visited);
static void encode_vector_internal(buffer dest, table dictionary, vector v, u64 *total, table visited);
static void encode_integer(buffer dest, value v);
static void encode_value_internal(buffer dest, table dictionary, value v, u64 *total, table visited)
{
    if (!v) {
        push_header(dest, immediate, type_buffer, 0);
    } else if (is_tuple(v)) {
        encode_tuple_internal(dest, dictionary, (tuple)v, total, visited);
    } else if (is_vector(v)) {
        encode_vector_internal(dest, dictionary, (vector)v, total, visited);
    } else if (is_integer(v)) {
        encode_integer(dest, v);
    } else if (tagof(v) == tag_string /* not untyped */) {
        encode_string(dest, (string)v);
    } else {
        if (v != null_value) {
            msg_err("%s: untyped value %v, len %d, from %p", func_ss, v,
                    buffer_length((buffer)v), __builtin_return_address(0));
            print_frame_trace_from_here();
        }
        push_header(dest, immediate, type_buffer, buffer_length((buffer)v));
        assert(push_buffer(dest, (buffer)v));
    }
}

// could close over encoder!
// these are special cases of a slightly more general scheme
void encode_eav(buffer dest, table dictionary, tuple e, symbol a, value v, u64 *obsolete)
{
    // this can be push value really..dont need to assume that its already
    // been rooted - merge these two cases - maybe methodize the tuple interface
    // (set/get/iterate)
    u64 d = u64_from_pointer(table_find(dictionary, e));
    if (d) {
        tuple_debug("encode_eav: e (%v) indirect at index 0x%lx\n", e, d);
        push_header(dest, reference, type_tuple, 1);
        push_varint(dest, d);
    } else {
        tuple_debug("encode_eav: e (%v) immediate at index 0x%lx\n",
                    e, dictionary->count + 1);
        push_header(dest, immediate, type_tuple, 1);
        srecord(dictionary, e);
    }
    table visited = allocate_table(transient, identity_key, pointer_equal);
    assert(visited != INVALID_ADDRESS);
    table_set(visited, e, (void *)1);
    tuple_debug("   encoding symbol \"%b\" with value %v\n", symbol_string(a), v);
    encode_symbol(dest, dictionary, a);
    encode_value_internal(dest, dictionary, v, 0, visited);
    deallocate_table(visited);
    if (obsolete) {
        value old_v = get(e, a);
        if (old_v) {
            (*obsolete)++;
            if (!v)
                (*obsolete)++;
        }
    }
}

static boolean no_encode(value v)
{
    return (v && is_tuple(v) && get(v, sym(no_encode)));
}

closure_function(1, 2, boolean, encode_value_count_each,
                 u64 *, count,
                 value s, value v)
{
    if (!no_encode(v))
        (*bound(count))++;
    return true;
}

closure_function(4, 2, boolean, encode_tuple_each,
                 buffer, dest, table, dictionary, u64 *, total, table, visited,
                 value s, value v)
{
    assert(is_symbol(s));
    tuple_debug("   s %b, v %p, tag %d\n", symbol_string(s), v, tagof(v));
    if (no_encode(v))
        return true;
    encode_symbol(bound(dest), bound(dictionary), s);
    encode_value_internal(bound(dest), bound(dictionary), v, bound(total), bound(visited));
    if (bound(total))
        (*bound(total))++;
    return true;
}

static void encode_tuple_internal(buffer dest, table dictionary, tuple t, u64 *total, table visited)
{
    tuple_debug("%s: dest %p, dictionary %p, tuple %p\n", func_ss, dest, dictionary, t);
    u64 d = u64_from_pointer(table_find(dictionary, t));
    u64 count = 0;

    if (!(visited && table_find(visited, t)))
        iterate(t, stack_closure(encode_value_count_each, &count));

    if (d) {
        push_header(dest, reference, type_tuple, count);
        push_varint(dest, d);
    } else {
        push_header(dest, immediate, type_tuple, count);
        srecord(dictionary, t);
    }

    if (count > 0) {
        table_set(visited, t, (void *)1);
        iterate(t, stack_closure(encode_tuple_each, dest, dictionary, total, visited));
    }
}

void encode_tuple(buffer dest, table dictionary, tuple t, u64 *total)
{
    table visited = allocate_table(transient, identity_key, pointer_equal);
    assert(visited != INVALID_ADDRESS);
    encode_tuple_internal(dest, dictionary, t, total, visited);
    deallocate_table(visited);
}

void encode_value(buffer dest, table dictionary, value v, u64 *total)
{
    table visited = allocate_table(transient, identity_key, pointer_equal);
    assert(visited != INVALID_ADDRESS);
    encode_value_internal(dest, dictionary, v, total, visited);
    deallocate_table(visited);
}

closure_function(4, 2, boolean, encode_vector_each,
                 buffer, dest, table, dictionary, u64 *, total, table, visited,
                 value a, value v)
{
    tuple_debug("   a %v, v %p, tag %d\n", a, v, tagof(v));
    if (no_encode(v))
        v = 0;                  /* must retain order - encode null instead? */
    encode_value_internal(bound(dest), bound(dictionary), v, bound(total), bound(visited));
    if (bound(total))
        (*bound(total))++;
    return true;
}

static void encode_vector_internal(buffer dest, table dictionary, vector v, u64 *total, table visited)
{
    tuple_debug("%s: dest %p, dictionary %p, vector %v\n", func_ss, dest, dictionary, v);
    u64 d = u64_from_pointer(table_find(dictionary, v));
    u64 count;
    if (!(visited && table_find(visited, v)))
        count = vector_length(v);
    else
        count = 0;
    if (d) {
        push_header(dest, reference, type_vector, count);
        push_varint(dest, d);
    } else {
        push_header(dest, immediate, type_vector, count);
        srecord(dictionary, v);
    }
    if (count > 0) {
        table_set(visited, v, (void *)1);
        iterate(v, stack_closure(encode_vector_each, dest, dictionary, total, visited));
    }
}

static void encode_integer(buffer dest, value v)
{
    tuple_debug("%s: dest %p, v %v\n", func_ss, dest, v);
    u64 abs;
    boolean neg = is_signed_integer_value(v);
    if (neg) {
        s64 x;
        assert(s64_from_value(v, &x));
        abs = -x;
    } else {
        assert(u64_from_value(v, &abs));
    }
    push_header(dest, immediate, type_integer, neg);
    push_varint(dest, abs);
}

void deallocate_value(value v)
{
    if (is_immediate(v))
        return;
    value_tag tag = tagof(v);
    switch (tag) {
    case tag_unknown:
        /* untyped buffer or string */
        deallocate_buffer((buffer)v);
        break;
    case tag_string:
        deallocate_string((string)v);
        break;
    case tag_symbol:
        /* no safe way to dealloc symbols yet */
        break;
    case tag_table_tuple:
        deallocate_table((table)v);
        break;
    case tag_function_tuple:
        /* XXX No standard interface to remove function tuple...release a refcount? */
        break;
    case tag_vector:
        deallocate_vector((vector)v);
        break;
    case tag_integer:
        if (!is_immediate(v))
            deallocate_buffer((buffer)v);
        break;
    default:
        halt("%s: unknown tag type %d\n", func_ss, tag);
    }
}

void init_integers(heap h)
{
    iheap = h;
}

void init_tuples(heap h)
{
    theap = h;
}
