#include <runtime.h>

//#define TUPLE_DEBUG
#if defined(TUPLE_DEBUG)
#define tuple_debug(x, ...) do { rprintf("TUPLE: " x, ##__VA_ARGS__); } while(0)
#else
#define tuple_debug(x, ...)
#endif

BSS_RO_AFTER_INIT static heap theap;

// use runtime tags directly?
#define type_tuple 1
#define type_buffer 0

#define immediate 1
#define reference 0

value get(value e, symbol a)
{
    u16 tag = tagof(e);
    tuple t = (tuple)e;
    switch (tag) {
    case tag_table_tuple:
        return table_find(&t->t, a);
    case tag_function_tuple:
        return apply(t->f.g, a);
    default:
        assert(0);
    }
}

void set(value e, symbol a, value v)
{
    u16 tag = tagof(e);
    tuple t = (tuple)e;
    switch (tag) {
    case tag_table_tuple:
        table_set(&t->t, a, v);
        break;
    case tag_function_tuple:
        apply(t->f.s, a, v);
        break;
    default:
        assert(0);
    }
}

boolean iterate(value e, binding_handler h)
{
    u16 tag = tagof(e);
    tuple t = (tuple)e;
    switch (tag) {
    case tag_table_tuple:
        table_foreach(&t->t, a, v) {
            if (!apply(h, a, v))
                return false;
        }
        return true;
    case tag_function_tuple:
        return apply(t->f.i, h);
    default:
        assert(0);
    }
}

closure_function(1, 2, boolean, tuple_count_each,
                 int *, count,
                 value, s, value, v)
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
        assert(0);
    }
}

closure_function(2, 2, boolean, tuple_get_symbol_each,
                 value, val, symbol *, sym,
                 value, s, value, v)
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
    return tag(allocate_table(theap, key_from_symbol, pointer_equal), tag_table_tuple);
}

void destruct_tuple(tuple t, boolean recursive);

closure_function(2, 2, boolean, destruct_tuple_each,
                 tuple, t, boolean, recursive,
                 value, s, value, v)
{
    if (is_tuple(v)) {
        if (bound(recursive))
            destruct_tuple(v, true);
    } else if (v != null_value) {
        deallocate_value(v);
    }
    return true;
}

void destruct_tuple(tuple t, boolean recursive)
{
    iterate(t, stack_closure(destruct_tuple_each, t, recursive));
    deallocate_value(t);
}

void timm_dealloc(tuple t)
{
    if (t != STATUS_OK)
        destruct_tuple(t, true);
}

// header: immediate(1)
//         type(1)
//         varint encoded unsigned
// no error path
static u64 pop_header(buffer f, boolean *imm, u8 *type)
{
    u8 a = pop_u8(f);
    tuple_debug("pop %x\n", a);
    *imm = a>>7;    
    *type = (a>>6) & 1;
    
    u64 len = a & 0x1f;
    if (a & (1<<5)) {
        do {
            a = pop_u8(f);
            tuple_debug("pop %x extra\n", a);
            len = (len<<7) | (a & 0x7f);
        } while(a & 0x80);
    }
    tuple_debug("header: %s %s %lx\n",
        (*imm) ? "immediate" : "reference",
        (*type) ? "tuple" : "buffer",
        len);
    return len;
}

static void push_header(buffer b, boolean imm, u8 type, u64 length)
{
    // is msb off by one?
    int bits = msb(length) + 1;
    int words = 0;
    // (imm type ext) 
    if (bits > 5)
        words = ((bits - 5) + (7 - 1)) / 7;
    assert(buffer_extend(b, words + 1));

    tuple_debug("push header: %s %s decimal length:0x%lx bits:%d words:%d\n",
                imm ? "immediate" : "reference",
                type ? "tuple" : "buffer",
                length,
                bits,
                words);
    u8 first = (imm << 7) |  (type << 6) | (((words)?1:0)<<5) | (length >> (words * 7));
    tuple_debug("push %x\n", first);
    push_u8(b, first);

    int i = words;
    while (i-- > 0) {
        u8 v =  ((length >> (i * 7)) & 0x7f) | (i ? 0x80 : 0);
        tuple_debug("push %x extra\n", v);
        push_u8(b, v);
    }
}

// h is for buffer values, copy them out
// would be nice to merge into a tuple dest, but it changes the loop and makes
// it weird in the reference case
value decode_value(heap h, table dictionary, buffer source, u64 *total,
                   u64 *obsolete)
{
    u8 type;
    boolean imm;
    u64 len = pop_header(source, &imm, &type);

    if (type == type_tuple) {
        tuple t;
    
        if (imm == immediate) {
            t = allocate_tuple();
            tuple_debug("decode_value: immediate, alloced tuple %v\n", t);
            drecord(dictionary, t);
        } else {
            u64 e = pop_varint(source);
            t = table_find(dictionary, pointer_from_u64(e));
            if (!t) halt("indirect tuple not found: 0x%lx, offset %d\n", e, source->start);
            tuple_debug("decode_value: indirect 0x%lx -> 0x%lx\n", e, u64_from_pointer(t));
        }

        for (int i = 0; i < len ; i++) {
            u8 nametype;
            // nametype is always buffer. can we use that bit?
            u64 nlen = pop_header(source, &imm, &nametype);
            symbol s;
            if (imm) {
                buffer n = wrap_buffer(transient, buffer_ref(source, 0), nlen);
                s = intern(n);
                drecord(dictionary, s);
                source->start += nlen;                                
            } else {
                s = table_find(dictionary, pointer_from_u64(nlen));
                if (!s) halt("indirect symbol not found: 0x%lx, offset %d\n", nlen, source->start);
            }
            value nv = decode_value(h, dictionary, source, total, obsolete);
            if (obsolete) {
                value old_v = get(t, s);
                if (old_v) {
                    (*obsolete)++;
                    if (!nv)
                        (*obsolete)++;
                }
            }
            set(t, s, nv);
            if (total)
                (*total)++;
        }
        tuple_debug("decode_value: decoded tuple %v\n", t);
        return t;
    } else {
        if (len == 0)
            return 0;
        buffer b;
        if (imm == immediate) {
            // doesn't seem like we should always need to take a copy in all cases
            b = allocate_buffer(h, len);
            assert(buffer_write(b, buffer_ref(source, 0), len));
            source->start += len;
        } else {
            b = table_find(dictionary, pointer_from_u64(len));
            if (!b) halt("indirect buffer not found: 0x%lx, offset %d\n", len, source->start);
        }
        tuple_debug("decode_value: %s buffer %p (%b)\n",
                    imm == immediate ? "immediate" : "indirect", b, b);
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

static void encode_tuple_internal(buffer dest, table dictionary, tuple t, u64 *total, table visited);
static void encode_value_internal(buffer dest, table dictionary, value v, u64 *total, table visited)
{
    if (!v) {
        push_header(dest, immediate, type_buffer, 0);
    }
    else if (is_tuple(v)) {
        encode_tuple_internal(dest, dictionary, (tuple)v, total, visited);
    } else {
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

closure_function(1, 2, boolean, encode_tuple_count_each,
                 u64 *, count,
                 value, s, value, v)
{
    if (!no_encode(v))
        (*bound(count))++;
    return true;
}

closure_function(4, 2, boolean, encode_tuple_each,
                 buffer, dest, table, dictionary, u64 *, total, table, visited,
                 value, s, value, v)
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
    tuple_debug("%s: dest %p, dictionary %p, tuple %p\n", __func__, dest, dictionary, t);
    u64 d = u64_from_pointer(table_find(dictionary, t));
    u64 count = 0;

    if (!(visited && table_find(visited, t)))
        iterate(t, stack_closure(encode_tuple_count_each, &count));

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

void deallocate_value(tuple t)
{
    value_tag tag = tagof(t);
    switch (tag) {
    case tag_table_tuple:
        deallocate_table((table)t);
        break;
    case tag_function_tuple:
        /* XXX No standard interface to remove function tuple...release a refcount? */
        break;
    default:
        /* XXX assuming string buffer until we have complete type coverage */
        deallocate_buffer((buffer)t);
        break;
    }
}

void init_tuples(heap h)
{
    theap = h;
}
