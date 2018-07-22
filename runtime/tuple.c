#include <runtime.h>

static heap theap;

// use runtime tags directly?
#define type_tuple 1
#define type_buffer 0

#define immediate 1
#define reference 0

static inline void drecord(table dictionary, void *x)
{
    table_set(dictionary, pointer_from_u64((u64)dictionary->count)+1, x);
}

static inline void srecord(table dictionary, void *x)
{
    table_set(dictionary, x, pointer_from_u64((u64)dictionary->count)+1);
}


// decode dictionary can really be a vector
// region?
tuple allocate_tuple()
{
    return tag(allocate_table(theap, key_from_symbol, pointer_equal), tag_tuple);
}

// header: immediate(1)
//         type(1)
//         varint encoded unsigned
// no error path
static u64 pop_header(buffer f, boolean *imm, u8 *type)
{
    u64 zag = f->start;
    u8 a = pop_u8(f);
    *imm = a>>7;    
    *type = (a>>6) & 1;
    
    u64 len = a & 0x3f;
    if (a & (1<<5)) {
        do {
            u8 a = pop_u8(f);
            len = (len<<7) + (a & 127);
        } while(a & 0x80);
    }
    return len;
}

static void push_header(buffer b, boolean imm, u8 type, u64 length)
{
    int bits = msb(length);
    int words = 0;
    buffer_extend(b, words + 1);
    // (imm type ext) 
    if (bits > 5) words = (bits - 5)/7;
    u8 first = (imm << 7) |  (type << 6) | (((words)?1:0)<<5) | (length >> (words * 7));
    push_u8(b, first);
    for (int i = 0; i<words; i++) 
        *((u8 *)b->contents + b->start + (words - i)) = (length >> (i * 7)) | (i?0x80:0);

    b->end += words;
}

// h is for buffer values, copy them out
// would be nice to merge into a tuple dest, but it changes the loop and makes
// it weird in the reference case
value decode_value(heap h, tuple dictionary, buffer source)
{
    u8 type;
    boolean imm;
    u64 len = pop_header(source, &imm, &type);

    if (type == type_tuple) {
        tuple t;
    
        if (imm == immediate) {
            t = allocate_tuple();
            drecord(dictionary, t);
        } else {
            u64 e = pop_varint(source);
            t = table_find(dictionary, pointer_from_u64(e));
            if (!t) halt("indrect entry not found %d", e);
        }

        for (int i = 0; i < len ; i++) {
            u8 nametype, valuetype;
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
                if (!s) rprintf("missing decode dictionary symbol %d\n", nlen);                
            }
            value nv = decode_value(h, dictionary, source);
            table_set(t, s, nv);
        }
        return t;
    } else {
        if (imm == immediate) {
            // doesn't seem like we should always need to take a copy in all cases
            buffer b = allocate_buffer(h, len);
            buffer_write(b, buffer_ref(source, 0), len);
            source->start += len;
            return b;
        } else {
            return table_find(dictionary, pointer_from_u64(len));
        }
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
        push_buffer(dest, sb);
        srecord(dictionary, s);
    }
}

void encode_tuple(buffer dest, table dictionary, tuple t);
void encode_value(buffer dest, table dictionary, value v)
{
    if (tagof(v) == tag_tuple) {
        encode_tuple(dest, dictionary, (tuple)v);
    } else {
        push_header(dest, immediate, type_buffer, buffer_length((buffer)v));
        push_buffer(dest, (buffer)v);
    }
}

// could close over encoder!
// these are special cases of a slightly more general scheme
void encode_eav(buffer dest, table dictionary, tuple e, symbol a, value v)
{
    // this can be push value really..dont need to assume that its already
    // been rooted - merge these two cases - maybe methodize the tuple interface
    // (set/get/iterate)
    u64 d = u64_from_pointer(table_find(dictionary, e));
    if (d) {
        push_header(dest, reference, type_tuple, 1);
        push_varint(dest, d);
    } else {
        push_header(dest, immediate, type_tuple, 1);
        srecord(dictionary, e);
    }
    encode_symbol(dest, dictionary, a);
    encode_value(dest, dictionary, v);
}

// immediate only
void encode_tuple(buffer dest, table dictionary, tuple t)
{
    u64 tuple_id;

    push_header(dest, immediate, type_tuple, t->count);
    srecord(dictionary, t);
    table_foreach (t, n, v) {
        encode_symbol(dest, dictionary, n);
        encode_value(dest, dictionary, v);
    }        
}

void init_tuples(heap h)
{
    theap = h;
}

