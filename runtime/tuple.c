#include <runtime.h>

heap theap;

// use runtime tags directly?
#define type_tuple 1
#define type_buffer 0

#define immediate 0
#define reference 1

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

// dict is number to symbol
// h is for buffer values, copy them out
void *deserialize_tuple(heap h, tuple dictionary, buffer source)
{
    u8 type;
    boolean imm;
    u64 len = pop_header(source, &imm, &type);
    if (type) {
        tuple t = allocate_tuple();
        for (int i = 0; i < len ; i++) {
            u8 nametype, valuetype;
            u64 nlen = pop_header(source, &imm, &nametype);
            symbol s;
            if (nametype) {
                s = table_find(dictionary, pointer_from_u64(nlen));
                //                if (!s) rprintf("missing decode dictionary symbol %d\n", nlen);
            } else {
                buffer n = alloca_wrap_buffer(buffer_ref(source, 0), nlen);
                void *index = pointer_from_u64((u64)dictionary->count);
                table_set(dictionary, index, s = intern(n));
                source->start += nlen;                
            }
            table_set(t,s, deserialize_tuple(h, dictionary,source));
        }
        return t;
    } else {
        buffer b = allocate_buffer(h, len);
        // doesn't seem like this should be neccessary in all cases
        runtime_memcpy(buffer_ref(b, 0), source->contents + source->start, len);
        source->start += len;
        return b;
    }
}

// could close over encoder!
// these are special cases of a slightly more general scheme
void encode_eav(buffer dest, table dictionary, tuple e, symbol a, value v)
{

    
    push_header(dest, reference, type_tuple, dictionary->count);
    //    push_varint(dest, soft_map(t));

}

void encode_value(buffer dest, table dictionary, value v)
{
    if (tagof(v) == tag_tuple) {
        encode_tuple(dest, dictionary, (tuple)v);
    } else {
        push_header(dest, immediate, type_buffer, buffer_length((buffer)v));
        push_buffer(dest, (buffer)v);
    }

}

// immediate only
void encode_tuple(buffer dest, table dictionary, tuple t)
{
    u64 tuple_id;

    push_header(dest, immediate, type_tuple, t->count);
    table_foreach (t, n, v) {
        
        u64 sn;
        if ((sn = u64_from_pointer(table_find(dictionary, n)))) {
            // references dont necessarily need types
            push_header(dest, reference, type_tuple, sn - 1);
        } else {
            sn = dictionary->count;
            table_set(dictionary, n, pointer_from_u64(sn + 1));
            push_header(dest, immediate, type_tuple, buffer_length(symbol_string(n)));
            push_buffer(dest, symbol_string(n));
        }
        encode_value(dest, dictionary, v);
    }        
}

void init_tuples(heap h)
{
    theap = h;
}

#ifndef BITS32
void print_tuple(buffer b, tuple t)
{
    boolean sub = false;
    bprintf(b, "(");
    table_foreach(t, n, v) {
        if (sub) {
            push_character(b, ' ');
        }
        bprintf(b, "%b:", symbol_string((symbol)n));
        if (tagof(v) == tag_tuple) {
            print_tuple(b, v);
        } else {
            bprintf(b, "%b", v);
        }
        sub = true;
    }
    bprintf(b, ")");
}
#endif
