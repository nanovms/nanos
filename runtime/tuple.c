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

// h is for buffer values, copy them out
value decode_value(heap h, tuple dictionary, buffer source)
{
    u8 type;
    boolean imm;
    u64 len = pop_header(source, &imm, &type);
    
    if (type == type_tuple) {
        tuple t;
        if (imm) {
            t = allocate_tuple();
            table_set(dictionary, pointer_from_u64((u64)dictionary->count), t);
        } else {
            t = table_find(dictionary, pointer_from_u64(pop_varint(source)));
            // if !t err
        }
        
        for (int i = 0; i < len ; i++) {
            u8 nametype, valuetype;
            // nametype is always buffer. can we use that bit?
            u64 nlen = pop_header(source, &imm, &nametype);
            symbol s;
            if (imm) {
                buffer n = alloca_wrap_buffer(buffer_ref(source, 0), nlen);
                table_set(dictionary, pointer_from_u64((u64)dictionary->count), s = intern(n));
                source->start += nlen;                                
            } else {
                s = table_find(dictionary, pointer_from_u64(nlen));
                //                if (!s) rprintf("missing decode dictionary symbol %d\n", nlen);                
            }
            table_set(t,s, decode_value(h, dictionary, source));
        }
        return t;
    } else {
        if (imm) {
            // doesn't seem like we should always need to take a copy in all cases
            buffer b = allocate_buffer(h, len);
            runtime_memcpy(buffer_ref(b, 0), source->contents + source->start, len);
            source->start += len;
        } else {
            return table_find(dictionary, pointer_from_u64(len));
        }
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
    if (!d) {
        halt("shouldda implemented encode eav better or had a pre-existing tuple");
    }
    push_header(dest, reference, type_tuple, 1);
    push_varint(dest, d);
    // what happened to soft_create
    push_header(dest, immediate, type_buffer, buffer_length((buffer)v));
    push_buffer(dest, (buffer)v);    
    encode_value(dest, dictionary, v);
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
            push_header(dest, reference, type_tuple, sn);
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

