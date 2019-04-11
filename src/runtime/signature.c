#include <runtime.h>

void buffer_signature(buffer b, signature dest)
{
    buffer s = alloca_wrap_buffer(dest, sizeof(signature));
    sha256(s, b);
}

void signature_xor(signature sdest, signature source)
{
    sdest->s[0] ^= source->s[0];
    sdest->s[1] ^= source->s[1];
    sdest->s[2] ^= source->s[2];
    sdest->s[3] ^= source->s[3];    
}

void tuple_signature(tuple t, signature dest)
{
    u64 slen = sizeof(struct signature);
    zero(dest, slen);
    table_foreach(t, n, v) {
        buffer b = little_stack_buffer(2*slen);
        buffer nv = little_stack_buffer(slen);
        
        buffer_signature(symbol_string(n), buffer_ref(b, 0));
        if (tagof(v) == tag_tuple) {
            tuple_signature(v, buffer_ref(b, slen));
        } else {
            buffer_signature(v, buffer_ref(b, slen));
        }
        sha256(nv, b);
        signature_xor(dest, buffer_ref(nv, 0));
    }
}

static inline boolean signature_equal(void *a, void* b)
{
    return runtime_memcmp(a, b, sizeof(struct signature));
}

static inline key signature_key(void *z)
{
    u64 *s = (u64 *)z;
    return s[0] ^ s[1] ^ s[2] ^ s[3];
}

table allocate_signature_table(heap h)
{
    return allocate_table(h, signature_key, signature_equal);
}

