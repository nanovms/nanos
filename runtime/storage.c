#include <runtime.h>


typedef u32 offset;

typedef struct storage  {
    offset bucket_count;
    offset *buckets;
    buffer b;
} *storage;
    
#define ENTRY_ALIGNMENT_LOG 5


void buffer_write_le32(buffer b, u32 x)
{
    *(u32 *)(b->contents+b->end) = x;
    b->end += sizeof(u32);
}

/*
 * entry layout
 *   u32 next
 *   u32 keylen
 *   ..key.. 
 *   u32 vlen
 *   ..val.. (not aligned)
 *   aligned
 */

static boolean compare_bytes(void *a, void *b, bytes len)
{
    for (int i = 0; i < len ; i++)
        if (((u8 *)a)[i] != ((u8 *)b)[i])
            return false;
    return true;
}

boolean storage_lookup(storage s, buffer key, void **base, bytes *length)
{
    offset where = s->buckets[fnv64(key) % s->bucket_count];
    
    while (where) {
        offset *e = key->contents + (where<<ENTRY_ALIGNMENT_LOG);
        if ((e[1] == buffer_length(key)) &&
            compare_bytes(key->contents, (void *)(e+3), e[1])) 
            return true;
        where = e[0];
    }
    return false;
}

// for some reason I think we can dedup bodies here easily, idk why
// alignment, empty space.. elminate this indirect?  or add indirection
// for keys?
void storage_set(storage s, buffer key, u64 voff, u64 vlen)
{
    u64 b = fnv64(key) % s->bucket_count;
    int nlen = pad(buffer_length(key), ENTRY_ALIGNMENT_LOG) + 5 * sizeof(offset);
    offset loc = s->b->end >> ENTRY_ALIGNMENT_LOG;
    offset *n = s->b->contents + s->b->end;
    buffer_extend(s->b, nlen);

    buffer_write_le32(s->b, s->buckets[b]);
    buffer_write_le32(s->b, voff);
    buffer_write_le32(s->b, vlen);
    buffer_write_le32(s->b, buffer_length(key));
    s->buckets[b] = loc;
    push_buffer(s->b, key);
    s->b->end += nlen;
}


// key and value and length + offset
void iterate(storage s, void (*f)(void *key, void *value))
{
    offset *k = s->buckets;
    for (offset i; i < s->bucket_count; i++) {
        offset where = k[i];
        while (where) {
            void *key = k+where;
            void *value = (void *)(k +where + 1) + *(u32 *)key;
            f(key, value);
            where = k[where];
        }   
    }
}
 
storage create_storage(heap h, int buckets, buffer b, u64 *off)
{
    storage s = allocate(h, sizeof(struct storage));
    s->b = b;
    s->bucket_count = buckets;
    buffer_write_be32(b, buckets);
    s->buckets = b->contents + b->end;
    b->end += buckets * sizeof(offset);
    runtime_memset(s->buckets, 0, buckets * sizeof(offset));
    return s;
}

storage wrap_storage(heap h, void *base, u64 length)
{
    storage s = allocate(h, sizeof(struct storage));
    s->b = allocate(h, sizeof(struct buffer));
    s->b->contents = base;
    s->b->start = 0;
    s->b->end = length;
    s->b->length = length;        

    s->bucket_count = *(u32 *)(s->b->contents);
    s->buckets = s->b->contents + sizeof(u32);
    return s;
}

