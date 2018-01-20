#include <runtime.h>

typedef u32 offset;
#define ENTRY_ALIGNMENT_LOG 5

typedef buffer index;

static inline u32 bucket_count(index z)
{
    *(offset *)z->contents;
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

static boolean lookup(index i, buffer key, void **base, bytes length)
{
    offset *k = ((offset *)i->contents) + 1;
    offset id = fnv64(key) % bucket_count(i);
    offset where = k[id+1]; // first is the bucketlength
    
    while (where) {
        u32 klen = k[where];
        if ((klen == buffer_length(key)) &&
            (buffer_length(key) == klen) &&
            compare_bytes(key->contents, k+where+1, klen)) 
            return true;
        where = k[where];
    }
    return false;
}

// for some reason I think we can dedup bodies here easily, idk why
void index_set(buffer index, buffer key, buffer value)
{
    offset *buckets = ((offset *)index->contents)+1;
    // one for klen, one for vlen, one for next
    int nlen = pad(buffer_length(key) + buffer_length(value) + 3*sizeof(offset), (1<<ENTRY_ALIGNMENT_LOG));
    offset id = fnv64(key) % bucket_count(index);

    offset *n = index->contents + index->end;
    buffer_extend(index, nlen);
    
    buffer_write(index, buckets+id, 4);
    buckets[id] = index->end >> ENTRY_ALIGNMENT_LOG;
    buffer_write_be32(index, buffer_length(key));
    push_buffer(index, key);
    buffer_write_be32(index, buffer_length(value));
    // buffer lost his alignment
    push_buffer(index, value);
    int padlen = pad(buffer_length(index), (1<<ENTRY_ALIGNMENT_LOG)) - buffer_length(index);
    buffer_extend(index, padlen);
    index->end += padlen;
}

// key and value and length + offset
void iterate(buffer map, void (*f)(void *key, void *value))
{
    offset *k = ((offset *)map->contents) + 1;
    offset count = bucket_count(map);
    for (offset i; i < count; i++) {
        offset where = k[i];
        while (where) {
            void *key = k+where;
            void *value = (void *)(k +where + 1) + *(u32 *)key;
            f(key, value);
            where = k[where];
        }   
    }
}

buffer create_index(heap h, int buckets)
{
    return allocate_buffer(h, 100);
}

