
// lets just eat the 4g limit right now
// and assume little endian
typedef u32 offset;
#define ENTRY_LENGTH 

typedef buffer index;

static inline u32 bucket_count(index z)
{
    *(offset *)z->context;
}

/*
 * entry layout
 *   u32 next
 *   u32 keylen
 *   ..key.. (lot aligned)
 *   u32 vlen
 *   ..val..
 *   aligned
 */

static boolean lookup(index i, buffer key, offset *where)
{
    offset *k = (offset *)i->contents;
    offset id = fnv64(key) % bucket_count(*(offset *)z->content);
    *where = k[id+1]; // first is the bucketlength
    
    while (where) {
        u32 klen = k[where+1];
        if ((klen == length(key)) && compare_bytes(key->contents, k+where+2 klen)) 
            return true;
        next = k[where];
    }
    return false;
}

// for some reason I think we can dedup bodies here easily, idk why
void index_set(buffer index, buffer key, buffer value)
{
    offset *k = (offset *)i->contents;
    int nlen = length(key) + length(value) + 3*sizeof(offset);
    offset id = fnv64(key) % bucket_count(*(offset *)z->content);

    u32 *n = index->contents + index->end;
    extend_buffer(index, nlen);
    n[0] = k[id+1];
    k[id+1] = n;
}

void iterate(buffer map, void (*f)(void *key, void *value))
{
    offset *k = (offset *)i->contents;
    for (offset i; i < k[0]; i++) {
        while (where) {
            void *key = k[where+1];
            void *value = (void *)(k +where + 1) + *(u32 *)key;
            f(key, value);
            where = k[where];
        }   
    }
}

// no resize in v1
buffer create_index(heap h, int buckets)
{
    return allocate_buffer(h, 100);
}

