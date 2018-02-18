#include <sruntime.h>

struct snode snode_invalid = {INVALID_ADDRESS, 0};

void buffer_write_le32(buffer b, u32 x)
{
    *(u32 *)(b->contents+b->end) = x;
    b->end += sizeof(u32);
}

static inline u32 *bucket_count(buffer b, u64 start)
{
    return (u32 *)(b->contents+start);
}

static inline u32 *snode_bucket_count(snode n)
{
    return (u32 *)(n.base+n.offset);
}

static inline u32 *buckets(buffer b, u64 start)
{
    return bucket_count(b, start) + 1;
}

// for some reason I think we can dedup bodies here easily, idk why
// alignment, empty space.. elminate this indirect?  or add indirection
// for keys?
void storage_set(buffer b, u32 start, buffer key, u32 voff, u32 vlen)
{
    offset *slot = buckets(b, start) + (fnv64(key) & *bucket_count(b, start));
    int pk = pad(buffer_length(key), (1<<ENTRY_ALIGNMENT_LOG));
    int nlen = pk + 4 * sizeof(offset);
    offset loc = b->end >> ENTRY_ALIGNMENT_LOG;
    buffer_extend(b, nlen);
    u32 next = *slot;
    buffer_write_le32(b, next);
    buffer_write_le32(b, voff >> ENTRY_ALIGNMENT_LOG);
    buffer_write_le32(b, vlen);
    buffer_write_le32(b, buffer_length(key));
    *slot = loc;
    push_buffer(b, key);
    b->end += pk - buffer_length(key);
}



u64 init_storage(buffer b, int buckets)
{
    u64 off = b->end;
    u64 len = log2(buckets); // not yet a thing!
    buffer_write_le32(b, (1<<len) -1);
    int blen = buckets * sizeof(offset);
    buffer_extend(b, blen);
    zero(b->contents + b->end, blen);
    b->end += blen;
    return off;
}


u64 serialize(buffer out, table t)
{
    // could perfect hash here
    u64 off = init_storage(out, 1<<log2(t->count));

    table_foreach(t, k, v)  {
        if (k == sym(contents)) {
            buffer b = v;
            u64 start = out->end; 
            buffer_write(out, b->contents + b->start, buffer_length(b));
            out->end += pad(out->end, 4) - out->end;
            storage_set(out, off, k, start, buffer_length(b));
        } else {
            storage_set(out, off, k, serialize (out, (table)v), 0);
        }
    }
    return off;
}

