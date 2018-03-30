
// entry
//   key - offset into symbol table
//   offset - offset into body
//   length - body length or -1 for snode


#define storage_type_tuple 1
#define storage_type_unaligned 2
#define storage_type_aligned 3
#define STORAGE_TYPE_OFFSET 30
#define STORAGE_SLOT_SIZE 8

static inline boolean compare_bytes(void *a, void *b, bytes len)
{
    for (int i = 0; i < len ; i++) {
        if (((u8 *)a)[i] != ((u8 *)b)[i])
            return false;
    }
    return true;
}


#define ENTRY_ALIGNMENT_LOG 2
typedef u32 offset;

#define STORAGE_LEN_MAP (-1ul)

#define naddr(__n, __o) (__n.base + (__o << ENTRY_ALIGNMENT_LOG))
#define is_empty(__n) ((__n).base == INVALID_ADDRESS)

// really for stage2 looking up /kernel
static inline boolean snode_lookup(buffer s, char *key, u64 *off)
{
    struct buffer b;
    b.contents = s->contents;
    b.start = s->start;

    u64 count = pop_varint(&b);
    u32 *entries = buffer_ref(&b, 0);
    int klen = runtime_strlen(key);

    for (int i = 0; i < count; i++) {
        // slots are two words long
        b.start = entries[i*2];
        u64 symlen = pop_varint(&b);
        if ((symlen == klen) && compare_bytes(key, buffer_ref(&b, 0), klen)) {
            *off = entries[i*2 + 1] & MASK(STORAGE_TYPE_OFFSET);
            return true;
        }
    }
    return false;
}
