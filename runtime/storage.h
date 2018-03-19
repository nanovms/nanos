
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

// this is a buffer actually
// note that node is an immediate and not a pointer just
// to cut down on trash
typedef struct snode {
    void *base;
    u64 offset;
} snode;

#define STORAGE_LEN_MAP (-1ul)

#define naddr(__n, __o) (__n.base + (__o << ENTRY_ALIGNMENT_LOG))
#define is_empty(__n) ((__n).base == INVALID_ADDRESS)


#if 0
u64 init_storage(buffer b, int buckets);
void storage_set(buffer b, u32 start, buffer key, u32 offset, u32 length);

#define bfill(__b, __c, __l) (__b->contents = __c, __b->end = __l, __b->start =0)

#define storage_foreach(__n, __nam, __val)\
    for (u32 *__buckets = (u32 *)(__n.base + __n.offset), __i = 0; __i<*__buckets; __i++) \
        for (struct buffer __nb, __vb, *__nam=&__nb, *__val=&__vb; __val; __val = (void *)0) \
            for (offset *__w =(u32 *)__buckets + __i + 1, *__e;\
                 *__w &&  (__e = naddr(__n, *__w)), (bfill(__nam, __e + 4, __e[3]), bfill(__val, naddr(__n, __e[1]), __e[2]));\
                 __w = __e)


extern struct node node_invalid;
#endif

// really for stage2 looking up /kernel
static inline boolean snode_lookup(snode n, char *key, u32 *off)
{
    struct buffer b;
    b.contents = n.base;
    b.start = n.offset;

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
