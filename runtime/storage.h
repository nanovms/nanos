
// entry
//   key - offset into symbol table
//   offset - offset into body
//   length - body length or -1 for snode


static inline boolean compare_bytes(char *a, void *b, bytes len)
{
    for (int i = 0; i < len ; i++) {
        if (!a[i]) return false;
        if (((u8 *)a)[i] != ((u8 *)b)[i])
            return false;
    }
    return true;
}


#define ENTRY_ALIGNMENT_LOG 2
typedef u32 offset;

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
static inline boolean storage_lookup(snode n, char *key, u32 *off, u32 *length)
{
    int klen = runtime_strlen(key);
    u32 *count = n.base + (u64_from_pointer(n.offset) << ENTRY_ALIGNMENT_LOG);
    for (int i = 0; i < *count; i++) {
        offset *e = naddr(n, count[i + 1]);
        if ((e[3] == klen) &&
            compare_bytes(key, (void *)(e+4), e[3])) {
            *off = (e[1] << ENTRY_ALIGNMENT_LOG);
            *length = e[2];
            return true;
        }
    }
    return false;
}
