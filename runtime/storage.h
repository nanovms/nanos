


#define ENTRY_ALIGNMENT_LOG 2
typedef u32 offset;

// note that node is an immediate and not a pointer just
// to cut down on trash
typedef struct node {
    void *base;
    u64 offset;
} node;

u64 init_storage(buffer b, int buckets);
void storage_set(buffer b, u64 start, buffer key, u64 offset, u64 length);
boolean storage_lookup(node n, buffer key, u64 *offset, bytes *length);
boolean storage_resolve_contents(node n, vector path, void **storage, u64 *slength);
node storage_resolve(node n, vector path);
boolean node_contents(node n, void **storage, u64 *slength);

#define bfill(__b, __c, __l) (__b->contents = __c, __b->end = __l, __b->start =0)
#define naddr(__n, __o) (__n.base + (__o << ENTRY_ALIGNMENT_LOG))

#define storage_foreach(__n, __nam, __val)\
    for (u32 *__buckets = (u32 *)(__n.base + __n.offset), __i = 0; __i<*__buckets; __i++) \
        for (struct buffer __nb, __vb, *__nam=&__nb, *__val=&__vb; __val; __val = (void *)0) \
            for (offset *__w =(u32 *)__buckets + __i + 1, *__e;\
                 *__w &&  (__e = naddr(__n, *__w)), (bfill(__nam, __e + 4, __e[3]), bfill(__val, naddr(__n, __e[1]), __e[2]));\
                 __w = __e)

#define storage_vector_foreach(__n, __i, __v)\
    for (struct buffer __x, __vn, *__v=&__vn;v;v=0) \
    for (node __k ; __k.base == 0; ) \
       for (u64 __i =0, __j;\
            (__x.end = __x.start = 0, __x.length = sizeof(__j), __x.contents = (void *)&__j, format_number(&__x, i, 10, 1),  !is_empty(__k=storage_lookup_node(__n, &__x))) && \
             node_contents(__k, &__vn.contents, &__vn.end); i++)


#define is_empty(__n) ((__n).base == INVALID_ADDRESS)

node storage_lookup_node(node n, buffer key);
