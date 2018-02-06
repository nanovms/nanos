
// note that node is an immediate and not a pointer just
// to cut down on trash
typedef struct node {
    void *base;
    u64 offset;
} node;

u64 init_storage(buffer b, int buckets);
void storage_set(buffer b, u64 start, buffer key, u64 offset, u64 length);
boolean storage_lookup(node n, buffer key, u64 *offset, bytes *length);
boolean storage_resolve(node n, vector path, void **storage, u64 *slength);

// first = 0 has to be at the bottom
#define  storage_foreach(__b, __p, __n, __v) \
    for (int __first = 1;__first;)\
    for (struct buffer __x, __y;__first;)\
    for (buffer __n = &__x, __v = &__y ; __first; __first = 0)    
    
#define storage_vector_foreach(__b, __p, __i, __v)\
    for (int __first = 1;__first;__first = 0)\
    for (struct buffer __x, __y;__first;)\
    for (buffer __v = &__x ; __first;)            

static inline buffer storage_buffer(heap h, node n, vector path)
{
    void *base;
    u64 length;
    buffer b = allocate(h, sizeof(struct buffer));
    b->start = 0;
    if (!storage_resolve(n, path, &b->contents, &b->end)) {
        return 0;
    }
    return b;
}

#define is_empty(__n) ((__n).base == INVALID_ADDRESS)

// too much conversion
static inline boolean node_property(buffer b, node n, char *name)
{
    b->contents = name;
    b->start = 0;
    b->end = runtime_strlen(name);
    u64 off;
    if (!storage_lookup(n, b, &off, &b->length)) 
        return false;
    b->contents = n.base + off;
    b->end = b->length;
    return true;
}
    
