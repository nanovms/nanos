
u64 init_storage(buffer b, int buckets);
void storage_set(buffer b, u64 start, buffer key, u64 offset, u64 length);
boolean storage_lookup(buffer b, u64 start, buffer key, u64 *offset, bytes *length);
boolean storage_resolve(buffer fs, vector path, void **storage, u64 *slength);

#define  storage_foreach(__b, __p, __n, __v) \
    for (int __first = 1;__first;__first = 0)\
    for (struct buffer __x, __y;__first;)\
    for (buffer __n = &__x, __v = &__y ; __first;)    
    
#define storage_vector_foreach(__b, __p, __i, __v)\
    for (int __first = 1;__first;__first = 0)\
    for (struct buffer __x, __y;__first;)\
    for (buffer __v = &__x ; __first;)            

#define  storage_buffer(__h, __b, __n) ((void *)0)
