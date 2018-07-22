typedef struct table *table;

typedef u64 key;

table allocate_table(heap h, key (*key_function)(void *x), boolean (*equal_function)(void *x, void *y));
int table_elements(table t);


typedef struct entry {
    void *v;
    key k;
    void *c; 
    struct entry *next;
} *entry;

struct table {
    heap h;
    int buckets;
    int count;
    entry *entries;
    key (*key_function)(void *x);
    boolean (*equals_function)(void *x, void *y);
};

void *table_find (table t, void *c);
//void *table_find_key (table t, void *c, void **kr);
void table_set (table t, void *c, void *v);

#define eZ(x,y) ((entry) x)->y

#define tablev(__z) ((table)valueof(__z))
// much threadsafe...think about start
#define table_foreach(__t, __k, __v)\
    for (int __i = 0 ; __i< tablev(__t)->buckets; __i++) \
        for (void *__k, *__v, *__j = (tablev(__t)->entries[__i]), *__next;    \
             __j && (__next =  eZ((__j), next) , __k = eZ(__j, c), __v = eZ(__j, v)); \
             __j = __next)

static inline boolean pointer_equal(void *a, void* b)
{
    return a == b;
}

// should try to fold since the lower bits are driven to zero by alignment
static inline key identity_key(void *a)
{
    return u64_from_pointer(a);
}


extern void serial_out(u8);

static inline key fnv64(void *z)
{
    buffer b = z;
    u64 hash = 0xcbf29ce484222325;
    u64 fnv_prime = 1099511628211;
    for (int i = 0; i < buffer_length(b); i++) {
        hash ^= byte(b, i);
        hash *= fnv_prime;
    }
    return hash;
}
