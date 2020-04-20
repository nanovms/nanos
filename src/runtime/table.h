typedef struct table *table;

typedef u64 key;

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

table allocate_table(heap h, key (*key_function)(void *x), boolean (*equal_function)(void *x, void *y));
void deallocate_table(table t);
void table_validate(table t, char *n);
int table_elements(table t);
void *table_find(table t, void *c);
//void *table_find_key (table t, void *c, void **kr);
void table_set(table t, void *c, void *v);
void table_clear(table t);

#define eZ(x,y) ((entry) x)->y

#define tablev(__z) ((table)valueof(__z))
#define table_foreach(__t, __k, __v)\
    for (int __i = 0 ; __i< tablev(__t)->buckets; __i++) \
        for (void *__k, *__v, *__j = (tablev(__t)->entries[__i]), *__next;    \
             __j && (__next =  eZ((__j), next) , __k = eZ(__j, c), __v = eZ(__j, v)); \
             __j = __next)

boolean pointer_equal(void *a, void* b);
key identity_key(void *a);
