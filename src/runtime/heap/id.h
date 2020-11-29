typedef struct id_heap {
    struct heap h;
    boolean (*add_range)(struct id_heap *i, u64 base, u64 length);
    boolean (*set_area)(struct id_heap *i, u64 base, u64 length, boolean validate, boolean allocate);
    void (*set_randomize)(struct id_heap *i, boolean randomize);
    u64 (*alloc_subrange)(struct id_heap *i, bytes count, u64 start, u64 end);
    void (*set_next)(struct id_heap *i, u64 next);
    /* private */
#ifdef KERNEL
    struct spinlock lock;
#endif
    u64 page_order;
    u64 allocated;
    u64 total;
    u64 flags;
    heap meta;
    heap map;
    heap parent;
    rangemap ranges;
} *id_heap;

id_heap create_id_heap(heap meta, heap map, u64 base, u64 length, bytes pagesize, boolean locking);
id_heap create_id_heap_backed(heap meta, heap map, heap parent, bytes pagesize, boolean locking);
id_heap allocate_id_heap(heap meta, heap map, bytes pagesize, boolean locking); /* id heap with no ranges */
#define destroy_id_heap(__h) destroy_heap(&(__h)->h)
#define id_heap_add_range(__h, __b, __l) ((__h)->add_range(__h, __b, __l))
#define id_heap_set_area(__h, __b, __l, __v, __a) ((__h)->set_area(__h, __b, __l, __v, __a))
#define id_heap_set_randomize(__h, __r) ((__h)->set_randomize(__h, __r))
#define id_heap_alloc_subrange(__h, __c, __s, __e) ((__h)->alloc_subrange(__h, __c, __s, __e))
#define id_heap_set_next(__h, __n) ((__h)->set_next(__h, __n))

/* If count == 1, the return value is guaranteed to be the lowest-numbered
 * non-allocated id starting from min. */
static inline u64 id_heap_alloc_gte(id_heap h, bytes count, u64 min)
{
    id_heap_set_next(h, min);
    return id_heap_alloc_subrange(h, count, min, infinity);
}
