#pragma once
// should consider a drain function
struct heap {
    struct table metadata;
    u64 (*alloc)(struct heap *h, bytes b);
    void (*dealloc)(struct heap *h, u64 a, bytes b);
    void (*destroy)(struct heap *h);
    bytes pagesize;
    bytes allocated;
};

heap debug_heap(heap m, heap p);
heap create_id_heap(heap h, u64 base, u64 length, bytes pagesize);
heap create_id_heap_backed(heap h, heap parent, bytes pagesize);
heap allocate_id_heap(heap h, bytes pagesize); /* id heap with no ranges */
boolean id_heap_add_range(heap h, u64 base, u64 length);
boolean id_heap_set_area(heap h, u64 base, u64 length, boolean validate, boolean allocate);
u64 id_heap_total(heap h);
void id_heap_set_randomize(heap h, boolean randomize);
u64 id_heap_alloc_subrange(heap h, bytes count, u64 start, u64 end);
static inline u64 id_heap_alloc_gte(heap h, bytes count, u64 min)
{
    return id_heap_alloc_subrange(h, count, min, infinity);
}

heap wrap_freelist(heap meta, heap parent, bytes size);
heap allocate_objcache(heap meta, heap parent, bytes objsize, bytes pagesize);
boolean objcache_validate(heap h);
heap objcache_from_object(u64 obj, bytes parent_pagesize);
heap allocate_mcache(heap meta, heap parent, int min_order, int max_order, bytes pagesize);

// really internals

static inline void *page_of(void *x, bytes pagesize)
{
    return((void *)((unsigned long)x &
                    (~((unsigned long)pagesize-1))));
}

static inline int subdivide(int quantum, int per, int s, int o)
{
    // this overallocates
    int base = ((s-o)/quantum) * per;
    return (pad(o + base, quantum));
}

#define allocate_u64(__h, __b) ((__h)->alloc(__h, __b))
#define allocate(__h, __b) pointer_from_u64(allocate_u64(__h, __b))

#define deallocate_u64(__h, __b, __s) ((__h)->dealloc(__h, __b, __s))
#define deallocate(__h, __b, __s) deallocate_u64(__h, u64_from_pointer(__b), __s)

#define allocate_zero(__h, __b) ({\
            u64 __len =  __b;\
            void *x = allocate(__h, __len);       \
            if (x != INVALID_ADDRESS) zero(x, __len);    \
            x; })

static inline void leak(heap h, u64 x, bytes length)
{
}

