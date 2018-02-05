
// should consider a drain function
typedef struct heap {
    u64 (*alloc)(struct heap *h, bytes b);
    void (*dealloc)(struct heap *h, u64 a, bytes b);
    void (*destroy)();
    bytes pagesize;
    bytes allocated;
} *heap;

heap allocate_leaky_heap(heap parent);
heap allocate_pagechunk(heap h, bytes s);
heap allocate_pagecache(heap h);
heap allocate_rolling_heap(heap h);

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

#define allocate_u64(__h, __b) (__h)->alloc(__h, __b)
#define allocate(__h, __b) pointer_from_u64(allocate_u64(__h, __b))

#define deallocate(__h, __b, __s) ((__h)->dealloc(__h, u64_from_pointer(__b), __s))

#define allocate_zero(__h, __b) ({\
        void *x = allocate(__h, __b);\
        zero(x, __b);\
        x; })

