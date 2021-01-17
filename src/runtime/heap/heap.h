// should consider a drain function
struct heap {
    struct table metadata;
    u64 (*alloc)(struct heap *h, bytes b);
    void (*dealloc)(struct heap *h, u64 a, bytes b);
    void (*destroy)(struct heap *h);
    bytes (*allocated)(struct heap *h);
    bytes (*total)(struct heap *h);
    bytes pagesize;
};

heap debug_heap(heap m, heap p);

static inline u64 heap_allocated(heap h)
{
    return h->allocated ? h->allocated(h) : INVALID_PHYSICAL;
}

static inline u64 heap_total(heap h)
{
    return h->total ? h->total(h) : INVALID_PHYSICAL;
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

static inline void *allocate_align(heap h, bytes size, int order)
{
    assert(order > 1);
    int msize = sizeof(u64) * 2;
    u64 tsize = size + (1<<order) + msize;
    u64 v = h->alloc(h, tsize);
    if (v == INVALID_PHYSICAL)
        return pointer_from_u64(v);
    u64 *p = pointer_from_u64((v + (1<<order) + msize) & ~MASK(order));
    assert(u64_from_pointer(p) + size <= v + tsize);
    assert(u64_from_pointer(p) - v >= msize);
    p[-1] = v;
    p[-2] = tsize;
    return (void *)p;
}

static inline void deallocate_align(heap h, void *a)
{
    u64 *p = a;
    u64 v = p[-1];
    u64 tsize = p[-2];
    assert(v != 0);
    assert(v != INVALID_PHYSICAL);
    assert(tsize > 0);
    h->dealloc(h, v, tsize);
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

#define destroy_heap(__h) do { if (__h) (__h)->destroy(__h); } while(0)

static inline void leak(heap h, u64 x, bytes length)
{
}

