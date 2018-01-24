
typedef u8 regionbody[20];
typedef regionbody *region;

#define INVALID_ADDRESS ((void *)0xffffffffffffffffull)

#define region_base(__r) (((u64 *)__r)[0])
#define region_length(__r) (((u64 *)__r)[1])
#define region_type(__r) (((u32 *)__r)[4])
#define regions ((region)pointer_from_u64(ABSOLUTION - sizeof(regionbody)))

#define REGION_PHYSICAL 1
#define REGION_DEVICE 2
#define REGION_VIRTUAL 3

static inline region create_region(u64 base, u64 length, int type)
{
    for (region e = regions; ;e -= 1) {
        if (!region_type(e)) {
            region_type(e) = type;
            region_base(e) = base;
            region_length(e) = length;
            return e;
        }
    }
}

typedef struct region_heap {
    struct heap h;
    region r;
} *region_heap;

    
static inline void *allocate_region(heap h, bytes size)
{
    region_heap rh = (region_heap)h;    
    if (region_length(rh->r) < size) return INVALID_ADDRESS;
    void *result = pointer_from_u64(region_base(rh->r));
    region_base(rh->r) += size;
    region_length(rh->r) -= size;
    return result;
}

static inline void *allocate_region_top(heap h, bytes size)
{
    region_heap rh = (region_heap)h;
    if (region_length(rh->r) < size) return INVALID_ADDRESS;    
    void *result = pointer_from_u64(region_base(rh->r) + region_length(rh->r) - size);
    region_length(rh->r) -= size;
    return result;
}

static inline heap region_allocator(region_heap h, region e, u64 pagesize)
{
    h->h.allocate = allocate_region;
    h->h.pagesize = pagesize;
    h->r = e;
    return (heap)h;
}

static inline heap region_allocator_top(region_heap h, region e)
{
    h->h.allocate = allocate_region_top;
    h->r = e;
    return (heap)h;
}
