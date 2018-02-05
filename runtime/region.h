
typedef u8 regionbody[20];
typedef regionbody *region;

#define region_base(__r) (((u64 *)__r)[0])
#define region_length(__r) (((u64 *)__r)[1])
#define region_type(__r) (((u32 *)__r)[4])
#define regions ((region)pointer_from_u64(ABSOLUTION - sizeof(regionbody)))

#define REGION_PHYSICAL 1
#define REGION_DEVICE 2
#define REGION_VIRTUAL 3
#define REGION_IDENTITY 4
#define REGION_VERBOTEN 5 // identity but allocated

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
    int type;
} *region_heap;


// fix complexity
static inline u64 allocate_region(heap h, bytes size)
{
    region_heap rh = (region_heap)h;
    u64 len = pad(size, h->pagesize);
    
    for (region e = regions; region_type(e);e -= 1) {
        if ((region_type(e) == rh->type) && (region_length(e) >= len)){
            u64 result = region_base(e);
            region_base(e) += size;
            region_length(e) -= size;
            return result;
        }
    }
    return u64_from_pointer(INVALID_ADDRESS);
}

static inline heap region_allocator(heap h, u64 pagesize, int type)
{
    region_heap rh = allocate(h, sizeof(struct region_heap));
    rh->h.alloc = allocate_region;
    rh->h.pagesize = pagesize;
    rh->type = type;
    return (heap)h;
}

