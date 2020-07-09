struct region {
    u64 base;
    u64 length;
    u32 type;
} __attribute__((packed));

typedef struct region *region;

/* compute address of the e820 region records retrieved in stage1 - must match layout in stage1.s */
#define regions ((region)pointer_from_u64(0x7c00 + 0x200 - (4 * 16 + 2) - sizeof(struct region)))
#define for_regions(__r) for (region __r = regions; __r->type; __r -= 1)

#define REGION_PHYSICAL          1 /* available physical memory */
#define REGION_DEVICE            2 /* e820 physical region configured for i/o */
#define REGION_INITIAL_PAGES     10 /* for page table allocations in stage2 and early stage3 */
#define REGION_FILESYSTEM        12 /* offset on disk for the filesystem, see if we can get disk info from the bios */
#define REGION_KERNIMAGE         13 /* location of kernel elf image loaded by stage2 */
#define REGION_RECLAIM           14 /* areas to be unmapped and reclaimed in stage3 (only stage2 stack presently) */

static inline region create_region(u64 base, u64 length, int type)
{
    region r = regions;
    for (; r->type; r -= 1)
        ;
    r->base = base;
    r->length = length;
    r->type = type;
    (r-1)->type = 0;
    return r;
}

typedef struct region_heap {
    struct heap h;
    int type;
} *region_heap;

static inline u64 allocate_region(heap h, bytes size)
{
    region_heap rh = (region_heap)h;
    u64 len = pad(size, h->pagesize);
    u64 base = 0;
    region r = 0;

    /* Select the lowest physical region that's within 32-bit space. */
    for_regions(e) {
        if ((e->type != rh->type) ||
            ((e->length & ~MASK(PAGELOG)) < len) ||
            (e->base + e->length > U64_FROM_BIT(32)))
            continue;

        base = e->base;
        r = e;
        break;
    }
    assert(r != 0);
    if (base == 0)
        return u64_from_pointer(INVALID_ADDRESS);

    u64 result = ((base + r->length) & ~MASK(PAGELOG)) - len;
    r->length = result - base;
    return result;
}

static inline void region_heap_init(region_heap rh, u64 pagesize, int type)
{
    rh->h.dealloc = leak;
    rh->h.alloc = allocate_region;
    rh->h.pagesize = pagesize;
    rh->type = type;
}

static inline heap region_allocator(heap h, u64 pagesize, int type)
{
    region_heap rh = allocate(h, sizeof(struct region_heap));
    if (rh == INVALID_ADDRESS)
        return INVALID_ADDRESS;
    region_heap_init(rh, pagesize, type);
    return (heap)rh;
}


static inline void print_regions()
{
    for_regions(e){    
         print_u64(e->type);
         console(" ");
         print_u64(e->base);
         console(" ");
         print_u64(e->length);
         console("\n");
    }
}
