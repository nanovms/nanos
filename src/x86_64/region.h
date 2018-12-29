#pragma once
typedef u8 regionbody[20];
typedef regionbody *region;

#define for_regions(__r) for (region __r = regions; region_type(__r);__r -= 1)

// see stage2.s - pass from Makefile? argument?
#define region_start 0x7dfe

#define region_base(__r) (((u64 *)__r)[0])
#define region_length(__r) (((u64 *)__r)[1])
#define region_type(__r) (((u32 *)__r)[4])
#define regions ((region)pointer_from_u64(region_start - sizeof(regionbody)))

#define REGION_PHYSICAL 1 // available physical memory
#define REGION_DEVICE 2   // e820 physical region configured for i/o
#define REGION_VIRTUAL 3  // marks allocated instead of available regions
#define REGION_IDENTITY 4 // use for page tables
#define REGION_FILESYSTEM 5 // offset on disk for the filesystem, see if we can get disk info from the bios
#define REGION_KERNIMAGE 6 // location of kernel elf image loaded by stage2

static inline region create_region(u64 base, u64 length, int type)
{
    region r = regions;
    for (;region_type(r);r -= 1);
    region_type(r) = type;
    region_base(r) = base;
    region_length(r) = length;
    return r;
}

typedef struct region_heap {
    struct heap h;
    int type;
} *region_heap;


// fix complexity - rtrie
static inline u64 allocate_region(heap h, bytes size)
{
    region_heap rh = (region_heap)h;
    u64 len = pad(size, h->pagesize);
    u64 base = 0;
    region r;

    /* Select the highest physical region that's within 32-bit space. */
    for_regions(e) {
        if ((region_type(e) != rh->type) ||
            ((region_length(e) & ~MASK(PAGELOG)) < len) ||
            (region_base(e) + region_length(e) > U64_FROM_BIT(32)))
            continue;
        if (region_base(e) > base) {
            base = region_base(e);
            r = e;
        }
    }

    if (base == 0)
        return u64_from_pointer(INVALID_ADDRESS);

    /* Carve allocations from top of region, mainly to get identity
       mappings out of the way of commonly-used areas in low memory. */
    u64 result = ((base + region_length(r)) & ~MASK(PAGELOG)) - len;
    region_length(r) = result - base;
    return result;
}

static inline heap region_allocator(heap h, u64 pagesize, int type)
{
    region_heap rh = allocate(h, sizeof(struct region_heap));
    rh->h.dealloc = leak;
    rh->h.alloc = allocate_region;    
    rh->h.pagesize = pagesize;
    rh->type = type;
    return (heap)rh;
}


static inline void print_regions()
{
    for_regions(e){    
         print_u64(region_type(e));
         console(" ");
         print_u64(region_base(e));
         console(" ");
         print_u64(region_length(e));                  
         console("\n");
    }
}
