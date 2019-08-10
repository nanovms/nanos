#pragma once

struct region {
    u64 base;
    u64 length;
    u32 type;
} __attribute__((packed));

typedef struct region *region;

#define regions ((region)pointer_from_u64(0x7c00 + 0x200 - (4 * 16 + 2) - sizeof(struct region)))
#define for_regions(__r) for (region __r = regions; __r->type; __r -= 1)

#define REGION_PHYSICAL 1 // available physical memory
#define REGION_DEVICE 2   // e820 physical region configured for i/o
#define REGION_VIRTUAL 3  // marks allocated instead of available regions
#define REGION_IDENTITY 4 // use for page tables
#define REGION_FILESYSTEM 5 // offset on disk for the filesystem, see if we can get disk info from the bios
#define REGION_KERNIMAGE 6 // location of kernel elf image loaded by stage2

static inline region create_region(u64 base, u64 length, int type)
{
    region r = regions;
    for (; r->type; r -= 1)
        ;
    r->base = base;
    r->length = length;
    r->type = type;
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
    region r;

    /* Select the highest physical region that's within 32-bit space. */
    for_regions(e) {
        if ((e->type != rh->type) ||
            ((e->length & ~MASK(PAGELOG)) < len) ||
            (e->base + e->length > U64_FROM_BIT(32)))
            continue;
        if (e->base > base) {
            base = e->base;
            r = e;
        }
    }

    if (base == 0)
        return u64_from_pointer(INVALID_ADDRESS);

    /* If this region intersects the kernel map, shrink the region
       such that allocations begin below the kernel. */
    u64 end = base + r->length;
    if (end > KERNEL_RESERVE_START) {
        if (base < KERNEL_RESERVE_START) {
            r->length -= end - KERNEL_RESERVE_START;
        } else {
            /* Really we should just select the next region, but this
               seems so unlikely... */
            assert(base >= KERNEL_RESERVE_END);
        }
    }

    /* Carve allocations from top of region, mainly to get identity
       mappings out of the way of commonly-used areas in low memory. */
    u64 result = ((base + r->length) & ~MASK(PAGELOG)) - len;
    r->length = result - base;
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
         print_u64(e->type);
         console(" ");
         print_u64(e->base);
         console(" ");
         print_u64(e->length);
         console("\n");
    }
}
