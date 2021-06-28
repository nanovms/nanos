#include <kernel.h>

//#define DEBUG_HUGE_BACKED_HEAP
#ifdef DEBUG_HUGE_BACKED_HEAP
#define huge_backed_debug(x, ...) do {rprintf(x, ##__VA_ARGS__);} while(0)
#else
#define huge_backed_debug(x, ...)
#endif

typedef struct huge_backed_heap {
    struct backed_heap bh;
    heap meta;
    id_heap physical;
    bitmap mapped;
} *huge_backed_heap;

#define HUGE_BACKED_IDX_LIMIT ((HUGE_BACKED_LIMIT - HUGE_BACKED_BASE) >> HUGE_BACKED_PAGELOG)

static inline u64 huge_backed_base_from_index(huge_backed_heap hb, int index)
{
    return HUGE_BACKED_BASE + ((u64)index << HUGE_BACKED_PAGELOG);
}

static inline u64 huge_backed_alloc_internal(huge_backed_heap hb, bytes size)
{
    u64 len = pad(size, hb->bh.h.pagesize);
    u64 p = id_heap_alloc_subrange(hb->physical, len, 0, HUGE_BACKED_LIMIT);
    if (p == INVALID_PHYSICAL)
        return p;
    u64 v = virt_from_huge_backed_phys(p);
    huge_backed_debug("%s: size 0x%lx, len 0x%lx, p 0x%lx, v 0x%lx\n",
                      __func__, size, len, p, v);
    return v;
}

static u64 huge_backed_alloc(heap h, bytes size)
{
    return huge_backed_alloc_internal((huge_backed_heap)h, size);
}

static inline void huge_backed_dealloc_internal(huge_backed_heap hb, u64 x, bytes size)
{
    u64 len = pad(size, hb->bh.h.pagesize);
    u64 phys = phys_from_huge_backed_virt(x);
    deallocate_u64((heap)hb->physical, phys, len);
    huge_backed_debug("%s: addr 0x%lx, phys 0x%lx, size 0x%lx, len 0x%lx\n",
                      __func__, x, phys, size, len);
}

static void huge_backed_dealloc(heap h, u64 x, bytes size)
{
    huge_backed_dealloc_internal((huge_backed_heap)h, x, size);
}

/* pass through to phys ... */
static bytes huge_backed_allocated(heap h)
{
    return heap_allocated((heap)((huge_backed_heap)h)->physical);
}

static bytes huge_backed_total(heap h)
{
    return heap_total((heap)((huge_backed_heap)h)->physical);
}

static void *huge_backed_alloc_map(backed_heap bh, bytes len, u64 *phys)
{
    u64 a = huge_backed_alloc_internal((huge_backed_heap)bh, len);
    if (phys)
        *phys = phys_from_huge_backed_virt(a);
    return pointer_from_u64(a);
}

static void huge_backed_dealloc_unmap(backed_heap bh, void *virt, u64 phys, bytes len)
{
    huge_backed_dealloc_internal((huge_backed_heap)bh, u64_from_pointer(virt), len);
}

/* Though the bitmap is currently only used during initialization, it would be
   needed if we ever have to support hotplug memory. Just leave it. */
static void add_huge_page(huge_backed_heap hb, int index)
{
    assert(index <= HUGE_BACKED_IDX_LIMIT);
    if (!bitmap_get(hb->mapped, index)) {
        u64 length = U64_FROM_BIT(HUGE_BACKED_PAGELOG);
        u64 vbase = huge_backed_base_from_index(hb, index);
        u64 pbase = index * length;
        map(vbase, pbase, length, pageflags_writable(pageflags_memory()));
        bitmap_set(hb->mapped, index, 1);
    }
}

closure_function(1, 1, void, physmem_range_handler,
                 huge_backed_heap, hb,
                 range, r)
{
#ifdef DEBUG_HUGE_BACKED_HEAP
    console("huge_backed_heap: add phys [");
    print_u64(r.start);
    console(", ");
    print_u64(r.end);
    console("); ");
#endif
    r = range_rshift(r, HUGE_BACKED_PAGELOG);
    r.end = MIN(r.end, HUGE_BACKED_IDX_LIMIT);
#ifdef DEBUG_HUGE_BACKED_HEAP
    console("idx [");
    print_u64(r.start);
    console(", ");
    print_u64(r.end);
    console(")\n");
#endif
    for (int i = r.start; i <= r.end; i++)
        add_huge_page(bound(hb), i);
}

static void huge_backed_init_maps(huge_backed_heap hb)
{
    /* iterate through phys id heap ranges and add mappings */
    id_heap_range_foreach(hb->physical, stack_closure(physmem_range_handler, hb));
}

backed_heap allocate_huge_backed_heap(heap meta, id_heap physical)
{
    huge_backed_heap hb = allocate(meta, sizeof(*hb));
    if (hb == INVALID_ADDRESS)
        return INVALID_ADDRESS;
    hb->bh.h.alloc = huge_backed_alloc;
    hb->bh.h.dealloc = huge_backed_dealloc;
    hb->bh.h.allocated = huge_backed_allocated;
    hb->bh.h.total = huge_backed_total;
    hb->bh.h.pagesize = physical->h.pagesize;
    hb->bh.h.management = 0;
    hb->bh.alloc_map = huge_backed_alloc_map;
    hb->bh.dealloc_unmap = huge_backed_dealloc_unmap;
    hb->meta = meta;
    hb->physical = physical;
    hb->mapped = allocate_bitmap(meta, meta, HUGE_BACKED_IDX_LIMIT);
    huge_backed_init_maps(hb);
    return &hb->bh;
}
