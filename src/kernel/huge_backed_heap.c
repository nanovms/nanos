#include <kernel.h>

//#define DEBUG_HUGE_BACKED_HEAP
#ifdef DEBUG_HUGE_BACKED_HEAP
#define huge_backed_debug(x, ...) do {rprintf(x, ##__VA_ARGS__);} while(0)
#else
#define huge_backed_debug(x, ...)
#endif

typedef struct huge_backed_heap {
    struct backed_heap bh;
    struct spinlock lock;
    heap meta;
    heap physical;
    bitmap mapped;
} *huge_backed_heap;

#define HUGE_BACKED_IDX_LIMIT ((HUGE_BACKED_LIMIT - HUGE_BACKED_BASE) >> HUGE_BACKED_PAGELOG)

static inline int huge_backed_get_index(huge_backed_heap hb, u64 paddr)
{
    return (paddr >> HUGE_BACKED_PAGELOG);
}

static inline u64 huge_backed_base_from_index(huge_backed_heap hb, int index)
{
    return HUGE_BACKED_BASE + ((u64)index << HUGE_BACKED_PAGELOG);
}

static inline u64 huge_backed_heap_add_physical(huge_backed_heap hb, u64 p)
{
    int index = huge_backed_get_index(hb, p);
    assert(index < HUGE_BACKED_IDX_LIMIT);
    boolean mapped = bitmap_get(hb->mapped, index);
    u64 offset = p & MASK(HUGE_BACKED_PAGELOG);
    u64 vbase = huge_backed_base_from_index(hb, index);
    u64 pbase = p & ~MASK(HUGE_BACKED_PAGELOG);
    huge_backed_debug("index %d, mapped %d\n", index, mapped);
    if (!mapped) {
        u64 length = U64_FROM_BIT(HUGE_BACKED_PAGELOG);
        huge_backed_debug("   map vbase 0x%lx, pbase 0x%lx, length 0x%lx\n", vbase, pbase, length);
        map(vbase, pbase, length, pageflags_writable(pageflags_memory()));
        bitmap_set(hb->mapped, index, 1);
    }
    return vbase + offset;
}

static inline u64 huge_backed_alloc_internal(huge_backed_heap hb, bytes size)
{
    u64 len = pad(size, hb->bh.h.pagesize);
    u64 p = allocate_u64(hb->physical, len);
    if (p == INVALID_PHYSICAL)
        return p;
    huge_backed_debug("%s: size 0x%lx, len 0x%lx, p 0x%lx, ", __func__, size, len, p);
    return huge_backed_heap_add_physical(hb, p);
}

static inline boolean huge_backed_heap_validate_physical(huge_backed_heap hb, u64 p)
{
    return bitmap_get(hb->mapped, huge_backed_get_index(hb, p));
}

static u64 huge_backed_alloc(heap h, bytes size)
{
    return huge_backed_alloc_internal((huge_backed_heap)h, size);
}

static void huge_backed_dealloc(heap h, u64 x, bytes size)
{
    // XXX todo
}

static void huge_backed_destroy(heap h)
{
    // XXX todo
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
        *phys = a & ~HUGE_BACKED_BASE;
    return pointer_from_u64(a);
}

static void huge_backed_dealloc_unmap(backed_heap bh, void *virt, u64 phys, bytes len)
{
    // XXX todo
}

backed_heap allocate_huge_backed_heap(heap meta, heap physical)
{
    huge_backed_heap hb = allocate(meta, sizeof(*hb));
    if (hb == INVALID_ADDRESS)
        return INVALID_ADDRESS;
    hb->bh.h.alloc = huge_backed_alloc;
    hb->bh.h.dealloc = huge_backed_dealloc;
    hb->bh.h.destroy = huge_backed_destroy;
    hb->bh.h.allocated = huge_backed_allocated;
    hb->bh.h.total = huge_backed_total;
    hb->bh.h.pagesize = physical->pagesize;
    hb->bh.h.management = 0;
    hb->bh.alloc_map = huge_backed_alloc_map;
    hb->bh.dealloc_unmap = huge_backed_dealloc_unmap;
    hb->meta = meta;
    hb->physical = physical;
    hb->mapped = allocate_bitmap(meta, meta, HUGE_BACKED_IDX_LIMIT);
    bitmap_extend(hb->mapped, HUGE_BACKED_IDX_LIMIT - 1);
    return &hb->bh;
}
