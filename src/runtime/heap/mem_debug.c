#ifdef KERNEL
#include <kernel.h>
#else
#include <runtime.h>
#endif

/* This debug wrapper allocates extra space (defined at heap creation) around
 * both sides of the requested allocation and sets a header at the beginning of
 * the extra space with the allocation size and allocation return address. The
 * deallocation size is checked against the saved allocation size to make sure
 * they match. The size of the padding on either side is specified at heap
 * creation, where 0 uses the default value. Use a non-zero padding if the heap
 * is expected to return aligned values. The backed_heap version of this wrapper
 * defaults to PAGESIZE padding.
 * Additional checks can be performed if defined:
 * MEMDBG_OVERRUN sets a pattern in the padding around the requested allocation
 * that is checked on deallocation to see if it has been modified, indicating
 * an overrun (0xcafefade).
 * MEMDBG_INIT sets a pattern on the requested allocation to try to trigger a
 * fault is something uses the memory without initialization (0xfeedbeef).
 * MEMDBG_FREE sets a pattern on deallocation for the entire allocation to try
 * to catch any use after free (0xdeaddead).
 */
#define MEMDBG_OVERRUN
#define MEMDBG_INIT
#define MEMDBG_FREE

#define DBG_HDR_SIG 0xd00d00d00d00d00d
#define PAD_MIN 64
#define PAD_MIN_BACKED PAGESIZE

typedef struct mem_debug_heap {
    struct heap h;
    heap parent;
    u64 padsize;
    u32 objsize;
} *mem_debug_heap;

#ifdef KERNEL
typedef struct mem_debug_backed_heap {
    struct backed_heap bh;
    backed_heap parent;
    u64 padsize;
} *mem_debug_backed_heap;
#endif

typedef struct mem_debug_hdr {
    u64 sig;
    u64 allocsize;
    u64 padsize;
    u64 alloc_addr;
} *mem_debug_hdr;

u32 pat_init = 0xfeedbeef;
u32 pat_freed = 0xdeaddead;
u32 pat_redzone = 0xcafefade;

#if defined(MEMDBG_OVERRUN) || defined(MEMDBG_INIT) || defined(MEMDBG_FREE)
static void set_pattern(void *v, bytes sz, void *p, bytes psz)
{
    u8 *bp = v;
    for (s64 ssz = sz; ssz > 0; ssz -= psz, bp += psz)
        runtime_memcpy(bp, p, MIN(psz, ssz));
}
#endif

#if defined(MEMDBG_OVERRUN)
static boolean check_pattern(void *v, bytes sz, void *p, bytes psz)
{
    u8 *bp = v;
    for (s64 ssz = sz; ssz > 0; ssz -= psz, bp += psz)
        if (runtime_memcmp(bp, p, MIN(psz, ssz)) != 0)
            return false;
    return true;
}
#endif

static void get_debug_alloc_size(bytes b, bytes padsize, bytes *nb, bytes *padding)
{
    *padding = MAX(padsize, PAD_MIN);
    *nb = *padding * 2 + b;
    if (padsize >= PAGESIZE)
        *nb = pad(*nb, PAGESIZE);
}

/* These functions use volatile so the hdr address won't be optimized out when debugging. */
static u64 alloc_check(volatile mem_debug_hdr hdr, bytes b, bytes padding)
{
#ifdef MEMDBG_OVERRUN
    set_pattern(hdr + 1, padding - sizeof(*hdr), &pat_redzone, sizeof(pat_redzone));
    set_pattern((u8 *)hdr + padding + b, padding, &pat_redzone, sizeof(pat_redzone));
#endif
    hdr->sig = DBG_HDR_SIG;
    hdr->allocsize = b;
    hdr->padsize = padding;
    u8 *buf = (u8 *)hdr + padding;
#ifdef MEMDBG_INIT
    set_pattern(buf, b, &pat_init, sizeof(pat_init));
#endif
    return u64_from_pointer(buf);
}

static void dealloc_check(volatile mem_debug_hdr hdr, u64 a, bytes b, bytes nb, bytes padding)
{
    assert(hdr->sig == DBG_HDR_SIG);
    assert(b == hdr->allocsize);
#ifdef MEMDBG_OVERRUN
    assert(check_pattern(hdr + 1, padding - sizeof(*hdr), &pat_redzone, sizeof(pat_redzone)));
    assert(check_pattern(pointer_from_u64(a + b), padding, &pat_redzone, sizeof(pat_redzone)));
#endif
#ifdef MEMDBG_FREE
    set_pattern(hdr, nb, &pat_freed, sizeof(pat_freed));
#endif
}

static u64 mem_debug_alloc(heap h, bytes b)
{
    mem_debug_heap mdh = (mem_debug_heap)h;
    bytes padding, nb;

    if (mdh->objsize)
        b = mdh->objsize;
    get_debug_alloc_size(b, mdh->padsize, &nb, &padding);
    mem_debug_hdr hdr = allocate(mdh->parent, nb);
    if (hdr == INVALID_ADDRESS)
        return INVALID_PHYSICAL;
    hdr->alloc_addr = u64_from_pointer(__builtin_extract_return_addr(__builtin_return_address(0)));
    return alloc_check(hdr, b, padding);
}

static void mem_debug_dealloc(heap h, u64 a, bytes b)
{
    mem_debug_heap mdh = (mem_debug_heap)h;
    bytes padding, nb;

    if (mdh->objsize)
        b = mdh->objsize;
    get_debug_alloc_size(b, mdh->padsize, &nb, &padding);
    mem_debug_hdr hdr = (mem_debug_hdr)pointer_from_u64(a - padding);
    dealloc_check(hdr, a, b, nb, padding);
    deallocate(mdh->parent, u64_from_pointer(hdr), nb);
}

static u64 mem_debug_allocated(heap h)
{
    return heap_allocated((heap)((mem_debug_heap)h)->parent);
}

static u64 mem_debug_total(heap h)
{
    return heap_total((heap)((mem_debug_heap)h)->parent);
}

heap mem_debug(heap meta, heap parent, u64 padsize)
{
    build_assert(PAD_MIN > sizeof(mem_debug_hdr));
    mem_debug_heap mdh = allocate_zero(meta, sizeof(*mdh));
    mdh->parent = parent;
    mdh->h.pagesize = parent->pagesize;
    mdh->h.alloc = mem_debug_alloc;
    mdh->h.dealloc = mem_debug_dealloc;
    mdh->h.allocated = mem_debug_allocated;
    mdh->h.total = mem_debug_total;
    mdh->h.management = 0;      /* TODO */
    mdh->padsize = MAX(padsize, PAD_MIN);
    return &mdh->h;
}

heap mem_debug_objcache(heap meta, heap parent, u64 objsize, u64 pagesize)
{
    mem_debug_heap mdh = allocate_zero(meta, sizeof(*mdh));
    u64 newsize;
    u64 padding = objsize >= PAGESIZE ? PAGESIZE : PAD_MIN;

    newsize = objsize + padding * 2;
    mdh->parent = (heap)allocate_wrapped_objcache(meta, parent, newsize, pagesize, &mdh->h);
    mdh->h.pagesize = objsize;
    mdh->h.alloc = mem_debug_alloc;
    mdh->h.dealloc = mem_debug_dealloc;
    mdh->h.total = mem_debug_allocated;
    mdh->h.allocated = mem_debug_total;
    mdh->h.management = 0;      /* TODO */
    mdh->padsize = padding;
    mdh->objsize = objsize;
    return &mdh->h;
}

#ifdef KERNEL
static void *mem_debug_backed_alloc_map_nohdr(backed_heap h, bytes b, u64 *phys)
{
    mem_debug_backed_heap mdh = (mem_debug_backed_heap)h;
    void *v = alloc_map(mdh->parent, b, phys);
#ifdef MEMDBG_INIT
    set_pattern(v, b, &pat_init, sizeof(pat_init));
#endif
    return v;
}

static void mem_debug_backed_dealloc_unmap_nohdr(backed_heap h, void *v, u64 p, bytes b)
{
    mem_debug_backed_heap mdh = (mem_debug_backed_heap)h;
#ifdef MEMDBG_FREE
    set_pattern(v, b, &pat_freed, sizeof(pat_freed));
#endif
    dealloc_unmap(mdh->parent, v, p, b);
}

static void *mem_debug_backed_alloc_map(backed_heap h, bytes b, u64 *phys)
{
    mem_debug_backed_heap mdh = (mem_debug_backed_heap)h;
    bytes padding, nb;
    u64 nphys;

    get_debug_alloc_size(b, mdh->padsize, &nb, &padding);
    mem_debug_hdr hdr = alloc_map(mdh->parent, nb, &nphys);
    if (hdr == INVALID_ADDRESS)
        return INVALID_ADDRESS;
    assert(alloc_check(hdr, b, padding) == u64_from_pointer(hdr) + padding);
    hdr->alloc_addr = u64_from_pointer(__builtin_extract_return_addr(__builtin_return_address(0)));
    if (phys)
        *phys = nphys + padding;
    return (u8 *)hdr + padding;
}

static void mem_debug_backed_dealloc_unmap(backed_heap h, void *v, u64 p, bytes b)
{
    mem_debug_backed_heap mdh = (mem_debug_backed_heap)h;
    bytes padding, nb;
    u64 a = u64_from_pointer(v);

    get_debug_alloc_size(b, mdh->padsize, &nb, &padding);
    mem_debug_hdr hdr = (mem_debug_hdr)pointer_from_u64(a - padding);
    dealloc_check(hdr, a, b, nb, padding);
    dealloc_unmap(mdh->parent, hdr, p ? p - padding : 0, nb);
}

static u64 mem_debug_backed_alloc(heap h, bytes b)
{
    return u64_from_pointer(alloc_map((backed_heap)h, b, 0));
}

static void mem_debug_backed_dealloc(heap h, u64 a, bytes b)
{
    dealloc_unmap((backed_heap)h, pointer_from_u64(a), 0, b);
}

static u64 mem_debug_backed_allocated(heap h)
{
    return heap_allocated((heap)((mem_debug_backed_heap)h)->parent);
}

static u64 mem_debug_backed_total(heap h)
{
    return heap_total((heap)((mem_debug_backed_heap)h)->parent);
}

backed_heap mem_debug_backed(heap meta, backed_heap parent, u64 padsize, boolean nohdr)
{
    mem_debug_backed_heap mbh = allocate_zero(meta, sizeof(*mbh));
    mbh->parent = parent;
    mbh->bh.h.pagesize = parent->h.pagesize;
    mbh->bh.h.alloc = mem_debug_backed_alloc;
    mbh->bh.h.dealloc = mem_debug_backed_dealloc;
    mbh->bh.alloc_map = nohdr ? mem_debug_backed_alloc_map_nohdr : mem_debug_backed_alloc_map;
    mbh->bh.dealloc_unmap = nohdr ? mem_debug_backed_dealloc_unmap_nohdr : mem_debug_backed_dealloc_unmap;
    mbh->padsize = MAX(padsize, PAD_MIN_BACKED);
    mbh->bh.h.allocated = mem_debug_backed_allocated;
    mbh->bh.h.total = mem_debug_backed_total;
    return &mbh->bh;
}
#endif
