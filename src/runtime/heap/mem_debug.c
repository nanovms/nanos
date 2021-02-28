#ifdef KERNEL
#include <kernel.h>
#else
#include <runtime.h>
#endif

#define DBG_HDR_SIG 0xfabfacedbaddecaf
#define PAD_MIN 64

#define MEMDBG_OVERRUN
#define MEMDBG_INIT
#define MEMDBG_FREE

typedef struct memdbg_heap {
    struct heap h;
    heap parent;
    u64 padsize;
} *memdbg_heap;

#ifdef KERNEL
typedef struct memdbg_backed_heap {
    struct backed_heap bh;
    backed_heap parent;
    u64 padsize;
} *memdbg_backed_heap;
#endif

typedef struct memdbg_hdr {
    u64 sig;
    u64 asize;
    u64 padsize;
    u64 caller_ip;
} *memdbg_hdr;

u32 pat_init = 0xfeedbeef;
u32 pat_freed = 0xdeaddead;
u32 pat_redzone = 0xcafefade;

static void set_pattern(void *v, bytes sz, void *p, bytes psz)
{
    u8 *bp = v;
    for (; sz > 0; sz -= psz, bp += psz)
        runtime_memcpy(bp, p, MIN(psz, sz));
}

static boolean check_pattern(void *v, bytes sz, void *p, bytes psz)
{
    u8 *bp = v;
    for (; sz > 0; sz -= psz, bp += psz)
        if (runtime_memcmp(bp, p, MIN(psz, sz)) != 0)
            return false;
    return true;
}

static void get_debug_alloc_size(bytes b, bytes padsize, bytes *nb, bytes *padding)
{
    *padding = MAX(padsize, PAD_MIN);
    *nb = *padding * 2 + b;
    if (padsize >= PAGESIZE)
        *nb = pad(*nb, PAGESIZE);
}

static u64 alloc_check(volatile memdbg_hdr hdr, bytes b, bytes padding)
{
    #ifdef MEMDBG_OVERRUN
    set_pattern(hdr, padding, &pat_redzone, sizeof(pat_redzone));
    set_pattern((u8 *)hdr + padding + b, padding, &pat_redzone, sizeof(pat_redzone));
    #endif
    hdr->sig = DBG_HDR_SIG;
    hdr->asize = b;
    hdr->padsize = padding;
    u8 *buf = (u8 *)hdr + padding;
    #ifdef MEMDBG_INIT
    set_pattern(buf, b, &pat_init, sizeof(pat_init));
    #endif
    return u64_from_pointer(buf);
}

static void dealloc_check(volatile memdbg_hdr hdr, u64 a, bytes b, bytes nb, bytes padding)
{
    assert(hdr->sig == DBG_HDR_SIG);
    assert(b == hdr->asize);
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
    memdbg_heap mdh = (memdbg_heap)h;
    bytes padding, nb;

    get_debug_alloc_size(b, mdh->padsize, &nb, &padding);
    memdbg_hdr hdr = allocate(mdh->parent, nb);
    if (hdr == INVALID_ADDRESS)
        return INVALID_PHYSICAL;
    return alloc_check(hdr, b, padding);
}

static void mem_debug_dealloc(heap h, u64 a, bytes b)
{
    memdbg_heap mdh = (memdbg_heap)h;
    bytes padding, nb;

    get_debug_alloc_size(b, mdh->padsize, &nb, &padding);
    memdbg_hdr hdr = (memdbg_hdr)pointer_from_u64(a - padding);
    dealloc_check(hdr, a, b, nb, padding);
    deallocate(mdh->parent, u64_from_pointer(hdr), nb);
}

heap mem_debug_heap(heap meta, heap parent, u64 padsize)
{
    build_assert(PAD_MIN > sizeof(memdbg_hdr));
    memdbg_heap mdh = allocate(meta, sizeof(*mdh));
    mdh->parent = parent;
    mdh->h.alloc = mem_debug_alloc;
    mdh->h.dealloc = mem_debug_dealloc;
    mdh->padsize = MAX(padsize, PAD_MIN);
    return &mdh->h;
}

#ifdef KERNEL
static void *mem_debug_backed_alloc_map(backed_heap h, bytes b, u64 *phys)
{
    memdbg_backed_heap mdh = (memdbg_backed_heap)h;
    bytes padding, nb;
    u64 nphys;

    get_debug_alloc_size(b, mdh->padsize, &nb, &padding);
    memdbg_hdr hdr = alloc_map(mdh->parent, nb, &nphys);
    if (hdr == INVALID_ADDRESS)
        return INVALID_ADDRESS;
    assert(alloc_check(hdr, b, padding) == (u64)((u8 *)hdr + padding));
    hdr->caller_ip = u64_from_pointer(__builtin_return_address(1));
    if (phys)
        *phys = nphys + padding;
    return (u8 *)hdr + padding;
}

static void mem_debug_backed_dealloc_unmap(backed_heap h, void *v, u64 p, bytes b)
{
    memdbg_backed_heap mdh = (memdbg_backed_heap)h;
    bytes padding, nb;
    u64 a = u64_from_pointer(v);

    get_debug_alloc_size(b, mdh->padsize, &nb, &padding);
    memdbg_hdr hdr = (memdbg_hdr)pointer_from_u64(a - padding);
    dealloc_check(hdr, a, b, nb, padding);
    dealloc_unmap(mdh->parent, hdr, 0, nb);
}

static u64 mem_debug_backed_alloc(heap h, bytes b)
{
    return u64_from_pointer(mem_debug_backed_alloc_map((backed_heap)h, b, 0));
}

static void mem_debug_backed_dealloc(heap h, u64 a, bytes b)
{
    mem_debug_backed_dealloc_unmap((backed_heap)h, pointer_from_u64(a), 0, b);
}

backed_heap mem_debug_backed_heap(heap meta, backed_heap parent, u64 padsize)
{
    memdbg_backed_heap mbh = allocate(meta, sizeof(*mbh));
    mbh->parent = parent;
    mbh->bh.h.alloc = mem_debug_backed_alloc;
    mbh->bh.h.dealloc = mem_debug_backed_dealloc;
    mbh->bh.alloc_map = mem_debug_backed_alloc_map;
    mbh->bh.dealloc_unmap = mem_debug_backed_dealloc_unmap;
    mbh->padsize = MAX(padsize, PAD_MIN);
    return &mbh->bh;
}
#endif