#include <kernel.h>
#include <storage.h>
#include <pagecache.h>

#include "virtio_internal.h"
#include "virtio_mmio.h"
#include "virtio_pci.h"

//#define VIRTIO_BALLOON_DEBUG
//#define VIRTIO_BALLOON_VERBOSE
#ifdef VIRTIO_BALLOON_DEBUG
#define virtio_balloon_debug(x, ...) do {tprintf(sym(vtbln), 0, ss(x), ##__VA_ARGS__);} while(0)
#ifdef VIRTIO_BALLOON_VERBOSE
#define virtio_balloon_verbose virtio_balloon_debug
#else
#define virtio_balloon_verbose(x, ...)
#endif
#else
#define virtio_balloon_debug(x, ...)
#define virtio_balloon_verbose(x, ...)
#endif

#define VIRTIO_BALLOON_RETRY_INTERVAL_SEC 5

/* Virtio interface is always 4K pages. */
#define VIRTIO_BALLOON_PAGE_ORDER PAGELOG

/* These are units that we allocate from the physical heap. */
#define VIRTIO_BALLOON_ALLOC_ORDER 21
#define VIRTIO_BALLOON_ALLOC_SIZE U64_FROM_BIT(VIRTIO_BALLOON_ALLOC_ORDER)
#define VIRTIO_BALLOON_PAGES_PER_ALLOC U64_FROM_BIT(VIRTIO_BALLOON_ALLOC_ORDER - \
                                                    VIRTIO_BALLOON_PAGE_ORDER)

#define VIRTIO_BALLOON_F_MUST_TELL_HOST 1
#define VIRTIO_BALLOON_F_STATS_VQ       2
#define VIRTIO_BALLOON_F_DEFLATE_ON_OOM 4

struct virtio_balloon_stat {
#define VIRTIO_BALLOON_S_SWAP_IN      0
#define VIRTIO_BALLOON_S_SWAP_OUT     1
#define VIRTIO_BALLOON_S_MAJFLT       2
#define VIRTIO_BALLOON_S_MINFLT       3
#define VIRTIO_BALLOON_S_MEMFREE      4
#define VIRTIO_BALLOON_S_MEMTOT       5
#define VIRTIO_BALLOON_S_AVAIL        6
#define VIRTIO_BALLOON_S_CACHES       7
#define VIRTIO_BALLOON_S_HTLB_PGALLOC 8
#define VIRTIO_BALLOON_S_HTLB_PGFAIL  9
#define VIRTIO_BALLOON_S_MAX          10

    /* explicitly little endian */
    u16 tag;
    u64 val;
} __attribute__((packed));

struct virtio_balloon {
    heap general;
    backed_heap backed;
    id_heap physical;
    vtdev dev;
    virtqueue inflateq;
    virtqueue deflateq;
    virtqueue statsq;
    struct timer retry_timer;
    closure_struct(timer_handler, timer_task);
    struct virtio_balloon_stat *stats;
    u64 stats_phys;
    int next_tag;
    u32 actual_pages;
    struct list in_balloon;
    struct list free;
} virtio_balloon;

typedef struct balloon_page {
    u32 addrs[VIRTIO_BALLOON_PAGES_PER_ALLOC]; /* must be first */
    struct list l;
    u64 phys;
} *balloon_page;

struct virtio_balloon_config {
    /* explicitly little endian */
    u32 num_pages;
    u32 actual;
} __attribute__((packed));

#define VIRTIO_BALLOON_R_NUM_PAGES (offsetof(struct virtio_balloon_config *, num_pages))
#define VIRTIO_BALLOON_R_ACTUAL    (offsetof(struct virtio_balloon_config *, actual))

static inline boolean balloon_must_tell_host(void)
{
    return (virtio_balloon.dev->features & VIRTIO_BALLOON_F_MUST_TELL_HOST) != 0;
}

static inline boolean balloon_has_stats_vq(void)
{
    return (virtio_balloon.dev->features & VIRTIO_BALLOON_F_STATS_VQ) != 0;
}

static u64 phys_base_from_balloon_page(balloon_page bp)
{
    return bp->addrs[0] << VIRTIO_BALLOON_PAGE_ORDER;
}

static void update_actual_pages(s64 delta)
{
    assert(delta > 0 || virtio_balloon.actual_pages >= -delta);
    virtio_balloon.actual_pages += delta;
    virtio_balloon_verbose("%s: delta %ld, now %ld\n", func_ss, delta, virtio_balloon.actual_pages);
    vtdev_cfg_write_4(virtio_balloon.dev, VIRTIO_BALLOON_R_ACTUAL,
                      htole32(virtio_balloon.actual_pages));
}

closure_function(1, 1, void, inflate_complete,
                 balloon_page, bp,
                 u64 len)
{
    balloon_page bp = bound(bp);
    virtio_balloon_verbose("%s: balloon_page %p (phys base 0x%lx)\n", func_ss, bp,
                           phys_base_from_balloon_page(bp));
    list_insert_after(&virtio_balloon.in_balloon, &bp->l);
    update_actual_pages(VIRTIO_BALLOON_PAGES_PER_ALLOC);
    closure_finish();
}

static balloon_page allocate_balloon_page(void)
{
    list l = list_get_next(&virtio_balloon.free);
    if (l) {
        list_delete(l);
        return struct_from_list(l, balloon_page, l);
    }
    u64 bp_phys;
    balloon_page bp = alloc_map(virtio_balloon.backed, sizeof(struct balloon_page), &bp_phys);
    assert(bp != INVALID_ADDRESS);
    bp->phys = bp_phys;
    return bp;
}

static u64 virtio_balloon_inflate(u64 n_balloon_pages)
{
    virtqueue vq = virtio_balloon.inflateq;
    virtio_balloon_debug("%s: n_balloon_pages %d\n", func_ss, n_balloon_pages);

    u64 inflated = 0;
    while (inflated < n_balloon_pages) {
        if (heap_free((heap)virtio_balloon.physical) <
            (BALLOON_MEMORY_MINIMUM + VIRTIO_BALLOON_ALLOC_SIZE))
            break;
        u64 phys = allocate_u64((heap)virtio_balloon.physical, VIRTIO_BALLOON_ALLOC_SIZE);
        if (phys == INVALID_PHYSICAL) {
            /* We shouldn't get down to the minimum. This ought to be an error
               or assertion failure, however we can't completely account for
               effects of fragmentation in the physical id heap. Emit a
               warning and quit inflating for now. */
            msg_err("failed to allocate balloon page from physical heap\n");
            break;
        }

        balloon_page bp = allocate_balloon_page();
        assert(bp != INVALID_ADDRESS);
        vqmsg m = allocate_vqmsg(vq);
        assert(m != INVALID_ADDRESS);
        u32 base_pfn = phys >> VIRTIO_BALLOON_PAGE_ORDER;
        for (int i = 0; i < VIRTIO_BALLOON_PAGES_PER_ALLOC; i++)
            bp->addrs[i] = base_pfn + i;
        vqmsg_push(vq, m, bp->phys, sizeof(bp->addrs), false);
        vqfinish c = closure(virtio_balloon.general, inflate_complete, bp);
        assert(c != INVALID_ADDRESS);
        virtio_balloon_verbose("   alloc: phys 0x%lx, bp %p, complete %p, phys heap free: %ld\n",
                               phys, bp, c, heap_free((heap)virtio_balloon.physical));
        vqmsg_commit(vq, m, c);
        inflated++;
    }

    return inflated;
}

static void return_balloon_page_memory(balloon_page bp)
{
    u64 phys_base = phys_base_from_balloon_page(bp);
    virtio_balloon_verbose("%s: balloon_page %p (phys base 0x%lx)\n", func_ss, bp, phys_base);
    deallocate_u64((heap)virtio_balloon.physical, phys_base, VIRTIO_BALLOON_ALLOC_SIZE);
    virtio_balloon_verbose("   phys heap free: %ld\n", heap_free((heap)virtio_balloon.physical));
}

closure_function(1, 1, void, deflate_complete,
                 balloon_page, bp,
                 u64 len)
{
    balloon_page bp = bound(bp);
    virtio_balloon_verbose("%s: bp %p, len %ld\n", func_ss, bound(bp), len);
    if (balloon_must_tell_host())
        return_balloon_page_memory(bound(bp));
    list_insert_before(&virtio_balloon.free, &bp->l);
    update_actual_pages(-VIRTIO_BALLOON_PAGES_PER_ALLOC);
    closure_finish();
}

static u64 virtio_balloon_deflate(u64 n_balloon_pages)
{
    virtqueue vq = virtio_balloon.deflateq;
    virtio_balloon_debug("%s: n_balloon_pages %ld\n", func_ss, n_balloon_pages);
    u64 deflated = 0;
    while (deflated < n_balloon_pages) {
        list l = list_get_next(&virtio_balloon.in_balloon);
        if (!l)
            break;
        list_delete(l);
        balloon_page bp = struct_from_list(l, balloon_page, l);
        vqmsg m = allocate_vqmsg(vq);
        assert(m != INVALID_ADDRESS);
        vqmsg_push(vq, m, bp->phys, sizeof(bp->addrs), false);
        vqfinish c = closure(virtio_balloon.general, deflate_complete, bp);
        assert(c != INVALID_ADDRESS);
        vqmsg_commit(vq, m, c);
        if (!balloon_must_tell_host())
            return_balloon_page_memory(bp);
        deflated++;
    }
    return deflated;
}

void virtio_balloon_update(void)
{
    remove_timer(kernel_timers, &virtio_balloon.retry_timer, 0);

    u32 num_pages = le32toh(vtdev_cfg_read_4(virtio_balloon.dev, VIRTIO_BALLOON_R_NUM_PAGES));
    virtio_balloon_debug("%s: num_pages %d, actual %d\n", func_ss, num_pages,
                        virtio_balloon.actual_pages);
    s32 delta = num_pages - virtio_balloon.actual_pages;
    if (delta > 0) {
        u64 inflate = (delta + VIRTIO_BALLOON_PAGES_PER_ALLOC - 1) >>
            (VIRTIO_BALLOON_ALLOC_ORDER - VIRTIO_BALLOON_PAGE_ORDER);
        u64 inflated = virtio_balloon_inflate(inflate);
        virtio_balloon_debug("   inflated balloon by %ld pages (%ld MB)\n",
                             inflated * VIRTIO_BALLOON_PAGES_PER_ALLOC,
                             inflated << (VIRTIO_BALLOON_ALLOC_ORDER - 20));
        if (inflated < inflate) {
            virtio_balloon_debug("   %ld balloon pages left to inflate\n", inflate - inflated);
            virtio_balloon_debug("   starting timer\n");
            register_timer(kernel_timers, &virtio_balloon.retry_timer, CLOCK_ID_MONOTONIC,
                           seconds(VIRTIO_BALLOON_RETRY_INTERVAL_SEC),
                           false, 0, (timer_handler)&virtio_balloon.timer_task);
        }
    } else if (delta < 0) {
        u64 deflate = (-delta) >> (VIRTIO_BALLOON_ALLOC_ORDER - VIRTIO_BALLOON_PAGE_ORDER);
        u64 deflated = virtio_balloon_deflate(deflate);
        virtio_balloon_debug("   deflated balloon by %ld pages (%ld MB)\n",
                             deflated * VIRTIO_BALLOON_PAGES_PER_ALLOC,
                             deflated << (VIRTIO_BALLOON_ALLOC_ORDER - 20));
        (void)deflated;
    }
    virtio_balloon_debug("   physical heap free: %ld\n",
                         heap_free((heap)virtio_balloon.physical));
}

closure_function(1, 0, void, virtio_balloon_config_change,
                 vtdev, v)
{
    virtio_balloon_debug("%s\n", func_ss);
    virtio_balloon_update();
}

closure_func_basic(mem_cleaner, u64, virtio_balloon_deflater,
                   u64 deflate_bytes)
{
    virtio_balloon_debug("deflate of %ld bytes requested\n", deflate_bytes);
    u64 deflate = ((deflate_bytes + MASK(VIRTIO_BALLOON_ALLOC_ORDER))
                   >> VIRTIO_BALLOON_ALLOC_ORDER);
    u64 deflated = virtio_balloon_deflate(deflate);
    virtio_balloon_debug("   deflated balloon by %ld pages (%ld MB)\n",
                             deflated * VIRTIO_BALLOON_PAGES_PER_ALLOC,
                             deflated << (VIRTIO_BALLOON_ALLOC_ORDER - 20));
    return deflated << VIRTIO_BALLOON_ALLOC_ORDER;
}

static inline void write_stat(u16 tag, u64 val)
{
    virtio_balloon_debug("   tag %d, val 0x%lx\n", tag, val);
    assert(virtio_balloon.next_tag < VIRTIO_BALLOON_S_MAX);
    u16 le_tag;
    u64 le_val;
    if (vtdev_is_modern(virtio_balloon.dev)) {
        le_tag = htole16(tag);
        le_val = htole64(val);
    } else {
        le_tag = tag;
        le_val = val;
    }
    /* use memcpy to avoid unaligned writes */
    runtime_memcpy(&virtio_balloon.stats[virtio_balloon.next_tag].tag, &le_tag, sizeof(le_tag));
    runtime_memcpy(&virtio_balloon.stats[virtio_balloon.next_tag].val, &le_val, sizeof(le_val));
    virtio_balloon.next_tag++;
}

closure_func_basic(vqfinish, void, virtio_balloon_enqueue_stats,
                   u64 len)
{
    /* enqueue one descriptor for device to return upon stats request */
    virtqueue vq = virtio_balloon.statsq;
    assert(vq);
    virtio_balloon_debug("%s\n", func_ss);

    virtio_balloon.next_tag = 0;
    write_stat(VIRTIO_BALLOON_S_SWAP_IN, 0);
    write_stat(VIRTIO_BALLOON_S_SWAP_OUT, 0);
    write_stat(VIRTIO_BALLOON_S_MAJFLT, mm_stats.major_faults);
    write_stat(VIRTIO_BALLOON_S_MINFLT, mm_stats.minor_faults);
    write_stat(VIRTIO_BALLOON_S_MEMFREE, heap_free((heap)virtio_balloon.physical));
    write_stat(VIRTIO_BALLOON_S_MEMTOT, heap_total((heap)virtio_balloon.physical));
    write_stat(VIRTIO_BALLOON_S_AVAIL, heap_free((heap)virtio_balloon.physical));
    write_stat(VIRTIO_BALLOON_S_CACHES, pagecache_get_occupancy());
    write_stat(VIRTIO_BALLOON_S_HTLB_PGALLOC, 0);
    write_stat(VIRTIO_BALLOON_S_HTLB_PGFAIL, 0);

    vqmsg m = allocate_vqmsg(vq);
    assert(m != INVALID_ADDRESS);
    vqmsg_push(vq, m, virtio_balloon.stats_phys,
               sizeof(struct virtio_balloon_stat) * virtio_balloon.next_tag, false);
    vqmsg_commit(vq, m, (vqfinish)closure_self());
}

static void virtio_balloon_init_statsq(void)
{
    /* enqueue one descriptor for device to return upon stats request */
    virtqueue vq = virtio_balloon.statsq;
    assert(vq);
    virtio_balloon_debug("%s\n", func_ss);

    vqfinish c = closure_func(virtio_balloon.general, vqfinish, virtio_balloon_enqueue_stats);
    assert(c != INVALID_ADDRESS);
    vqmsg m = allocate_vqmsg(vq);
    assert(m != INVALID_ADDRESS);
    vqmsg_push(vq, m, virtio_balloon.stats_phys,
               8 /* arbitrary; zero-len queue not allowed */, false);
    vqmsg_commit(vq, m, c);
}

closure_func_basic(timer_handler, void, virtio_balloon_timer_task,
                   u64 expiry, u64 overruns)
{
    if (overruns != timer_disabled) {
        virtio_balloon_debug("%s\n", func_ss);
        virtio_balloon_update();
    }
}

static boolean virtio_balloon_attach(heap general, backed_heap backed, id_heap physical, vtdev v)
{
    virtio_balloon_debug("   dev_features 0x%lx, features 0x%lx\n",
                         v->dev_features, v->features);
    virtio_balloon.general = general;
    virtio_balloon.backed = backed;
    virtio_balloon.physical = physical;
    virtio_balloon.dev = v;
    virtio_balloon.actual_pages = 0;
    list_init(&virtio_balloon.in_balloon);
    list_init(&virtio_balloon.free);
    init_timer(&virtio_balloon.retry_timer);
    init_closure_func(&virtio_balloon.timer_task, timer_handler, virtio_balloon_timer_task);

    thunk t = closure(general, virtio_balloon_config_change, v);
    assert(t != INVALID_ADDRESS);
    status s = virtio_register_config_change_handler(v, t);
    if (!is_ok(s))
        goto fail;
    s = virtio_alloc_virtqueue(v, ss("virtio balloon inflateq"), 0, &virtio_balloon.inflateq);
    if (!is_ok(s))
        goto fail;
    s = virtio_alloc_virtqueue(v, ss("virtio balloon deflateq"), 1, &virtio_balloon.deflateq);
    if (!is_ok(s))
        goto fail;
    if (balloon_has_stats_vq()) {
        virtio_balloon.stats = alloc_map(backed, sizeof(virtio_balloon.stats),
                                         &virtio_balloon.stats_phys);
        assert(virtio_balloon.stats != INVALID_ADDRESS);
        s = virtio_alloc_virtqueue(v, ss("virtio balloon statsq"), 2, &virtio_balloon.statsq);
        if (!is_ok(s))
            goto fail;
    } else {
        virtio_balloon.statsq = 0;
    }
    virtio_balloon_debug("   virtqueues allocated, setting driver status OK\n");
    vtdev_set_status(v, VIRTIO_CONFIG_STATUS_DRIVER_OK);
    update_actual_pages(0);
    virtio_balloon_update();
    mem_cleaner bd = closure_func(general, mem_cleaner, virtio_balloon_deflater);
    assert(bd != INVALID_ADDRESS);
    if (!mm_register_mem_cleaner(bd))
        deallocate_closure(bd);
    if (balloon_has_stats_vq())
        virtio_balloon_init_statsq();
    return true;
  fail:
    msg_err("failed to attach: %v\n", s);
    return false;
}

closure_function(3, 1, boolean, vtpci_balloon_probe,
                 heap, general, backed_heap, backed, id_heap, physical,
                 pci_dev d)
{
    virtio_balloon_debug("%s\n", func_ss);
    if (!vtpci_probe(d, VIRTIO_ID_BALLOON))
        return false;

    virtio_balloon_debug("   attaching\n", __func__);
    vtdev v = (vtdev)attach_vtpci(bound(general), bound(backed), d,
                                  (VIRTIO_BALLOON_F_STATS_VQ |
                                   VIRTIO_BALLOON_F_MUST_TELL_HOST));
    return virtio_balloon_attach(bound(general), bound(backed), bound(physical), v);
}

void init_virtio_balloon(kernel_heaps kh)
{
    virtio_balloon_debug("%s\n", func_ss);
    heap h = heap_locked(kh);
    register_pci_driver(closure(h, vtpci_balloon_probe, h, heap_linear_backed(kh), heap_physical(kh)), 0);
}
