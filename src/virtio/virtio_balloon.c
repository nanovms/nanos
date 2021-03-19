#include <kernel.h>
#include <storage.h>

#include "virtio_internal.h"
#include "virtio_mmio.h"
#include "virtio_pci.h"

//#define VIRTIO_BALLOON_DEBUG
//#define VIRTIO_BALLOON_VERBOSE
#ifdef VIRTIO_BALLOON_DEBUG
#define virtio_balloon_debug(x, ...) do {rprintf("VTBLN: " x, ##__VA_ARGS__);} while(0)
#ifdef VIRTIO_BALLOON_VERBOSE
#define virtio_balloon_verbose virtio_balloon_debug
#else
#define virtio_balloon_verbose(x, ...)
#endif
#else
#define virtio_balloon_debug(x, ...)
#define virtio_balloon_verbose(x, ...)
#endif

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

struct virtio_balloon {
    heap general;
    backed_heap backed;
    id_heap physical;
    vtdev dev;
    virtqueue inflateq;
    virtqueue deflateq;
    virtqueue statsq;
    u32 actual_pages;
    struct list in_balloon;
    struct list free;
} virtio_balloon;

/* XXX alignment requirement? */
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

static u64 phys_base_from_balloon_page(balloon_page bp)
{
    return bp->addrs[0] << PAGELOG;
}

static void update_actual_pages(s64 delta)
{
    assert(delta > 0 || virtio_balloon.actual_pages >= -delta);
    virtio_balloon.actual_pages += delta;
    virtio_balloon_verbose("%s: delta %ld, now %ld\n", __func__, delta, virtio_balloon.actual_pages);
    vtdev_cfg_write_4(virtio_balloon.dev, VIRTIO_BALLOON_R_ACTUAL,
                      htole32(virtio_balloon.actual_pages));
}

closure_function(1, 1, void, inflate_complete,
                 balloon_page, bp,
                 u64, len)
{
    balloon_page bp = bound(bp);
    virtio_balloon_verbose("%s: balloon_page %p (phys base 0x%lx)\n", __func__, bp,
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
    virtio_balloon_debug("%s: n_balloon_pages %d\n", __func__, n_balloon_pages);

    u64 inflated = 0;
    while (inflated < n_balloon_pages) {
        /* XXX: cannot take fragmentation into account... */
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
    virtio_balloon_verbose("%s: balloon_page %p (phys base 0x%lx)\n", __func__, bp, phys_base);
    deallocate_u64((heap)virtio_balloon.physical, phys_base, VIRTIO_BALLOON_ALLOC_SIZE);
    virtio_balloon_verbose("   phys heap free: %ld\n", heap_free((heap)virtio_balloon.physical));
}

closure_function(1, 1, void, deflate_complete,
                 balloon_page, bp,
                 u64, len)
{
    balloon_page bp = bound(bp);
    virtio_balloon_verbose("%s: bp %p, len %ld\n", __func__, bound(bp), len);
    if (balloon_must_tell_host())
        return_balloon_page_memory(bound(bp));
    list_insert_before(&virtio_balloon.free, &bp->l);
    update_actual_pages(-VIRTIO_BALLOON_PAGES_PER_ALLOC);
    closure_finish();
}

static u64 virtio_balloon_deflate(u64 n_balloon_pages)
{
    virtqueue vq = virtio_balloon.deflateq;
    virtio_balloon_debug("%s: n_balloon_pages %ld\n", __func__, n_balloon_pages);
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
    u32 num_pages = le32toh(vtdev_cfg_read_4(virtio_balloon.dev, VIRTIO_BALLOON_R_NUM_PAGES));
    virtio_balloon_debug("%s: num_pages %d, actual %d\n", __func__, num_pages,
                        virtio_balloon.actual_pages);
    s32 delta = num_pages - virtio_balloon.actual_pages;
    if (delta > 0) {
        u64 inflate = (delta + VIRTIO_BALLOON_PAGES_PER_ALLOC - 1) >>
            (VIRTIO_BALLOON_ALLOC_ORDER - VIRTIO_BALLOON_PAGE_ORDER);
        u64 inflated = virtio_balloon_inflate(inflate);
        assert(inflated != INVALID_PHYSICAL);
        virtio_balloon_debug("   inflated balloon by %ld pages (%ld MB)\n",
                             inflated * VIRTIO_BALLOON_PAGES_PER_ALLOC,
                             inflated << (VIRTIO_BALLOON_ALLOC_ORDER - 20));
        if (inflated < inflate) {
            /* XXX set up timer to retry... */
            rprintf("%ld balloon pages left to inflate\n", inflate - inflated);
        }
    } else if (delta < 0) {
        u64 deflate = (-delta) >> (VIRTIO_BALLOON_ALLOC_ORDER - VIRTIO_BALLOON_PAGE_ORDER);
        u64 deflated = virtio_balloon_deflate(deflate);
        assert(deflated != INVALID_PHYSICAL);
        virtio_balloon_debug("   deflated balloon by %ld pages (%ld MB)\n",
                             deflated * VIRTIO_BALLOON_PAGES_PER_ALLOC,
                             deflated << (VIRTIO_BALLOON_ALLOC_ORDER - 20));
    }
    virtio_balloon_debug("   physical heap free: %ld\n",
                         heap_free((heap)virtio_balloon.physical));
}

closure_function(1, 0, void, virtio_balloon_config_change,
                 vtdev, v)
{
    virtio_balloon_debug("%s\n", __func__);
    virtio_balloon_update();
}

closure_function(0, 1, u64, virtio_balloon_deflater,
                 u64, deflate_bytes)
{
    virtio_balloon_debug("%s: deflate of %ld bytes requested\n", __func__, deflate_bytes);
    u64 deflate = ((deflate_bytes + MASK(VIRTIO_BALLOON_ALLOC_ORDER))
                   >> VIRTIO_BALLOON_ALLOC_ORDER);
    u64 deflated = virtio_balloon_deflate(deflate);
    assert(deflated != INVALID_PHYSICAL);
    virtio_balloon_debug("   deflated balloon by %ld pages (%ld MB)\n",
                             deflated * VIRTIO_BALLOON_PAGES_PER_ALLOC,
                             deflated << (VIRTIO_BALLOON_ALLOC_ORDER - 20));
    return deflated << VIRTIO_BALLOON_ALLOC_ORDER;
}

static boolean virtio_balloon_attach(heap general, backed_heap backed, id_heap physical, vtdev v)
{
    virtio_balloon_debug("   dev_features 0x%lx, features 0x%lx\n",
                         v->dev_features, v->features);
    thunk t = closure(general, virtio_balloon_config_change, v);
    assert(t != INVALID_ADDRESS);
    status s = virtio_register_config_change_handler(v, t, runqueue);
    if (!is_ok(s))
        goto fail;
    s = virtio_alloc_virtqueue(v, "virtio balloon inflateq", 0, runqueue,
                               &virtio_balloon.inflateq);
    if (!is_ok(s))
        goto fail;
    s = virtio_alloc_virtqueue(v, "virtio balloon deflateq", 1, runqueue,
                               &virtio_balloon.deflateq);
    if (!is_ok(s))
        goto fail;
    /* XXX: statsq */
    virtio_balloon.general = general;
    virtio_balloon.backed = backed;
    virtio_balloon.physical = physical;
    virtio_balloon.dev = v;
    virtio_balloon.actual_pages = 0;
    list_init(&virtio_balloon.in_balloon);
    list_init(&virtio_balloon.free);
    virtio_balloon_debug("   virtqueues allocated, setting driver status OK\n");
    vtdev_set_status(v, VIRTIO_CONFIG_STATUS_DRIVER_OK);
    update_actual_pages(0);
    virtio_balloon_update();
    balloon_deflater bd = closure(general, virtio_balloon_deflater);
    assert(bd != INVALID_ADDRESS);
    mm_register_balloon_deflater(bd);
    return true;
  fail:
    rprintf("%s: failed to attach: %v\n", __func__, s);
    return false;
}

closure_function(3, 1, boolean, vtpci_balloon_probe,
                 heap, general, backed_heap, backed, id_heap, physical,
                 pci_dev, d)
{
    virtio_balloon_debug("%s\n", __func__);
    if (!vtpci_probe(d, VIRTIO_ID_BALLOON))
        return false;

    virtio_balloon_debug("   attaching\n", __func__);
    vtdev v = (vtdev)attach_vtpci(bound(general), bound(backed), d,
                                  VIRTIO_BALLOON_F_MUST_TELL_HOST);
    return virtio_balloon_attach(bound(general), bound(backed), bound(physical), v);
}

void init_virtio_balloon(kernel_heaps kh)
{
    virtio_balloon_debug("%s\n", __func__);
    heap h = heap_locked(kh);
    register_pci_driver(closure(h, vtpci_balloon_probe, h, kh->backed, heap_physical(kh)));
}
