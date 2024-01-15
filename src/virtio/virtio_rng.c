#include <kernel.h>

//#define VIRTIO_RNG_DEBUG
#ifdef VIRTIO_RNG_DEBUG
#define virtio_rng_debug(x, ...) do {tprintf(sym(vtrng), 0, x, ##__VA_ARGS__);} while(0)
#else
#define virtio_rng_debug(x, ...)
#endif

#include "virtio_internal.h"
#include "virtio_mmio.h"
#include "virtio_pci.h"

#define VIRTIO_RNG_BUFSIZE 32768

struct entropy_buf;

declare_closure_struct(1, 1, void, ebuf_fill_complete,
                       struct entropy_buf *, ebuf,
                       u64, len);

typedef struct entropy_buf {
    void *buf;
    u64 phys;
    closure_struct(ebuf_fill_complete, fill_complete);
    int offset;
    int len;
    boolean filling;
} *entropy_buf;

struct virtio_rng {
    heap general;
    backed_heap backed;
    vtdev dev;
    virtqueue requestq;
    struct entropy_buf ebufs[2];
    u8 ebuf_idx;
    u32 initialized;
} virtio_rng;

/* no lock, single consumer thanks to rng mutex */

static inline entropy_buf current_ebuf(void)
{
    return &virtio_rng.ebufs[virtio_rng.ebuf_idx];
}

static void virtio_rng_fill(entropy_buf ebuf)
{
    virtio_rng_debug("%s: ebuf %p\n", __func__, ebuf);
    virtqueue vq = virtio_rng.requestq;
    vqmsg m = allocate_vqmsg(vq);
    assert(m != INVALID_ADDRESS);
    ebuf->filling = true;
    vqmsg_push(vq, m, ebuf->phys, VIRTIO_RNG_BUFSIZE, true);
    vqmsg_commit(vq, m, (vqfinish)&ebuf->fill_complete);
}

define_closure_function(1, 1, void, ebuf_fill_complete,
                        entropy_buf, ebuf,
                        u64, len)
{
    virtio_rng_debug("%s: len %ld\n", __func__, len);
    assert(len <= VIRTIO_RNG_BUFSIZE);
    bound(ebuf)->offset = 0;
    bound(ebuf)->len = len;
    bound(ebuf)->filling = false;
    if (compare_and_swap_32(&virtio_rng.initialized, false, true)) {
        random_reseed();
    }
}

static void virtio_init_ebufs(void)
{
    virtio_rng_debug("%s\n", __func__);
    for (int i = 0; i < 2; i++) {
        entropy_buf ebuf = &virtio_rng.ebufs[i];
        ebuf->buf = alloc_map(virtio_rng.backed, VIRTIO_RNG_BUFSIZE, &ebuf->phys);
        assert(ebuf->buf != INVALID_ADDRESS);
        init_closure(&ebuf->fill_complete, ebuf_fill_complete, ebuf);
        ebuf->offset = ebuf->len = 0;
        virtio_rng_fill(ebuf);
    }
    virtio_rng.ebuf_idx = 0;
}

static bytes virtio_rng_get_seed(void *seed, bytes len)
{
    bytes filled = 0;
    while (len - filled > 0) {
        entropy_buf ebuf = current_ebuf();
        if (ebuf->filling)
            break;
        bytes n = MIN(len - filled, ebuf->len - ebuf->offset);
        runtime_memcpy(seed + filled, ebuf->buf + ebuf->offset, n);
        filled += n;
        ebuf->offset += n;
        if (ebuf->offset >= ebuf->len) {
            virtio_rng.ebuf_idx ^= 1;
            virtio_rng_fill(ebuf);
        }
    }
    virtio_rng_debug("%s: filled %ld\n", __func__, filled);
    return filled;
}

static boolean virtio_rng_attach(heap general, backed_heap backed, vtdev v)
{
    virtio_rng_debug("   dev_features 0x%lx, features 0x%lx\n", v->dev_features, v->features);
    virtio_rng.general = general;
    virtio_rng.backed = backed;
    virtio_rng.dev = v;
    virtio_rng.initialized = false;

    status s = virtio_alloc_virtqueue(v, "virtio rng requestq", 0, &virtio_rng.requestq);
    if (!is_ok(s))
        goto fail;

    virtio_rng_debug("   virtqueues allocated, setting driver status OK\n");
    vtdev_set_status(v, VIRTIO_CONFIG_STATUS_DRIVER_OK);
    virtio_init_ebufs();
    preferred_get_seed = virtio_rng_get_seed;
    return true;
  fail:
    msg_err("failed to attach: %v\n", s);
    return false;
}

closure_function(3, 1, boolean, vtpci_rng_probe,
                 heap, general, backed_heap, backed, id_heap, physical,
                 pci_dev, d)
{
    virtio_rng_debug("%s\n", __func__);
    if (!vtpci_probe(d, VIRTIO_ID_ENTROPY))
        return false;

    virtio_rng_debug("   attaching\n", __func__);
    vtdev v = (vtdev)attach_vtpci(bound(general), bound(backed), d, 0);
    return virtio_rng_attach(bound(general), bound(backed), v);
}

void init_virtio_rng(kernel_heaps kh)
{
    virtio_rng_debug("%s\n", __func__);
    heap h = heap_locked(kh);
    register_pci_driver(closure(h, vtpci_rng_probe, h, heap_linear_backed(kh), heap_physical(kh)), 0);
}
