/* Specifications at
 * http://docs.oasis-open.org/virtio/virtio/v1.0/cs04/virtio-v1.0-cs04.html,
 * section 4.2 "Virtio Over MMIO". */

#include <kernel.h>
#include <page.h>

#ifdef __x86_64__
#include <apic.h>
#endif

#include "virtio_internal.h"
#include "virtio_mmio.h"

#define VTMMIO_INT_VRING    (1 << 0)
#define VTMMIO_INT_CONFIG   (1 << 1)

//#define VIRTIO_MMIO_DEBUG
#ifdef VIRTIO_MMIO_DEBUG
#define virtio_mmio_debug(x, ...) rprintf("VTMMIO: " x "\n", ##__VA_ARGS__)
#else
#define virtio_mmio_debug(x, ...)
#endif

static struct list vtmmio_devices = {
        &vtmmio_devices, &vtmmio_devices
};

void virtio_mmio_parse(kernel_heaps kh, const char *str, int len)
{
    buffer b = alloca_wrap_buffer(str, len);
    int optname_len = buffer_strchr(b, '=');
    if (optname_len < 0)
        return;
    if ((optname_len == sizeof("device") - 1) &&
            !buffer_memcmp(b, "device", optname_len)) {
        /* Syntax: device=<memsize>@<membase>:<irq> */
        buffer_consume(b, optname_len + 1);
        u64 memsize;
        if ((buffer_strchr(b, '@') < 0) || !parse_int(b, 10, &memsize))
            return;
        char suffix = (char)pop_u8(b);
        if ((suffix == 'k') || (suffix == 'K'))
            memsize *= KB;
        else if ((suffix == 'm') || (suffix == 'M'))
            memsize *= MB;
        else if (suffix != '@')   /* unexpected character */
            return;
        if (suffix != '@')
            buffer_consume(b, 1);
        if (buffer_strchr(b, ':') < 0)
            return;
        u64 membase;
        u64 irq;
        if ((pop_u8(b) != '0') || (pop_u8(b) != 'x') ||
                !parse_int(b, 16, &membase) || (pop_u8(b) != ':') ||
                !parse_int(b, 10, &irq))
            return;
        virtio_mmio_debug("new device");
        heap h = heap_general(kh);
        vtmmio dev = allocate(h, sizeof(*dev));
        assert(dev != INVALID_ADDRESS);
        dev->membase = membase;
        dev->memsize = memsize;
        dev->irq = irq;
        dev->vbase = allocate((heap)heap_virtual_huge(kh), memsize);
        assert(dev->vbase != INVALID_ADDRESS);
        map(u64_from_pointer(dev->vbase), membase, memsize, PAGE_DEV_FLAGS);
        dev->irq_vector = 0;
        dev->vq_handlers = allocate_vector(h, 2);
        assert(dev->vq_handlers != INVALID_ADDRESS);
        list_push_back(&vtmmio_devices, &dev->l);
    }
}

void vtmmio_probe_devs(vtmmio_probe probe)
{
    list_foreach(&vtmmio_devices, e) {
        vtmmio dev = struct_from_list(e, vtmmio, l);
        if ((dev->memsize < VTMMIO_OFFSET_CONFIG) ||
                (vtmmio_get_u32(dev, VTMMIO_OFFSET_MAGIC) != 0x74726976) ||
                (vtmmio_get_u32(dev, VTMMIO_OFFSET_VERSION) != 2))
            continue;
        u8 status = vtmmio_get_status(dev);
        if (status == VIRTIO_CONFIG_STATUS_RESET)
            vtmmio_set_u32(dev, VTMMIO_OFFSET_STATUS, VIRTIO_CONFIG_STATUS_ACK);
        if (!(status & VIRTIO_CONFIG_STATUS_DRIVER)) {
            virtio_mmio_debug("probing device at 0x%lx(0x%lx), irq %d",
                dev->membase, dev->memsize, dev->irq);
            apply(probe, dev);
        }
    }
}

void vtmmio_set_status(vtmmio dev, u8 status)
{
    if (status != VIRTIO_CONFIG_STATUS_RESET)
        status |= vtmmio_get_status(dev);
    vtmmio_set_u32(dev, VTMMIO_OFFSET_STATUS, status);
}

static boolean vtmmio_negotatiate_features(vtmmio dev, u64 mask)
{
    vtdev virtio_dev = &dev->virtio_dev;
    mask |= VIRTIO_F_VERSION_1;

    vtmmio_set_u32(dev, VTMMIO_OFFSET_DEVFEATSEL, 1);
    virtio_dev->dev_features = vtmmio_get_u32(dev, VTMMIO_OFFSET_DEVFEATURES);
    vtmmio_set_u32(dev, VTMMIO_OFFSET_DEVFEATSEL, 0);
    virtio_dev->dev_features = (virtio_dev->dev_features << 32) |
            vtmmio_get_u32(dev, VTMMIO_OFFSET_DEVFEATURES);
    virtio_mmio_debug("device features 0x%lx, mask 0x%lx",
                      virtio_dev->dev_features, mask);
    if (!(virtio_dev->dev_features & VIRTIO_F_VERSION_1)) {
        msg_err("unsupported device features 0x%lx for device at 0x%x\n",
            virtio_dev->dev_features, dev->membase);
        return false;
    }
    virtio_dev->features = virtio_dev->dev_features & mask;
    vtmmio_set_u32(dev, VTMMIO_OFFSET_DRVFEATSEL, 0);
    vtmmio_set_u32(dev, VTMMIO_OFFSET_DRVFEATURES, (u32)virtio_dev->features);
    vtmmio_set_u32(dev, VTMMIO_OFFSET_DRVFEATSEL, 1);
    vtmmio_set_u32(dev, VTMMIO_OFFSET_DRVFEATURES,
                   (u32)(virtio_dev->features >> 32));
    vtmmio_set_status(dev, VIRTIO_CONFIG_STATUS_FEATURE);
    return (vtmmio_get_status(dev) & VIRTIO_CONFIG_STATUS_FEATURE);
}

define_closure_function(1, 2, void, vtmmio_notify,
                        vtmmio, dev,
                        u16, queue_index, bytes, notify_offset)
{
    vtmmio_set_u32(bound(dev), notify_offset, queue_index);
}

boolean attach_vtmmio(heap h, heap page_allocator, vtmmio d, u64 feature_mask)
{
    virtio_mmio_debug("attaching device at 0x%lx, irq %d", d->membase, d->irq);
    vtmmio_set_status(d, VIRTIO_CONFIG_STATUS_DRIVER);
    if (!vtmmio_negotatiate_features(d, feature_mask)) {
        msg_err("could not negotiate features for device at 0x%x\n",
            d->membase);
        return false;
    }
    init_closure(&d->notify, vtmmio_notify, d);
    d->virtio_dev.notify = (vtdev_notify)&d->notify;
    virtio_attach(h, page_allocator, VTIO_TRANSPORT_MMIO, &d->virtio_dev);
    return true;
}

define_closure_function(1, 0, void, vtmmio_irq,
                        vtmmio, dev)
{
    vtmmio dev = bound(dev);
    u32 status = vtmmio_get_u32(dev, VTMMIO_OFFSET_INTSTATUS);
    virtio_mmio_debug("int status 0x%x", status);
    vtmmio_set_u32(dev, VTMMIO_OFFSET_INTACK, status);
    if (status & VTMMIO_INT_VRING) {
        thunk vq_handler;
        vector_foreach(dev->vq_handlers, vq_handler) {
            apply(vq_handler);
        }
    }
}

status vtmmio_alloc_virtqueue(vtmmio dev, const char *name, int idx,
                              struct virtqueue **result)
{
    virtio_mmio_debug("allocating virtqueue %d (%s)", idx, name);
    struct virtqueue *vq;
    vtmmio_set_u32(dev, VTMMIO_OFFSET_QUEUESEL, idx);
    assert(vtmmio_get_u32(dev, VTMMIO_OFFSET_QUEUEREADY) == 0);
    u32 size = vtmmio_get_u32(dev, VTMMIO_OFFSET_QUEUENUMMAX);
    assert(size > 0);
    if (size > U16_MAX)
        size = U16_MAX;
    thunk handler;
    status s = virtqueue_alloc(&dev->virtio_dev, name, idx, size,
        VTMMIO_OFFSET_QUEUENOTIFY, PAGESIZE, &vq, &handler);
    if (!is_ok(s))
        return s;
    if (!dev->irq_vector) {
        dev->irq_vector = allocate_interrupt();
        assert(dev->irq_vector != INVALID_PHYSICAL);
        register_interrupt(dev->irq_vector,
                           init_closure(&dev->irq_handler, vtmmio_irq, dev),
                           name);
        // XXX arm
#ifdef __x86_64__
        ioapic_set_int(dev->irq, dev->irq_vector);
#endif
    }
    vector_push(dev->vq_handlers, handler);
    vtmmio_set_u32(dev, VTMMIO_OFFSET_QUEUENUM, size);
    vtmmio_set_u64(dev, VTMMIO_OFFSET_QUEUEDESCLOW, virtqueue_desc_paddr(vq));
    vtmmio_set_u64(dev, VTMMIO_OFFSET_QUEUEAVAILLOW, virtqueue_avail_paddr(vq));
    vtmmio_set_u64(dev, VTMMIO_OFFSET_QUEUEUSEDLOW, virtqueue_used_paddr(vq));
    vtmmio_set_u32(dev, VTMMIO_OFFSET_QUEUEREADY, 1);
    *result = vq;
    return STATUS_OK;
}
