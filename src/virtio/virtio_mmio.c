/* Specifications at
 * http://docs.oasis-open.org/virtio/virtio/v1.0/cs04/virtio-v1.0-cs04.html,
 * section 4.2 "Virtio Over MMIO". */

#include <kernel.h>
#include <drivers/acpi.h>

#ifdef __x86_64__
#include <apic.h>
#endif

#include "virtio_internal.h"
#include "virtio_mmio.h"

#define VTMMIO_INT_VRING    (1 << 0)
#define VTMMIO_INT_CONFIG   (1 << 1)

//#define VIRTIO_MMIO_DEBUG
#ifdef VIRTIO_MMIO_DEBUG
#define virtio_mmio_debug(x, ...) tprintf(sym(vtmmio), 0, ss(x "\n"), ##__VA_ARGS__)
#else
#define virtio_mmio_debug(x, ...)
#endif

RO_AFTER_INIT static struct list vtmmio_devices = {
        &vtmmio_devices, &vtmmio_devices
};

closure_function(1, 1, void, vtmmio_new_dev,
                 kernel_heaps, kh,
                 acpi_mmio_dev adev)
{
    virtio_mmio_debug("new device");
    kernel_heaps kh = bound(kh);
    heap h = heap_general(kh);
    vtmmio dev = allocate(h, sizeof(*dev));
    assert(dev != INVALID_ADDRESS);
    dev->membase = adev->membase;
    dev->memsize = adev->memsize;
    dev->irq = adev->irq;
    u64 page_offset = dev->membase & PAGEMASK;
    dev->vbase = allocate((heap)heap_virtual_huge(kh), page_offset + dev->memsize);
    assert(dev->vbase != INVALID_ADDRESS);
    map(u64_from_pointer(dev->vbase), dev->membase - page_offset, page_offset + dev->memsize,
        pageflags_writable(pageflags_device()));
    dev->vbase += page_offset;
    dev->irq_vector = 0;
    dev->vq_handlers = allocate_vector(h, 2);
    assert(dev->vq_handlers != INVALID_ADDRESS);
    vtmmio_set_status(dev, VIRTIO_CONFIG_STATUS_RESET);
    list_push_back(&vtmmio_devices, &dev->l);
}

closure_function(1, 2, void, vtmmio_cmdline_parse,
                 kernel_heaps, kh,
                 const char *str, int len)
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
        struct acpi_mmio_dev adev = {
            .membase = membase,
            .memsize = memsize,
            .irq = irq,
        };
        apply(stack_closure(vtmmio_new_dev, bound(kh)), &adev);
    }
}

void virtio_mmio_enum_devs(kernel_heaps kh)
{
    cmdline_consume(ss("virtio_mmio"), stack_closure(vtmmio_cmdline_parse, kh));
    acpi_get_vtmmio_devs(stack_closure(vtmmio_new_dev, kh));
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
        msg_err("vtmmio: unsupported device features 0x%lx for device at 0x%x",
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

closure_func_basic(vtdev_notify, void, vtmmio_notify,
                   u16 queue_index, bytes notify_offset)
{
    vtmmio_set_u32(struct_from_closure(vtmmio, notify), notify_offset, queue_index);
}

boolean attach_vtmmio(heap h, backed_heap page_allocator, vtmmio d, u64 feature_mask)
{
    virtio_mmio_debug("attaching device at 0x%lx, irq %d", d->membase, d->irq);
    vtmmio_set_status(d, VIRTIO_CONFIG_STATUS_DRIVER);
    if (!vtmmio_negotatiate_features(d, feature_mask)) {
        msg_err("vtmmio: could not negotiate features for device at 0x%x",
            d->membase);
        return false;
    }
    init_closure_func(&d->notify, vtdev_notify, vtmmio_notify);
    d->virtio_dev.notify = (vtdev_notify)&d->notify;
    virtio_attach(h, page_allocator, VTIO_TRANSPORT_MMIO, &d->virtio_dev);
    return true;
}

closure_func_basic(thunk, void, vtmmio_irq)
{
    vtmmio dev = struct_from_closure(vtmmio, irq_handler);
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

status vtmmio_alloc_virtqueue(vtmmio dev, sstring name, int idx, range cpu_affinity,
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
        dev->irq_vector = allocate_mmio_interrupt();
        assert(dev->irq_vector != INVALID_PHYSICAL);
        register_interrupt(dev->irq_vector,
                           init_closure_func(&dev->irq_handler, thunk, vtmmio_irq),
                           name);
        // XXX arm
#ifdef __x86_64__
        ioapic_set_int(dev->irq, dev->irq_vector, irq_get_target_cpu(cpu_affinity));
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
