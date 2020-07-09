#include <kernel.h>

#include "virtio_internal.h"
#include "virtio_mmio.h"
#include "virtio_pci.h"

u32 vtdev_cfg_read_4(vtdev dev, u64 offset)
{
    switch (dev->transport) {
    case VTIO_TRANSPORT_MMIO:
        return vtmmio_get_u32((vtmmio)dev, VTMMIO_OFFSET_CONFIG + offset);
    case VTIO_TRANSPORT_PCI:
        return pci_bar_read_4(&((vtpci)dev)->device_config, offset);
    default:
        return 0;
    }
}

void vtdev_cfg_read_mem(vtdev dev, void *dest, bytes len)
{
    switch (dev->transport) {
    case VTIO_TRANSPORT_MMIO:
        runtime_memcpy(dest, ((vtmmio)dev)->vbase + VTMMIO_OFFSET_CONFIG, len);
        break;
    case VTIO_TRANSPORT_PCI:
        for (int i = 0; i < len; i++)
            *((u8 *)dest + i) = pci_bar_read_1(&((vtpci)dev)->device_config, i);
        break;
    default:
        break;
    }
}

void vtdev_set_status(vtdev dev, u8 status)
{
    switch (dev->transport) {
    case VTIO_TRANSPORT_MMIO:
        vtmmio_set_status((vtmmio)dev, status);
        break;
    case VTIO_TRANSPORT_PCI:
        vtpci_set_status((vtpci)dev, status);
        break;
    default:
        break;
    }
}

status virtio_alloc_virtqueue(vtdev dev, const char *name, int idx,
                             struct virtqueue **result)
{
    switch (dev->transport) {
    case VTIO_TRANSPORT_MMIO:
        return vtmmio_alloc_virtqueue((vtmmio)dev, name, idx, result);
    case VTIO_TRANSPORT_PCI:
        return vtpci_alloc_virtqueue((vtpci)dev, name, idx, result);
    default:
        return timm("status", "unknown transport %d", dev->transport);
    }
}
