#include <kernel.h>

#include "virtio_internal.h"
#include "virtio_mmio.h"
#include "virtio_pci.h"

u8 vtdev_cfg_read_1(vtdev dev, u64 offset)
{
    switch (dev->transport) {
    case VTIO_TRANSPORT_MMIO:
        return vtmmio_get_u8((vtmmio)dev, VTMMIO_OFFSET_CONFIG + offset);
    case VTIO_TRANSPORT_PCI:
        return pci_bar_read_1(&((vtpci)dev)->device_config, offset);
    default:
        return 0;
    }
}

void vtdev_cfg_write_1(vtdev dev, u64 offset, u8 value)
{
    switch (dev->transport) {
    case VTIO_TRANSPORT_MMIO:
        vtmmio_set_u8((vtmmio)dev, VTMMIO_OFFSET_CONFIG + offset, value);
        break;
    case VTIO_TRANSPORT_PCI:
        pci_bar_write_1(&((vtpci)dev)->device_config, offset, value);
        break;
    }
}

u16 vtdev_cfg_read_2(vtdev dev, u64 offset)
{
    switch (dev->transport) {
    case VTIO_TRANSPORT_MMIO:
        return vtmmio_get_u16((vtmmio)dev, VTMMIO_OFFSET_CONFIG + offset);
    case VTIO_TRANSPORT_PCI:
        return pci_bar_read_2(&((vtpci)dev)->device_config, offset);
    default:
        return 0;
    }
}

void vtdev_cfg_write_2(vtdev dev, u64 offset, u16 value)
{
    switch (dev->transport) {
    case VTIO_TRANSPORT_MMIO:
        vtmmio_set_u16((vtmmio)dev, VTMMIO_OFFSET_CONFIG + offset, value);
        break;
    case VTIO_TRANSPORT_PCI:
        pci_bar_write_2(&((vtpci)dev)->device_config, offset, value);
        break;
    }
}

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

void vtdev_cfg_write_4(vtdev dev, u64 offset, u32 value)
{
    switch (dev->transport) {
    case VTIO_TRANSPORT_MMIO:
        vtmmio_set_u32((vtmmio)dev, VTMMIO_OFFSET_CONFIG + offset, value);
        break;
    case VTIO_TRANSPORT_PCI:
        pci_bar_write_4(&((vtpci)dev)->device_config, offset, value);
        break;
    }
}

void vtdev_cfg_read_mem(vtdev dev, u64 offset, void *dest, bytes len)
{
    switch (dev->transport) {
    case VTIO_TRANSPORT_MMIO:
        runtime_memcpy(dest, ((vtmmio)dev)->vbase + VTMMIO_OFFSET_CONFIG + offset, len);
        break;
    case VTIO_TRANSPORT_PCI:
        for (int i = 0; i < len; i++)
            *((u8 *)dest + i) = pci_bar_read_1(&((vtpci)dev)->device_config, offset + i);
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

status virtio_alloc_vq_aff(vtdev dev, sstring name, int idx, range cpu_affinity,
                           struct virtqueue **result)
{
    switch (dev->transport) {
    case VTIO_TRANSPORT_MMIO:
        return vtmmio_alloc_virtqueue((vtmmio)dev, name, idx, cpu_affinity, result);
    case VTIO_TRANSPORT_PCI:
        return vtpci_alloc_virtqueue((vtpci)dev, name, idx, cpu_affinity, result);
    default:
        return timm("status", "unknown transport %d", dev->transport);
    }
}

status virtio_register_config_change_handler(vtdev dev, thunk handler)
{
    switch (dev->transport) {
    case VTIO_TRANSPORT_MMIO:
        return timm("status", "not implemented");
    case VTIO_TRANSPORT_PCI:
        return vtpci_register_config_change_handler((vtpci)dev, handler);
    default:
        return timm("status", "unknown transport %d", dev->transport);
    }
}
