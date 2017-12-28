#include <virtio_internal.h>

struct vnet {
    vtpci dev;
    u16 port;
    struct virtqueue *txq;
};

status vnet_transmit(vnet vn, struct pbuf *b)
{
    // this is all checksum offload
    struct virtio_net_hdr *hdr;
    
    return virtqueue_enqueue(vn->txq, hdr, b, 0, 1);
}

void vnet_hardware_address(vnet vn, u8 *dest)
{
    // fix, this per-device offset is variable
    for (int i = 0; i < ETHER_ADDR_LEN; i++)
        dest[i] =  in8(vn->dev->base+24+i);
}

vnet init_vnet(vtpci dev)
{
    vnet vn = allocate(general, sizeof(struct vnet));

    // where is config in port space? -
    // #define VIRTIO_PCI_CONFIG_OFF(msix_enabled)     ((msix_enabled) ? 24 : 20)
    
    return vn;
}

