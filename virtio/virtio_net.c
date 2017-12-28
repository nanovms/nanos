#include <virtio_internal.h>

struct vnet {
    u16 port;
    u8 hwaddr[ETHER_ADDR_LEN];
    struct virtqueue *txq;
};

status vnet_transmit(vnet v, struct pbuf *b)
{
    // this is all checksum offload
    struct virtio_net_hdr *hdr;
    
    return virtqueue_enqueue(v->txq, hdr, b, 0, 1);
}

vnet init_vnet(vtpci dev)
{
    vnet vn = allocate(general, sizeof(struct vnet));

    // where is config in port space? -
    // #define VIRTIO_PCI_CONFIG_OFF(msix_enabled)     ((msix_enabled) ? 24 : 20)
    for (int i = 0; i < ETHER_ADDR_LEN; i++)
        // where is the etheraddr?
        vn->hwaddr[i] =  in8(dev->base+24+i);
    
    return vn;
}

