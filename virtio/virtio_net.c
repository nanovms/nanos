#include <virtio_internal.h>

typedef struct vnet {
    u16 port;
    u8 hwaddr[ETHER_ADDR_LEN];
} *vnet;


void vnet_transmit(vnet v, void *base, int length)
{
}

vnet init_vnet()
{
    // allocation
    static struct vnet vs;
    struct vnet *v = &vs;

    // where is config in port space?
    for (int i = 0; i < ETHER_ADDR_LEN; i++) 
        v->hwaddr[i] =  in8(v->port+i);

}

