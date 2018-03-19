/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2011, Bryan Venteicher <bryanv@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* Driver for the VirtIO PCI interface. */

#include <virtio_internal.h>
#include <pci.h>


#define VIRTIO_PCI_CONFIG(_sc)                                          \
    VIRTIO_PCI_CONFIG_OFF((((_sc)->vtpci_flags & VTPCI_FLAG_MSIX)) != 0)


static void vtpci_select_virtqueue(struct vtpci *sc, int idx)
{
    out16(sc->base + VIRTIO_PCI_QUEUE_SEL, idx);
}

static uint8_t vtpci_get_status(vtpci dev)
{
    return (in8(dev->base+ VIRTIO_PCI_STATUS));
}


static void vtpci_set_status(vtpci dev, uint8_t status)
{
    if (status != VIRTIO_CONFIG_STATUS_RESET)
        status |= vtpci_get_status(dev);

    out8(dev->base + VIRTIO_PCI_STATUS, status);
}

status vtpci_alloc_virtqueue(vtpci dev,
                             int idx,
                             thunk h,
                             struct virtqueue **result)
{

    vtpci_select_virtqueue(dev, idx);
    uint16_t size = in16(dev->base + VIRTIO_PCI_QUEUE_NUM);

    int i = allocate_msi(h); 
    status s = virtqueue_alloc(dev, idx, size, VIRTIO_PCI_VRING_ALIGN,
                               h, result);
    if (!is_ok(s)) return s;

    out32(dev->base + VIRTIO_PCI_QUEUE_PFN,
          virtqueue_paddr(*result) >> VIRTIO_PCI_QUEUE_ADDR_SHIFT);

    out16(dev->base + VIRTIO_MSI_QUEUE_VECTOR, i);

    return STATUS_OK;
}

void vtpci_notify_virtqueue(struct vtpci *sc, uint16_t queue)
{
    out16(sc->base + VIRTIO_PCI_QUEUE_NOTIFY, queue);
}


vtpci attach_vtpci(heap h, int bus, int slot, int func)
{
    struct vtpci *dev = allocate(h, sizeof(struct vtpci));
    int rid;
    u32 length;

    u32 base = pci_readbar(bus, slot, func, 0, &length);
    dev->base = base & ~1; // io bars have the bottom bit set
    pci_set_bus_master(bus, slot, func);

    vtpci_set_status(dev, VIRTIO_CONFIG_STATUS_RESET);
    vtpci_set_status(dev, VIRTIO_CONFIG_STATUS_ACK);
    vtpci_set_status(dev, VIRTIO_CONFIG_STATUS_DRIVER);

    u32 features = in32(dev->base + 0);
    
    u32 badness = VIRTIO_F_BAD_FEATURE | VIRTIO_NET_F_CSUM | VIRTIO_NET_F_GUEST_CSUM |
        VIRTIO_NET_F_GUEST_TSO4 | VIRTIO_NET_F_GUEST_TSO6 |  VIRTIO_NET_F_GUEST_ECN|
        VIRTIO_NET_F_GUEST_UFO | VIRTIO_NET_F_CTRL_VLAN | VIRTIO_NET_F_MQ;

    out32(dev->base+4, features & VIRTIO_NET_F_MAC);
    vtpci_set_status(dev, VIRTIO_CONFIG_STATUS_FEATURE); 

    int nvqs = 16;
    dev->vtpci_vqs = allocate_zero(h, nvqs * sizeof(struct virtqueue));
    dev->general = h;

    // init_vnet(dev);
    vtpci_set_status(dev, VIRTIO_CONFIG_STATUS_DRIVER_OK);

    return dev;
}
