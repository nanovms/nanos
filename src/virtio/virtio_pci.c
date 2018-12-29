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

static u8 vtpci_get_status(vtpci dev)
{
    return (in8(dev->base+ VIRTIO_PCI_STATUS));
}


static void vtpci_set_status(vtpci dev, u8 status)
{
    if (status != VIRTIO_CONFIG_STATUS_RESET)
        status |= vtpci_get_status(dev);

    out8(dev->base + VIRTIO_PCI_STATUS, status);
}

// xxx 
void allocate_msi(int slot, int msi_slot, thunk h);

status vtpci_alloc_virtqueue(vtpci dev,
                             int idx,
                             struct virtqueue **result)
{
    struct virtqueue *vq;
    out16(dev->base + VIRTIO_PCI_QUEUE_SEL, idx);    
    u16 size = in16(dev->base + VIRTIO_PCI_QUEUE_NUM);
    thunk handler;
    status s = virtqueue_alloc(dev, idx, size, VIRTIO_PCI_VRING_ALIGN, &vq, &handler);
    if (!is_ok(s)) return s;
    allocate_msi(dev->slot, idx, handler);     
    out32(dev->base + VIRTIO_PCI_QUEUE_PFN, virtqueue_paddr(vq) >> VIRTIO_PCI_QUEUE_ADDR_SHIFT);
    out16(dev->base + VIRTIO_MSI_QUEUE_VECTOR, idx);
    *result = vq;
    return STATUS_OK;
}

void vtpci_notify_virtqueue(vtpci dev, u16 queue)
{
    out16(dev->base + VIRTIO_PCI_QUEUE_NOTIFY, queue);
}


vtpci attach_vtpci(heap h, heap page_allocator, int bus, int slot, int func, u64 feature_mask)
{
    struct vtpci *dev = allocate(h, sizeof(struct vtpci));
    u32 length;

    dev->slot = slot;
    u32 base = pci_readbar(bus, slot, func, 0, &length);
    dev->base = base & ~1; // io bars have the bottom bit set
    pci_set_bus_master(bus, slot, func);

    vtpci_set_status(dev, VIRTIO_CONFIG_STATUS_RESET);
    vtpci_set_status(dev, VIRTIO_CONFIG_STATUS_ACK);
    vtpci_set_status(dev, VIRTIO_CONFIG_STATUS_DRIVER);

    u32 features = in32(dev->base + 0);

    out32(dev->base+4, features & feature_mask);
    vtpci_set_status(dev, VIRTIO_CONFIG_STATUS_FEATURE); 

    dev->general = h;
    dev->contiguous = page_allocator;    

    vtpci_set_status(dev, VIRTIO_CONFIG_STATUS_DRIVER_OK);

    return dev;
}
