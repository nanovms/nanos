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

#define vtpci_setup_msi_interrupt vtpci_setup_legacy_interrupt

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


static int vtpci_with_feature(vtpci dev, uint64_t feature)
{
    return ((dev->vtpci_features & feature) != 0);
}

status vtpci_alloc_virtqueue(vtpci dev,
                             int idx,
                             handler intr,
                             int maxindirsz,
                             struct virtqueue **result)
{
    uint16_t size;
    vtpci_select_virtqueue(dev, idx);
    size = in16(dev->base + VIRTIO_PCI_QUEUE_NUM);
    
    status s = virtqueue_alloc(dev, "foo", idx, size, VIRTIO_PCI_VRING_ALIGN,
                               0xFFFFFFFFUL,  intr, maxindirsz, result);
    if (!is_ok(s)) return s;
    
    out32(dev->base + VIRTIO_PCI_QUEUE_PFN,
          virtqueue_paddr(*result) >> VIRTIO_PCI_QUEUE_ADDR_SHIFT);

    return STATUS_OK;
}

static status vtpci_register_msix_vector(struct vtpci *dev,
                                      int offset,
                                      struct vtpci_interrupt *intr)
{
    uint16_t vector = VIRTIO_MSI_NO_VECTOR;

    out16(dev->base + offset, vector);
    
    /* Read vector to determine if the host had sufficient resources. */
    if (in16(dev->base + offset) != vector) 
        return allocate_status("insufficient host resources for MSIX interrupts\n");

    return STATUS_OK;
}

static status vtpci_alloc_interrupt(vtpci dev,
                                    int rid,
                                    struct vtpci_interrupt *intr)
{

    int irq = 10; // bus_alloc_resource_any(dev, SYS_RES_IRQ, &rid, flags);
    intr->irq = irq;
    return STATUS_OK;
}


static status vtpci_setup_intr(vtpci dev)
{
    status s;
    struct vtpci_interrupt *intr;
    int i, nvectors;

    for (nvectors = 0, i = 0; i < dev->vtpci_nvqs; i++) {
        nvectors++;
    }

    int nmsix, cnt, required;

    /* Allocate an additional vector for the config changes. */
    required = nvectors + 1;

    cnt = required;
    //    if (pci_alloc_msix(dev, &cnt) == 0 && cnt >= required) {
    //        dev->vtpci_nmsix_resources = required;
    //        return STATUS_OK;
    //    }

    int rid, nvq_intrs, error;

    rid = 0;
    rid = 1;

    intr = &dev->vtpci_device_interrupt;
    //    intr->vti_irq = 0; // 
    //    intr->vti_rid = rid;

    s = vtpci_alloc_interrupt(dev, rid, intr);
    if (!is_ok(s)) return s;

    /* Subtract one for the configuration changed interrupt. */
    nvq_intrs = dev->vtpci_nmsix_resources - 1;

    intr = dev->vtpci_msix_vq_interrupts = allocate_zero(general, nvq_intrs *
                                                         sizeof(struct vtpci_interrupt));
    if (dev->vtpci_msix_vq_interrupts == NULL)
        return status_nomem();
    
    for (int i = 0; rid ++, i < nvq_intrs; i++, intr++) {
        status s = vtpci_alloc_interrupt(dev, rid, intr);
        if (!is_ok(s))
            return (s);
    }

    intr = &dev->vtpci_device_interrupt;

    //    s = bus_setup_intr(intr->vti_irq, NULL,
    //                           vtpci_config_intr, sc, &intr->vti_handler);
    
    if (!is_ok(s))  return (s);

    struct virtqueue *vqx;
    intr = dev->vtpci_msix_vq_interrupts;

    for (int i = 0; i < dev->vtpci_nvqs; i++) {
        vqx = &dev->vtpci_vqs[i];

        /*        error = bus_setup_intr(dev->vtpci_dev, intr->vti_irq, type,
                               vtpci_vq_intr_filter, vtpci_vq_intr, vqx->vtv_vq,
                               &intr->vti_handler);*/

        intr++;
    }

    if (!is_ok(s))  return (s);
    struct vtpci_interrupt *tintr;
    int idx, offset;

    intr = &dev->vtpci_device_interrupt;
    offset = VIRTIO_MSI_CONFIG_VECTOR;

    s = vtpci_register_msix_vector(dev, offset, intr);
    if (!is_ok(s)) return s;

    intr = dev->vtpci_msix_vq_interrupts;
    offset = VIRTIO_MSI_QUEUE_VECTOR;

    for (idx = 0; idx < dev->vtpci_nvqs; idx++) {
        vtpci_select_virtqueue(dev, idx);
        tintr = intr;
        uint16_t vector = VIRTIO_MSI_NO_VECTOR;
        
        out16(dev->base + offset, vector);
        
        /* Read vector to determine if the host had sufficient resources. */
        if (in16(dev->base + offset) != vector) 
            return allocate_status("insufficient host resources for MSIX interrupts\n");
        
        if (!is_ok(s)) return s;
    }
    
    return STATUS_OK;
}

static void vtpci_vq_intr(void *xvq)
{
    struct virtqueue *vq;

    vq = xvq;
    virtqueue_intr(vq);
}

void vtpci_notify_virtqueue(struct vtpci *sc, uint16_t queue)
{
    out16(sc->base + VIRTIO_PCI_QUEUE_NOTIFY, queue);
}

vtpci attach_vtpci(int bus, int slot, int func)
{
    struct vtpci *dev = allocate(general, sizeof(struct vtpci));
    int rid;

    // io base was configured
    u32 base = pci_cfgread(bus, slot, func, 0x10, 4);
    print_u64(base);
    console("\n");    
    dev->base = base & ~1;

    //    rid = PCIR_BAR(1);
    //    sc->vtpci_msix_res = 0;/*bus_alloc_resource_any(dev,
    //                             SYS_RES_MEMORY, &rid, RF_ACTIVE);*/

    vtpci_set_status(dev, VIRTIO_CONFIG_STATUS_RESET);
    
    /* Tell the host we've noticed this device. */

    vtpci_set_status(dev, VIRTIO_CONFIG_STATUS_ACK);
    vtpci_set_status(dev, VIRTIO_CONFIG_STATUS_DRIVER);
    vtpci_set_status(dev, VIRTIO_CONFIG_STATUS_DRIVER_OK);

    u32 k;
    k = in32(dev->base + VIRTIO_PCI_STATUS);
    console("biggy:\n");
    print_u64(k);
    console("\n");
    
    k = in32(dev->base + VIRTIO_PCI_HOST_FEATURES);
    console("biggy:\n");
    print_u64(k);
    console("\n");
    
    k = in32(dev->base + 1);
    console("biggy:\n");
    print_u64(k);
    console("\n");
    k = in16(dev->base + VIRTIO_PCI_QUEUE_NUM);
    console("queueis:\n");
    print_u64(k);
    console("\n");
    int nvqs = 16;
    dev->vtpci_vqs = allocate_zero(general, nvqs * sizeof(struct virtqueue));

    vnet v = init_vnet(dev);
    unsigned char x[] = {0x45};
    struct buffer b;
    b.contents = x;
    b.start = 0;
    b.end = sizeof(x);
    b.next = NULL;
    
    vnet_transmit(v, b);
    
    return dev;
}
