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

struct vtpci_interrupt {
    struct resource		*vti_irq;
    int			 vti_rid;
    void			*vti_handler;
};

struct vtpci_virtqueue {
    struct virtqueue	*vtv_vq;
    int			 vtv_no_intr;
};

struct vtpci {
    u64 base; //io region base
    uint64_t			 vtpci_features;
    uint32_t			 vtpci_flags;

    // remove
#define VTPCI_FLAG_NO_MSI		0x0001
#define VTPCI_FLAG_NO_MSIX		0x0002
#define VTPCI_FLAG_LEGACY		0x1000
#define VTPCI_FLAG_MSI			0x2000
#define VTPCI_FLAG_MSIX			0x4000
#define VTPCI_FLAG_SHARED_MSIX		0x8000
#define VTPCI_FLAG_ITYPE_MASK		0xF000


    struct virtio_feature_desc	*vtpci_child_feat_desc;

    int				 vtpci_nvqs;
    struct vtpci_virtqueue		*vtpci_vqs;

    /*
     * Ideally, each virtqueue that the driver provides a callback for will
     * receive its own MSIX vector. If there are not sufficient vectors
     * available, then attempt to have all the VQs share one vector. For
     * MSIX, the configuration changed notifications must be on their own
     * vector.
     *
     * If MSIX is not available, we will attempt to have the whole device
     * share one MSI vector, and then, finally, one legacy interrupt.
     */
    struct vtpci_interrupt		 vtpci_device_interrupt;
    struct vtpci_interrupt		*vtpci_msix_vq_interrupts;
    int				 vtpci_nmsix_resources;
    void *vtpci_msix_res; // not a res
};

typedef struct vtpci *vtpci;

#define vtpci_setup_msi_interrupt vtpci_setup_legacy_interrupt

#define VIRTIO_PCI_CONFIG(_sc)                                          \
    VIRTIO_PCI_CONFIG_OFF((((_sc)->vtpci_flags & VTPCI_FLAG_MSIX)) != 0)


static void vtpci_select_virtqueue(struct vtpci *sc, int idx)
{
    out16(sc->base + VIRTIO_PCI_QUEUE_SEL, idx);
}

static uint8_t
vtpci_get_status(vtpci dev)
{
    return (in8(dev->base+ VIRTIO_PCI_STATUS));
}


static void vtpci_set_status(vtpci dev, uint8_t status)
{
    if (status != VIRTIO_CONFIG_STATUS_RESET)
        status |= vtpci_get_status(dev);

    out8(dev->base + VIRTIO_PCI_STATUS, status);
}


static status vtpci_attach(vtpci dev)
{
    struct vtpci *sc;
    vtpci child;
    int rid;

    // xxx - this looks like we set a bit in the pci configuration space? freebsd is pretty
    // coy about it
    //   pci_enable_busmaster(dev);

    //    rid = PCIR_BAR(0);
    sc->base = 0; /*bus_alloc_resource_any(dev, SYS_RES_IOPORT, &rid,
                         RF_ACTIVE);*/
    if (sc->base == 0) 
        return allocate_status("cannot map I/O space\n");


    //    rid = PCIR_BAR(1);
    sc->vtpci_msix_res = 0;/*bus_alloc_resource_any(dev,
                             SYS_RES_MEMORY, &rid, RF_ACTIVE);*/

    vtpci_set_status(dev, VIRTIO_CONFIG_STATUS_RESET);
    
    /* Tell the host we've noticed this device. */

    vtpci_set_status(dev, VIRTIO_CONFIG_STATUS_ACK);
    vtpci_set_status(dev, VIRTIO_CONFIG_STATUS_DRIVER);
    vtpci_set_status(dev, VIRTIO_CONFIG_STATUS_DRIVER_OK);

    return (0);
}

static uint64_t vtpci_negotiate_features(vtpci dev, uint64_t child_features)
{
    uint64_t host_features, features;

    host_features = in32(dev->base + VIRTIO_PCI_HOST_FEATURES);

    /*
     * Limit negotiated features to what the driver, virtqueue, and
     * host all support.
     */
    features = host_features & child_features;
    features = virtqueue_filter_features(features);
    dev->vtpci_features = features;

    out32(dev->base + VIRTIO_PCI_GUEST_FEATURES, features);

    return (features);
}

static int vtpci_with_feature(vtpci dev, uint64_t feature)
{
    return ((dev->vtpci_features & feature) != 0);
}

static status vtpci_alloc_virtqueues(vtpci dev, int flags, int nvqs, struct vq_alloc_info *vq_info)
{
    struct virtqueue *vq;
    struct vtpci_virtqueue *vqx;
    int idx;
    uint16_t size;

    dev->vtpci_vqs = allocate_zero(general, nvqs * sizeof(struct vtpci_virtqueue));

    if (dev->vtpci_vqs == NULL) return status_nomem();

    for (idx = 0; idx < nvqs; idx++) {
        vqx = &dev->vtpci_vqs[idx];
        struct vq_alloc_info *info = &vq_info[idx];

        vtpci_select_virtqueue(dev, idx);
        size = in16(dev->base + VIRTIO_PCI_QUEUE_NUM);

        status s = virtqueue_alloc(dev, "foo", idx, size, VIRTIO_PCI_VRING_ALIGN,
                                0xFFFFFFFFUL, info, &vq);
        if (!is_ok(s)) return s;

        out32(dev->base + VIRTIO_PCI_QUEUE_PFN,
              virtqueue_paddr(vq) >> VIRTIO_PCI_QUEUE_ADDR_SHIFT);

        vqx->vtv_vq = *info->vqai_vq = vq;
        vqx->vtv_no_intr = info->vqai_intr == NULL;

        dev->vtpci_nvqs++;
    }

    return STATUS_OK;
}

static status vtpci_register_msix_vector(struct vtpci *dev,
                                      int offset,
                                      struct vtpci_interrupt *intr)
{
    uint16_t vector;
    
    if (intr != NULL) {
        /* Map from guest rid to host vector. */
        vector = intr->vti_rid - 1;
    } else
        vector = VIRTIO_MSI_NO_VECTOR;

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

    void *irq = 0; // bus_alloc_resource_any(dev, SYS_RES_IRQ, &rid, flags);

    intr->vti_irq = irq;
    intr->vti_rid = rid;

    return STATUS_OK;
}


static status vtpci_setup_intr(vtpci dev)
{
    status s;
    struct vtpci_interrupt *intr;
    int i, nvectors;

    for (nvectors = 0, i = 0; i < dev->vtpci_nvqs; i++) {
        if (dev->vtpci_vqs[i].vtv_no_intr == 0)
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
    intr->vti_irq = 0; // 
    intr->vti_rid = rid;

    s = vtpci_alloc_interrupt(dev, rid, intr);
    if (!is_ok(s) || dev->vtpci_flags & (VTPCI_FLAG_LEGACY | VTPCI_FLAG_MSI))
        return s;

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

    struct vtpci_virtqueue *vqx;
    intr = dev->vtpci_msix_vq_interrupts;

    for (int i = 0; i < dev->vtpci_nvqs; i++) {
        vqx = &dev->vtpci_vqs[i];

        if (vqx->vtv_no_intr)
            continue;

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

        if (dev->vtpci_vqs[idx].vtv_no_intr)
            tintr = NULL;
        else
            tintr = intr;

        uint16_t vector;

        if (intr != NULL) {
            /* Map from guest rid to host vector. */
            vector = intr->vti_rid - 1;
        } else
            vector = VIRTIO_MSI_NO_VECTOR;
        
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

