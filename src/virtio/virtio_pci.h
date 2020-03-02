/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright IBM Corp. 2007
 *
 * Authors:
 *  Anthony Liguori  <aliguori@us.ibm.com>
 *
 * This header is BSD licensed so anyone can use the definitions to implement
 * compatible drivers/servers.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of IBM nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL IBM OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include <pci.h>

typedef struct vtpci *vtpci;

struct vtpci {
    struct pci_dev _dev;
    pci_dev dev;

    u64 base; //io region base
    u64 features;

    heap contiguous;
    heap general;
    struct virtio_feature_desc	*vtpci_child_feat_desc;

    int vtpci_nvqs;
    struct virtqueue *vtpci_vqs;
};

/* VirtIO ABI version, this must match exactly. */
#define VIRTIO_PCI_ABI_VERSION	0

/*
 * VirtIO Header, located in BAR 0.
 */
#define VIRTIO_PCI_HOST_FEATURES  0  /* host's supported features (32bit, RO)*/
#define VIRTIO_PCI_GUEST_FEATURES 4  /* guest's supported features (32, RW) */
#define VIRTIO_PCI_QUEUE_PFN      8  /* physical address of VQ (32, RW) */
#define VIRTIO_PCI_QUEUE_NUM      12 /* number of ring entries (16, RO) */
#define VIRTIO_PCI_QUEUE_SEL      14 /* current VQ selection (16, RW) */
#define VIRTIO_PCI_QUEUE_NOTIFY	  16 /* notify host regarding VQ (16, RW) */
#define VIRTIO_PCI_STATUS         18 /* device status register (8, RW) */
#define VIRTIO_PCI_ISR            19 /* interrupt status register, reading
				      * also clears the register (8, RO) */
/* Only if MSIX is enabled: */
#define VIRTIO_MSI_CONFIG_VECTOR  20 /* configuration change vector (16, RW) */
#define VIRTIO_MSI_QUEUE_VECTOR   22 /* vector for selected VQ notifications
					(16, RW) */
#define VIRTIO_MSI_DEVICE_CONFIG  24

/* The bit of the ISR which indicates a device has an interrupt. */
#define VIRTIO_PCI_ISR_INTR	0x1
/* The bit of the ISR which indicates a device configuration change. */
#define VIRTIO_PCI_ISR_CONFIG	0x2
/* Vector value used to disable MSI for queue. */
#define VIRTIO_MSI_NO_VECTOR	0xFFFF

/*
 * The remaining space is defined by each driver as the per-driver
 * configuration space.
 */
#define VIRTIO_PCI_CONFIG_OFF(msix_enabled)     ((msix_enabled) ? 24 : 20)
#define VIRTIO_PCI_QUEUE_ADDR_SHIFT	12
#define VIRTIO_PCI_VRING_ALIGN	4096

vtpci attach_vtpci(heap h, heap page_allocator, pci_dev d, u64 feature_mask);
status vtpci_alloc_virtqueue(vtpci dev, const char *name, int idx, struct virtqueue **result);
void vtpci_set_status(vtpci dev, u8 status);

/* VirtIO PCI vendor/device ID. */
#define VIRTIO_PCI_VENDORID	0x1AF4
#define VIRTIO_PCI_DEVICEID_MIN	0x1000
#define VIRTIO_PCI_DEVICEID_MAX	0x103F
#define VIRTIO_PCI_DEVICEID_NETWORK 0x1000
#define VIRTIO_PCI_DEVICEID_STORAGE 0x1001
#define VIRTIO_PCI_DEVICEID_BALLOON 0x1002
#define VIRTIO_PCI_DEVICEID_CONSOLE 0x1003
#define VIRTIO_PCI_DEVICEID_SCSI    0x1004
#define VIRTIO_PCI_DEVICEID_ENTROPY 0x1005
#define VIRTIO_PCI_DEVICEID_FILESYSTEM_9P 0x1009
