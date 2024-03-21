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

#include <kernel.h>
#include "virtio_internal.h"
#include "virtio_pci.h"

//#define VIRTIO_PCI_DEBUG
#ifdef VIRTIO_PCI_DEBUG
# define virtio_pci_debug(x, ...) do {tprintf(sym(virtio_pci), 0, ss(x), ##__VA_ARGS__);} while(0)
#else
# define virtio_pci_debug(...) do { } while(0)
#endif // defined(VIRTIO_PCI_DEBUG)

/*
 * Legacy device config offsets, located in BAR0
 */
#define VIRTIO_PCI_HOST_FEATURES     0  /* host's supported features (32bit, RO)*/
#define VIRTIO_PCI_GUEST_FEATURES    4  /* guest's supported features (32, RW) */
#define VIRTIO_PCI_QUEUE_PFN         8  /* physical address of VQ (32, RW) */
#define VIRTIO_PCI_QUEUE_NUM         12 /* number of ring entries (16, RO) */
#define VIRTIO_PCI_QUEUE_SEL         14 /* current VQ selection (16, RW) */
#define VIRTIO_PCI_QUEUE_NOTIFY	     16 /* notify host regarding VQ (16, RW) */
#define VIRTIO_PCI_STATUS            18 /* device status register (8, RW) */
#define VIRTIO_PCI_ISR               19 /* interrupt status register, reading
				         * also clears the register (8, RO) */
#define VIRTIO_NON_MSI_DEVICE_CONFIG 20 /* device config start without msi */
#define VIRTIO_MSI_CONFIG_VECTOR     20 /* configuration change vector (16, RW) */
#define VIRTIO_MSI_QUEUE_VECTOR      22 /* vector for selected VQ notifications (16, RW) */
#define VIRTIO_MSI_DEVICE_CONFIG     24 /* device config start with msi */

/*
 * Modern device PCI capabilities
 */
#define VIRTIO_PCI_CAP_COMMON_CFG    1 /* Common configuration */
#define VIRTIO_PCI_CAP_NOTIFY_CFG    2 /* Notifications */
#define VIRTIO_PCI_CAP_ISR_CFG       3 /* ISR Status */
#define VIRTIO_PCI_CAP_DEVICE_CFG    4 /* Device specific configuration */
#define VIRTIO_PCI_CAP_PCI_CFG       5 /* PCI configuration access */

/* This is the PCI capability header: */
struct vtpci_cap {
    u8 cap_vndr;                     /* Generic PCI field: PCI_CAP_ID_VNDR */
    u8 cap_next;                     /* Generic PCI field: next ptr. */
    u8 cap_len;                      /* Generic PCI field: capability length */
    u8 cfg_type;                     /* Identifies the structure. */
    u8 bar;                          /* Where to find it. */
    u8 padding[3];                   /* Pad to full dword. */
    u32 offset;                      /* Offset within bar. */
    u32 length;                      /* Length of the structure, in bytes. */
} __attribute__((packed));

#define VTPCI_CAP_R_LEN              (offsetof(struct vtpci_cap *, cap_len))
#define VTPCI_CAP_R_TYPE             (offsetof(struct vtpci_cap *, cfg_type))
#define VTPCI_CAP_R_BAR              (offsetof(struct vtpci_cap *, bar))
#define VTPCI_CAP_R_OFFSET           (offsetof(struct vtpci_cap *, offset))
#define VTPCI_CAP_R_LENGTH           (offsetof(struct vtpci_cap *, length))

/*
 * Modern device notify capability
 */
struct vtpci_notify_cap {
    struct vtpci_cap cap;
    u32 offset_multiplier;           /* Multiplier for queue_notify_off */
} __attribute__((packed));

#define VTPCI_NOTIFY_CAP_R_OFFSET_MULTIPLIER (offsetof(struct vtpci_notify_cap *, offset_multiplier))

/*
 * Modern device common config
 */
struct vtpci_common_config {
    /* About the whole device. */
    u32 device_feature_select;       /* read-write */
    u32 device_feature;              /* read-only for driver */
    u32 driver_feature_select;       /* read-write */
    u32 driver_feature;              /* read-write */
    u16 config_msix_vector;          /* read-write */
    u16 num_queues;                  /* read-only for driver */
    u8 device_status;                /* read-write */
    u8 config_generation;            /* read-only for driver */

    /* About a specific virtqueue. */
    u16 queue_select;                /* read-write */
    u16 queue_size;                  /* read-write, power of 2, or 0. */
    u16 queue_msix_vector;           /* read-write */
    u16 queue_enable;                /* read-write */
    u16 queue_notify_off;            /* read-only for driver */
    u64 queue_desc;                  /* read-write */
    u64 queue_avail;                 /* read-write */
    u64 queue_used;                  /* read-write */
} __attribute__((packed));

#define VTPCI_R_DEVICE_FEATURE_SELECT (offsetof(struct vtpci_common_config *, device_feature_select))
#define VTPCI_R_DEVICE_FEATURE        (offsetof(struct vtpci_common_config *, device_feature))
#define VTPCI_R_DRIVER_FEATURE_SELECT (offsetof(struct vtpci_common_config *, driver_feature_select))
#define VTPCI_R_DRIVER_FEATURE        (offsetof(struct vtpci_common_config *, driver_feature))
#define VTPCI_R_CONFIG_MSIX_VECTOR    (offsetof(struct vtpci_common_config *, config_msix_vector))
#define VTPCI_R_NUM_QUEUES            (offsetof(struct vtpci_common_config *, num_queues))
#define VTPCI_R_DEVICE_STATUS         (offsetof(struct vtpci_common_config *, device_status))
#define VTPCI_R_CONFIG_GENERATION     (offsetof(struct vtpci_common_config *, config_generation))
#define VTPCI_R_QUEUE_SELECT          (offsetof(struct vtpci_common_config *, queue_select))
#define VTPCI_R_QUEUE_SIZE            (offsetof(struct vtpci_common_config *, queue_size))
#define VTPCI_R_QUEUE_MSIX_VECTOR     (offsetof(struct vtpci_common_config *, queue_msix_vector))
#define VTPCI_R_QUEUE_ENABLE          (offsetof(struct vtpci_common_config *, queue_enable))
#define VTPCI_R_QUEUE_NOTIFY_OFF      (offsetof(struct vtpci_common_config *, queue_notify_off))
#define VTPCI_R_QUEUE_DESC            (offsetof(struct vtpci_common_config *, queue_desc))
#define VTPCI_R_QUEUE_AVAIL           (offsetof(struct vtpci_common_config *, queue_avail))
#define VTPCI_R_QUEUE_USED            (offsetof(struct vtpci_common_config *, queue_used))

boolean vtpci_probe(pci_dev d, int virtio_dev_id)
{
    virtio_pci_debug("%s: vendor is 0x%x, virtio_dev_id 0x%x\n", func_ss,
                     pci_get_vendor(d), virtio_dev_id);
    if (pci_get_vendor(d) != VIRTIO_PCI_VENDORID) {
        return false;
    }

    u16 device = pci_get_device(d);
    virtio_pci_debug("   device is 0x%x\n", device);
    if (device < VIRTIO_PCI_DEVICEID_MIN || device > VIRTIO_PCI_DEVICEID_MAX) {
        return false;
    }

    if (device >= VIRTIO_PCI_DEVICEID_MODERN_MIN) {
        virtio_pci_debug("   device is modern\n");
        // modern device
        return device == VIRTIO_PCI_DEVICEID_MODERN_MIN + virtio_dev_id;
    }

    // legacy device
    virtio_pci_debug("subdev %d, virtio_dev_id %d\n", pci_get_subdevice(d), virtio_dev_id);
    return pci_get_subdevice(d) == virtio_dev_id;
}

static u8 vtpci_get_status(vtpci dev)
{
    return pci_bar_read_1(&dev->common_config, dev->regs[VTPCI_REG_DEVICE_STATUS]);
}

void vtpci_set_status(vtpci dev, u8 status)
{
    if (status != VIRTIO_CONFIG_STATUS_RESET)
        status |= vtpci_get_status(dev);

    pci_bar_write_1(&dev->common_config, dev->regs[VTPCI_REG_DEVICE_STATUS], status);
    if (status == VIRTIO_CONFIG_STATUS_RESET) {
        while (vtpci_get_status(dev) != VIRTIO_CONFIG_STATUS_RESET) {
            virtio_pci_debug("%s: waiting for VIRTIO_CONFIG_STATUS_RESET\n", func_ss);
            kern_pause();
        }
    }
}

boolean vtpci_is_modern(vtpci dev)
{
    return vtdev_is_modern(&dev->virtio_dev);
}

static void vtpci_modern_write_8(struct pci_bar *b, bytes offset, u64 val)
{
    pci_bar_write_4(b, offset, val & MASK(32));
    pci_bar_write_4(b, offset + 4, val >> 32);
}

static u8 vtpci_get_isr_status(vtpci dev)
{
    return pci_bar_read_1(&dev->common_config, dev->regs[VTPCI_REG_ISR_STATUS]);
}

closure_function(1, 0, void, vtpci_non_msix_irq,
                 vtpci, dev)
{
    vtpci dev = bound(dev);
    virtio_pci_debug("%s: dev %p\n", func_ss, dev);

    /* read and clear interrupt status */
    u8 isr_status = vtpci_get_isr_status(dev);
    virtio_pci_debug("   isr status 0x%x\n", isr_status);
    if ((isr_status & VIRTIO_PCI_ISR_INTR) && dev->vq_handlers) {
        thunk t;
        vector_foreach(dev->vq_handlers, t) {
            assert(t && t != INVALID_ADDRESS);
            virtio_pci_debug("      applying queue handler %F\n", t);
            apply(t);
        }
    }

    if ((isr_status & VIRTIO_PCI_ISR_CONFIG) && dev->config_handler) {
        virtio_pci_debug("       queueing config change handler %F\n",
                         dev->config_handler);
        async_apply_bh((thunk)dev->config_handler);
    }
}

static void vtpci_register_non_msix_irq(vtpci dev, range cpu_affinity)
{
    if (dev->non_msix_handler)
        return;
    dev->non_msix_handler = closure(dev->virtio_dev.general, vtpci_non_msix_irq, dev);
    assert(dev->non_msix_handler != INVALID_ADDRESS);
    dev->vq_handlers = allocate_vector(dev->virtio_dev.general, 2);
    assert(dev->vq_handlers != INVALID_ADDRESS);

    /* XXX should really have separate dev name and queue names */
    pci_setup_irq_aff(dev->dev, dev->non_msix_handler, ss("vtpci non-msix"), cpu_affinity);
}

static void vtpci_register_non_msix_queue_handler(vtpci dev, thunk handler, range cpu_affinity)
{
    vtpci_register_non_msix_irq(dev, cpu_affinity);
    vector_push(dev->vq_handlers, handler);
}

static void vtpci_register_non_msix_config_handler(vtpci dev, thunk handler, range cpu_affinity)
{
    vtpci_register_non_msix_irq(dev, cpu_affinity);
    assert(!dev->config_handler);
    dev->config_handler = handler;
}

static status vtpci_setup_msix(vtpci dev, thunk handler, sstring name, range cpu_affinity,
                               int cfg_reg)
{
    int msi_slot = allocate_u64(dev->msix_entries, 1);
    if (msi_slot < 0)
        return timm("status", "failed to find free MSI-X slot");
    if (pci_setup_msix_aff(dev->dev, msi_slot, handler, name, cpu_affinity) == INVALID_PHYSICAL)
        return timm("status", "failed to allocate MSI-X vector");
    pci_bar_write_2(&dev->common_config, dev->regs[cfg_reg], msi_slot);
    int check_idx = pci_bar_read_2(&dev->common_config, dev->regs[cfg_reg]);
    if (check_idx == msi_slot)
        return STATUS_OK;
    else
        return timm("status", "cannot configure MSI-X vector");
}

status vtpci_alloc_virtqueue(vtpci dev,
                             sstring name,
                             int idx,
                             range cpu_affinity,
                             struct virtqueue **result)
{
    // allocate virtqueue
    struct virtqueue *vq;
    pci_bar_write_2(&dev->common_config, dev->regs[VTPCI_REG_QUEUE_SELECT], idx);
    u16 size = pci_bar_read_2(&dev->common_config, dev->regs[VTPCI_REG_QUEUE_SIZE]);
    assert(size > 0);
    thunk handler;
    bytes notify_offset = vtpci_is_modern(dev) ?
        pci_bar_read_2(&dev->common_config, VTPCI_R_QUEUE_NOTIFY_OFF) * dev->notify_offset_multiplier :
        VIRTIO_PCI_QUEUE_NOTIFY;

    virtio_pci_debug("%s: name %s, notify_offset 0x%lx\n", func_ss, name, notify_offset);
    status s = virtqueue_alloc(&dev->virtio_dev, name, idx, size, notify_offset,
                               VIRTIO_PCI_VRING_ALIGN, &vq, &handler);
    if (!is_ok(s))
        return s;

    if (dev->msix_entries) {
        // setup virtqueue MSI-X interrupt
        s = vtpci_setup_msix(dev, handler, name, cpu_affinity, VTPCI_REG_QUEUE_MSIX_VECTOR);
        if (!is_ok(s))
            return s;
    } else {
        vtpci_register_non_msix_queue_handler(dev, handler, cpu_affinity);
    }

    // queue ring
    if (vtpci_is_modern(dev)) {
        virtio_pci_debug("%s: desc 0x%lx, avail 0x%lx, used 0x%lx\n", func_ss,
                virtqueue_desc_paddr(vq), virtqueue_avail_paddr(vq), virtqueue_used_paddr(vq));
        vtpci_modern_write_8(&dev->common_config, VTPCI_R_QUEUE_DESC, virtqueue_desc_paddr(vq));
        vtpci_modern_write_8(&dev->common_config, VTPCI_R_QUEUE_AVAIL, virtqueue_avail_paddr(vq));
        vtpci_modern_write_8(&dev->common_config, VTPCI_R_QUEUE_USED, virtqueue_used_paddr(vq));
        pci_bar_write_2(&dev->common_config, VTPCI_R_QUEUE_ENABLE, 1);
    } else {
        pci_bar_write_4(&dev->common_config, VIRTIO_PCI_QUEUE_PFN, virtqueue_desc_paddr(vq) >> VIRTIO_PCI_QUEUE_ADDR_SHIFT);
    }

    *result = vq;
    return STATUS_OK;
}

closure_function(2, 0, void, vtpci_config_change_msix_irq,
                 vtpci, dev, thunk, handler)
{
    virtio_pci_debug("%s: dev %p, queueing config change handler %F\n",
                     func_ss, bound(dev), bound(handler));
    async_apply_bh(bound(handler));
}

status vtpci_register_config_change_handler(vtpci dev, thunk handler)
{
    virtio_pci_debug("%s: dev %p, handler %p (%F)\n", func_ss, dev, handler, handler);
    range cpu_affinity = irange(0, 0);
    if (dev->msix_entries) {
        thunk t = closure(dev->virtio_dev.general, vtpci_config_change_msix_irq, dev, handler);
        assert(t != INVALID_ADDRESS);

        // XXX vtdev name
        return vtpci_setup_msix(dev, t, ss("config change"), cpu_affinity,
                                VTPCI_REG_CONFIG_MSIX_VECTOR);
    } else {
        vtpci_register_non_msix_config_handler(dev, handler, cpu_affinity);
    }
    return STATUS_OK;
}

static void vtpci_legacy_alloc_resources(vtpci dev)
{
    dev->regs[VTPCI_REG_DEVICE_STATUS] = VIRTIO_PCI_STATUS;
    dev->regs[VTPCI_REG_QUEUE_SELECT] = VIRTIO_PCI_QUEUE_SEL;
    dev->regs[VTPCI_REG_QUEUE_SIZE] = VIRTIO_PCI_QUEUE_NUM;
    dev->regs[VTPCI_REG_QUEUE_MSIX_VECTOR] = VIRTIO_MSI_QUEUE_VECTOR;
    dev->regs[VTPCI_REG_CONFIG_MSIX_VECTOR] = VIRTIO_MSI_CONFIG_VECTOR;
    dev->regs[VTPCI_REG_ISR_STATUS] = VIRTIO_PCI_ISR;

    pci_bar_init(dev->dev, &dev->common_config, 0, 0, -1);
    runtime_memcpy(&dev->notify_config, &dev->common_config, sizeof(dev->notify_config));
    pci_bar_init(dev->dev, &dev->device_config, 0,
                 dev->msix_entries ? VIRTIO_MSI_DEVICE_CONFIG :
                 VIRTIO_NON_MSI_DEVICE_CONFIG, -1);
}

static u32 vtpci_modern_find_cap(vtpci dev, u8 cfg_type, struct pci_bar *b)
{
    for (u32 cp = pci_find_cap(dev->dev, PCIY_VENDOR); cp != 0; cp = pci_find_next_cap(dev->dev, PCIY_VENDOR, cp)) {
        u8 c = pci_cfgread(dev->dev, cp + VTPCI_CAP_R_TYPE, 1);
        if (c != cfg_type)
            continue;

        if (b) {
            u8 bar = pci_cfgread(dev->dev, cp + VTPCI_CAP_R_BAR, 1);
            u8 cap_len = pci_cfgread(dev->dev, cp + VTPCI_CAP_R_LEN, 1);
            assert(cap_len >= sizeof(struct vtpci_cap));
            virtio_pci_debug("%s: cp 0x%x, cfg_type %d: cap_len %d\n", func_ss, cp, cfg_type, cap_len);
            u32 offset = pci_cfgread(dev->dev, cp + VTPCI_CAP_R_OFFSET, 4);
            u32 length = pci_cfgread(dev->dev, cp + VTPCI_CAP_R_LENGTH, 4);
            pci_bar_init(dev->dev, b, bar, offset, length);
        }
        return cp;
    }

    return 0;
}

static void vtpci_modern_alloc_resources(vtpci dev)
{
    dev->regs[VTPCI_REG_DEVICE_STATUS] = VTPCI_R_DEVICE_STATUS;
    dev->regs[VTPCI_REG_QUEUE_SELECT] = VTPCI_R_QUEUE_SELECT;
    dev->regs[VTPCI_REG_QUEUE_SIZE] = VTPCI_R_QUEUE_SIZE;
    dev->regs[VTPCI_REG_QUEUE_MSIX_VECTOR] = VTPCI_R_QUEUE_MSIX_VECTOR;
    dev->regs[VTPCI_REG_CONFIG_MSIX_VECTOR] = VTPCI_R_CONFIG_MSIX_VECTOR;
    dev->regs[VTPCI_REG_ISR_STATUS] = VIRTIO_PCI_ISR;

    // scan PCI capabilities
    vtpci_modern_find_cap(dev, VIRTIO_PCI_CAP_COMMON_CFG, &dev->common_config);
    u32 cp = vtpci_modern_find_cap(dev, VIRTIO_PCI_CAP_NOTIFY_CFG, &dev->notify_config);
    if (cp) {
        dev->notify_offset_multiplier = pci_cfgread(dev->dev, cp + VTPCI_NOTIFY_CAP_R_OFFSET_MULTIPLIER, 4);
        virtio_pci_debug("%s: notify_offset_multiplier 0x%x\n", func_ss, dev->notify_offset_multiplier);
    }
    vtpci_modern_find_cap(dev, VIRTIO_PCI_CAP_DEVICE_CFG, &dev->device_config);
}

closure_func_basic(vtdev_notify, void, vtpci_notify,
                   u16 queue_index, bytes notify_offset)
{
    virtio_pci_debug("%s: queue %d, notify_offset 0x%x\n", func_ss,
                     queue_index, notify_offset);
    pci_bar_write_2(&struct_from_closure(vtpci, notify)->notify_config, notify_offset, queue_index);
}

vtpci attach_vtpci(heap h, backed_heap page_allocator, pci_dev d, u64 feature_mask)
{
    struct vtpci *dev = allocate(h, sizeof(struct vtpci));
    assert(dev != INVALID_ADDRESS);
    vtdev virtio_dev = &dev->virtio_dev;

    boolean is_modern = pci_get_device(d) >= VIRTIO_PCI_DEVICEID_MODERN_MIN;
    if (is_modern)
        feature_mask |= VIRTIO_F_VERSION_1;
    virtio_pci_debug("%s: dev %x%s\n", func_ss, pci_get_device(d),
                     is_modern ? ss(" (modern)") : sstring_empty());

    dev->dev = d;
    int msix_entries = pci_enable_msix(dev->dev);
    if (msix_entries > 0) {
        dev->msix_entries = (heap)create_id_heap(h, h, 0, msix_entries, 1, false);
        assert(dev->msix_entries != INVALID_ADDRESS);
    } else {
        dev->msix_entries = 0;
    }
    if (feature_mask & VIRTIO_F_VERSION_1) {
        vtpci_modern_alloc_resources(dev);
    } else {
        vtpci_legacy_alloc_resources(dev);
    }
    pci_set_bus_master(dev->dev);
    pci_enable_io_and_memory(dev->dev);

    vtpci_set_status(dev, VIRTIO_CONFIG_STATUS_RESET);
    vtpci_set_status(dev, VIRTIO_CONFIG_STATUS_ACK);
    vtpci_set_status(dev, VIRTIO_CONFIG_STATUS_DRIVER);

    if (is_modern) {
        // read device features
        u32 f0, f1;
        pci_bar_write_4(&dev->common_config, VTPCI_R_DEVICE_FEATURE_SELECT, 0);
        f0 = pci_bar_read_4(&dev->common_config, VTPCI_R_DEVICE_FEATURE);
        pci_bar_write_4(&dev->common_config, VTPCI_R_DEVICE_FEATURE_SELECT, 1);
        f1 = pci_bar_read_4(&dev->common_config, VTPCI_R_DEVICE_FEATURE);
        virtio_dev->dev_features = ((u64) f1 << 32) | f0;

        // write negotiated features
        virtio_dev->features = virtio_dev->dev_features & feature_mask;
        pci_bar_write_4(&dev->common_config, VTPCI_R_DRIVER_FEATURE_SELECT, 0);
        pci_bar_write_4(&dev->common_config, VTPCI_R_DRIVER_FEATURE, virtio_dev->features & MASK(32));
        pci_bar_write_4(&dev->common_config, VTPCI_R_DRIVER_FEATURE_SELECT, 1);
        pci_bar_write_4(&dev->common_config, VTPCI_R_DRIVER_FEATURE, virtio_dev->features >> 32);
    } else {
        // read device features
        virtio_dev->dev_features = pci_bar_read_4(&dev->common_config, VIRTIO_PCI_HOST_FEATURES);

        // write negotiated features
        virtio_dev->features = virtio_dev->dev_features & feature_mask;
        pci_bar_write_4(&dev->common_config, VIRTIO_PCI_GUEST_FEATURES, virtio_dev->features);
    }
    virtio_pci_debug("%s: device features 0x%lx, negotiated features 0x%lx\n",
                     func_ss, virtio_dev->dev_features, virtio_dev->features);
    vtpci_set_status(dev, VIRTIO_CONFIG_STATUS_FEATURE);

    init_closure_func(&dev->notify, vtdev_notify, vtpci_notify);
    dev->virtio_dev.notify = (vtdev_notify)&dev->notify;
    virtio_attach(h, page_allocator, VTIO_TRANSPORT_PCI, virtio_dev);
    dev->non_msix_handler = 0;
    dev->vq_handlers = 0;
    dev->config_handler = 0;
    return dev;
}
