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

#include <virtio_internal.h>

#define VQ_RING_DESC_CHAIN_END  32768
#define VRING_DESC_F_NEXT       1
#define VRING_DESC_F_WRITE      2
#define VRING_DESC_F_INDIRECT	4

/* shared with vqmsg with next unused */
struct vring_desc {
    u64 busaddr;                /* phys for now */
    u32 len;
    u16 flags;
    u16 next;
} __attribute__((packed));

struct vring_avail {
    u16 flags;
    u16 idx;
    u16 ring[0];
} __attribute__((packed));

struct vring_used_elem {
    /* Index of start of used descriptor chain. */
    u32 id;
    /* Total length of the descriptor chain which was written to. */
    u32 len;
};

struct vring_used {
    u16 flags;
    u16 idx;
    struct vring_used_elem ring[0];
} __attribute__((packed));

typedef struct vqmsg {
    struct list l;
    u64 count;
    buffer descv;               /* XXX should be a variable stride vector */
    vqfinish completion;
} *vqmsg;
    
typedef struct virtqueue {
    vtpci dev;
    u16 entries;
    u16 queue_index;
    void *ring_mem;
    volatile struct vring_desc *desc;
    volatile struct vring_avail *avail;
    volatile struct vring_used *used;    
    u64 free_cnt;               /* atomic */
    u16 desc_idx;               /* producer only */
    u16 used_idx;               /* irq only */
    struct list msgqueue;
    vqmsg msgs[0];
} *virtqueue;

/* Most uses here are a chain of 3 or less descriptors. */
#define VQMSG_DEFAULT_SIZE     3
vqmsg allocate_vqmsg(virtqueue vq)
{
    heap h = vq->dev->general;
    vqmsg m = allocate(h, sizeof(struct vqmsg));
    list_init(&m->l);
    m->count = 0;
    m->descv = allocate_buffer(h, sizeof(struct vring_desc) * VQMSG_DEFAULT_SIZE);
    if (m->descv == INVALID_ADDRESS) {
        deallocate(h, m, sizeof(struct vqmsg));
        return INVALID_ADDRESS;
    }
    m->completion = 0;          /* fill on queue */
    return m;
}

/* must be safe at interrupt level */
void deallocate_vqmsg_irq(virtqueue vq, vqmsg m)
{
    deallocate_buffer(m->descv);
    deallocate(vq->dev->general, m, sizeof(struct vqmsg));
}

void vqmsg_push(virtqueue vq, vqmsg m, void * addr, u32 len, boolean write)
{
    buffer_extend(m->descv, (m->count + 1) * sizeof(struct vring_desc));
    struct vring_desc * d = buffer_ref(m->descv, m->count * sizeof(struct vring_desc));
    d->busaddr = physical_from_virtual(addr);
    d->len = len;
    d->flags = write ? VRING_DESC_F_WRITE : 0;
    d->next = 0;
    m->count++;
}

static void virtqueue_fill(virtqueue vq);
static void virtqueue_fill_irq(virtqueue vq);

void vqmsg_commit(virtqueue vq, vqmsg m, vqfinish completion)
{
    m->completion = completion;
    /* XXX noirq */
    list_insert_after(&vq->msgqueue, &m->l);
    virtqueue_fill(vq);
}

static CLOSURE_1_0(vq_interrupt, void, virtqueue);
static void vq_interrupt(virtqueue vq)
{
    volatile struct vring_used_elem *uep;
    vqmsg *vqm = (void *)(vq+1);
    
    read_barrier();
    while (vq->used_idx != vq->used->idx) {
        uep = &vq->used->ring[vq->used_idx & (vq->entries - 1)];
        vqmsg m = vqm[uep->id];
        apply(m->completion, uep->len);
        vq->used_idx++;
        fetch_and_add(&vq->free_cnt, m->count);
        vqm[uep->id] = 0;
        deallocate_vqmsg_irq(vq, m);
    }

    virtqueue_fill_irq(vq);
}

status virtqueue_alloc(vtpci dev,
                       u16 queue,
                       u16 size,
                       int align,
                       virtqueue *vqp,
                       thunk *t)
{
    virtqueue vq;
    u64 d = size * sizeof(struct vring_desc);
    u64 avail_end = pad(d + sizeof(*vq->avail) + sizeof(vq->avail->ring[0]) * size, align);
    u64 alloc = avail_end + sizeof(*vq->used) + sizeof(vq->used->ring[0]) * size;
    vq = allocate(dev->general, sizeof(struct virtqueue) + size * sizeof(vqmsg));
    
    if (vq == INVALID_ADDRESS) 
        return timm("status", "cannot allocate virtqueue");
    
    vq->dev = dev;
    vq->queue_index = queue;
    vq->entries = size;
    vq->free_cnt = size;

    if ((vq->ring_mem = allocate_zero(dev->contiguous, alloc)) != INVALID_ADDRESS) {
        vq->desc = (struct vring_desc *) vq->ring_mem;
        vq->avail = (struct vring_avail *) (vq->desc + size);
        vq->used = (struct vring_used *) (vq->ring_mem  + avail_end);
        *t = closure(dev->general, vq_interrupt, vq);
        *vqp = vq;
        list_init(&vq->msgqueue);
        return 0;
    }

    return(timm("status", "cannot allocate memory for virtqueue ring"));
}

physical virtqueue_paddr(struct virtqueue *vq)
{
    return (physical_from_virtual(vq->ring_mem));
}

void virtqueue_notify(struct virtqueue *vq)
{
    /* Ensure updated avail->idx is visible to host. */
    memory_barrier();
    vtpci_notify_virtqueue(vq->dev, vq->queue_index);
}

/* called from interrupt level or with ints disabled */
static void virtqueue_fill_irq(virtqueue vq)
{
    vqmsg *vqm = (void *)(vq + 1);
    u16 idx = vq->desc_idx;
    list l = &vq->msgqueue;
    list n = list_get_next(l);

    while (n && n != &vq->msgqueue) {
        vqmsg m = struct_from_list(n, vqmsg, l);
        u16 head = idx;
        if (vq->free_cnt < m->count)
            return;

        assert(m->completion);
        vqm[idx] = m;

        struct vring_desc *p = buffer_ref(m->descv, 0);
        for (int i = 0; i < m->count; i++) {
            u16 next = (idx + 1) & (vq->entries - 1);
            volatile struct vring_desc *dst = vq->desc + idx;
            struct vring_desc src = *p++;
            if (i < m->count - 1) {
                src.flags |= VRING_DESC_F_NEXT;
                src.next = next;
            }
            *dst = src;
            idx = next;
        }

        u16 avail_idx = vq->avail->idx & (vq->entries - 1);
        vq->avail->ring[avail_idx] = head;
        vq->avail->idx++;
        vq->free_cnt -= m->count;

        list nn = list_get_next(n);
        list_delete(n);
        n = nn;
    }

    vq->desc_idx = idx;
    virtqueue_notify(vq);
}

static void virtqueue_fill(virtqueue vq)
{
    /* XXX same as irq for now, save/disable/restore later */
    virtqueue_fill_irq(vq);
}
