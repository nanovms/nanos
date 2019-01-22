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

#define VQ_RING_DESC_CHAIN_END 32768

#define VRING_DESC_F_NEXT       1
#define VRING_DESC_F_WRITE      2
#define VRING_DESC_F_INDIRECT	4

struct virtqueue {
    void *dev;
    u16 entries;
    u16 queue_index;
    void *ring_mem;
    struct vring_desc *desc;
    struct vring_avail *avail;
    volatile struct vring_used *used;    
    u16	free_cnt;
    u16	desc_idx;
    u16 avail_idx;
    u16 used_idx;
    thunk completions[0];
};


// start figuring out an encoding framework - these structs are fragile
struct vring_desc {
    u64 addr;    /* Address (guest-physical). */
    u32 len;     /* Length. */
    u16 flags;        /* The flags as indicated above. */
    u16 next;         /* We chain unused descriptors via this, too. */
};

struct vring_avail {
    u16 flags;
    u16 idx;
    u16 ring[0];
};

/* uint32_t is used here for ids for padding reasons. */
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
};


static CLOSURE_1_0(vq_interrupt, void, virtqueue);
static void vq_interrupt(struct virtqueue *vq)
{
    volatile struct vring_used_elem *uep;
    vqfinish *vqf = (void *)(vq+1);
    
    read_barrier();
    while (vq->used_idx != vq->used->idx) {
        uep = &vq->used->ring[vq->used_idx  & (vq->entries - 1)];
        // reclaim the desc space
        apply(vqf[uep->id],  uep->len);
        vq->used_idx++; 
    }
}


status virtqueue_alloc(vtpci dev,
                       u16 queue,
                       u16 size,
                       int align,
                       struct virtqueue **vqp,
                       thunk *t)
{
    struct virtqueue *vq;
    u64 d = size * sizeof(struct vring_desc);
    u64 avail_end =  pad(d + sizeof(*vq->avail) + sizeof(vq->avail->ring[0]) * size, align);
    u64 alloc = avail_end + sizeof(*vq->used) + sizeof(vq->used->ring[0]) * size;
    vq = allocate(dev->general, sizeof(struct virtqueue) + size * sizeof(vqfinish));
    
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
    /* this was 'mb', i have read_barrier and write_barrier - they are both
    the same, cant be right*/
    read_barrier();
    vtpci_notify_virtqueue(vq->dev, vq->queue_index);
}

status virtqueue_enqueue(struct virtqueue *vq,
                         /* not an ideal writev, but good enough for  today */
                         void **as,
                         bytes *lengths,
                         boolean *writables,
                         int segments,
                         vqfinish completion)
{
    int needed = 0;
    u16 idx = vq->desc_idx;
    u16 hidx = idx;

    if (vq->free_cnt < segments)
        return timm("status", "no room in queue");

    // allocate descs from a heap
    for (int i = 0; i < segments; i++) {
        struct vring_desc *dp =  vq->desc + idx;
        u64 p = physical_from_virtual(as[i]);
        u16 flags =0;
        dp->addr = p;
        
        vqfinish *vqa = (void *)(vq + 1);
        vqa[idx] = completion; // just the last guy?
        dp->len = lengths[i];
        idx = (idx +1)&(vq->entries - 1);
        if (i != (segments-1)) {
            flags |= VRING_DESC_F_NEXT;
            dp->next = idx; //since this never changes, freebsd built it in advance
        } 
        if (writables[i]) flags |= VRING_DESC_F_WRITE;
        dp->flags = flags;
    }

    vq->desc_idx = idx;
    vq->free_cnt -= needed;

    u16 avail_idx  = vq->avail->idx & (vq->entries - 1);
    vq->avail->ring[avail_idx] = hidx;
    write_barrier();
    vq->avail->idx++;
    virtqueue_notify(vq);
    return STATUS_OK;
}


