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

/*
 * Implements the virtqueue interface as basically described
 * in the original VirtIO paper.
 */

#include <virtio_internal.h>
/*
 * The maximum virtqueue size is 2^15. Use that value as the end of
 * descriptor chain terminator since it will never be a valid index
 * in the descriptor table. This is used to verify we are correctly
 * handling vq_free_cnt.
 */
#define VQ_RING_DESC_CHAIN_END 32768



static int vq_ring_enable_interrupt(struct virtqueue *vq, uint16_t ndesc)
{
    /*
     * Enable interrupts, making sure we get the latest index of
     * what's already been consumed.
     */
    if (vq->vq_flags & VIRTQUEUE_FLAG_EVENT_IDX)
        vring_used_event(&vq->vq_ring) = vq->vq_used_cons_idx + ndesc;
    else
        vq->vq_ring.avail->flags &= ~VRING_AVAIL_F_NO_INTERRUPT;

    memory_barrier;

    /*
     * Enough items may have already been consumed to meet our threshold
     * since we last checked. Let our caller know so it processes the new
     * entries.
     */
    if (virtqueue_nused(vq) > ndesc)
        return (1);

    return (0);
}


static void vq_ring_free_chain(struct virtqueue *vq, uint16_t desc_idx)
{
    struct vring_desc *dp;

    dp = &vq->vq_ring.desc[desc_idx];
    dp->next = vq->vq_desc_head_idx;
    vq->vq_desc_head_idx = desc_idx;
}

status virtqueue_alloc(vtpci dev,
                       uint16_t queue,
                       uint16_t size,
                       int align,
                       struct virtqueue **vqp)
{
    status s = STATUS_OK;
    struct virtqueue *vq;
    u64 alloc = size * sizeof(struct vring_desc) + 6 + 2*size + 6 + 8*size;

    vq = allocate(dev->general, sizeof(struct virtqueue));

    if (vq == INVALID_ADDRESS) 
        return allocate_status("cannot allocate virtqueue\n");

    vq->vq_dev = dev;
    vq->vq_queue_index = queue;
    vq->vq_nentries = size;
    vq->vq_free_cnt = size;

    //    if (VIRTIO_BUS_WITH_FEATURE(dev, VIRTIO_RING_F_EVENT_IDX) != 0)
    vq->vq_flags |= VIRTQUEUE_FLAG_EVENT_IDX;
    vq->vq_ring_mem = allocate_zero(dev->contiguous, alloc);

    if (vq->vq_ring_mem == INVALID_ADDRESS) {
        s = allocate_status("cannot allocate memory for virtqueue ring\n");
        goto fail;
    }

    vq->vq_ring.num = vq->vq_nentries;
    vq->vq_ring.desc = (struct vring_desc *) vq->vq_ring_mem;
    vq->vq_ring.avail = (struct vring_avail *) (vq->vq_ring_mem + size*sizeof(struct vring_desc));
    vq->vq_ring.used = (void *)
        (((unsigned long) &vq->vq_ring.avail->ring[vq->vq_nentries] + align-1) & ~(align-1));
    *vqp = vq;

 fail:
    return (s);
}

physical virtqueue_paddr(struct virtqueue *vq)
{
    return (physical_from_virtual(vq->vq_ring_mem));
}

int virtqueue_size(struct virtqueue *vq)
{
    return (vq->vq_nentries);
}

int virtqueue_nfree(struct virtqueue *vq)
{
    return (vq->vq_free_cnt);
}

int virtqueue_empty(struct virtqueue *vq)
{
    return (vq->vq_nentries == vq->vq_free_cnt);
}

int virtqueue_full(struct virtqueue *vq)
{
    return (vq->vq_free_cnt == 0);
}

void virtqueue_notify(struct virtqueue *vq)
{
    /* Ensure updated avail->idx is visible to host. */
    /* this was 'mb', i have read_barrier and write_barrier - they are both
    the same, cant be right*/
    read_barrier();
    vtpci_notify_virtqueue(vq->vq_dev, vq->vq_queue_index);
}

int virtqueue_nused(struct virtqueue *vq)
{
    uint16_t used_idx, nused;

    used_idx = vq->vq_ring.used->idx;

    nused = (uint16_t)(used_idx - vq->vq_used_cons_idx);

    return (nused);
}


status virtqueue_enqueue(struct virtqueue *vq,
                         void *cookie,
                         /* not an ideal writev, but good enough for  today */
                         void **as,
                         bytes *lengths,
                         boolean *writables,
                         int segments)
{
    int needed;
    uint16_t idx = vq->vq_desc_head_idx;
    uint16_t hidx = idx;

    if (vq->vq_free_cnt < segments)
        return allocate_status("no room in queue");

    rprintf ("qneueue segs %d\n", segments);
    for (int i = 0; i < segments; i++) {
        struct vring_desc *dp =  vq->vq_ring.desc + idx;
        u16 flags =0;
        dp->addr = physical_from_virtual(as[i]);
        dp->len = lengths[i];
        idx = (idx +1)&(vq->vq_nentries - 1);
        if (i != (segments -1)) {
            flags |= VRING_DESC_F_NEXT;
            dp->next = idx; //since this never changes, freebsd built it in advance
        } 
        if (writables[i]) flags |= VRING_DESC_F_WRITE;
        dp->flags = flags;
    }

    vq->vq_desc_head_idx = idx;
    vq->vq_free_cnt -= needed;

    uint16_t avail_idx  = vq->vq_ring.avail->idx & (vq->vq_nentries - 1);
    vq->vq_ring.avail->ring[avail_idx] = hidx;
    write_barrier();
    vq->vq_ring.avail->idx++;    

    return STATUS_OK;
}

void *virtqueue_dequeue(struct virtqueue *vq, uint32_t *len)
{
    struct vring_used_elem *uep;
    void *cookie;
    uint16_t used_idx, desc_idx;

    if (vq->vq_used_cons_idx == vq->vq_ring.used->idx)
        return ((void *)0);

    used_idx = vq->vq_used_cons_idx++ & (vq->vq_nentries - 1);
    uep = &vq->vq_ring.used->ring[used_idx];

    read_barrier();
    desc_idx = (uint16_t) uep->id;
    if (len) *len = uep->len;

    vq_ring_free_chain(vq, desc_idx);

    return (cookie);
}
