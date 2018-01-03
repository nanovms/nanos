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



static void vq_ring_update_avail(struct virtqueue *vq, uint16_t desc_idx)
{
    uint16_t avail_idx;

    /*
     * Place the head of the descriptor chain into the next slot and make
     * it usable to the host. The chain is made available now rather than
     * deferring to virtqueue_notify() in the hopes that if the host is
     * currently running on another CPU, we can keep it processing the new
     * descriptor.
     */
    avail_idx = vq->vq_ring.avail->idx & (vq->vq_nentries - 1);
    vq->vq_ring.avail->ring[avail_idx] = desc_idx;

    write_barrier();
    vq->vq_ring.avail->idx++;

    /* Keep pending count until virtqueue_notify(). */
    vq->vq_queued_cnt++;
}


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
    struct vq_desc_extra *dxp;

    dp = &vq->vq_ring.desc[desc_idx];
    dxp = &vq->vq_descx[desc_idx];
    vq->vq_free_cnt += dxp->ndescs;
    dxp->ndescs--;
    /*
     * We must append the existing free chain, if any, to the end of
     * newly freed chain. If the virtqueue was completely used, then
     * head would be VQ_RING_DESC_CHAIN_END (ASSERTed above).
     */
    dp->next = vq->vq_desc_head_idx;
    vq->vq_desc_head_idx = desc_idx;
}

status virtqueue_alloc(void *dev,
                       string name, 
                       uint16_t queue,
                       uint16_t size,
                       int align,
                       handler interrupt,
                       struct virtqueue **vqp)
{
    status s = STATUS_OK;
    struct virtqueue *vq;

    if (log2(size) != size) {
        return allocate_status("virtqueue %d (%s) size is not a power of 2: %d\n",
                               queue, name, size);
    } 
    vq = allocate(general, sizeof(struct virtqueue) +  size * sizeof(struct vq_desc_extra));

    if (!vq) 
        return allocate_status("cannot allocate virtqueue\n");
    vq->vq_dev = dev;
    vq->name = name;
    vq->vq_queue_index = queue;
    vq->vq_nentries = size;
    vq->vq_free_cnt = size;
    vq->interrupt = interrupt;

    //    if (VIRTIO_BUS_WITH_FEATURE(dev, VIRTIO_RING_F_EVENT_IDX) != 0)
    vq->vq_flags |= VIRTQUEUE_FLAG_EVENT_IDX;

    vq->vq_ring_size = pad(vring_size(size, align), PAGESIZE);
    vq->vq_ring_mem = allocate_zero(contiguous, vq->vq_ring_size);

    if (!vq->vq_ring_mem) {
        s = allocate_status("cannot allocate memory for virtqueue ring\n");
        goto fail;
    }

    vq->vq_ring.num = vq->vq_nentries;
    vq->vq_ring.desc = (struct vring_desc *) vq->vq_ring_mem;
    vq->vq_ring.avail = (struct vring_avail *) (vq->vq_ring_mem +
                                                vq->vq_nentries * sizeof(struct vring_desc));
    vq->vq_ring.used = (void *)
        (((unsigned long) &vq->vq_ring.avail->ring[vq->vq_nentries] + align-1) & ~(align-1));

    *vqp = vq;

 fail:
    return (s);
}

physical virtqueue_paddr(struct virtqueue *vq)
{
    return (vtophys(vq->vq_ring_mem));
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
    vq->vq_queued_cnt = 0;
}

int virtqueue_nused(struct virtqueue *vq)
{
    uint16_t used_idx, nused;

    used_idx = vq->vq_ring.used->idx;

    nused = (uint16_t)(used_idx - vq->vq_used_cons_idx);

    return (nused);
}


void virtqueue_intr(struct virtqueue *vq)
{
    apply(vq->interrupt);
}

int virtqueue_enable_intr(struct virtqueue *vq)
{
    return (vq_ring_enable_interrupt(vq, 0));
}

int virtqueue_postpone_intr(struct virtqueue *vq, vq_postpone_t hint)
{
    uint16_t ndesc, avail_idx;

    avail_idx = vq->vq_ring.avail->idx;
    ndesc = (uint16_t)(avail_idx - vq->vq_used_cons_idx);

    switch (hint) {
    case VQ_POSTPONE_SHORT:
        ndesc = ndesc / 4;
        break;
    case VQ_POSTPONE_LONG:
        ndesc = (ndesc * 3) / 4;
        break;
    case VQ_POSTPONE_EMPTIED:
        break;
    }

    return (vq_ring_enable_interrupt(vq, ndesc));
}


status virtqueue_enqueue(struct virtqueue *vq,
                         void *cookie,
                         /* not an ideal writev, but good enough for  today */
                         void **as,
                         bytes *lengths,
                         boolean *writables,
                         int segments)
{
    struct vq_desc_extra *dxp;
    int needed;
    uint16_t head_idx, idx;
    head_idx = idx = vq->vq_desc_head_idx;

    if (vq->vq_free_cnt < segments)
        return allocate_status("no room in queue");

    dxp = &vq->vq_descx[idx];
    dxp->cookie = cookie;
    dxp->ndescs = segments;
    for (int i = 0; i < segments; i++) {
        struct vring_desc *dp =  vq->vq_ring.desc + idx;
        u16 flags =0;
        dp->addr = vtophys(as[i]);
        dp->len = lengths[i];
        idx = (idx +1);
        if (i != (segments -1)) {
            flags |= VRING_DESC_F_NEXT;
            // free preloaded this
            dp->next = idx;
        } 
        if (writables[i]) flags |= VRING_DESC_F_WRITE;
        dp->flags = flags;
    }

    vq->vq_desc_head_idx = idx;
    vq->vq_free_cnt -= needed;
        
    vq_ring_update_avail(vq, head_idx);

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

    cookie = vq->vq_descx[desc_idx].cookie;
    vq->vq_descx[desc_idx].cookie = 0;

    return (cookie);
}
