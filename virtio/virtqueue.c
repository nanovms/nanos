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



static void
vq_ring_update_avail(struct virtqueue *vq, uint16_t desc_idx)
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


static int
vq_ring_use_indirect(struct virtqueue *vq, int needed)
{

    if ((vq->vq_flags & VIRTQUEUE_FLAG_INDIRECT) == 0)
        return (0);

    if (vq->vq_max_indirect_size < needed)
        return (0);

    if (needed < 2)
        return (0);

    return (1);
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

static int
vq_ring_must_notify_host(struct virtqueue *vq)
{
    uint16_t new_idx, prev_idx, event_idx;

    if (vq->vq_flags & VIRTQUEUE_FLAG_EVENT_IDX) {
        new_idx = vq->vq_ring.avail->idx;
        prev_idx = new_idx - vq->vq_queued_cnt;
        event_idx = vring_avail_event(&vq->vq_ring);

        return (vring_need_event(event_idx, new_idx, prev_idx) != 0);
    }

    return ((vq->vq_ring.used->flags & VRING_USED_F_NO_NOTIFY) == 0);
}

static void vq_ring_notify_host(struct virtqueue *vq)
{
    vtpci_notify_virtqueue(vq->vq_dev, vq->vq_queue_index);
}

static void vq_ring_free_chain(struct virtqueue *vq, uint16_t desc_idx)
{
    struct vring_desc *dp;
    struct vq_desc_extra *dxp;

    dp = &vq->vq_ring.desc[desc_idx];
    dxp = &vq->vq_descx[desc_idx];
    vq->vq_free_cnt += dxp->ndescs;
    dxp->ndescs--;

    if ((dp->flags & VRING_DESC_F_INDIRECT) == 0) {
        while (dp->flags & VRING_DESC_F_NEXT) {
            dp = &vq->vq_ring.desc[dp->next];
            dxp->ndescs--;
        }
    }
    /*
     * We must append the existing free chain, if any, to the end of
     * newly freed chain. If the virtqueue was completely used, then
     * head would be VQ_RING_DESC_CHAIN_END (ASSERTed above).
     */
    dp->next = vq->vq_desc_head_idx;
    vq->vq_desc_head_idx = desc_idx;
}

uint64_t virtqueue_filter_features(uint64_t features)
{
    uint64_t mask;

    mask = (1 << VIRTIO_TRANSPORT_F_START) - 1;
    mask |= VIRTIO_RING_F_INDIRECT_DESC;
    mask |= VIRTIO_RING_F_EVENT_IDX;

    return (features & mask);
}


static status virtqueue_init_indirect(struct virtqueue *vq, int indirect_size)
{
    struct vq_desc_extra *dxp;
    int i, size;

#if 0
    if (VIRTIO_BUS_WITH_FEATURE(dev, VIRTIO_RING_F_INDIRECT_DESC) == 0) {
        /*
         * Indirect descriptors requested by the driver but not
         * negotiated. Return zero to keep the initialization
         * going: we'll run fine without.
         */
        if (bootverbose)
            printf("virtqueue %d (%s) requested "
                   "indirect descriptors but not negotiated\n",
                   vq->vq_queue_index, vq->vq_name);
        return (0);
    }
#endif
    size = indirect_size * sizeof(struct vring_desc);
    vq->vq_max_indirect_size = indirect_size;
    vq->vq_indirect_mem_size = size;
    vq->vq_flags |= VIRTQUEUE_FLAG_INDIRECT;

    for (i = 0; i < vq->vq_nentries; i++) {
        dxp = &vq->vq_descx[i];

        dxp->indirect = allocate(contiguous, size);
        if (dxp->indirect == NULL) 
            return allocate_status("cannot allocate indirect list\n");

        dxp->indirect_paddr = vtophys(dxp->indirect);
        int i;
        
        memset(dxp->indirect, 0, vq->vq_indirect_mem_size);
        
        for (i = 0; i < vq->vq_max_indirect_size - 1; i++)
            dxp->indirect[i].next = i + 1;
        dxp->indirect[i].next = VQ_RING_DESC_CHAIN_END;
    }

    return (0);
}


status virtqueue_alloc(void *dev,
                       string name, 
                       uint16_t queue,
                       uint16_t size,
                       int align,
                       physical highaddr,
                       handler interrupt,
                       int maxindirsz,
                       struct virtqueue **vqp)
{
    status s;
    struct virtqueue *vq;
    int error;

    *vqp = NULL;
    error = 0;

    if (size == 0) {
        return allocate_status("virtqueue %d (%s) does not exist (size is zero)\n",
                               queue, name);
    } else if (log2(size) != size) {
        return allocate_status("virtqueue %d (%s) size is not a power of 2: %d\n",
                               queue, name, size);
    } 

    vq = allocate(general, sizeof(struct virtqueue) +  size * sizeof(struct vq_desc_extra));
        
    if (vq == NULL) 
        return allocate_status("cannot allocate virtqueue\n");

    vq->name = name;
    vq->vq_queue_index = queue;
    vq->vq_alignment = align;
    vq->vq_nentries = size;
    vq->vq_free_cnt = size;
    vq->interrupt = interrupt;

    //    if (VIRTIO_BUS_WITH_FEATURE(dev, VIRTIO_RING_F_EVENT_IDX) != 0)
    vq->vq_flags |= VIRTQUEUE_FLAG_EVENT_IDX;

    if (maxindirsz > 1)
        if (!is_ok(s = virtqueue_init_indirect(vq, maxindirsz))) goto fail;

    vq->vq_ring_size = pad(vring_size(size, align), PAGESIZE);
    vq->vq_ring_mem = allocate(contiguous, vq->vq_ring_size);
    if (vq->vq_ring_mem == NULL) {
        s = allocate_status("cannot allocate memory for virtqueue ring\n");
        goto fail;
    }


    struct vring *vr;
    char *ring_mem;
    int i, rsize;

    ring_mem = vq->vq_ring_mem;
    rsize = vq->vq_nentries;
    vr = &vq->vq_ring;

    vring_init(vr, rsize, ring_mem, vq->vq_alignment);

    for (i = 0; i < rsize - 1; i++)
        vr->desc[i].next = i + 1;
    vr->desc[i].next = VQ_RING_DESC_CHAIN_END;

    virtqueue_disable_intr(vq);

    *vqp = vq;

 fail:
    if (!is_ok(s)) virtqueue_free(vq);
    return (s);
}


void virtqueue_free(struct virtqueue *vq)
{

    if (vq->vq_free_cnt != vq->vq_nentries) {
        cprintf("%s: freeing non-empty virtqueue, "
                "leaking %d entries\n", vq->vq_name,
                vq->vq_nentries - vq->vq_free_cnt);
    }

    if (vq->vq_flags & VIRTQUEUE_FLAG_INDIRECT) {
            struct vq_desc_extra *dxp;
            int i;
            
            for (i = 0; i < vq->vq_nentries; i++) {
                dxp = &vq->vq_descx[i];
                
                if (dxp->indirect == NULL)
                    break;
                
                deallocate(contiguous, dxp->indirect, 0);
            }
            
    }

    if (vq->vq_ring_mem != NULL) 
        deallocate(contiguous, vq->vq_ring_mem, vq->vq_ring_size);

    deallocate(general, vq, sizeof(struct virtqueue));
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

    if (vq_ring_must_notify_host(vq))
        vq_ring_notify_host(vq);
    vq->vq_queued_cnt = 0;
}

int
virtqueue_nused(struct virtqueue *vq)
{
    uint16_t used_idx, nused;

    used_idx = vq->vq_ring.used->idx;

    nused = (uint16_t)(used_idx - vq->vq_used_cons_idx);

    return (nused);
}

int
virtqueue_intr_filter(struct virtqueue *vq)
{

    if (vq->vq_used_cons_idx == vq->vq_ring.used->idx)
        return (0);

    virtqueue_disable_intr(vq);

    return (1);
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

/*
 * Note this is only considered a hint to the host.
 */
void virtqueue_disable_intr(struct virtqueue *vq)
{
    if (vq->vq_flags & VIRTQUEUE_FLAG_EVENT_IDX) {
        vring_used_event(&vq->vq_ring) = vq->vq_used_cons_idx -
            vq->vq_nentries - 1;
    } else
        vq->vq_ring.avail->flags |= VRING_AVAIL_F_NO_INTERRUPT;
}

static uint16_t vq_ring_enqueue_buffer(struct virtqueue *vq,
                                       struct vring_desc *desc,
                                       uint16_t head_idx,
                                       struct pbuf *b,
                                       int readable,
                                       int writable)
{
    struct vring_desc *dp;
    int i, needed;
    uint16_t idx;

    needed = readable + writable;

    for (;i < needed; b = b->next) {
        dp = &desc[idx];
        //        dp->addr = vtophys(b->contents);
        //        dp->len = buffer_length(b);
        dp->flags = 0;
        
        if (i < needed - 1)
            dp->flags |= VRING_DESC_F_NEXT;
        if (i >= readable)
            dp->flags |= VRING_DESC_F_WRITE;
    }

    return (idx);
}

static void vq_ring_enqueue_indirect(struct virtqueue *vq,
                                     void *cookie,
                                     struct pbuf *b,
                                     int readable,
                                     int writable)
{
    struct vring_desc *dp;
    struct vq_desc_extra *dxp;
    int needed;
    uint16_t head_idx;

    needed = readable + writable;

    head_idx = vq->vq_desc_head_idx;
    dp = &vq->vq_ring.desc[head_idx];
    dxp = &vq->vq_descx[head_idx];
    dxp->cookie = cookie;
    dxp->ndescs = 1;
    dp->addr = dxp->indirect_paddr;
    dp->len = needed * sizeof(struct vring_desc);
    dp->flags = VRING_DESC_F_INDIRECT;
    vq_ring_enqueue_buffer(vq, dxp->indirect, 0, b, readable, writable);
    vq->vq_desc_head_idx = dp->next;
    vq->vq_free_cnt--;
    vq_ring_update_avail(vq, head_idx);
}


status virtqueue_enqueue(struct virtqueue *vq, void *cookie, struct pbuf *b,int readable, int writable)
{
    struct vq_desc_extra *dxp;
    int needed;
    uint16_t head_idx, idx;

    needed = readable + writable;

    if (needed < 1)
        return allocate_status("inavlid queue");
    if (vq->vq_free_cnt == 0)
        return allocate_status("attempt to enqueue in full queue");

    if (vq_ring_use_indirect(vq, needed)) {
        vq_ring_enqueue_indirect(vq, cookie, b, readable, writable);
        return (0);
    } else if (vq->vq_free_cnt < needed)
        return allocate_status("message too big");

    head_idx = vq->vq_desc_head_idx;
    dxp = &vq->vq_descx[head_idx];

    dxp->cookie = cookie;
    dxp->ndescs = needed;

    idx = vq_ring_enqueue_buffer(vq, vq->vq_ring.desc, head_idx,
                                 b, readable, writable);

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
        return (NULL);

    used_idx = vq->vq_used_cons_idx++ & (vq->vq_nentries - 1);
    uep = &vq->vq_ring.used->ring[used_idx];

    read_barrier();
    desc_idx = (uint16_t) uep->id;
    if (len != NULL)
        *len = uep->len;

    vq_ring_free_chain(vq, desc_idx);

    cookie = vq->vq_descx[desc_idx].cookie;
    vq->vq_descx[desc_idx].cookie = NULL;

    return (cookie);
}

void *virtqueue_drain(struct virtqueue *vq, int *last)
{
    void *cookie;
    int idx;

    cookie = NULL;
    idx = *last;

    while (idx < vq->vq_nentries && cookie == NULL) {
        if ((cookie = vq->vq_descx[idx].cookie) != NULL) {
            vq->vq_descx[idx].cookie = NULL;
            /* Free chain to keep free count consistent. */
            vq_ring_free_chain(vq, idx);
        }
        idx++;
    }

    *last = idx;

    return (cookie);
}

void virtqueue_dump(struct virtqueue *vq)
{

    cprintf("VQ: %s - size=%d; free=%d; used=%d; queued=%d; "
            "desc_head_idx=%d; avail.idx=%d; used_cons_idx=%d; "
            "used.idx=%d; used_event_idx=%d; avail.flags=0x%x; used.flags=0x%x\n",
            vq->vq_name, vq->vq_nentries, vq->vq_free_cnt,
            virtqueue_nused(vq), vq->vq_queued_cnt, vq->vq_desc_head_idx,
            vq->vq_ring.avail->idx, vq->vq_used_cons_idx,
            vq->vq_ring.used->idx,
            vring_used_event(&vq->vq_ring),
            vq->vq_ring.avail->flags,
            vq->vq_ring.used->flags);
}
