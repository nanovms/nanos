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

#ifdef VIRTQUEUE_DEBUG
# define virtqueue_debug rprintf
#else
# define virtqueue_debug(...) do { } while(0)
#endif // defined(VIRTQUEUE_DEBUG)

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
    u16 last_used_idx;          /* irq only */
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
    // ensure we see up-to-date used->idx (updated by host)
    memory_barrier();
    virtqueue_debug("%s: ENTRY: vq %p (entries %d, last_used_idx %d, used->idx %d)\n",
        __func__, vq, (u64) vq->entries, (u64) vq->last_used_idx, (u64) vq->used->idx);
    
    while (vq->last_used_idx != vq->used->idx) {
        volatile struct vring_used_elem *uep = vq->used->ring + (vq->last_used_idx & (vq->entries - 1));
        virtqueue_debug("%s: last_used_idx %d, id %d, len %d\n",
            __func__, (u64) vq->last_used_idx, (u64) uep->id, (u64) uep->len);
        vqmsg m = vq->msgs[uep->id];
        apply(m->completion, uep->len);

        vq->last_used_idx++;
        fetch_and_add(&vq->free_cnt, m->count);
        vq->msgs[uep->id] = 0;
        deallocate_vqmsg_irq(vq, m);
    }

    virtqueue_fill_irq(vq);
    virtqueue_debug("%s: EXIT: vq %p (last_used_idx %d)\n", __func__, vq, (u64) vq->last_used_idx);
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
    u64 alloc = avail_end + pad(sizeof(*vq->used) + sizeof(vq->used->ring[0]) * size, align);
    vq = allocate(dev->general, sizeof(struct virtqueue) + size * sizeof(vqmsg));
    
    if (vq == INVALID_ADDRESS) 
        return timm("status", "cannot allocate virtqueue");
    
    virtqueue_debug("%s: virtqueue %p: idx %d, size %d, alloc %d\n",
        __func__, vq, (u64) queue, (u64) size, alloc);
    vq->dev = dev;
    vq->queue_index = queue;
    vq->entries = size;
    vq->free_cnt = size;

    if ((vq->ring_mem = allocate_zero(dev->contiguous, alloc)) != INVALID_ADDRESS) {
        vq->desc = (struct vring_desc *) vq->ring_mem;
        for (int i = 0; i < vq->entries - 1; i++)
            vq->desc[i].next = i + 1;
        vq->avail = (struct vring_avail *) (vq->desc + size);
        vq->used = (struct vring_used *) (vq->ring_mem  + avail_end);
        virtqueue_debug("%s: desc %p, avail %p, used %p\n", __func__, vq->desc, vq->avail, vq->used);
        *t = closure(dev->general, vq_interrupt, vq);
        *vqp = vq;
        list_init(&vq->msgqueue);
        return 0;
    }

    return(timm("status", "cannot allocate memory for virtqueue ring"));
}

physical virtqueue_paddr(virtqueue vq)
{
    return (physical_from_virtual(vq->ring_mem));
}

static void virtqueue_notify(virtqueue vq)
{
    /* Ensure updated avail->idx is visible to host. */
    memory_barrier();
    vtpci_notify_virtqueue(vq->dev, vq->queue_index);
}

/* called from interrupt level or with ints disabled */
static void virtqueue_fill_irq(virtqueue vq)
{
    virtqueue_debug("%s: ENTRY (entries %d, desc_idx %d, avail->idx %d)\n",
        __func__, (u64) vq->entries, (u64) vq->desc_idx, (u64) vq->avail->idx);
    list n = list_get_next(&vq->msgqueue);

    u16 added = 0;
    while (n && n != &vq->msgqueue) {
        vqmsg m = struct_from_list(n, vqmsg, l);
        if (vq->free_cnt < m->count) {
            virtqueue_debug("%s: virtqueue %p: queue full (vq->free_cnt %d)\n",
                __func__, vq, vq->free_cnt);
            break;
        }

        assert(m->completion);
        u16 head = vq->desc_idx;
        vq->msgs[head] = m;

        for (int i = 0; i < m->count; i++) {
            struct vring_desc *src = buffer_ref(m->descv, i * sizeof(*src));
            volatile struct vring_desc *d = vq->desc + vq->desc_idx;
            d->busaddr = src->busaddr;
            d->len = src->len;
            d->flags = src->flags;
            if (i < m->count - 1)
                d->flags |= VRING_DESC_F_NEXT;
            vq->desc_idx = d->next;

#if 0
            virtqueue_debug("%s: virtqueue %p: msg %p (count %d): desc->flags 0x%P, desc->next %d\n",
                __func__, vq, m, (u64) m->count, (u64) d->flags, (u64) d->next);
#endif
        }

        u16 avail_idx = (vq->avail->idx + added++) & (vq->entries - 1);
        vq->avail->ring[avail_idx] = head;
        virtqueue_debug("%s: virtqueue %p: msg %p (count %d): avail->ring[%d] = %d\n",
            __func__, vq, m, (u64) m->count, (u64) avail_idx, (u64) head);
        fetch_and_add(&vq->free_cnt, -m->count);

        list nn = list_get_next(n);
        list_delete(n);
        n = nn;
    }

    if (added > 0) {
        // ensure desc and avail ring updates above are visible before updating avail->idx
        write_barrier();
        vq->avail->idx += added;

        // ensure used->flags update is visible (updated by host)
        memory_barrier();
        if (vq->used->flags != VRING_USED_F_NO_NOTIFY) {
            virtqueue_debug("%s: notifying virtqueue %p (added %d, avail->idx %d)\n",
                __func__, vq, (u64) added, (u64) vq->avail->idx);
            virtqueue_notify(vq);
        }
    }
    virtqueue_debug("%s: EXIT (desc_idx %d)\n", __func__, (u64) vq->desc_idx);
}

static void virtqueue_fill(virtqueue vq)
{
    /* XXX same as irq for now, save/disable/restore later */
    virtqueue_fill_irq(vq);
}
