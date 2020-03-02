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

#include <kernel.h>
#include <page.h>

#include "virtio_internal.h"

//#define VIRTQUEUE_DEBUG
//#define VIRTQUEUE_DEBUG_VERBOSE
#ifdef VIRTQUEUE_DEBUG
# define virtqueue_debug rprintf
#else
# define virtqueue_debug(...) do { } while(0)
#endif // defined(VIRTQUEUE_DEBUG)

#ifdef VIRTQUEUE_DEBUG_VERBOSE
# define virtqueue_debug_verbose rprintf
#else
# define virtqueue_debug_verbose(...) do { } while(0)
#endif // defined(VIRTQUEUE_DEBUG_VERBOSE)

#define VQ_RING_DESC_CHAIN_END  32768
#define VRING_DESC_F_NEXT       1
#define VRING_DESC_F_WRITE      2
#define VRING_DESC_F_INDIRECT   4

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
    struct list l;              /* vq->msgqueue when queued, or chained for bh process */
    union {
        u64 count;              /* descriptor count when queued */
        u64 len;                /* length on return */
    };
    buffer descv;               /* XXX should be a variable stride vector */
    vqfinish completion;
} *vqmsg;
    
typedef struct virtqueue {
    vtpci dev;
    const char *name;
    u16 entries;
    u16 queue_index;
    void *ring_mem;
    volatile struct vring_desc *desc;
    volatile struct vring_avail *avail;
    volatile struct vring_used *used;    
    u64 free_cnt;               /* atomic */
    u16 desc_idx;               /* head of descriptor free list */
    u16 last_used_idx;          /* irq only */
    int max_queued;
    struct list msgqueue;
    queue servicequeue;
    thunk service;
    struct spinlock fill_lock;  /* XXX - tmp hack for smp */
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

void deallocate_vqmsg(virtqueue vq, vqmsg m)
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

void vqmsg_commit(virtqueue vq, vqmsg m, vqfinish completion)
{
    m->completion = completion;
    /* XXX noirq */
    list_push_back(&vq->msgqueue, &m->l);
    virtqueue_fill(vq);
}

closure_function(1, 0, void, vq_interrupt,
                 virtqueue, vq)
{
    // ensure we see up-to-date used->idx (updated by host)
    memory_barrier();
    virtqueue vq = bound(vq);
    virtqueue_debug_verbose("%s: ENTRY: vq %p: entries %d, last_used_idx %d, used->idx %d, desc_idx %d\n",
        __func__, vq, vq->entries, vq->last_used_idx, vq->used->idx, vq->desc_idx);
    
    int processed = 0;
    struct list q;
    list_init(&q);
    spin_lock(&vq->fill_lock);
    while (vq->last_used_idx != vq->used->idx) {
        volatile struct vring_used_elem *uep = vq->used->ring + (vq->last_used_idx & (vq->entries - 1));
        virtqueue_debug_verbose("%s: vq %p: last_used_idx %d, id %d, len %d\n",
            __func__, vq, vq->last_used_idx, uep->id, uep->len);
        u16 head = uep->id;
        vqmsg m = vq->msgs[head];

        /* return descriptor(s) to free list */
        int dcount = 1;
        volatile struct vring_desc *d = vq->desc + head;
        while ((d->flags & VRING_DESC_F_NEXT)) {
            d = vq->desc + d->next;
            dcount++;
        }
        assert(dcount == m->count);
        d->next = vq->desc_idx;
        vq->desc_idx = head;

        vq->last_used_idx++;
        processed++;
        fetch_and_add(&vq->free_cnt, m->count);
        m->len = uep->len;
        vq->msgs[head] = 0;
        virtqueue_debug("add msg %p\n", m);
        list_insert_before(&q, &m->l);
    }
    spin_unlock(&vq->fill_lock);

    if (processed > 0) {
        /* a little trick ... collapse the list head for queueing */
        list l = list_get_next(&q);
        assert(l);
        list_delete(&q);
        assert(enqueue(vq->servicequeue, l));
        enqueue(bhqueue, vq->service);
    }

    virtqueue_fill(vq);
    virtqueue_debug("%s: EXIT: vq %p: processed %d, last_used_idx %d, desc_idx %d\n",
        __func__, vq, processed, vq->last_used_idx, vq->desc_idx);
}

closure_function(1, 0, void, virtqueue_service_vqmsgs,
                 virtqueue, vq)
{
    virtqueue vq = bound(vq);
    virtqueue_debug("%s enter, vq %s\n", __func__, vq->name);
    list l;
    while ((l = (list)dequeue(vq->servicequeue)) != INVALID_ADDRESS) {
        struct list q;
        list_insert_before(l, &q);
        list_foreach(&q, p) {
            vqmsg m = struct_from_list(p, vqmsg, l);
            virtqueue_debug("  msg %p, competion %F, len %ld\n", m, m->completion, m->len);
            apply(m->completion, m->len);
            list_delete(p);
            deallocate_vqmsg(vq, m);
        }
    }
    virtqueue_debug("%s exit\n", __func__);
}

status virtqueue_alloc(vtpci dev,
                       const char *name,
                       u16 queue,
                       u16 size,
                       int align,
                       virtqueue *vqp,
                       thunk *t)
{
    virtqueue vq;
    u64 d = size * sizeof(struct vring_desc);
    u64 avail_end = pad(d + sizeof(*vq->avail) + sizeof(vq->avail->ring[0]) * size, align);
    bytes alloc = avail_end + pad(sizeof(*vq->used) + sizeof(vq->used->ring[0]) * size, align);
    u64 vq_alloc_size = sizeof(struct virtqueue) + size * sizeof(vqmsg);
    vq = allocate(dev->general, vq_alloc_size);
    
    if (vq == INVALID_ADDRESS) 
        return timm("status", "cannot allocate virtqueue");
    
    virtqueue_debug("%s: vq %s: idx %d, size %d, alloc %d\n",
                    __func__, vq->name, queue, size, alloc);
    vq->dev = dev;
    vq->name = name;
    vq->queue_index = queue;
    vq->entries = size;
    vq->free_cnt = size;
    vq->max_queued = 0;
    list_init(&vq->msgqueue);
    vq->servicequeue = allocate_queue(dev->general, 512);
    assert(vq->servicequeue != INVALID_ADDRESS);
    vq->service = closure(dev->general, virtqueue_service_vqmsgs, vq);
    spin_lock_init(&vq->fill_lock);

    if ((vq->ring_mem = allocate_zero(dev->contiguous, alloc)) == INVALID_ADDRESS) {
        deallocate(dev->general, vq, vq_alloc_size);
        return(timm("status", "cannot allocate memory for virtqueue ring"));
    }

    vq->desc = (struct vring_desc *) vq->ring_mem;
    vq->avail = (struct vring_avail *) (vq->desc + size);
    vq->used = (struct vring_used *) (vq->ring_mem  + avail_end);
    virtqueue_debug("%s: vq %s: desc %p, avail %p, used %p\n",
                    __func__, vq->name, vq->desc, vq->avail, vq->used);

    // initialize descriptor chains
    for (int i = 0; i < vq->entries - 1; i++)
        vq->desc[i].next = i + 1;
    vq->desc[vq->entries - 1].next = VQ_RING_DESC_CHAIN_END;

    *t = closure(dev->general, vq_interrupt, vq);
    *vqp = vq;
    return STATUS_OK;
}

void virtqueue_set_max_queued(virtqueue vq, int max_queued)
{
    vq->max_queued = max_queued;
    virtqueue_debug("%s: vq %s: max_queued = %d\n", __func__, vq->name, vq->max_queued);
}

physical virtqueue_paddr(virtqueue vq)
{
    return (physical_from_virtual(vq->ring_mem));
}

u16 virtqueue_entries(virtqueue vq)
{
    return vq->entries;
}

static int virtqueue_notify(virtqueue vq)
{
    // ensure used->flags update is visible to us
    // and updated avail->idx is visible to host
    memory_barrier();
    int should_notify = (vq->used->flags & VRING_USED_F_NO_NOTIFY) == 0;
    if (should_notify)
        vtpci_notify_virtqueue(vq->dev, vq->queue_index);
    return should_notify;
}

/* called from interrupt level or with ints disabled */
static void virtqueue_fill(virtqueue vq)
{
    virtqueue_debug_verbose("%s: ENTRY: vq %s: entries %d, desc_idx %d, avail->idx %d\n",
        __func__, vq->name, vq->entries, vq->desc_idx, vq->avail->idx);

    /* irqs already disabled */
    spin_lock(&vq->fill_lock);
    list n = list_get_next(&vq->msgqueue);
    u16 added = 0;
    while (n && n != &vq->msgqueue) {
        vqmsg m = struct_from_list(n, vqmsg, l);
        if (vq->free_cnt < m->count) {
            virtqueue_debug_verbose("%s: vq %s: queue full (vq->free_cnt %ld)\n",
                __func__, vq->name, vq->free_cnt);
            break;
        }
        assert(vq->free_cnt <= vq->entries);
        if (vq->max_queued > 0 && vq->entries - vq->free_cnt >= vq->max_queued) {
            virtqueue_debug_verbose("%s: vq %s: max queued reached (vq->max_queued %d, vq->free_cnt %ld)\n",
                __func__, vq->name, vq->max_queued, vq->free_cnt);
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

            virtqueue_debug_verbose("%s: vq %s: msg %p (count %d): desc->flags 0x%x, desc->next %d\n",
                __func__, vq->name, m, m->count, d->flags, d->next);
        }

        u16 avail_idx = vq->avail->idx & (vq->entries - 1);
        vq->avail->ring[avail_idx] = head;
        virtqueue_debug_verbose("%s: vq %s: msg %p (count %d): avail->ring[%d] = %d\n",
            __func__, vq->name, m, m->count, avail_idx, head);
        fetch_and_add(&vq->free_cnt, -m->count);
        added++;

        // ensure desc and avail ring updates above are visible before updating avail->idx
        write_barrier();
        vq->avail->idx++;

        list nn = list_get_next(n);
        list_delete(n);
        n = nn;
    }

    int notified = 0;
    if (added > 0)
        notified = virtqueue_notify(vq);
    (void) notified;
    spin_unlock(&vq->fill_lock);
    virtqueue_debug("%s: EXIT: vq %s: added %d, notified %d, desc_idx %d\n",
        __func__, vq->name, added, notified, vq->desc_idx);
}
