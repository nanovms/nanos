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
#include "virtio_internal.h"

//#define VIRTQUEUE_DEBUG
//#define VIRTQUEUE_DEBUG_VERBOSE
#ifdef VIRTQUEUE_DEBUG
# define virtqueue_debug(x, ...) do {tprintf(sym(virtqueue), 0, ss(x), ##__VA_ARGS__);} while(0)
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
    struct list l;              /* vq->msg_queue when queued, or chained for bh process */
    union {
        u64 count;              /* descriptor count when queued */
        u64 len;                /* length on return */
    };
    buffer descv;               /* XXX should be a variable stride vector */
    vqfinish completion;
} *vqmsg;
    
typedef struct virtqueue {
    vtdev dev;
    sstring name;
    u16 entries;
    u16 queue_index;
    bytes notify_offset;
    void *ring_mem;
    volatile struct vring_desc *desc;
    volatile struct vring_avail *avail;
    volatile struct vring_used *used;    
    u16 *avail_event;
    u16 *used_event;
    boolean polling;
    boolean events_enabled;
    u64 free_cnt;               /* atomic */
    u16 desc_idx;               /* head of descriptor free list */
    u16 last_used_idx;          /* irq only */
    struct list msg_queue;
    struct list free_msgs;
    u32 msg_seqno;
    struct spinlock lock;
    vqmsg msgs[0];
} *virtqueue;

/* Most uses here are a chain of 3 or less descriptors. */
#define VQMSG_DEFAULT_SIZE     3
vqmsg allocate_vqmsg(virtqueue vq)
{
    vqmsg m;
    u64 irqflags = spin_lock_irq(&vq->lock);
    list l = list_get_next(&vq->free_msgs);
    if (!l) {
        spin_unlock_irq(&vq->lock, irqflags);
        heap h = vq->dev->general;
        m = allocate(h, sizeof(struct vqmsg));
        if (m == INVALID_ADDRESS)
            return INVALID_ADDRESS;
        m->descv = allocate_buffer(h, sizeof(struct vring_desc) * VQMSG_DEFAULT_SIZE);
        if (m->descv == INVALID_ADDRESS) {
            deallocate(h, m, sizeof(struct vqmsg));
            return INVALID_ADDRESS;
        }
    } else {
        m = struct_from_list(l, vqmsg, l);
        list_delete(l);
        spin_unlock_irq(&vq->lock, irqflags);
        buffer_clear(m->descv);
    }
    list_init(&m->l);
    m->count = 0;
    m->completion = 0;          /* fill on queue */
    return m;
}

void vqmsg_push(virtqueue vq, vqmsg m, u64 phys_addr, u32 len, boolean write)
{
    assert(buffer_extend(m->descv, sizeof(struct vring_desc)));
    struct vring_desc * d = buffer_ref(m->descv, m->count * sizeof(struct vring_desc));
    d->busaddr = phys_addr;
    d->len = len;
    d->flags = write ? VRING_DESC_F_WRITE : 0;
    d->next = 0;
    buffer_produce(m->descv, sizeof(struct vring_desc));
    m->count++;
    virtqueue_debug_verbose("%s: vq %s, vqmsg %p, phys_addr 0x%lx, len 0x%x, %s, m->count now %d\n",
                            func_ss, vq->name, m, phys_addr, len, write ? "write" : "read", m->count);
}

static void virtqueue_fill(virtqueue vq);

/* If seqno is non-null, the value it points to is set to a sequence number whose value is
 * initialized (when the virtqueue is created) to zero and incremented by one each time this
 * function is called with a nun-null seqno. This allows callers to determine e.g. the order in
 * which messages are received from a remote peer. */
void vqmsg_commit_seqno(virtqueue vq, vqmsg m, vqfinish completion, u32 *seqno, boolean kick)
{
    m->completion = completion;
    virtqueue_debug_verbose("%s: vq %s, vqmsg %p, completion %p (%F)\n",
                            func_ss, vq->name, m, completion, completion);
    u64 irqflags = spin_lock_irq(&vq->lock);
    if (seqno)
        *seqno = vq->msg_seqno++;
    list_push_back(&vq->msg_queue, &m->l);
    if (kick)
        virtqueue_fill(vq);
    spin_unlock_irq(&vq->lock, irqflags);
}

void virtqueue_kick(virtqueue vq)
{
    spinlock lock = &vq->lock;
    u64 irqflags = spin_lock_irq(lock);
    virtqueue_fill(vq);
    spin_unlock_irq(lock, irqflags);
}

static void vq_poll(virtqueue vq)
{
    // ensure we see up-to-date used->idx (updated by host)
    memory_barrier();
    
    while (vq->last_used_idx != vq->used->idx) {
        volatile struct vring_used_elem *uep = vq->used->ring + (vq->last_used_idx & (vq->entries - 1));
        virtqueue_debug_verbose("%s: vq %s: last_used_idx %d, id %d, len %d\n",
                                func_ss, vq->name, vq->last_used_idx, uep->id, uep->len);
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
        fetch_and_add(&vq->free_cnt, m->count);
        m->len = uep->len;
        vq->msgs[head] = 0;
        virtqueue_debug("add msg %p\n", m);

        async_apply_1(m->completion, (void*)m->len);

        /* TODO should probably observe a limit / drain method here */
        list_insert_after(&vq->free_msgs, &m->l);
    }
}

closure_function(1, 0, void, vq_interrupt,
                 virtqueue, vq)
{
    virtqueue vq = bound(vq);
    virtqueue_debug_verbose("%s: ENTRY: vq %s: entries %d, last_used_idx %d, used->idx %d, desc_idx %d\n",
                            func_ss, vq->name, vq->entries,
                            vq->last_used_idx, vq->used->idx, vq->desc_idx);

    spin_lock(&vq->lock);
  poll:
    vq_poll(vq);
    if (!vq->polling && (vq->dev->features & VIRTIO_F_RING_EVENT_IDX) &&
        (vq->last_used_idx != *vq->used_event)) {
        *vq->used_event = vq->last_used_idx;
        /* Poll again, to cover cases where a new buffer has been used after the previous poll but
         * before updating used_event. */
        goto poll;
    }
    virtqueue_fill(vq);
    virtqueue_debug("%s: EXIT: vq %s: last_used_idx %d, desc_idx %d\n",
                    func_ss, vq->name, vq->last_used_idx, vq->desc_idx);
    spin_unlock(&vq->lock);
}

status virtqueue_alloc(vtdev dev,
                       sstring name,
                       u16 queue_index,
                       u16 size,
                       bytes notify_offset,
                       int align,
                       virtqueue *vqp,
                       thunk *t)
{
    u64 vq_alloc_size = sizeof(struct virtqueue) + size * sizeof(vqmsg);
    virtqueue vq = allocate_zero(dev->general, vq_alloc_size);
    bytes avail_offset = size * sizeof(struct vring_desc);
    bytes used_offset = pad(avail_offset + sizeof(*vq->avail) + sizeof(vq->avail->ring[0]) * size +
                            sizeof(u16) /* used_event */, align);
    bytes alloc = used_offset + pad(sizeof(*vq->used) + sizeof(vq->used->ring[0]) * size +
                                    sizeof(u16) /* avail_event */, align);
    
    if (vq == INVALID_ADDRESS) 
        return timm("status", "cannot allocate virtqueue");
    
    vq->dev = dev;
    vq->name = name;
    virtqueue_debug("%s: vq %s: idx %d, size %d, alloc %d\n",
                    func_ss, vq->name, queue_index, size, alloc);
    vq->queue_index = queue_index;
    vq->notify_offset = notify_offset;
    vq->entries = size;
    vq->free_cnt = size;
    list_init(&vq->msg_queue);
    list_init(&vq->free_msgs);
    spin_lock_init(&vq->lock);

    if ((vq->ring_mem = allocate_zero(&dev->contiguous->h, alloc)) == INVALID_ADDRESS) {
        deallocate(dev->general, vq, vq_alloc_size);
        return(timm("status", "cannot allocate memory for virtqueue ring"));
    }

    vq->desc = (struct vring_desc *) vq->ring_mem;
    vq->avail = (struct vring_avail *) (vq->ring_mem + avail_offset);
    vq->used = (struct vring_used *) (vq->ring_mem + used_offset);
    virtqueue_debug("%s: vq %p: desc %p, avail %p, used %p\n",
                    func_ss, vq, vq->desc, vq->avail, vq->used);
    vq->avail_event = (void *)(vq->used + 1) + sizeof(vq->used->ring[0]) * size;
    vq->used_event = (void *)(vq->avail + 1) + sizeof(vq->avail->ring[0]) * size;
    vq->events_enabled = true;

    // initialize descriptor chains
    for (int i = 0; i < vq->entries - 1; i++)
        vq->desc[i].next = i + 1;
    vq->desc[vq->entries - 1].next = VQ_RING_DESC_CHAIN_END;

    *t = closure(dev->general, vq_interrupt, vq);
    *vqp = vq;
    return STATUS_OK;
}

physical virtqueue_desc_paddr(virtqueue vq)
{
    return physical_from_virtual(vq->ring_mem);
}

physical virtqueue_avail_paddr(virtqueue vq)
{
    return physical_from_virtual((void *)vq->avail);
}

physical virtqueue_used_paddr(virtqueue vq)
{
    return physical_from_virtual((void *)vq->used);
}

u16 virtqueue_entries(virtqueue vq)
{
    return vq->entries;
}

u16 virtqueue_free_entries(virtqueue vq)
{
    return vq->free_cnt;
}

static void vq_enable_events(virtqueue vq)
{
    if (vq->dev->features & VIRTIO_F_RING_EVENT_IDX)
        *vq->used_event = vq->last_used_idx;
    else
        vq->avail->flags &= ~VRING_AVAIL_F_NO_INTERRUPT;
    vq->events_enabled = true;
}

static void vq_disable_events(virtqueue vq)
{
    if (vq->dev->features & VIRTIO_F_RING_EVENT_IDX)
        /* set an arbitrary value, we will still receive an interrupt every 64K messages */
        *vq->used_event = (u16)-1;
    else
        vq->avail->flags |= VRING_AVAIL_F_NO_INTERRUPT;
    vq->events_enabled = false;
}

void virtqueue_set_polling(virtqueue vq, boolean enable)
{
    if (enable)
        vq_disable_events(vq);
    else
        vq_enable_events(vq);
    vq->polling = enable;
}

static int virtqueue_notify(virtqueue vq, u16 added)
{
    // ensure used->flags update is visible to us
    // and updated avail->idx is visible to host
    memory_barrier();
    int should_notify;
    if (vq->dev->features & VIRTIO_F_RING_EVENT_IDX)
        should_notify = ((vq->avail->idx - *vq->avail_event - 1) < added) || (added == vq->entries);
    else
        should_notify = ((vq->used->flags & VRING_USED_F_NO_NOTIFY) == 0);
    if (should_notify)
        apply(vq->dev->notify, vq->queue_index, vq->notify_offset);
    return should_notify;
}

/* called with lock held */
static void virtqueue_fill(virtqueue vq)
{
    virtqueue_debug("%s: ENTRY: vq %s: entries %d, desc_idx %d, avail->idx %d, avail->flags 0x%x\n",
                    func_ss, vq->name, vq->entries, vq->desc_idx, vq->avail->idx, vq->avail->flags);

    list n = list_get_next(&vq->msg_queue);
    u16 added = 0;
  begin:
    if (vq->polling)
        vq_poll(vq);
    while (n && n != &vq->msg_queue) {
        vqmsg m = struct_from_list(n, vqmsg, l);
        virtqueue_debug_verbose("   vqmsg %p, count %d\n", m, m->count);
        if (vq->free_cnt < m->count) {
            virtqueue_debug_verbose("      vq %s: queue full (vq->free_cnt %ld)\n",
                vq->name, vq->free_cnt);
            break;
        }
        assert(vq->free_cnt <= vq->entries);

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

            virtqueue_debug_verbose("      - desc_idx %d, vring_desc %p, busaddr 0x%lx, "
                                    "len 0x%x, flags 0x%x, next %d\n", vq->desc_idx, d, d->busaddr,
                                    d->len, d->flags, d->next);
        }

        u16 avail_idx = vq->avail->idx & (vq->entries - 1);
        vq->avail->ring[avail_idx] = head;
        virtqueue_debug_verbose("      avail->ring[%d] = %d\n", avail_idx, head);
        fetch_and_add(&vq->free_cnt, -m->count);
        added++;

        // ensure desc and avail ring updates above are visible before updating avail->idx
        write_barrier();
        vq->avail->idx++;

        list nn = list_get_next(n);
        list_delete(n);
        n = nn;
    }
    if (vq->polling) {
        /* If the queue is full and there are messages waiting to be sent, enable interrupts even if
         * we are in polling mode, because we want to be notified as soon as a new message can be
         * sent. */
        if (!vq->events_enabled && !list_empty(&vq->msg_queue)) {
            vq_enable_events(vq);
            goto begin;
        } else if (vq->events_enabled && list_empty(&vq->msg_queue)) {
            vq_disable_events(vq);
        }
    }

    int notified = 0;
    if (added > 0)
        notified = virtqueue_notify(vq, added);
    (void) notified;
    virtqueue_debug_verbose("   added %d, notified %d, desc_idx %d\n", added, notified, vq->desc_idx);
}
