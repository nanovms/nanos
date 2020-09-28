/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2007-2009 Kip Macy <kmacy@freebsd.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 *
 */
#ifndef _BUF_RING_H_
#define _BUF_RING_H_

struct buf_ring {
    volatile uint32_t   br_prod_head;
    volatile uint32_t   br_prod_tail;
    int                 br_prod_size;
    int                 br_prod_mask;
    uint64_t        br_drops;
    volatile uint32_t   br_cons_head __aligned(CACHE_LINE_SIZE);
    volatile uint32_t   br_cons_tail;
    int         br_cons_size;
    int                 br_cons_mask;
    void            *br_ring[0] __aligned(CACHE_LINE_SIZE);
    int                 br_size;
};

static __inline void *
buf_ring_peek_clear_sc(struct buf_ring *br)
{
#ifdef DEBUG_BUFRING
    void *ret;

    if (!mtx_owned(br->br_lock))
        panic("lock not held on single consumer dequeue");
#endif

    if (br->br_cons_head == br->br_prod_tail)
        return (0);

#if defined(__arm__) || defined(__aarch64__)
    /*
     * The barrier is required there on ARM and ARM64 to ensure, that
     * br->br_ring[br->br_cons_head] will not be fetched before the above
     * condition is checked.
     * Without the barrier, it is possible, that buffer will be fetched
     * before the enqueue will put mbuf into br, then, in the meantime, the
     * enqueue will update the array and the br_prod_tail, and the
     * conditional check will be true, so we will return previously fetched
     * (and invalid) buffer.
     */
    atomic_thread_fence_acq();
#endif

#ifdef DEBUG_BUFRING
    /*
     * Single consumer, i.e. cons_head will not move while we are
     * running, so atomic_swap_ptr() is not necessary here.
     */
    ret = br->br_ring[br->br_cons_head];
    br->br_ring[br->br_cons_head] = NULL;
    return (ret);
#else
    return (br->br_ring[br->br_cons_head]);
#endif
}

/*
 * Used to return a buffer (most likely already there)
 * to the top of the ring. The caller should *not*
 * have used any dequeue to pull it out of the ring
 * but instead should have used the peek() function.
 * This is normally used where the transmit queue
 * of a driver is full, and an mbuf must be returned.
 * Most likely whats in the ring-buffer is what
 * is being put back (since it was not removed), but
 * sometimes the lower transmit function may have
 * done a pullup or other function that will have
 * changed it. As an optimization we always put it
 * back (since jhb says the store is probably cheaper),
 * if we have to do a multi-queue version we will need
 * the compare and an atomic.
 */
static __inline void
buf_ring_putback_sc(struct buf_ring *br, void *new)
{
    assert(br->br_cons_head != br->br_prod_tail); // Buf-Ring has none in putback
    br->br_ring[br->br_cons_head] = new;
}

static __inline int
buf_ring_empty(struct buf_ring *br)
{

    return (br->br_cons_head == br->br_prod_tail);
}

/*
 * multi-producer safe lock-free ring buffer enqueue
 *
 */
static __inline int
buf_ring_enqueue(struct buf_ring *br, void *buf)
{
    uint32_t p_head, p_next, c_tail;
#ifdef DEBUG_BUFRING
    int i;

    /*
     * Note: It is possible to encounter an mbuf that was removed
     * via drbr_peek(), and then re-added via drbr_putback() and
     * trigger a spurious panic.
     */
    for (i = br->br_c_head; i != br->br_p_head;
         i = ((i + 1) & br->br_c_mask))
        if(br->br_ring[i] == buf)
            panic("buf=%p already enqueue at %d prod=%d cons=%d",
                buf, i, br->br_p_tail, br->br_c_tail);
#endif
    // disabel preemption
    u64 flags = irq_disable_save();
    do {
        p_head = br->br_prod_head;
        p_next = (p_head + 1) & br->br_prod_mask;
        c_tail = br->br_cons_tail;

        if (p_next == c_tail) {
            read_barrier();
            if (p_head == br->br_prod_head &&
                c_tail == br->br_cons_tail) {
                br->br_drops++;
                irq_restore(flags);
                return (ENOBUFS);
            }
            continue;
        }
    } while (!atomic_cmpset32(&br->br_prod_head, p_head, p_next));
#ifdef DEBUG_BUFRING
    if (br->br_ring[p_head] != NULL)
        panic("dangling value in enqueue");
#endif
    br->br_ring[p_head] = buf;

    /*
     * If there are other enqueues in progress
     * that preceded us, we need to wait for them
     * to complete
     */
    while (br->br_prod_tail != p_head)
        kern_pause();
    atomic_store_rel32(&br->br_prod_tail, p_next);
    irq_restore(flags);
    return (0);
}

/*
 * single-consumer dequeue
 * use where dequeue is protected by a lock
 * e.g. a network driver's tx queue lock
 */
static __inline void *
buf_ring_dequeue_sc(struct buf_ring *br)
{
    uint32_t c_head, cons_next;
#ifdef PREFETCH_DEFINED
    uint32_t cons_next_next;
#endif
    uint32_t p_tail;
    void *buf;

    /*
     * This is a workaround to allow using buf_ring on ARM and ARM64.
     * ARM64TODO: Fix buf_ring in a generic way.
     * REMARKS: It is suspected that br_cons_head does not require
     *   load_acq operation, but this change was extensively tested
     *   and confirmed it's working. To be reviewed once again in
     *   FreeBSD-12.
     *
     * Preventing following situation:

     * Core(0) - buf_ring_enqueue()                                       Core(1) - buf_ring_dequeue_sc()
     * -----------------------------------------                                       ----------------------------------------------
     *
     *                                                                                cons_head = br->br_cons_head;
     * atomic_cmpset_acq_32(&br->br_prod_head, ...));
     *                                                                                buf = br->br_ring[cons_head];     <see <1>>
     * br->br_ring[prod_head] = buf;
     * atomic_store_rel_32(&br->br_prod_tail, ...);
     *                                                                                prod_tail = br->br_prod_tail;
     *                                                                                if (cons_head == prod_tail)
     *                                                                                        return (NULL);
     *                                                                                <condition is false and code uses invalid(old) buf>`
     *
     * <1> Load (on core 1) from br->br_ring[cons_head] can be reordered (speculative readed) by CPU.
     */
#if defined(__arm__) || defined(__aarch64__)
    c_head = atomic_load_acq_32(&br->br_cons_head);
#else
    c_head = br->br_cons_head;
#endif
    p_tail = atomic_load_acq32(&br->br_prod_tail);

    cons_next = (c_head + 1) & br->br_cons_mask;
#ifdef PREFETCH_DEFINED
    cons_next_next = (c_head + 2) & br->br_cons_mask;
#endif

    if (c_head == p_tail)
        return (0);

#ifdef PREFETCH_DEFINED
    if (cons_next != prod_tail) {
        prefetch(br->br_ring[cons_next]);
        if (cons_next_next != prod_tail)
            prefetch(br->br_ring[cons_next_next]);
    }
#endif
    br->br_cons_head = cons_next;
    buf = br->br_ring[c_head];

#ifdef DEBUG_BUFRING
    br->br_ring[cons_head] = NULL;
    if (!mtx_owned(br->br_lock))
        panic("lock not held on single consumer dequeue");
    if (br->br_cons_tail != cons_head)
        panic("inconsistent list cons_tail=%d cons_head=%d",
            br->br_cons_tail, cons_head);
#endif
    br->br_cons_tail = cons_next;
    return (buf);
}

/*
 * single-consumer advance after a peek
 * use where it is protected by a lock
 * e.g. a network driver's tx queue lock
 */
static __inline void
buf_ring_advance_sc(struct buf_ring *br)
{
    uint32_t c_head, c_next;
    uint32_t p_tail;

    c_head = br->br_cons_head;
    p_tail = br->br_prod_tail;

    c_next = (c_head + 1) & br->br_cons_mask;
    if (c_head == p_tail)
        return;
    br->br_cons_head = c_next;
#ifdef DEBUG_BUFRING
    br->br_ring[cons_head] = NULL;
#endif
    br->br_cons_tail = c_next;
}

struct buf_ring *buf_ring_alloc(int count, heap h);
void buf_ring_free(struct buf_ring *br, heap h);

#endif /* _BUF_RING_H_ */
