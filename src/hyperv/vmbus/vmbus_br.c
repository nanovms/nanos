/*-
 * Copyright (c) 2009-2012,2016 Microsoft Corp.
 * Copyright (c) 2012 NetApp Inc.
 * Copyright (c) 2012 Citrix Inc.
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
#include <hyperv_internal.h>
#include "vmbus_reg.h"
#include "vmbus_brvar.h"

/* Amount of space available for write */
#define	VMBUS_BR_WAVAIL(r, w, z)	\
	(((w) >= (r)) ? ((z) - ((w) - (r))) : ((r) - (w)))

/* Increase bufing index */
#define VMBUS_BR_IDXINC(idx, inc, sz)	(((idx) + (inc)) % (sz))

void
vmbus_rxbr_intr_mask(struct vmbus_rxbr *rbr)
{
	rbr->rxbr_imask = 1;
	memory_barrier();
}

static __inline uint32_t
vmbus_rxbr_avail(const struct vmbus_rxbr *rbr)
{
	uint32_t rindex, windex;

	/* Get snapshot */
	rindex = rbr->rxbr_rindex;
	windex = rbr->rxbr_windex;

	return (rbr->rxbr_dsize -
	    VMBUS_BR_WAVAIL(rindex, windex, rbr->rxbr_dsize));
}

uint32_t
vmbus_rxbr_intr_unmask(struct vmbus_rxbr *rbr)
{
	rbr->rxbr_imask = 0;
	memory_barrier();

	/*
	 * Now check to see if the ring buffer is still empty.
	 * If it is not, we raced and we need to process new
	 * incoming channel packets.
	 */
	return vmbus_rxbr_avail(rbr);
}

static void
vmbus_br_setup(struct vmbus_br *br, void *buf, int blen)
{
	br->vbr = buf;
	br->vbr_dsize = blen - sizeof(struct vmbus_bufring);
}

void
vmbus_rxbr_init(struct vmbus_rxbr *rbr)
{
	spin_lock_init(&rbr->rxbr_lock);
}

void
vmbus_rxbr_deinit(struct vmbus_rxbr *rbr)
{
}

void
vmbus_rxbr_setup(struct vmbus_rxbr *rbr, void *buf, int blen)
{
	vmbus_br_setup(&rbr->rxbr, buf, blen);
}

void
vmbus_txbr_init(struct vmbus_txbr *tbr)
{
	spin_lock_init(&tbr->txbr_lock);
}

void
vmbus_txbr_deinit(struct vmbus_txbr *tbr)
{
}

void
vmbus_txbr_setup(struct vmbus_txbr *tbr, void *buf, int blen)
{
	vmbus_br_setup(&tbr->txbr, buf, blen);
}

/*
 * When we write to the ring buffer, check if the host needs to be
 * signaled.
 *
 * The contract:
 * - The host guarantees that while it is draining the TX bufring,
 *   it will set the br_imask to indicate it does not need to be
 *   interrupted when new data are added.
 * - The host guarantees that it will completely drain the TX bufring
 *   before exiting the read loop.  Further, once the TX bufring is
 *   empty, it will clear the br_imask and re-check to see if new
 *   data have arrived.
 */
static __inline boolean
vmbus_txbr_need_signal(const struct vmbus_txbr *tbr, uint32_t old_windex)
{
	memory_barrier();
	if (tbr->txbr_imask)
		return false;

	compiler_barrier();

	/*
	 * This is the only case we need to signal when the
	 * ring transitions from being empty to non-empty.
	 */
	if (old_windex == tbr->txbr_rindex)
		return true;

	return false;
}

static __inline uint32_t
vmbus_txbr_avail(const struct vmbus_txbr *tbr)
{
	uint32_t rindex, windex;

	/* Get snapshot */
	rindex = tbr->txbr_rindex;
	windex = tbr->txbr_windex;

	return VMBUS_BR_WAVAIL(rindex, windex, tbr->txbr_dsize);
}

static __inline uint32_t
vmbus_txbr_copyto(const struct vmbus_txbr *tbr, uint32_t windex,
    const void *src0, uint32_t cplen)
{
	const uint8_t *src = src0;
	uint8_t *br_data = tbr->txbr_data;
	uint32_t br_dsize = tbr->txbr_dsize;

	if (cplen > br_dsize - windex) {
		uint32_t fraglen = br_dsize - windex;

		/* Wrap-around detected */
		runtime_memcpy(br_data + windex, src, fraglen);
		runtime_memcpy(br_data, src + fraglen, cplen - fraglen);
	} else {
		runtime_memcpy(br_data + windex, src, cplen);
	}
	return VMBUS_BR_IDXINC(windex, cplen, br_dsize);
}

/*
 * Write scattered channel packet to TX bufring.
 *
 * The offset of this channel packet is written as a 64bits value
 * immediately after this channel packet.
 */
int
vmbus_txbr_write(struct vmbus_txbr *tbr, const struct iovec iov[], int iovlen,
    boolean *need_sig)
{
	uint32_t old_windex, windex, total;
	uint64_t save_windex;
	int i;

	total = 0;
	for (i = 0; i < iovlen; i++)
		total += iov[i].iov_len;
	total += sizeof(save_windex);

	u64 flags = spin_lock_irq(&tbr->txbr_lock);

	/*
	 * NOTE:
	 * If this write is going to make br_windex same as br_rindex,
	 * i.e. the available space for write is same as the write size,
	 * we can't do it then, since br_windex == br_rindex means that
	 * the bufring is empty.
	 */
	if (vmbus_txbr_avail(tbr) <= total) {
		spin_unlock_irq(&tbr->txbr_lock, flags);
		return (EAGAIN);
	}

	/* Save br_windex for later use */
	old_windex = tbr->txbr_windex;

	/*
	 * Copy the scattered channel packet to the TX bufring.
	 */
	windex = old_windex;
	for (i = 0; i < iovlen; i++) {
		windex = vmbus_txbr_copyto(tbr, windex,
		    iov[i].iov_base, iov[i].iov_len);
	}

	/*
	 * Set the offset of the current channel packet.
	 */
	save_windex = ((uint64_t)old_windex) << 32;
	windex = vmbus_txbr_copyto(tbr, windex, &save_windex,
	    sizeof(save_windex));

	/*
	 * Update the write index _after_ the channel packet
	 * is copied.
	 */
	compiler_barrier();
	tbr->txbr_windex = windex;

	spin_unlock_irq(&tbr->txbr_lock, flags);

	*need_sig = vmbus_txbr_need_signal(tbr, old_windex);

	return (0);
}

static __inline uint32_t
vmbus_rxbr_copyfrom(const struct vmbus_rxbr *rbr, uint32_t rindex,
    void *dst0, int cplen)
{
	uint8_t *dst = dst0;
	const uint8_t *br_data = rbr->rxbr_data;
	uint32_t br_dsize = rbr->rxbr_dsize;

	if (cplen > br_dsize - rindex) {
		uint32_t fraglen = br_dsize - rindex;

		/* Wrap-around detected. */
		runtime_memcpy(dst, br_data + rindex, fraglen);
		runtime_memcpy(dst + fraglen, br_data, cplen - fraglen);
	} else {
		runtime_memcpy(dst, br_data + rindex, cplen);
	}
	return VMBUS_BR_IDXINC(rindex, cplen, br_dsize);
}

int
vmbus_rxbr_peek(struct vmbus_rxbr *rbr, void *data, int dlen)
{
	u64 flags = spin_lock_irq(&rbr->rxbr_lock);

	/*
	 * The requested data and the 64bits channel packet
	 * offset should be there at least.
	 */
	if (vmbus_rxbr_avail(rbr) < dlen + sizeof(uint64_t)) {
		spin_unlock_irq(&rbr->rxbr_lock, flags);
		return (EAGAIN);
	}
	vmbus_rxbr_copyfrom(rbr, rbr->rxbr_rindex, data, dlen);

	spin_unlock_irq(&rbr->rxbr_lock, flags);

	return (0);
}

/*
 * NOTE:
 * We assume (dlen + skip) == sizeof(channel packet).
 */
int
vmbus_rxbr_read(struct vmbus_rxbr *rbr, void *data, int dlen, uint32_t skip)
{
	uint32_t rindex, br_dsize = rbr->rxbr_dsize;

	assert(dlen + skip > 0); //invalid dlen %d, offset %u", dlen, skip

	u64 flags = spin_lock_irq(&rbr->rxbr_lock);

	if (vmbus_rxbr_avail(rbr) < dlen + skip + sizeof(uint64_t)) {
		spin_unlock_irq(&rbr->rxbr_lock, flags);
		return (EAGAIN);
	}

	/*
	 * Copy channel packet from RX bufring.
	 */
	rindex = VMBUS_BR_IDXINC(rbr->rxbr_rindex, skip, br_dsize);
	rindex = vmbus_rxbr_copyfrom(rbr, rindex, data, dlen);

	/*
	 * Discard this channel packet's 64bits offset, which is useless to us.
	 */
	rindex = VMBUS_BR_IDXINC(rindex, sizeof(uint64_t), br_dsize);

	/*
	 * Update the read index _after_ the channel packet is fetched.
	 */
	compiler_barrier();
	rbr->rxbr_rindex = rindex;

	spin_unlock_irq(&rbr->rxbr_lock, flags);

	return (0);
}
