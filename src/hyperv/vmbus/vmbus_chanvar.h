/*-
 * Copyright (c) 2016 Microsoft Corp.
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
 *
 * $FreeBSD$
 */

#ifndef _VMBUS_CHANVAR_H_
#define _VMBUS_CHANVAR_H_

#include <hyperv.h>
#include <hyperv_busdma.h>
#include <vmbus.h>
#include "vmbus_reg.h"
#include "vmbus_brvar.h"

struct vmbus_channel {
	/*
	 * NOTE:
	 * Fields before ch_txbr are only accessed on this channel's
	 * target CPU.
	 */
	uint32_t			ch_flags;	/* VMBUS_CHAN_FLAG_ */

	/*
	 * RX bufring; immediately following ch_txbr.
	 */
	struct vmbus_rxbr		ch_rxbr;
	sbintime_t			ch_poll_intvl;
	thunk				ch_tq;
	task_fn_t			*ch_task;

	vmbus_chan_callback_t		ch_cb;
	void				*ch_cbarg;

	/*
	 * TX bufring; at the beginning of ch_bufring.
	 *
	 * NOTE:
	 * Put TX bufring and the following MNF/evtflag to a new
	 * cacheline, since they will be accessed on all CPUs by
	 * locking ch_txbr first.
	 *
	 * XXX
	 * TX bufring and following MNF/evtflags do _not_ fit in
	 * one 64B cacheline.
	 */
	struct vmbus_txbr		ch_txbr __aligned(CACHE_LINE_SIZE);
	uint32_t			ch_txflags;	/* VMBUS_CHAN_TXF_ */

	/*
	 * These are based on the vmbus_chanmsg_choffer.chm_montrig.
	 * Save it here for easy access.
	 */
	uint32_t			ch_montrig_mask;/* MNF trig mask */
	volatile uint32_t		*ch_montrig;	/* MNF trigger loc. */

	/*
	 * These are based on the vmbus_chanmsg_choffer.chm_chanid.
	 * Save it here for easy access.
	 */
	u64				ch_evtflag_mask;/* event flag */
	volatile u64			*ch_evtflag;	/* event flag loc. */

	/*
	 * Rarely used fields.
	 */

	struct hyperv_mon_param		*ch_monprm;
	struct hyperv_dma		ch_monprm_dma;

	uint32_t			ch_id;		/* channel id */
	vmbus_dev			ch_vmbus;

	int				ch_cpuid;	/* owner cpu */

	/*
	 * Virtual cpuid for ch_cpuid; it is used to communicate cpuid
	 * related information w/ Hyper-V.  If MSR_HV_VP_INDEX does not
	 * exist, ch_vcpuid will always be 0 for compatibility.
	 */
	uint32_t			ch_vcpuid;

	/*
	 * If this is a primary channel, ch_subchan* fields
	 * contain sub-channels belonging to this primary
	 * channel.
	 */
	struct spinlock			ch_subchan_lock;
	struct list			ch_subchans;
	int				ch_subchan_cnt;

	/* If this is a sub-channel */
	struct list			ch_sublink;	/* sub-channel link */
	struct vmbus_channel		*ch_prichan;	/* owner primary chan */

	void				*ch_bufring;	/* TX+RX bufrings */
	struct hyperv_dma		ch_bufring_dma;
	uint32_t			ch_bufring_gpadl;

	/* If this is a primary channel */
	struct list			ch_prilink;	/* primary chan link */

	struct list			ch_link;	/* channel link */

	uint32_t			ch_subidx;	/* subchan index */
	volatile uint32_t		ch_stflags;	/* atomic-op */
							/* VMBUS_CHAN_ST_ */
	struct hyperv_guid		ch_guid_type;
	struct hyperv_guid		ch_guid_inst;


	struct spinlock			ch_orphan_lock;
	struct vmbus_xact_ctx		*ch_orphan_xact;

	int				ch_refs;

} __aligned(CACHE_LINE_SIZE);

#define VMBUS_CHAN_ISPRIMARY(chan)	((chan)->ch_subidx == 0)

/*
 * If this flag is set, this channel's interrupt will be masked in ISR,
 * and the RX bufring will be drained before this channel's interrupt is
 * unmasked.
 *
 * This flag is turned on by default.  Drivers can turn it off according
 * to their own requirement.
 */
#define VMBUS_CHAN_FLAG_BATCHREAD	0x0002

#define VMBUS_CHAN_TXF_HASMNF		0x0001

#define VMBUS_CHAN_ST_OPENED_SHIFT	0
#define VMBUS_CHAN_ST_ONPRIL_SHIFT	1
#define VMBUS_CHAN_ST_ONSUBL_SHIFT	2
#define VMBUS_CHAN_ST_ONLIST_SHIFT	3
#define VMBUS_CHAN_ST_REVOKED_SHIFT	4	/* sticky */
#define VMBUS_CHAN_ST_OPENED		(1 << VMBUS_CHAN_ST_OPENED_SHIFT)
#define VMBUS_CHAN_ST_ONPRIL		(1 << VMBUS_CHAN_ST_ONPRIL_SHIFT)
#define VMBUS_CHAN_ST_ONSUBL		(1 << VMBUS_CHAN_ST_ONSUBL_SHIFT)
#define VMBUS_CHAN_ST_ONLIST		(1 << VMBUS_CHAN_ST_ONLIST_SHIFT)
#define VMBUS_CHAN_ST_REVOKED		(1 << VMBUS_CHAN_ST_REVOKED_SHIFT)

struct vmbus_softc;
struct vmbus_message;

void		vmbus_event_proc(vmbus_dev, int);
void		vmbus_event_proc_compat(vmbus_dev, int);
void		vmbus_chan_msgproc(vmbus_dev, const struct vmbus_message *);
void		vmbus_chan_destroy_all(struct vmbus_softc *);

struct vmbus_channel* vmbus_chan_choffer_open_channel(vmbus_dev, const struct vmbus_message *);

#endif	/* !_VMBUS_CHANVAR_H_ */
