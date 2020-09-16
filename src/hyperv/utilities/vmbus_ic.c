/*-
 * Copyright (c) 2014,2016 Microsoft Corp.
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
#include "vmbus_icreg.h"
#include "vmbus_icvar.h"
#include "vmbus.h"

#define VMBUS_IC_BRSIZE		(4 * PAGESIZE)

#define VMBUS_IC_VERCNT		2
#define VMBUS_IC_NEGOSZ		\
	__offsetof(struct vmbus_icmsg_negotiate, ic_ver[VMBUS_IC_VERCNT])
CTASSERT(VMBUS_IC_NEGOSZ < VMBUS_IC_BRSIZE);

int
vmbus_ic_negomsg(struct vmbus_ic_softc *sc, void *data, int *dlen0,
    uint32_t fw_ver, uint32_t msg_ver)
{
	struct vmbus_icmsg_negotiate *nego;
	int i, cnt, dlen = *dlen0, error;
	uint32_t sel_fw_ver, sel_msg_ver;
	bool has_fw_ver, has_msg_ver;

	/*
	 * Preliminary message verification.
	 */
	if (dlen < sizeof(*nego)) {
		vmbus_util_debug("truncated ic negotiate, len %d", dlen);
		return (EINVAL);
	}
	nego = data;

	if (nego->ic_fwver_cnt == 0) {
		vmbus_util_debug("ic negotiate does not contain "
		    "framework version %d", nego->ic_fwver_cnt);
		return (EINVAL);
	}
	if (nego->ic_msgver_cnt == 0) {
		vmbus_util_debug("ic negotiate does not contain "
		    "message version %d", nego->ic_msgver_cnt);
		return (EINVAL);
	}

	cnt = nego->ic_fwver_cnt + nego->ic_msgver_cnt;
	if (dlen < __offsetof(struct vmbus_icmsg_negotiate, ic_ver[cnt])) {
		vmbus_util_debug("ic negotiate does not contain "
		    "versions %d", dlen);
		return (EINVAL);
	}

	error = EOPNOTSUPP;

	/*
	 * Find the best match framework version.
	 */
	has_fw_ver = false;
	for (i = 0; i < nego->ic_fwver_cnt; ++i) {
		if (VMBUS_ICVER_LE(nego->ic_ver[i], fw_ver)) {
			if (!has_fw_ver) {
				sel_fw_ver = nego->ic_ver[i];
				has_fw_ver = true;
			} else if (VMBUS_ICVER_GT(nego->ic_ver[i],
			    sel_fw_ver)) {
				sel_fw_ver = nego->ic_ver[i];
			}
		}
	}
	if (!has_fw_ver) {
		vmbus_util_debug("failed to select framework version");
		goto done;
	}

	/*
	 * Fine the best match message version.
	 */
	has_msg_ver = false;
	for (i = nego->ic_fwver_cnt;
	    i < nego->ic_fwver_cnt + nego->ic_msgver_cnt; ++i) {
		if (VMBUS_ICVER_LE(nego->ic_ver[i], msg_ver)) {
			if (!has_msg_ver) {
				sel_msg_ver = nego->ic_ver[i];
				has_msg_ver = true;
			} else if (VMBUS_ICVER_GT(nego->ic_ver[i],
			    sel_msg_ver)) {
				sel_msg_ver = nego->ic_ver[i];
			}
		}
	}
	if (!has_msg_ver) {
		vmbus_util_debug("failed to select message version\n");
		goto done;
	}

	error = 0;
done:
#ifdef VMBUS_UTIL_DEBUG
    if (has_fw_ver) {
        vmbus_util_debug("sel framework version: "
            "%d.%d\n",
            VMBUS_ICVER_MAJOR(sel_fw_ver),
            VMBUS_ICVER_MINOR(sel_fw_ver));
    }
    for (i = 0; i < nego->ic_fwver_cnt; i++) {
        vmbus_util_debug("supp framework version: "
            "%d.%d\n",
            VMBUS_ICVER_MAJOR(nego->ic_ver[i]),
            VMBUS_ICVER_MINOR(nego->ic_ver[i]));
    }

    if (has_msg_ver) {
        vmbus_util_debug("sel message version: "
            "%d.%d\n",
            VMBUS_ICVER_MAJOR(sel_msg_ver),
            VMBUS_ICVER_MINOR(sel_msg_ver));
    }
    for (i = nego->ic_fwver_cnt;
        i < nego->ic_fwver_cnt + nego->ic_msgver_cnt; i++) {
        vmbus_util_debug("supp message version: "
            "%d.%d\n",
            VMBUS_ICVER_MAJOR(nego->ic_ver[i]),
            VMBUS_ICVER_MINOR(nego->ic_ver[i]));
    }
#endif // VMBUS_UTIL_DEBUG
	if (error)
		return (error);

	/* Record the selected versions. */
	sc->ic_fwver = sel_fw_ver;
	sc->ic_msgver = sel_msg_ver;

	/* One framework version. */
	nego->ic_fwver_cnt = 1;
	nego->ic_ver[0] = sel_fw_ver;

	/* One message version. */
	nego->ic_msgver_cnt = 1;
	nego->ic_ver[1] = sel_msg_ver;

	/* Update data size. */
	nego->ic_hdr.ic_dsize = VMBUS_IC_NEGOSZ -
	    sizeof(struct vmbus_icmsg_hdr);

	/* Update total size, if necessary. */
	if (dlen < VMBUS_IC_NEGOSZ)
		*dlen0 = VMBUS_IC_NEGOSZ;

	return (0);
}

void
vmbus_ic_attach(struct vmbus_ic_softc *sc, vmbus_chan_callback_t cb)
{
    sc->ic_buflen = VMBUS_IC_BRSIZE;
    sc->ic_buf = allocate_zero(sc->general, VMBUS_IC_BRSIZE);
    struct vmbus_channel *chan = sc->hs_dev->channel;

    /*
     * These services are not performance critical and do not need
     * batched reading. Furthermore, some services such as KVP can
     * only handle one message from the host at a time.
     * Turn off batched reading for all util drivers before we open the
     * channel.
     */
    vmbus_chan_set_readbatch(chan, false);

    vmbus_chan_open(chan, VMBUS_IC_BRSIZE, VMBUS_IC_BRSIZE, 0, 0, cb, sc);
}

int
vmbus_ic_sendresp(struct vmbus_ic_softc *sc, struct vmbus_channel *chan,
    void *data, int dlen, uint64_t xactid)
{
	struct vmbus_icmsg_hdr *hdr;
	int error;

	assert(dlen >= sizeof(*hdr)); //invalid data length
	hdr = data;

	hdr->ic_flags = VMBUS_ICMSG_FLAG_XACT | VMBUS_ICMSG_FLAG_RESP;
	error = vmbus_chan_send(chan, VMBUS_CHANPKT_TYPE_INBAND, 0,
	    data, dlen, xactid);
	if (error)
		vmbus_util_debug("resp send failed: %d", error);
	return (error);
}
