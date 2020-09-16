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
 *
 * $FreeBSD$
 */

#ifndef _VMBUS_ICVAR_H_
#define _VMBUS_ICVAR_H_

#include <hyperv.h>
#include <vmbus.h>

#ifdef VMBUS_UTIL_DEBUG
#define vmbus_util_debug(x, ...) do { rprintf("VMBUS UTIL: " x "\n", ##__VA_ARGS__); } while(0)
#else
#define vmbus_util_debug(x, ...)
#endif

struct vmbus_ic_softc {
   heap general;
   struct hv_device  *hs_dev;
   uint8_t        *ic_buf;
   int         ic_buflen;
   uint32_t    ic_fwver;   /* framework version */
   uint32_t    ic_msgver;  /* message version */
};

void            vmbus_ic_attach(struct vmbus_ic_softc *sc, vmbus_chan_callback_t cb);
int             vmbus_ic_negomsg(struct vmbus_ic_softc *sc, void *data,
                    int *dlen, uint32_t fw_ver, uint32_t msg_ver);
int             vmbus_ic_sendresp(struct vmbus_ic_softc *sc,
                    struct vmbus_channel *chan, void *data, int dlen,
                    uint64_t xactid);

#endif   /* !_VMBUS_ICVAR_H_ */
