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
#include <hyperv_busdma.h>
#include <vmbus_xact.h>
#include <net_system_structs.h>
#include "hyperv_var.h"
#include "vmbus_reg.h"
#include "vmbus_var.h"
#include "vmbus_brvar.h"
#include "vmbus_chanvar.h"

#define NULL 0

#ifdef VMBUS_CHAN_DEBUG
#define vmbus_chan_debug(x, ...) do {rprintf(" VMBUS CHAN: " x "\n", ##__VA_ARGS__);} while(0)
#else
#define vmbus_chan_debug(x, ...)
#endif

static void            vmbus_chan_update_evtflagcnt(
                    vmbus_dev vmbus,
                    const struct vmbus_channel *);
static struct vmbus_channel    *vmbus_chan_alloc(vmbus_dev);
static void         vmbus_chan_free(struct vmbus_channel *);
static int            vmbus_chan_add(struct vmbus_channel *);
static void            vmbus_chan_cpu_default(struct vmbus_channel *);
static void            vmbus_chan_set_chmap(struct vmbus_channel *);
static void            vmbus_chan_ins_prilist(vmbus_dev,
                    struct vmbus_channel *);
static void            vmbus_chan_ins_list(vmbus_dev,
                    struct vmbus_channel *);
static void            vmbus_chan_ins_sublist(struct vmbus_channel *,
                    struct vmbus_channel *);
static void            vmbus_chan_task(void *, int);
static void            vmbus_chan_task_nobatch(void *, int);
static void            vmbus_chan_msgproc_chrescind(vmbus_dev,
                    const struct vmbus_message *);

/*
 * Vmbus channel message processing.
 */
static const vmbus_chanmsg_proc_t
vmbus_chan_msgprocs[VMBUS_CHANMSG_TYPE_MAX] = {
    VMBUS_CHANMSG_PROC(CHRESCIND,    vmbus_chan_msgproc_chrescind),
    VMBUS_CHANMSG_PROC_WAKEUP(CHOPEN_RESP),
    VMBUS_CHANMSG_PROC_WAKEUP(GPADL_CONNRESP),
    VMBUS_CHANMSG_PROC_WAKEUP(GPADL_DISCONNRESP)
};

/*
 * Notify host that there are data pending on our TX bufring.
 */
static __inline void
vmbus_chan_signal_tx(const struct vmbus_channel *chan)
{
    atomic_set64(chan->ch_evtflag, chan->ch_evtflag_mask);
    if (chan->ch_txflags & VMBUS_CHAN_TXF_HASMNF)
        atomic_set32(chan->ch_montrig, chan->ch_montrig_mask);
    else
        hypercall_signal_event(chan->ch_monprm_dma.hv_paddr);
}

static void
vmbus_chan_ins_prilist(vmbus_dev sc, struct vmbus_channel *chan)
{

    if (atomic_testandset32(&chan->ch_stflags,
        VMBUS_CHAN_ST_ONPRIL_SHIFT))
        halt("channel is already on the prilist");
    list_push_back(&sc->vmbus_prichans, &chan->ch_prilink);
}

static void
vmbus_chan_ins_sublist(struct vmbus_channel *prichan,
    struct vmbus_channel *chan)
{

    if (atomic_testandset32(&chan->ch_stflags,
        VMBUS_CHAN_ST_ONSUBL_SHIFT))
        halt("channel is already on the sublist");
    list_push_back(&prichan->ch_subchans, &chan->ch_sublink);

    /* Bump sub-channel count. */
    prichan->ch_subchan_cnt++;
}

static void
vmbus_chan_ins_list(vmbus_dev sc, struct vmbus_channel *chan)
{
    if (atomic_testandset32(&chan->ch_stflags,
        VMBUS_CHAN_ST_ONLIST_SHIFT))
        halt("channel is already on the list");
    list_push_back(&sc->vmbus_chans, &chan->ch_link);
}

void
vmbus_chan_open(struct vmbus_channel *chan, int txbr_size, int rxbr_size,
    const void *udata, int udlen, vmbus_chan_callback_t cb, void *cbarg)
{
    struct vmbus_chan_br cbr;

    /*
     * Allocate the TX+RX bufrings.
     */
    assert(chan->ch_bufring == NULL); //bufrings are allocated
    chan->ch_bufring = allocate(chan->ch_vmbus->contiguous, txbr_size + rxbr_size);
    assert(chan->ch_bufring != INVALID_ADDRESS);
    assert((u64)chan->ch_bufring == pad((u64)chan->ch_bufring, PAGESIZE));
    chan->ch_bufring_dma.hv_paddr = physical_from_virtual(chan->ch_bufring);
    assert(chan->ch_bufring_dma.hv_paddr != INVALID_PHYSICAL);

    cbr.cbr = chan->ch_bufring;
    cbr.cbr_paddr = chan->ch_bufring_dma.hv_paddr;
    cbr.cbr_txsz = txbr_size;
    cbr.cbr_rxsz = rxbr_size;

    vmbus_chan_open_br(chan, &cbr, udata, udlen, cb, cbarg);
}

closure_function(1, 0, void, vmbus_chan_closure,
                 struct vmbus_channel *, chan)
{
    struct vmbus_channel *chan = bound(chan);
    chan->ch_task(chan, 0);
}

int
vmbus_chan_open_br(struct vmbus_channel *chan, const struct vmbus_chan_br *cbr,
    const void *udata, int udlen, vmbus_chan_callback_t cb, void *cbarg)
{
    vmbus_dev vmbus = chan->ch_vmbus;

    assert(udlen <= VMBUS_CHANMSG_CHOPEN_UDATA_SIZE);

    uint8_t *br = cbr->cbr;
    int txbr_size = cbr->cbr_txsz;
    int rxbr_size = cbr->cbr_rxsz;
    assert((txbr_size & PAGEMASK) == 0); //send bufring size is not multiple page
    assert((rxbr_size & PAGEMASK) == 0); //recv bufring size is not multiple page
    assert((cbr->cbr_paddr & PAGEMASK) == 0); //bufring is not page aligned

    /*
     * Zero out the TX/RX bufrings, in case that they were used before.
     */
    zero(br, txbr_size + rxbr_size);


    if (atomic_testandset32(&chan->ch_stflags,
        VMBUS_CHAN_ST_OPENED_SHIFT))
        halt("double-open chan%d", chan->ch_id);

    chan->ch_cb = cb;
    chan->ch_cbarg = cbarg;
    vmbus_chan_debug("OPEN_BR, cbarg = %x", chan->ch_cbarg);

    vmbus_chan_update_evtflagcnt(vmbus, chan);

    /* TX bufring comes first */
    vmbus_txbr_setup(&chan->ch_txbr, br, txbr_size);
    /* RX bufring immediately follows TX bufring */
    vmbus_rxbr_setup(&chan->ch_rxbr, br + txbr_size, rxbr_size);

    task_fn_t *task_fn;
    chan->ch_tq = closure(chan->ch_vmbus->general, vmbus_chan_closure, chan);
    if (chan->ch_flags & VMBUS_CHAN_FLAG_BATCHREAD)
        task_fn = vmbus_chan_task;
    else
        task_fn = vmbus_chan_task_nobatch;
    chan->ch_task = task_fn;

    /*
     * Connect the bufrings, both RX and TX, to this channel.
     */
    vmbus_chan_gpadl_connect(chan, cbr->cbr_paddr,
        txbr_size + rxbr_size, &chan->ch_bufring_gpadl);

    /*
     * Install this channel, before it is opened, but after everything
     * else has been setup.
     */
    vmbus_chan_set_chmap(chan);

    /*
     * Open channel w/ the bufring GPADL on the target CPU.
     */
    struct vmbus_chanmsg_chopen *req;
    int error = 0;
    struct vmbus_msghc *mh = vmbus_msghc_get(vmbus, sizeof(*req));
    if (mh == NULL) {
        vmbus_chan_debug("can not get msg hypercall for chopen(chan%d)",
            chan->ch_id);
        error = ENXIO;
        goto failed;
    }

    req = vmbus_msghc_dataptr(mh);
    req->chm_hdr.chm_type = VMBUS_CHANMSG_TYPE_CHOPEN;
    req->chm_chanid = chan->ch_id;
    req->chm_openid = chan->ch_id;
    req->chm_gpadl = chan->ch_bufring_gpadl;
    req->chm_vcpuid = chan->ch_vcpuid;
    req->chm_txbr_pgcnt = txbr_size >> PAGELOG;
    if (udlen > 0)
        runtime_memcpy(req->chm_udata, udata, udlen);

    boolean success = vmbus_msghc_exec(vmbus, mh);
    assert(success);

    const struct vmbus_message *msg = NULL;
    for (;;) {
        msg = vmbus_msghc_poll_result(vmbus, mh);
        if (msg != NULL)
            break;
        if (vmbus_chan_is_revoked(chan)) {
            int i;

            /*
             * NOTE:
             * Hypervisor does _not_ send response CHOPEN to
             * a revoked channel.
             */
            vmbus_chan_debug("chan%d is revoked, when it is being opened",
                chan->ch_id);

            /*
             * XXX
             * Add extra delay before cancel the hypercall
             * execution; mainly to close any possible
             * CHRESCIND and CHOPEN_RESP races on the
             * hypervisor side.
             */
#define REVOKE_LINGER    100
            for (i = 0; i < REVOKE_LINGER; ++i) {
                msg = vmbus_msghc_poll_result(vmbus, mh);
                if (msg != NULL)
                    break;
                kernel_delay(milliseconds(1));
            }
#undef REVOKE_LINGER
            if (msg == NULL)
                vmbus_msghc_exec_cancel(vmbus, mh);
            break;
        }
        kernel_delay(milliseconds(1));
    }
    uint32_t status;
    if (msg != NULL) {
        const struct vmbus_chanmsg_chopen_resp *chan_resp =
            (const struct vmbus_chanmsg_chopen_resp *)msg->msg_data;
        status = chan_resp->chm_status;
    } else {
        /* XXX any non-0 value is ok here. */
        status = 0xff;
    }

    vmbus_msghc_put(vmbus, mh);

    if (status == 0) {
        vmbus_chan_debug("chan%d opened", chan->ch_id);
        return (0);
    }

    vmbus_chan_debug("failed to open chan%d", chan->ch_id);
    error = ENXIO;

failed:
    if (chan->ch_bufring_gpadl != 0) {
        vmbus_chan_gpadl_disconnect(chan, chan->ch_bufring_gpadl);
        chan->ch_bufring_gpadl = 0;
    }
    atomic_clear32(&chan->ch_stflags, VMBUS_CHAN_ST_OPENED);
    return (error);
}

void
vmbus_chan_gpadl_connect(struct vmbus_channel *chan, bus_addr_t paddr,
    int size, uint32_t *gpadl0)
{
    vmbus_dev dev = chan->ch_vmbus;
    struct vmbus_msghc *mh;
    struct vmbus_chanmsg_gpadl_conn *req;
    uint32_t gpadl, status;

    assert(*gpadl0 == 0); //GPADL is not zero

    /*
     * Preliminary checks.
     */

    assert((size & PAGEMASK) == 0); //invalid GPA size %d, not multiple page size
    int page_count = size >> PAGELOG;

    assert((paddr & PAGEMASK) == 0); //GPA is not page aligned %jx", (uintmax_t)paddr
    uint64_t page_id = paddr >> PAGELOG;

    int range_len = __offsetof(struct vmbus_gpa_range, gpa_page[page_count]);
    /*
     * We don't support multiple GPA ranges.
     */
    assert(range_len < UINT16_MAX);

    /*
     * Allocate GPADL id.
     */
    gpadl = vmbus_gpadl_alloc(dev);

    /*
     * Connect this GPADL to the target channel.
     *
     * NOTE:
     * Since each message can only hold small set of page
     * addresses, several messages may be required to
     * complete the connection.
     */
    int cnt;
    if (page_count > VMBUS_CHANMSG_GPADL_CONN_PGMAX)
        cnt = VMBUS_CHANMSG_GPADL_CONN_PGMAX;
    else
        cnt = page_count;
    page_count -= cnt;

    size_t reqsz = __offsetof(struct vmbus_chanmsg_gpadl_conn,
        chm_range.gpa_page[cnt]);
    mh = vmbus_msghc_get(dev, reqsz);
    assert(mh != NULL); //can not get msg hypercall for gpadl_conn(chan%u)\n", chan->ch_id

    req = vmbus_msghc_dataptr(mh);
    req->chm_hdr.chm_type = VMBUS_CHANMSG_TYPE_GPADL_CONN;
    req->chm_chanid = chan->ch_id;
    req->chm_gpadl = gpadl;
    req->chm_range_len = range_len;
    req->chm_range_cnt = 1;
    req->chm_range.gpa_len = size;
    req->chm_range.gpa_ofs = 0;
    for (int i = 0; i < cnt; ++i)
        req->chm_range.gpa_page[i] = page_id++;

    boolean success = vmbus_msghc_exec(dev, mh);
    assert(success);

    while (page_count > 0) {
        struct vmbus_chanmsg_gpadl_subconn *subreq;

        if (page_count > VMBUS_CHANMSG_GPADL_SUBCONN_PGMAX)
            cnt = VMBUS_CHANMSG_GPADL_SUBCONN_PGMAX;
        else
            cnt = page_count;
        page_count -= cnt;

        reqsz = __offsetof(struct vmbus_chanmsg_gpadl_subconn,
            chm_gpa_page[cnt]);
        vmbus_msghc_reset(mh, reqsz);

        subreq = vmbus_msghc_dataptr(mh);
        subreq->chm_hdr.chm_type = VMBUS_CHANMSG_TYPE_GPADL_SUBCONN;
        subreq->chm_gpadl = gpadl;
        for (int i = 0; i < cnt; ++i)
            subreq->chm_gpa_page[i] = page_id++;

        vmbus_msghc_exec_noresult(mh);
    }
    assert(page_count == 0); //invalid page count %d", page_count

    const struct vmbus_message *msg = vmbus_msghc_wait_result(dev, mh);
    const struct vmbus_chanmsg_gpadl_connresp *connresp =
        (const struct vmbus_chanmsg_gpadl_connresp *)msg->msg_data;
    status = connresp->chm_status;

    vmbus_msghc_put(dev, mh);

   if (status != 0) {
       halt("gpadl_conn(chan%d) failed: %d\n", chan->ch_id, status);
   }

    /* Done; commit the GPADL id. */
    *gpadl0 = gpadl;

    vmbus_chan_debug("gpadl_conn(chan%d) succeeded", chan->ch_id);
}

/*
 * Disconnect the GPA from the target channel
 */
void
vmbus_chan_gpadl_disconnect(struct vmbus_channel *chan, uint32_t gpadl)
{
    vmbus_dev dev = chan->ch_vmbus;
    struct vmbus_msghc *mh;
    struct vmbus_chanmsg_gpadl_disconn *req;

    assert(gpadl != 0); //GPADL is zero

    mh = vmbus_msghc_get(dev, sizeof(*req));
    assert(mh != NULL);

    req = vmbus_msghc_dataptr(mh);
    req->chm_hdr.chm_type = VMBUS_CHANMSG_TYPE_GPADL_DISCONN;
    req->chm_chanid = chan->ch_id;
    req->chm_gpadl = gpadl;

    boolean success = vmbus_msghc_exec(dev, mh);
    assert(success);

    vmbus_msghc_wait_result(dev, mh);
    /* Discard result; no useful information */
    vmbus_msghc_put(dev, mh);
}

static void
vmbus_chan_set_chmap(struct vmbus_channel *chan)
{
    compiler_barrier();
    chan->ch_vmbus->vmbus_chmap[chan->ch_id] = chan;
}

int
vmbus_chan_send(struct vmbus_channel *chan, uint16_t type, uint16_t flags,
    void *data, int dlen, uint64_t xactid)
{
    struct vmbus_chanpkt pkt;
    int pktlen, pad_pktlen, hlen, error;
    uint64_t pad = 0;
    struct iovec iov[3];
    boolean send_evt;

    hlen = sizeof(pkt);
    pktlen = hlen + dlen;
    pad_pktlen = VMBUS_CHANPKT_TOTLEN(pktlen);
    assert(pad_pktlen <= vmbus_txbr_maxpktsz(&chan->ch_txbr)); // invalid packet size %d", pad_pktlen

    pkt.cp_hdr.cph_type = type;
    pkt.cp_hdr.cph_flags = flags;
    VMBUS_CHANPKT_SETLEN(pkt.cp_hdr.cph_hlen, hlen);
    VMBUS_CHANPKT_SETLEN(pkt.cp_hdr.cph_tlen, pad_pktlen);
    pkt.cp_hdr.cph_xactid = xactid;

    iov[0].iov_base = &pkt;
    iov[0].iov_len = hlen;
    iov[1].iov_base = data;
    iov[1].iov_len = dlen;
    iov[2].iov_base = &pad;
    iov[2].iov_len = pad_pktlen - pktlen;

    error = vmbus_txbr_write(&chan->ch_txbr, iov, 3, &send_evt);
    if (!error && send_evt)
        vmbus_chan_signal_tx(chan);
    return error;
}

int
vmbus_chan_send_sglist(struct vmbus_channel *chan,
    struct vmbus_gpa sg[], int sglen, void *data, int dlen, uint64_t xactid)
{
    struct vmbus_chanpkt_sglist pkt;
    int pktlen, pad_pktlen, hlen, error;
    struct iovec iov[4];
    boolean send_evt;
    uint64_t pad = 0;

    hlen = __offsetof(struct vmbus_chanpkt_sglist, cp_gpa[sglen]);
    pktlen = hlen + dlen;
    pad_pktlen = VMBUS_CHANPKT_TOTLEN(pktlen);
    assert(pad_pktlen <= vmbus_txbr_maxpktsz(&chan->ch_txbr)); //invalid packet size %d", pad_pktlen

    pkt.cp_hdr.cph_type = VMBUS_CHANPKT_TYPE_GPA;
    pkt.cp_hdr.cph_flags = VMBUS_CHANPKT_FLAG_RC;
    VMBUS_CHANPKT_SETLEN(pkt.cp_hdr.cph_hlen, hlen);
    VMBUS_CHANPKT_SETLEN(pkt.cp_hdr.cph_tlen, pad_pktlen);
    pkt.cp_hdr.cph_xactid = xactid;
    pkt.cp_rsvd = 0;
    pkt.cp_gpa_cnt = sglen;

    iov[0].iov_base = &pkt;
    iov[0].iov_len = sizeof(pkt);
    iov[1].iov_base = sg;
    iov[1].iov_len = sizeof(struct vmbus_gpa) * sglen;
    iov[2].iov_base = data;
    iov[2].iov_len = dlen;
    iov[3].iov_base = &pad;
    iov[3].iov_len = pad_pktlen - pktlen;

    error = vmbus_txbr_write(&chan->ch_txbr, iov, 4, &send_evt);
    if (!error && send_evt)
        vmbus_chan_signal_tx(chan);
    return error;
}

int
vmbus_chan_send_prplist(struct vmbus_channel *chan,
    struct vmbus_gpa_range *prp, int prp_cnt, void *data, int dlen,
    uint64_t xactid)
{
    struct vmbus_chanpkt_prplist pkt;
    int pktlen, pad_pktlen, hlen, error;
    struct iovec iov[4];
    boolean send_evt;
    uint64_t pad = 0;

    hlen = __offsetof(struct vmbus_chanpkt_prplist,
        cp_range[0].gpa_page[prp_cnt]);
    pktlen = hlen + dlen;
    pad_pktlen = VMBUS_CHANPKT_TOTLEN(pktlen);
    assert(pad_pktlen <= vmbus_txbr_maxpktsz(&chan->ch_txbr)); //invalid packet size

    pkt.cp_hdr.cph_type = VMBUS_CHANPKT_TYPE_GPA;
    pkt.cp_hdr.cph_flags = VMBUS_CHANPKT_FLAG_RC;
    VMBUS_CHANPKT_SETLEN(pkt.cp_hdr.cph_hlen, hlen);
    VMBUS_CHANPKT_SETLEN(pkt.cp_hdr.cph_tlen, pad_pktlen);
    pkt.cp_hdr.cph_xactid = xactid;
    pkt.cp_rsvd = 0;
    pkt.cp_range_cnt = 1;

    iov[0].iov_base = &pkt;
    iov[0].iov_len = sizeof(pkt);
    iov[1].iov_base = prp;
    iov[1].iov_len = __offsetof(struct vmbus_gpa_range, gpa_page[prp_cnt]);
    iov[2].iov_base = data;
    iov[2].iov_len = dlen;
    iov[3].iov_base = &pad;
    iov[3].iov_len = pad_pktlen - pktlen;

    error = vmbus_txbr_write(&chan->ch_txbr, iov, 4, &send_evt);
    if (!error && send_evt)
        vmbus_chan_signal_tx(chan);
    return error;
}

int
vmbus_chan_recv(struct vmbus_channel *chan, void *data, int *dlen0,
    uint64_t *xactid)
{
    struct vmbus_chanpkt_hdr pkt;
    int error, dlen, hlen;

    error = vmbus_rxbr_peek(&chan->ch_rxbr, &pkt, sizeof(pkt));
    if (error)
        return (error);

    if (pkt.cph_hlen < VMBUS_CHANPKT_HLEN_MIN) {
        vmbus_chan_debug("invalid hlen %d", pkt.cph_hlen);
        /* XXX this channel is dead actually. */
        return (EIO);
    }
    if (pkt.cph_hlen > pkt.cph_tlen) {
        vmbus_chan_debug("invalid hlen %d and tlen %d",
            pkt.cph_hlen, pkt.cph_tlen);
        /* XXX this channel is dead actually. */
        return (EIO);
    }

    hlen = VMBUS_CHANPKT_GETLEN(pkt.cph_hlen);
    dlen = VMBUS_CHANPKT_GETLEN(pkt.cph_tlen) - hlen;

    if (*dlen0 < dlen) {
        /* Return the size of this packet's data. */
        *dlen0 = dlen;
        return (ENOBUFS);
    }

    *xactid = pkt.cph_xactid;
    *dlen0 = dlen;

    /* Skip packet header */
    error = vmbus_rxbr_read(&chan->ch_rxbr, data, dlen, hlen);
    assert(!error); //vmbus_rxbr_read failed

    return (0);
}

int
vmbus_chan_recv_pkt(struct vmbus_channel *chan,
    struct vmbus_chanpkt_hdr *pkt, int *pktlen0)
{
    int error, pktlen, pkt_hlen;

    pkt_hlen = sizeof(*pkt);
    error = vmbus_rxbr_peek(&chan->ch_rxbr, pkt, pkt_hlen);
    if (error)
        return (error);

    if (pkt->cph_hlen < VMBUS_CHANPKT_HLEN_MIN) {
        vmbus_chan_debug("invalid hlen %d", pkt->cph_hlen);
        /* XXX this channel is dead actually. */
        return (EIO);
    }
    if (pkt->cph_hlen > pkt->cph_tlen) {
        vmbus_chan_debug("invalid hlen %d and tlen %d",
            pkt->cph_hlen, pkt->cph_tlen);
        /* XXX this channel is dead actually. */
        return (EIO);
    }

    pktlen = VMBUS_CHANPKT_GETLEN(pkt->cph_tlen);
    if (*pktlen0 < pktlen) {
        /* Return the size of this packet. */
        *pktlen0 = pktlen;
        return (ENOBUFS);
    }
    *pktlen0 = pktlen;

    /*
     * Skip the fixed-size packet header, which has been filled
     * by the above vmbus_rxbr_peek().
     */
    error = vmbus_rxbr_read(&chan->ch_rxbr, pkt + 1,
        pktlen - pkt_hlen, pkt_hlen);
    assert(!error); //vmbus_rxbr_read failed

    return (0);
}

static void
vmbus_chan_task(void *xchan, int pending_unused)
{
    struct vmbus_channel *chan = xchan;
    vmbus_chan_callback_t cb = chan->ch_cb;
    void *cbarg = chan->ch_cbarg;

    assert(chan->ch_poll_intvl == 0); //"chan%u: interrupted in polling mode", chan->ch_id

    /*
     * Optimize host to guest signaling by ensuring:
     * 1. While reading the channel, we disable interrupts from
     *    host.
     * 2. Ensure that we process all posted messages from the host
     *    before returning from this callback.
     * 3. Once we return, enable signaling from the host. Once this
     *    state is set we check to see if additional packets are
     *    available to read. In this case we repeat the process.
     *
     * NOTE: Interrupt has been disabled in the ISR.
     */
    for (;;) {
        uint32_t left;

        cb(chan, cbarg);

        left = vmbus_rxbr_intr_unmask(&chan->ch_rxbr);
        if (left == 0) {
            /* No more data in RX bufring; done */
            break;
        }
        vmbus_rxbr_intr_mask(&chan->ch_rxbr);
    }
}

static void
vmbus_chan_task_nobatch(void *xchan, int pending_unused)
{
    struct vmbus_channel *chan = xchan;

    assert(chan->ch_poll_intvl == 0); //chan%u: interrupted in polling mode", chan->ch_id
    chan->ch_cb(chan, chan->ch_cbarg);
}

static __inline void
vmbus_event_flags_proc(vmbus_dev sc, volatile u64 *event_flags,
    int flag_cnt)
{
    int f;

    for (f = 0; f < flag_cnt; ++f) {
        uint32_t chid_base;
        u64 flags;
        int chid_ofs;

        if (event_flags[f] == 0)
            continue;

        flags = atomic_swap64(&event_flags[f], 0);
        chid_base = f << VMBUS_EVTFLAG_SHIFT;

        while ((chid_ofs = ffsl(flags)) != 0) {
            struct vmbus_channel *chan;

            --chid_ofs; /* NOTE: ffsl is 1-based */
            flags &= ~(1UL << chid_ofs);

            chan = sc->vmbus_chmap[chid_base + chid_ofs];
            if (chan == NULL) {
                /* Channel is closed. */
                continue;
            }
            compiler_barrier();
            if (chan->ch_flags & VMBUS_CHAN_FLAG_BATCHREAD)
                vmbus_rxbr_intr_mask(&chan->ch_rxbr);
            if (!sc->poll_mode) {
                enqueue(bhqueue, chan->ch_tq);
            } else {
                apply(chan->ch_tq);
            }
        }
    }
}

void
vmbus_event_proc(vmbus_dev sc, int cpu)
{
    struct vmbus_evtflags *eventf;

    /*
     * On Host with Win8 or above, the event page can be checked directly
     * to get the id of the channel that has the pending interrupt.
     */
    eventf = VMBUS_PCPU_GET(sc, event_flags, cpu) + VMBUS_SINT_MESSAGE;
    vmbus_event_flags_proc(sc, eventf->evt_flags,
        VMBUS_PCPU_GET(sc, event_flags_cnt, cpu));
}

void
vmbus_event_proc_compat(vmbus_dev sc, int cpu)
{
    struct vmbus_evtflags *eventf;

    eventf = VMBUS_PCPU_GET(sc, event_flags, cpu) + VMBUS_SINT_MESSAGE;
    if (atomic_testandclear64(&eventf->evt_flags[0], 0)) {
        vmbus_event_flags_proc(sc, sc->vmbus_rx_evtflags,
            VMBUS_CHAN_MAX_COMPAT >> VMBUS_EVTFLAG_SHIFT);
    }
}

static void
vmbus_chan_update_evtflagcnt(vmbus_dev sc,
    const struct vmbus_channel *chan)
{

    volatile u32 *flag_cnt_ptr;
    int flag_cnt;

    flag_cnt = (chan->ch_id / VMBUS_EVTFLAG_LEN) + 1;
    flag_cnt_ptr = (u32*)VMBUS_PCPU_PTR(sc, event_flags_cnt, chan->ch_cpuid);

    for (;;) {
        int old_flag_cnt;

        old_flag_cnt = *flag_cnt_ptr;
        if (old_flag_cnt >= flag_cnt)
            break;
        if (atomic_cmpset32(flag_cnt_ptr, old_flag_cnt, flag_cnt)) {
            vmbus_chan_debug("chan%d update cpu%d flag_cnt to %d",
                    chan->ch_id, chan->ch_cpuid, flag_cnt);
            break;
        }
    }
}

static struct vmbus_channel *
vmbus_chan_alloc(vmbus_dev sc)
{
    struct vmbus_channel *chan;

    chan = allocate_zero(sc->general, sizeof(*chan));
    assert(chan != INVALID_ADDRESS);

    chan->ch_monprm = allocate_zero(sc->contiguous, sizeof(struct hyperv_mon_param));
    assert(chan->ch_monprm != INVALID_ADDRESS);
    assert((u64)chan->ch_monprm == pad((u64)chan->ch_monprm, HYPERCALL_PARAM_ALIGN));
    chan->ch_monprm_dma.hv_paddr = physical_from_virtual(chan->ch_monprm);
    assert(chan->ch_monprm_dma.hv_paddr != INVALID_PHYSICAL);

    chan->ch_refs = 1;
    chan->ch_vmbus = sc;

    spin_lock_init(&chan->ch_subchan_lock);
    list_init(&chan->ch_subchans);

    vmbus_rxbr_init(&chan->ch_rxbr);
    vmbus_txbr_init(&chan->ch_txbr);

    return chan;
}

static void
vmbus_chan_free(struct vmbus_channel *chan)
{
    assert(list_empty(&chan->ch_subchans) && chan->ch_subchan_cnt == 0); // still owns sub-channels
    assert((chan->ch_stflags &
        (VMBUS_CHAN_ST_OPENED |
         VMBUS_CHAN_ST_ONPRIL |
         VMBUS_CHAN_ST_ONSUBL |
         VMBUS_CHAN_ST_ONLIST)) == 0); // free busy channel
    assert(chan->ch_orphan_xact == NULL); // still has orphan xact installed
    assert(chan->ch_refs == 0); // invalid refcnt
    assert(chan->ch_poll_intvl == 0); // polling is activated

    deallocate(chan->ch_vmbus->contiguous, chan->ch_monprm, sizeof(struct hyperv_mon_param));
    vmbus_rxbr_deinit(&chan->ch_rxbr);
    vmbus_txbr_deinit(&chan->ch_txbr);
    deallocate(chan->ch_vmbus->general, chan, sizeof(*chan));
}

static int
vmbus_chan_add(struct vmbus_channel *newchan)
{
    vmbus_dev sc = newchan->ch_vmbus;

    if (newchan->ch_id == 0) {
        /*
         * XXX
         * Chan0 will neither be processed nor should be offered;
         * skip it.
         */
        vmbus_chan_debug("got chan0 offer, discard");
        return EINVAL;
    } else if (newchan->ch_id >= VMBUS_CHAN_MAX) {
        vmbus_chan_debug("invalid chan%d offer", newchan->ch_id);
        return EINVAL;
    }

    struct vmbus_channel *prichan = NULL;
    u64 flags = spin_lock_irq(&sc->vmbus_prichan_lock);
    list_foreach(&sc->vmbus_prichans, l) {
        assert(l);
        struct vmbus_channel *ch = struct_from_list(l, struct vmbus_channel *, ch_prilink);
        /*
         * Sub-channel will have the same type GUID and instance
         * GUID as its primary channel.
         */
        if (runtime_memcmp(&ch->ch_guid_type, &newchan->ch_guid_type,
            sizeof(struct hyperv_guid)) == 0 &&
            runtime_memcmp(&ch->ch_guid_inst, &newchan->ch_guid_inst,
            sizeof(struct hyperv_guid)) == 0) {
            prichan = ch;
            break;
        }
    }
    if (VMBUS_CHAN_ISPRIMARY(newchan)) {
        if (prichan == NULL) {
            /* Install the new primary channel */
            vmbus_chan_ins_prilist(sc, newchan);
            spin_unlock_irq(&sc->vmbus_prichan_lock, flags);
            goto done;
        } else {
            spin_unlock_irq(&sc->vmbus_prichan_lock, flags);
            vmbus_chan_debug("duplicated primary chan%d", newchan->ch_id);
            return EINVAL;
        }
    } else { /* Sub-channel */
        if (prichan == NULL) {
            spin_unlock_irq(&sc->vmbus_prichan_lock, flags);
            vmbus_chan_debug("no primary chan for chan%d", newchan->ch_id);
            return EINVAL;
        }
        /*
         * Found the primary channel for this sub-channel and
         * move on.
         *
         * XXX refcnt prichan
         */
    }
    spin_unlock_irq(&sc->vmbus_prichan_lock, flags);

    /*
     * This is a sub-channel; link it with the primary channel.
     */
    assert(!VMBUS_CHAN_ISPRIMARY(newchan)); //new channel is not sub-channel
    assert(prichan != NULL); //no primary channel

    /*
     * Reference count this sub-channel; it will be dereferenced
     * when this sub-channel is closed.
     */
    assert(newchan->ch_refs == 1); //"chan%u: invalid refcnt %d", newchan->ch_id, newchan->ch_refs
    atomic_add32((u32*)&newchan->ch_refs, 1);

    newchan->ch_prichan = prichan;

    flags = spin_lock_irq(&prichan->ch_subchan_lock);
    vmbus_chan_ins_sublist(prichan, newchan);
    spin_unlock_irq(&prichan->ch_subchan_lock, flags);
done:
    /*
     * Hook this channel up for later revocation.
     */
    flags = spin_lock_irq(&sc->vmbus_chan_lock);
    vmbus_chan_ins_list(sc, newchan);
    spin_unlock_irq(&sc->vmbus_chan_lock, flags);

    vmbus_chan_debug("chan%d subidx%d offer", newchan->ch_id, newchan->ch_subidx);

    /* Select default cpu for this channel. */
    vmbus_chan_cpu_default(newchan);

    return 0;
}

void
vmbus_chan_cpu_set(struct vmbus_channel *chan, int cpu)
{
    assert(cpu >= 0);// && cpu < mp_ncpus);//"invalid cpu %d", cpu

    if (chan->ch_vmbus->vmbus_version == VMBUS_VERSION_WS2008 ||
        chan->ch_vmbus->vmbus_version == VMBUS_VERSION_WIN7) {
        /* Only cpu0 is supported */
        cpu = 0;
    }

    chan->ch_cpuid = cpu;
    chan->ch_vcpuid = VMBUS_PCPU_GET(chan->ch_vmbus, vcpuid, cpu);

    vmbus_chan_debug("chan%d assigned to cpu%d [vcpu%d]",
            chan->ch_id, chan->ch_cpuid, chan->ch_vcpuid);
}

static void
vmbus_chan_cpu_default(struct vmbus_channel *chan)
{
    /*
     * By default, pin the channel to cpu0.  Devices having
     * special channel-cpu mapping requirement should call
     * vmbus_chan_cpu_{set,rr}().
     */
    vmbus_chan_cpu_set(chan, 0);
}

struct vmbus_channel*
vmbus_chan_choffer_open_channel(vmbus_dev sc,
    const struct vmbus_message *msg)
{
    const struct vmbus_chanmsg_choffer *offer;
    struct vmbus_channel *chan;

    offer = (const struct vmbus_chanmsg_choffer *)msg->msg_data;
    chan = vmbus_chan_alloc(sc);
    assert(chan != INVALID_ADDRESS);

    chan->ch_id = offer->chm_chanid;
    chan->ch_subidx = offer->chm_subidx;
    vmbus_chan_debug("offer ch_id %d ch_subidx %d", chan->ch_id, chan->ch_subidx);
    chan->ch_guid_type = offer->chm_chtype;
    chan->ch_guid_inst = offer->chm_chinst;

    /* Batch reading is on by default */
    chan->ch_flags |= VMBUS_CHAN_FLAG_BATCHREAD;

    chan->ch_monprm->mp_connid = VMBUS_CONNID_EVENT;
    if (sc->vmbus_version != VMBUS_VERSION_WS2008)
        chan->ch_monprm->mp_connid = offer->chm_connid;

    if (offer->chm_flags1 & VMBUS_CHOFFER_FLAG1_HASMNF) {
        int trig_idx;

        /*
         * Setup MNF stuffs.
         */
        chan->ch_txflags |= VMBUS_CHAN_TXF_HASMNF;

        trig_idx = offer->chm_montrig / VMBUS_MONTRIG_LEN;
        if (trig_idx >= VMBUS_MONTRIGS_MAX)
            halt("invalid monitor trigger %d", offer->chm_montrig);
        chan->ch_montrig =
            &sc->vmbus_mnf2->mnf_trigs[trig_idx].mt_pending;

        chan->ch_montrig_mask =
            1 << (offer->chm_montrig % VMBUS_MONTRIG_LEN);
    }

    /*
     * Setup event flag.
     */
    chan->ch_evtflag =
        &sc->vmbus_tx_evtflags[chan->ch_id >> VMBUS_EVTFLAG_SHIFT];
    chan->ch_evtflag_mask = 1UL << (chan->ch_id & VMBUS_EVTFLAG_MASK);

    int error = vmbus_chan_add(chan);
    if (error) {
        vmbus_chan_debug("add chan%d failed: %d", chan->ch_id, error);
        atomic_subtract32((u32*)&chan->ch_refs, 1);
        vmbus_chan_free(chan);
        chan = NULL;
    }
    return chan;
}

static void
vmbus_chan_msgproc_chrescind(vmbus_dev sc,
    const struct vmbus_message *msg)
{
    vmbus_chan_debug("Channel removal ignored");
}

void
vmbus_chan_msgproc(vmbus_dev sc, const struct vmbus_message *msg)
{
    vmbus_chanmsg_proc_t msg_proc;
    const struct vmbus_chanmsg_hdr *hdr = (const struct vmbus_chanmsg_hdr *)msg->msg_data;
    uint32_t msg_type = hdr->chm_type;
    assert(msg_type < VMBUS_CHANMSG_TYPE_MAX); //"invalid message type %u", msg_type

    msg_proc = vmbus_chan_msgprocs[msg_type];
    if (msg_proc != NULL)
        msg_proc(sc, msg);
}

void
vmbus_chan_set_readbatch(struct vmbus_channel *chan, bool on)
{
    if (!on)
        chan->ch_flags &= ~VMBUS_CHAN_FLAG_BATCHREAD;
    else
        chan->ch_flags |= VMBUS_CHAN_FLAG_BATCHREAD;
}

int
vmbus_chan_prplist_nelem(int br_size, int prpcnt_max, int dlen_max)
{
    int elem_size;

    elem_size = __offsetof(struct vmbus_chanpkt_prplist,
        cp_range[0].gpa_page[prpcnt_max]);
    elem_size += dlen_max;
    elem_size = VMBUS_CHANPKT_TOTLEN(elem_size);

    return (vmbus_br_nelem(br_size, elem_size));
}

bool
vmbus_chan_is_revoked(const struct vmbus_channel *chan)
{

    if (chan->ch_stflags & VMBUS_CHAN_ST_REVOKED)
        return (true);
    return (false);
}

void
vmbus_chan_poll_messages(struct vmbus_channel *chan)
{
    chan->ch_vmbus->vmbus_event_proc(chan->ch_vmbus, 0);
    vmbus_poll_messages(chan->ch_vmbus);
}
