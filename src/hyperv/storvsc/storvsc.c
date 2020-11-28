/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2009-2012,2016-2017 Microsoft Corp.
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

/**
 * StorVSC driver for Hyper-V.  This driver presents a SCSI HBA interface.
 * Host control blocks (HCBs) are converted into VSCSI protocol messages which
 * are delivered to the parent partition StorVSP driver over the Hyper-V VMBUS.
 */

#include <kernel.h>
#include <page.h>
#include <hyperv_internal.h>
#include <hyperv.h>
#include <vmbus.h>
#include <net_system_structs.h>
#include <virtio/scsi.h>
#include "hv_vstorage.h"

#ifdef STORVSC_DEBUG
#define storvsc_debug(x, ...) do { rprintf("STORVSC: " x "\n", ##__VA_ARGS__); } while(0)
#else
#define storvsc_debug(x, ...)
#endif

// TODO: move to scsi.h?
/*
 * Device Types
 */
#define T_CDROM     0x05
#define T_NODEVICE  0x1f

#define BTSTAT_SUCCESS 0
#define BTSTAT_NOT_SUCCESS 1

#define STORVSC_MAX_LUNS_PER_TARGET    (64)
#define STORVSC_MAX_IO_REQUESTS        (STORVSC_MAX_LUNS_PER_TARGET * 2)
#define BLKVSC_MAX_IDE_DISKS_PER_TARGET    (1)
#define BLKVSC_MAX_IO_REQUESTS        STORVSC_MAX_IO_REQUESTS
#define STORVSC_MAX_TARGETS        (2)

#define VSTOR_PKT_SIZE    (sizeof(struct vstor_packet) - vmscsi_size_delta)

/*
 * 33 segments are needed to allow 128KB maxio, in case the data
 * in the first page is _not_ PAGE_SIZE aligned, e.g.
 *
 *     |<----------- 128KB ----------->|
 *     |                               |
 *  0  2K 4K    8K   16K   124K  128K  130K
 *  |  |  |     |     |       |     |  |
 *  +--+--+-----+-----+.......+-----+--+--+
 *  |  |  |     |     |       |     |  |  | DATA
 *  |  |  |     |     |       |     |  |  |
 *  +--+--+-----+-----+.......------+--+--+
 *     |  |                         |  |
 *     | 1|            31           | 1| ...... # of segments
 */
#define STORVSC_DATA_SEGCNT_MAX        66   /* 256KB maxio */
#define STORVSC_DATA_SEGSZ_MAX        PAGE_SIZE
#define STORVSC_DATA_SIZE_MAX        \
    ((STORVSC_DATA_SEGCNT_MAX - 1) * STORVSC_DATA_SEGSZ_MAX)

struct storvsc_softc;

enum storvsc_request_type {
    WRITE_TYPE,
    READ_TYPE,
    UNKNOWN_TYPE
};

#define STORVSC_CDB_SIZE    16

struct storvsc_hcb {
    struct list links;

    u16 target;
    u16 lun;
    u32 data_len;
    void *data_addr;

    u8 cdb[STORVSC_CDB_SIZE];
    u16 host_status;
    u16 scsi_status;

    thunk completion;
    u32 alloc_len;                     // allocated data length
    void *data;                        // allocated data

    u8 sense[SENSE_BUFFER_SIZE];
};


static u32 hv_storvsc_use_win8ext_flags = 1;

#define HV_STORVSC_MAX_IO           512
#define HV_STORVSC_RINGBUFFER_SIZE  (64 * PAGESIZE)

#define STORVSC_MAX_IO                        \
    vmbus_chan_prplist_nelem(HV_STORVSC_RINGBUFFER_SIZE,    \
       STORVSC_DATA_SEGCNT_MAX, VSTOR_PKT_SIZE)

struct storvsc_gpa_range {
    struct vmbus_gpa_range    gpa_range;
    uint64_t        gpa_page[STORVSC_DATA_SEGCNT_MAX];
} __packed;

struct hv_storvsc_request {
    struct list link;
    struct vstor_packet        vstor_packet;
    int                prp_cnt;
    struct storvsc_gpa_range    prp_list;
    void                *sense_data;
    uint8_t                sense_info_len;
    struct storvsc_hcb      *hcb;
    struct storvsc_softc        *softc;
    volatile boolean        channel_wait_msg_flag;
};

struct storvsc_softc {
    heap general;
    heap contiguous;                /* physically */

    heap hcb_objcache;
    struct spinlock mem_lock;

    struct list hcb_queue;
    struct spinlock queue_lock;

    struct vmbus_channel        *hs_chan;
    struct list             hs_free_list;
    struct spinlock        hs_lock;
    struct storvsc_driver_props    *hs_drv_props;
    uint32_t            hs_num_out_reqs;
    struct hv_storvsc_request    hs_init_req;
    struct hv_device            *hs_dev;

    u16 target;
    u16 lun;
    u64 capacity;
    u64 block_size;
};

/*
 * The size of the vmscsi_request has changed in win8. The
 * additional size is for the newly added elements in the
 * structure. These elements are valid only when we are talking
 * to a win8 host.
 * Track the correct size we need to apply.
 */
static int vmscsi_size_delta = sizeof(struct vmscsi_win8_extension);

struct storvsc_driver_props {
    char        *drv_name;
    char        *drv_desc;
    uint8_t        drv_max_luns_per_target;
    uint32_t    drv_max_ios_per_target;
    uint32_t    drv_ringbuffer_size;
};

enum hv_storage_type {
    DRIVER_BLKVSC,
    DRIVER_STORVSC,
    DRIVER_UNKNOWN
};

#define HV_STORAGE_SUPPORTS_MULTI_CHANNEL 0x1

/* {ba6163d9-04a1-4d29-b605-72e2ffb1dc7f} */
static const struct hyperv_guid gStorVscDeviceType={
    .hv_guid = {0xd9, 0x63, 0x61, 0xba, 0xa1, 0x04, 0x29, 0x4d,
         0xb6, 0x05, 0x72, 0xe2, 0xff, 0xb1, 0xdc, 0x7f}
};

/* {32412632-86cb-44a2-9b5c-50d1417354f5} */
static const struct hyperv_guid gBlkVscDeviceType={
    .hv_guid = {0x32, 0x26, 0x41, 0x32, 0xcb, 0x86, 0xa2, 0x44,
         0x9b, 0x5c, 0x50, 0xd1, 0x41, 0x73, 0x54, 0xf5}
};

static struct storvsc_driver_props g_drv_props_table[] = {
    {"blkvsc", "Hyper-V IDE",
     BLKVSC_MAX_IDE_DISKS_PER_TARGET, BLKVSC_MAX_IO_REQUESTS,
     20*PAGESIZE},
    {"storvsc", "Hyper-V SCSI",
     STORVSC_MAX_LUNS_PER_TARGET, STORVSC_MAX_IO_REQUESTS,
     20*PAGESIZE}
};

/*
 * Sense buffer size changed in win8; have a run-time
 * variable to track the size we should use.
 */
static int sense_buffer_size = PRE_WIN8_STORVSC_SENSE_BUFFER_SIZE;

/*
 * The storage protocol version is determined during the
 * initial exchange with the host.  It will indicate which
 * storage functionality is available in the host.
*/
static int vmstor_proto_version;

struct vmstor_proto {
        int proto_version;
        int sense_buffer_size;
        int vmscsi_size_delta;
};

static const struct vmstor_proto vmstor_proto_list[] = {
        {
                VMSTOR_PROTOCOL_VERSION_WIN10,
                POST_WIN7_STORVSC_SENSE_BUFFER_SIZE,
                0
        },
        {
                VMSTOR_PROTOCOL_VERSION_WIN8_1,
                POST_WIN7_STORVSC_SENSE_BUFFER_SIZE,
                0
        },
        {
                VMSTOR_PROTOCOL_VERSION_WIN8,
                POST_WIN7_STORVSC_SENSE_BUFFER_SIZE,
                0
        },
        {
                VMSTOR_PROTOCOL_VERSION_WIN7,
                PRE_WIN8_STORVSC_SENSE_BUFFER_SIZE,
                sizeof(struct vmscsi_win8_extension),
        },
        {
                VMSTOR_PROTOCOL_VERSION_WIN6,
                PRE_WIN8_STORVSC_SENSE_BUFFER_SIZE,
                sizeof(struct vmscsi_win8_extension),
        }
};

static enum hv_storage_type storvsc_get_storage_type(hv_device *dev);
static void hv_storvsc_on_channel_callback(struct vmbus_channel *chan, void *xsc);
static void hv_storvsc_on_iocompletion( struct storvsc_softc *sc,
                    struct vstor_packet *vstor_packet, struct hv_storvsc_request *request);
static void hv_storvsc_connect_vsp(struct storvsc_softc *);
static void storvsc_report_luns(struct storvsc_softc *sc, storage_attach a, u16 target);
static void storvsc_test_unit_ready(struct storvsc_softc *sc, storage_attach a, u16 target, u16 lun, u16 retry_count);
static void storvsc_action_io_queued(struct storvsc_softc *sc, struct storvsc_hcb *hcb,
                                     u16 target, u16 lun, void *buf, u64 length);
static void storvsc_action(struct storvsc_softc *sc, struct storvsc_hcb *hcb, u16 target, u16 lun);
static void create_storvsc_request(struct storvsc_hcb *hcb, struct hv_storvsc_request *reqp);
static void storvsc_free_request(struct storvsc_softc *sc, struct hv_storvsc_request *reqp);
static void storvsc_io_done(struct hv_storvsc_request *reqp);
static void storvsc_process_hcb_queue(struct storvsc_softc *sc);

/* used for stripping non-printable characters of the inquiry data na extracting vendor */
static void storvsc_cam_strvis(u8 *dst, const u8 *src, int srclen, int dstlen)
{

    /* Trim leading/trailing spaces, nulls. */
    while (srclen > 0 && src[0] == ' ')
        src++, srclen--;
    while (srclen > 0
        && (src[srclen-1] == ' ' || src[srclen-1] == '\0'))
        srclen--;

    while (srclen > 0 && dstlen > 1) {
        u8 *cur_pos = dst;

        if (*src < 0x20 || *src >= 0x80) {
            /* SCSI-II Specifies that these should never occur. */
            /* non-printable character */
            if (dstlen > 4) {
                *cur_pos++ = '\\';
                *cur_pos++ = ((*src & 0300) >> 6) + '0';
                *cur_pos++ = ((*src & 0070) >> 3) + '0';
                *cur_pos++ = ((*src & 0007) >> 0) + '0';
            } else {
                *cur_pos++ = '?';
            }
        } else {
            /* normal character */
            *cur_pos++ = *src;
        }
        src++;
        srclen--;
        dstlen -= cur_pos - dst;
        dst = cur_pos;
    }
    *dst = '\0';
}

static inline void hv_storvsc_prepare_wait_for_message(struct hv_storvsc_request *req)
{
    req->channel_wait_msg_flag = true;
}

static inline void hv_storvsc_wait_for_channel_message(struct hv_storvsc_request *req)
{
    while (req->channel_wait_msg_flag) {
        vmbus_chan_poll_messages(req->softc->hs_chan);
        if (!req->channel_wait_msg_flag)
            break;
        kernel_delay(100);
    }
}

/**
 * @brief initialize channel connection to parent partition
 *
 * @param sc  a Hyper-V device pointer
 * @returns  0 on success, non-zero error on failure
 */
static void hv_storvsc_channel_init(struct storvsc_softc *sc)
{
    struct hv_storvsc_request *request = &sc->hs_init_req;
    zero(request, sizeof(struct hv_storvsc_request));
    struct vstor_packet *vstor_packet = &request->vstor_packet;
    request->softc = sc;

    /**
     * Initiate the vsc/vsp initialization protocol on the open channel
     */
    hv_storvsc_prepare_wait_for_message(request);

    vstor_packet->operation = VSTOR_OPERATION_BEGININITIALIZATION;
    vstor_packet->flags = REQUEST_COMPLETION_FLAG;


    int ret = vmbus_chan_send(sc->hs_chan,
        VMBUS_CHANPKT_TYPE_INBAND, VMBUS_CHANPKT_FLAG_RC,
        vstor_packet, VSTOR_PKT_SIZE, (uint64_t)request);
    assert(ret == 0);

    hv_storvsc_wait_for_channel_message(request);

    assert(vstor_packet->operation == VSTOR_OPERATION_COMPLETEIO);
    assert(vstor_packet->status == 0);

    for (int i = 0; i < _countof(vmstor_proto_list); i++) {
        /* reuse the packet for version range supported */

        zero(vstor_packet, sizeof(struct vstor_packet));
        vstor_packet->operation = VSTOR_OPERATION_QUERYPROTOCOLVERSION;
        vstor_packet->flags = REQUEST_COMPLETION_FLAG;

        vstor_packet->u.version.major_minor =
            vmstor_proto_list[i].proto_version;

        /* revision is only significant for Windows guests */
        vstor_packet->u.version.revision = 0;

        hv_storvsc_prepare_wait_for_message(request);
        ret = vmbus_chan_send(sc->hs_chan,
            VMBUS_CHANPKT_TYPE_INBAND, VMBUS_CHANPKT_FLAG_RC,
            vstor_packet, VSTOR_PKT_SIZE, (uint64_t)request);

        assert(ret == 0);

        hv_storvsc_wait_for_channel_message(request);

        assert(vstor_packet->operation == VSTOR_OPERATION_COMPLETEIO);
        if (vstor_packet->status == 0) {
            vmstor_proto_version =
                vmstor_proto_list[i].proto_version;
            sense_buffer_size =
                vmstor_proto_list[i].sense_buffer_size;
            vmscsi_size_delta =
                vmstor_proto_list[i].vmscsi_size_delta;
            break;
        }
    }

    assert(vstor_packet->status == 0);

    storvsc_debug("storvsc proto version: %d.%d",
                  VMSTOR_PROTOCOL_MAJOR(vmstor_proto_version),
                  VMSTOR_PROTOCOL_MINOR(vmstor_proto_version));

    /**
     * Query channel properties
     */
    zero(vstor_packet, sizeof(struct vstor_packet));
    vstor_packet->operation = VSTOR_OPERATION_QUERYPROPERTIES;
    vstor_packet->flags = REQUEST_COMPLETION_FLAG;

    hv_storvsc_prepare_wait_for_message(request);
    ret = vmbus_chan_send(sc->hs_chan,
        VMBUS_CHANPKT_TYPE_INBAND, VMBUS_CHANPKT_FLAG_RC,
        vstor_packet, VSTOR_PKT_SIZE, (uint64_t)request);
    assert(ret == 0);

    hv_storvsc_wait_for_channel_message(request);

    assert(vstor_packet->operation == VSTOR_OPERATION_COMPLETEIO);
    assert(vstor_packet->status == 0);


#ifdef STORVSC_DEBUG
    uint16_t max_subch = vstor_packet->u.chan_props.max_channel_cnt;
    // we don't use subchannels but let's report these capabilities
    /* multi-channels feature is supported by WIN8 and above version */
    uint32_t version = vmbus_current_version;
    boolean support_multichannel = false;
    if (version != VMBUS_VERSION_WIN7 && version != VMBUS_VERSION_WS2008 &&
        (vstor_packet->u.chan_props.flags &
         HV_STORAGE_SUPPORTS_MULTI_CHANNEL)) {
        support_multichannel = true;
    }

    storvsc_debug("max chans %d%s", max_subch + 1, support_multichannel ? ", multi-chan capable" : "");
#endif
    zero(vstor_packet, sizeof(struct vstor_packet));
    vstor_packet->operation = VSTOR_OPERATION_ENDINITIALIZATION;
    vstor_packet->flags = REQUEST_COMPLETION_FLAG;

    hv_storvsc_prepare_wait_for_message(request);
    ret = vmbus_chan_send(sc->hs_chan,
        VMBUS_CHANPKT_TYPE_INBAND, VMBUS_CHANPKT_FLAG_RC,
        vstor_packet, VSTOR_PKT_SIZE, (uint64_t)request);
    assert(ret == 0);

    hv_storvsc_wait_for_channel_message(request);

    assert(vstor_packet->operation == VSTOR_OPERATION_COMPLETEIO);
    assert(vstor_packet->status == 0);
}

/**
 * @brief Open channel connection to paraent partition StorVSP driver
 *
 * Open and initialize channel connection to parent partition StorVSP driver.
 *
 * @param pointer to a Hyper-V device
 * @returns 0 on success, non-zero error on failure
 */
static void hv_storvsc_connect_vsp(struct storvsc_softc *sc)
{
    struct vmstor_chan_props props;

    zero(&props, sizeof(struct vmstor_chan_props));

    /*
     * Open the channel
     */
    vmbus_chan_open(
        sc->hs_chan,
        sc->hs_drv_props->drv_ringbuffer_size,
        sc->hs_drv_props->drv_ringbuffer_size,
        (void *)&props,
        sizeof(struct vmstor_chan_props),
        hv_storvsc_on_channel_callback, sc, bhqueue);

    hv_storvsc_channel_init(sc);
}

/**
 * @brief Function to initiate an I/O request
 *
 * @param sc Hyper-V device pointer
 * @param request pointer to a request structure
 * @returns 0 on success, non-zero error on failure
 */
static int hv_storvsc_io_request(struct storvsc_softc *sc, struct hv_storvsc_request *request)
{
    struct vstor_packet *vstor_packet = &request->vstor_packet;

    vstor_packet->flags |= REQUEST_COMPLETION_FLAG;

    vstor_packet->u.vm_srb.length =
        sizeof(struct vmscsi_req) - vmscsi_size_delta;

    vstor_packet->u.vm_srb.sense_info_len = sense_buffer_size;

    vstor_packet->u.vm_srb.transfer_len =
        request->prp_list.gpa_range.gpa_len;

    vstor_packet->operation = VSTOR_OPERATION_EXECUTESRB;

    int ret;
    if (request->prp_list.gpa_range.gpa_len) {
        ret = vmbus_chan_send_prplist(sc->hs_chan,
            &request->prp_list.gpa_range, request->prp_cnt,
            vstor_packet, VSTOR_PKT_SIZE, (uint64_t)request);
    } else {
        ret = vmbus_chan_send(sc->hs_chan,
            VMBUS_CHANPKT_TYPE_INBAND, VMBUS_CHANPKT_FLAG_RC,
            vstor_packet, VSTOR_PKT_SIZE, (uint64_t)request);
    }

    if (ret != 0) {
        rprintf("Unable to send packet %p ret %d", vstor_packet, ret);
    } else {
        atomic_add32(&sc->hs_num_out_reqs, 1);
    }

    return (ret);
}

/**
 * Process IO_COMPLETION_OPERATION and ready
 * the result to be completed for upper layer
 * processing by the CAM layer.
 */
static void hv_storvsc_on_iocompletion(struct storvsc_softc *sc,
                                       struct vstor_packet *vstor_packet,
                                       struct hv_storvsc_request *request)
{
    struct vmscsi_req *vm_srb = &vstor_packet->u.vm_srb;

    /*
     * Copy some fields of the host's response into the request structure,
     * because the fields will be used later in storvsc_io_done().
     */
    request->vstor_packet.u.vm_srb.scsi_status = vm_srb->scsi_status;
    request->vstor_packet.u.vm_srb.srb_status = vm_srb->srb_status;
    request->vstor_packet.u.vm_srb.transfer_len = vm_srb->transfer_len;

    if (((vm_srb->scsi_status & 0xFF) == SCSI_STATUS_CHECK_COND) &&
            (vm_srb->srb_status & SRB_STATUS_AUTOSENSE_VALID)) {
        /* Autosense data available */

        assert(vm_srb->sense_info_len <= request->sense_info_len);

        runtime_memcpy(request->sense_data, vm_srb->u.sense_data,
            vm_srb->sense_info_len);

        request->sense_info_len = vm_srb->sense_info_len;
    }

    storvsc_io_done(request);
    atomic_subtract32(&sc->hs_num_out_reqs, 1);
    storvsc_process_hcb_queue(sc);
}

static void hv_storvsc_on_channel_callback(struct vmbus_channel *channel, void *xsc)
{
    int ret = 0;
    struct storvsc_softc *sc = xsc;
    uint32_t bytes_recvd;
    uint64_t request_id;
    uint8_t packet[pad(sizeof(struct vstor_packet), 8)];
    struct hv_storvsc_request *request;
    struct vstor_packet *vstor_packet;

    bytes_recvd = pad(VSTOR_PKT_SIZE, 8);
    ret = vmbus_chan_recv(channel, packet, (int*)&bytes_recvd, &request_id);
    assert(ret != ENOBUFS); //storvsc recvbuf is not large enough
    /* XXX check bytes_recvd to make sure that it contains enough data */

    while ((ret == 0) && (bytes_recvd > 0)) {
        request = (struct hv_storvsc_request *)request_id;

        if (request == &sc->hs_init_req) {
            runtime_memcpy(&request->vstor_packet, packet,
                   sizeof(struct vstor_packet));
            request->channel_wait_msg_flag = false;
        } else {
            vstor_packet = (struct vstor_packet *)packet;
            switch(vstor_packet->operation) {
            case VSTOR_OPERATION_COMPLETEIO:
                if (!request)
                    halt("VMBUS: storvsc received a "
                        "packet with 0 request id in "
                        "COMPLETEIO operation.");

                hv_storvsc_on_iocompletion(sc,
                            vstor_packet, request);
                break;
            case VSTOR_OPERATION_REMOVEDEVICE:
                storvsc_debug("VMBUS: storvsc operation %d not "
                    "implemented.", vstor_packet->operation);
                // not supported
                break;
            case VSTOR_OPERATION_ENUMERATE_BUS:
                // not supported
                halt("VSTOR_OPERATION_ENUMERATE_BUS not supported");
                break;
            default:
                break;
            }
        }

        bytes_recvd = pad(VSTOR_PKT_SIZE, 8);
        ret = vmbus_chan_recv(channel, packet, (int*)&bytes_recvd,
            &request_id);
        assert(ret != ENOBUFS); //storvsc recvbuf is not large enough
        /*
         * XXX check bytes_recvd to make sure that it contains
         * enough data
         */
    }
}

static void storvsc_init_requests(struct storvsc_softc *sc)
{
    list_init(&sc->hs_free_list);

    for (int i = 0; i < sc->hs_drv_props->drv_max_ios_per_target; ++i) {
        struct hv_storvsc_request *reqp = allocate(sc->general, sizeof(struct hv_storvsc_request));
        assert(reqp != INVALID_ADDRESS);
        reqp->softc = sc;
        list_push_back(&sc->hs_free_list, &reqp->link);
    }
}

static void storvsc_hcb_dealloc(struct storvsc_softc *sc, struct storvsc_hcb *hcb)
{
    u64 flags = spin_lock_irq(&sc->mem_lock);
    if (hcb->alloc_len) {
        deallocate(sc->contiguous, hcb->data, pad(hcb->alloc_len, sc->contiguous->pagesize));
    }
    deallocate(sc->hcb_objcache, hcb, sizeof(struct storvsc_hcb));
    spin_unlock_irq(&sc->mem_lock, flags);
}

static struct storvsc_hcb *storvsc_hcb_alloc(struct storvsc_softc* sc, u16 target, u16 lun, u8 cmd)
{
    int alloc_len = scsi_data_len(cmd);
    u64 flags = spin_lock_irq(&sc->mem_lock);
    struct storvsc_hcb *hcb = allocate(sc->hcb_objcache, sizeof(struct storvsc_hcb));
    assert(hcb != INVALID_ADDRESS);
    if (alloc_len) {
        hcb->data = allocate(sc->contiguous, alloc_len);
        assert(hcb->data != INVALID_ADDRESS);
        hcb->alloc_len = alloc_len;
    } else {
        hcb->data = 0;
        hcb->alloc_len = 0;
    }
    spin_unlock_irq(&sc->mem_lock, flags);
    zero(hcb->cdb, sizeof(hcb->cdb));
    hcb->cdb[0] = cmd;
    return hcb;
}

closure_function(5, 0, void, storvsc_scsi_io_done,
                 status_handler, sh, void *, buf, u64, len,
                 struct storvsc_softc*, s, struct storvsc_hcb*, hcb)
{
    struct storvsc_hcb *hcb = bound(hcb);

    status st = 0;
    if (hcb->host_status != BTSTAT_SUCCESS) {
        st = timm("result", "response %d", hcb->host_status);
    } else if (hcb->scsi_status != SCSI_STATUS_OK) {
        scsi_dump_sense(hcb->sense, sizeof(hcb->sense));
        st = timm("result", "status %d", hcb->scsi_status);
    }
    apply(bound(sh), st);
    closure_finish();
}

static void storvsc_io(struct storvsc_softc *sc, u8 cmd, void *buf, range blocks, status_handler sh)
{
    struct storvsc_hcb *r = storvsc_hcb_alloc(sc, sc->target, sc->lun, cmd);
    struct scsi_cdb_readwrite_16 *cdb = (struct scsi_cdb_readwrite_16 *)r->cdb;
    cdb->opcode = cmd;
    u32 nblocks = range_span(blocks);
    cdb->addr = htobe64(blocks.start);
    cdb->length = htobe32(nblocks);
    r->completion = closure(sc->general, storvsc_scsi_io_done, sh, buf, nblocks * sc->block_size, sc, r);
    storvsc_action_io_queued(sc, r, sc->target, sc->lun, buf, nblocks * sc->block_size);
}

closure_function(1, 3, void, storvsc_write,
                 struct storvsc_softc*, s,
                 void *, buf, range, blocks, status_handler, sh)
{
    storvsc_io(bound(s), SCSI_CMD_WRITE_16, buf, blocks, sh);
}

closure_function(1, 3, void, storvsc_read,
                 struct storvsc_softc*, s,
                 void *, buf, range, blocks, status_handler, sh)
{
    storvsc_io(bound(s), SCSI_CMD_READ_16, buf, blocks, sh);
}

closure_function(5, 0, void, storvsc_read_capacity_done,
                 storage_attach, a, u16, target, u16, lun,
                 struct storvsc_softc*, s, struct storvsc_hcb *, hcb)
{
    struct storvsc_softc* s = bound(s);
    u16 target = bound(target);
    u16 lun = bound(lun);
    struct storvsc_hcb *hcb = bound(hcb);
    storvsc_debug("%s: target %d, lun %d, host_status %d, scsi_status %d",
        __func__, target, lun, hcb->host_status, hcb->scsi_status);
    if (hcb->host_status != BTSTAT_SUCCESS) {
        scsi_dump_sense(hcb->sense, sizeof(hcb->sense));
        goto out;
    }
    if (hcb->scsi_status != SCSI_STATUS_OK) {
        scsi_dump_sense(hcb->sense, sizeof(hcb->sense));
        goto out;
    }

    if (s->capacity > 0) {
        // attach only first disk
        goto out;
    }

    struct scsi_res_read_capacity_16 *res = (struct scsi_res_read_capacity_16 *) hcb->data;
    u64 sectors = be64toh(res->addr) + 1; // returns address of last sector
    s->block_size = be32toh(res->length);
    s->capacity = sectors * s->block_size;
    s->target = target;
    s->lun = lun;
    storvsc_debug("%s: target %d, lun %d, block size 0x%lx, capacity 0x%lx",
        __func__, target, lun, s->block_size, s->capacity);

    block_io in = closure(s->general, storvsc_read, s);
    block_io out = closure(s->general, storvsc_write, s);
    apply(bound(a), in, out, s->capacity);
  out:
    closure_finish();
}

static void storvsc_next_target(struct storvsc_softc *sc, storage_attach a, u16 target)
{
    if (sc->capacity > 0) {
        // scan only until first disk is found
        return;
    }

    if (target >= STORVSC_MAX_TARGETS)
        return;

    // scan next target
    storvsc_report_luns(sc, a, target + 1);
}

closure_function(6, 0, void, storvsc_test_unit_ready_done,
                 storage_attach, a, u16, target, u16, lun, int, retry_count,
                 struct storvsc_softc*, s, struct storvsc_hcb *, hcb)
{
    struct storvsc_hcb *hcb = bound(hcb);
    struct storvsc_softc *sc = bound(s);
    storage_attach a = bound(a);
    u16 target = bound(target);
    u16 lun = bound(lun);
    int retry_count = bound(retry_count);

    storvsc_debug("%s: target %d, lun %d, host_status %d, scsi_status %d",
        __func__, target, lun, hcb->host_status, hcb->scsi_status);
    if (hcb->host_status != BTSTAT_SUCCESS) {
        storvsc_next_target(sc, a, target);
        goto out;
    }

    if (hcb->scsi_status != SCSI_STATUS_OK) {
        if (retry_count < 3) {
            storvsc_test_unit_ready(sc, a, target, lun, retry_count);
        } else {
            scsi_dump_sense(hcb->sense, sizeof(hcb->sense));
            storvsc_next_target(sc, a, target);
        }
        goto out;
    }

    // read capacity
    struct storvsc_hcb *r = storvsc_hcb_alloc(sc, target, lun, SCSI_CMD_SERVICE_ACTION);
    struct scsi_cdb_read_capacity_16 *cdb = (struct scsi_cdb_read_capacity_16 *)r->cdb;
    cdb->service_action = SRC16_SERVICE_ACTION;
    cdb->alloc_len = htobe32(r->alloc_len);
    r->completion = closure(sc->general, storvsc_read_capacity_done, a, target, lun, sc, r);
    storvsc_action(sc, r, target, lun);
  out:
    closure_finish();
}

static void storvsc_test_unit_ready(struct storvsc_softc *sc, storage_attach a, u16 target, u16 lun, u16 retry_count)
{
    struct storvsc_hcb *r = storvsc_hcb_alloc(sc, target, lun, SCSI_CMD_TEST_UNIT_READY);
    r->completion = closure(sc->general, storvsc_test_unit_ready_done, a, target, lun,
                              retry_count + 1, sc, r);
    storvsc_action(sc, r, target, lun);
}

closure_function(5, 0, void, storvsc_inquiry_done,
                 storage_attach, a, u16, target, u16, lun,
                 struct storvsc_softc*, s, struct storvsc_hcb *, hcb)
{
    struct storvsc_hcb *hcb = bound(hcb);
    u16 target = bound(target);
    u16 lun = bound(lun);
    storvsc_debug("%s: target %d, lun %d, host_status %d, scsi_status %d",
        __func__, target, lun, hcb->host_status, hcb->scsi_status);
    if (hcb->host_status != BTSTAT_SUCCESS || hcb->scsi_status != SCSI_STATUS_OK) {
        if (hcb->scsi_status != SCSI_STATUS_OK)
            scsi_dump_sense(hcb->sense, sizeof(hcb->sense));
        storvsc_next_target(bound(s), bound(a), target);
        closure_finish();
        return;
    }

#ifdef STORVSC_DEBUG
    struct scsi_res_inquiry *res = (struct scsi_res_inquiry *) hcb->data;
    storvsc_debug("%s: vendor %b, product %b, revision %b",
        __func__,
        alloca_wrap_buffer(res->vendor, sizeof(res->vendor)),
        alloca_wrap_buffer(res->product, sizeof(res->product)),
        alloca_wrap_buffer(res->revision, sizeof(res->revision)));
#endif

    // test unit ready
    storvsc_test_unit_ready(bound(s), bound(a), target, lun, 0);

    closure_finish();
}

closure_function(4, 0, void, storvsc_report_luns_done,
                 storage_attach, a, u16, target,
                 struct storvsc_softc*, s, struct storvsc_hcb *, hcb)
{
    struct storvsc_softc *sc = bound(s);
    struct storvsc_hcb *hcb = bound(hcb);
    u16 target = bound(target);
    storvsc_debug("%s: target %d, hcb: %x, host_status %d, scsi_status %d",
        __func__, target, hcb, hcb->host_status, hcb->scsi_status);
    if (hcb->host_status != BTSTAT_SUCCESS || hcb->scsi_status != SCSI_STATUS_OK) {
        if (hcb->scsi_status != SCSI_STATUS_OK)
            scsi_dump_sense(hcb->sense, sizeof(hcb->sense));
        storvsc_debug("%s: NOT SUCCESS: host_status %d, scsi_status %d", __func__, hcb->host_status,
                     hcb->scsi_status);
        storvsc_next_target(sc, bound(a), target);
        closure_finish();
        return;
    }

    struct scsi_res_report_luns *res = (struct scsi_res_report_luns *) hcb->data;
    u32 length = be32toh(res->length);
    u32 luns_num = length / sizeof(res->lundata[0]);
    storvsc_debug("%s: got %d luns", __func__, luns_num);
    u8 max_luns = sc->hs_drv_props->drv_max_luns_per_target;
    for (u32 i = 0; i < MIN(max_luns, luns_num); i++) {
        u16 lun = (res->lundata[i] & 0xffff) >> 8;
        storvsc_debug("%s: got lun %d (lundata 0x%08lx)", __func__, lun, res->lundata[i]);

        // inquiry
        struct storvsc_hcb *r = storvsc_hcb_alloc(sc, target, lun, SCSI_CMD_INQUIRY);
        struct scsi_cdb_inquiry *cdb = (struct scsi_cdb_inquiry *)r->cdb;
        /* does not work on Azure A0/A1 instances if r->alloc_len is set */
        cdb->length = htobe16(SHORT_INQUIRY_LENGTH);
        r->completion = closure(sc->general, storvsc_inquiry_done, bound(a), target, lun, sc, r);
        storvsc_action(sc, r, target, lun);
    }
    closure_finish();
}

static void storvsc_report_luns(struct storvsc_softc *sc, storage_attach a, u16 target)
{
    struct storvsc_hcb *r = storvsc_hcb_alloc(sc, target, 0, SCSI_CMD_REPORT_LUNS);
    struct scsi_cdb_report_luns *cdb = (struct scsi_cdb_report_luns *)r->cdb;
    cdb->select_report = RPL_REPORT_DEFAULT;
    cdb->length = htobe32(r->alloc_len);
    r->completion = closure(sc->general, storvsc_report_luns_done, a, target, sc, r);
    storvsc_action(sc, r, target, 0);
}

/**
 * @brief StorVSC attach function
 *
 * Function responsible for allocating per-device structures
 * scanning for available LUNs to be used for SCSI device peripherals.
 */
static status storvsc_attach(kernel_heaps kh, hv_device* device, storage_attach a)
{
    heap h = heap_locked(kh);

    struct storvsc_softc *sc = allocate_zero(h, sizeof(struct storvsc_softc));
    assert(sc != INVALID_ADDRESS);

    sc->general = h;
    sc->contiguous = heap_backed(kh);
    sc->hs_dev = device;

    enum hv_storage_type stor_type = storvsc_get_storage_type(device);
    switch (stor_type) {
    case DRIVER_BLKVSC:
        storvsc_debug("Enlightened ATA/IDE detected");
        break;
    case DRIVER_STORVSC:
        storvsc_debug("Enlightened SCSI device detected");
        break;
    case DRIVER_UNKNOWN:
        halt("Unknown storvsc device detected");
    }

    list_init(&sc->hcb_queue);
    spin_lock_init(&sc->queue_lock);
    // setup hcb cache
    sc->hcb_objcache = allocate_objcache(sc->general, sc->contiguous,
                                         sizeof(struct storvsc_hcb), PAGESIZE_2M);
    spin_lock_init(&sc->mem_lock);

    sc->hs_chan = device->channel;


    /* fill in driver specific properties */
    sc->hs_drv_props = &g_drv_props_table[stor_type];
    sc->hs_drv_props->drv_ringbuffer_size = HV_STORVSC_RINGBUFFER_SIZE;
    sc->hs_drv_props->drv_max_ios_per_target = HV_STORVSC_MAX_IO;
    storvsc_debug("storvsc ringbuffer size: %d, max_io: %d",
                  sc->hs_drv_props->drv_ringbuffer_size,
                  sc->hs_drv_props->drv_max_ios_per_target);

    spin_lock_init(&sc->hs_lock); //hvslck

    storvsc_init_requests(sc);

    hv_storvsc_connect_vsp(sc);

    // scan bus
    storvsc_report_luns(sc, a, 0);

    return STATUS_OK;
}

/**
 * @brief StorVSC device action function
 */
static boolean storvsc_action_io(struct storvsc_softc *sc, struct storvsc_hcb *hcb)
{
    u64 flags = spin_lock_irq(&sc->hs_lock);
    if (list_empty(&sc->hs_free_list)) {
        spin_unlock_irq(&sc->hs_lock, flags);
        return false;
    }

    struct list *l = list_get_next(&sc->hs_free_list);
    assert(l);
    list_delete(l);
    spin_unlock_irq(&sc->hs_lock, flags);

    struct hv_storvsc_request *reqp = struct_from_list(l, struct hv_storvsc_request *, link);

    /* XXX this is ugly */
    zero(reqp, sizeof(struct hv_storvsc_request));
    reqp->softc = sc;

    create_storvsc_request(hcb, reqp);

    int res = hv_storvsc_io_request(sc, reqp);
    if (res  != 0) {
        storvsc_debug("hv_storvsc_io_request failed with %d", res);
        storvsc_free_request(sc, reqp);
        return false;
    }
    return true;
}

static void storvsc_action_io_queued(struct storvsc_softc *sc, struct storvsc_hcb *hcb, u16 target, u16 lun,
                                     void *buf, u64 length)
{
    hcb->data_len = length;
    if (!hcb->data_len) {
        hcb->data_addr = 0;
    } else {
        hcb->data_addr = buf;
    }
    hcb->target = target;
    hcb->lun = lun;

    // order: put into hcb queue if not empty
    u64 flags = spin_lock_irq(&sc->queue_lock);
    if (!list_empty(&sc->hcb_queue)) {
        list_push_back(&sc->hcb_queue, &hcb->links);
        spin_unlock_irq(&sc->queue_lock, flags);
        return;
    }
    spin_unlock_irq(&sc->queue_lock, flags);

    if (!storvsc_action_io(sc, hcb)) {
        u64 flags = spin_lock_irq(&sc->queue_lock);
        list_push_back(&sc->hcb_queue, &hcb->links);
        spin_unlock_irq(&sc->queue_lock, flags);
    }
}

static inline void storvsc_action(struct storvsc_softc *sc, struct storvsc_hcb *hcb, u16 target, u16 lun)
{
    storvsc_action_io_queued(sc, hcb, target, lun, hcb->data, hcb->alloc_len);
}

/**
 * @brief Fill in a request structure based on a CAM control block
 *
 * Fills in a request structure based on the contents of a host control
 * block.  The request structure holds the payload information for
 * VSCSI protocol request.
 *
 * @param hcb pointer to a host contorl block
 * @param reqp pointer to a request structure
 */
static void create_storvsc_request(struct storvsc_hcb *hcb, struct hv_storvsc_request *reqp)
{
    reqp->vstor_packet.u.vm_srb.target_id = hcb->target;
    reqp->vstor_packet.u.vm_srb.lun = hcb->lun;

    reqp->vstor_packet.u.vm_srb.cdb_len = sizeof(hcb->cdb);
    runtime_memcpy(&reqp->vstor_packet.u.vm_srb.u.cdb, hcb->cdb, sizeof(hcb->cdb));
    if (hv_storvsc_use_win8ext_flags) {
        reqp->vstor_packet.u.vm_srb.win8_extension.time_out_value = 60;
        reqp->vstor_packet.u.vm_srb.win8_extension.srb_flags |=
            SRB_FLAGS_DISABLE_SYNCH_TRANSFER;
    }
    u8 opcode = hcb->cdb[0];
    if (opcode == SCSI_CMD_WRITE_16) {
        reqp->vstor_packet.u.vm_srb.data_in = WRITE_TYPE;
        if (hv_storvsc_use_win8ext_flags) {
            reqp->vstor_packet.u.vm_srb.win8_extension.srb_flags |=
                SRB_FLAGS_DATA_OUT;
        }
    } else {
        reqp->vstor_packet.u.vm_srb.data_in = READ_TYPE;
        if (hv_storvsc_use_win8ext_flags) {
            reqp->vstor_packet.u.vm_srb.win8_extension.srb_flags |=
                SRB_FLAGS_DATA_IN;
        }
    }

    reqp->sense_data     = &hcb->sense;
    reqp->sense_info_len = sizeof(hcb->sense);

    reqp->hcb = hcb;

    uint32_t bytes_to_copy = hcb->data_len;
    struct storvsc_gpa_range *prplist = &reqp->prp_list;
    uint32_t pfn_num = 0;
    while (bytes_to_copy != 0) {
        u64 phys_addr = physical_from_virtual(hcb->data_addr + (hcb->data_len - bytes_to_copy));
        assert(phys_addr != INVALID_PHYSICAL);
        if (pfn_num == 0) {
            prplist->gpa_range.gpa_len = hcb->data_len;
            prplist->gpa_range.gpa_ofs = phys_addr & PAGEMASK;
        }
        prplist->gpa_page[pfn_num] = phys_addr >> PAGELOG;
        int page_offset = phys_addr - page_from_pte(phys_addr);
        int bytes = MIN(PAGESIZE - page_offset, bytes_to_copy);
        bytes_to_copy -= bytes;
        pfn_num++;
    }
    reqp->prp_cnt = pfn_num;
    assert(reqp->prp_cnt <= STORVSC_DATA_SEGCNT_MAX);
}

static uint32_t is_scsi_valid(const struct scsi_res_inquiry *inq_data)
{
    u8 type;

    type = SID_TYPE(inq_data);
    if (type == T_NODEVICE)
        return (0);
    if (SID_QUAL(inq_data) == SID_QUAL_BAD_LU)
        return (0);
    return (1);
}

static void storvsc_process_hcb_queue(struct storvsc_softc *sc) {
    u64 flags = spin_lock_irq(&sc->queue_lock);
    list_foreach(&sc->hcb_queue, i) {
        assert(i);
        struct storvsc_hcb *hcb = struct_from_list(i, struct storvsc_hcb *, links);
        if (!storvsc_action_io(sc, hcb))
            break;
        list_delete(i);
    }
    spin_unlock_irq(&sc->queue_lock, flags);
}

/**
 * @brief completion function
 *
 * @param reqp pointer to a request structure
 */
static void storvsc_io_done(struct hv_storvsc_request *reqp)
{
    struct storvsc_softc *sc = reqp->softc;
    struct vmscsi_req *vm_srb = &reqp->vstor_packet.u.vm_srb;

    struct storvsc_hcb *hcb = reqp->hcb;
    u8 opcode = hcb->cdb[0];

    int srb_status = SRB_STATUS(vm_srb->srb_status);
    if (vm_srb->scsi_status == SCSI_STATUS_OK) {
        if (srb_status != SRB_STATUS_SUCCESS) {
            /*
             * If there are errors, for example, invalid LUN,
             * host will inform VM through SRB status.
             */
            if (srb_status == SRB_STATUS_INVALID_LUN) {
                storvsc_debug("invalid LUN %d for op: %d", vm_srb->lun, opcode);
            } else {
                storvsc_debug("Unknown SRB flag: %d for op: %d", srb_status, opcode);
            }
            hcb->host_status = BTSTAT_NOT_SUCCESS;
        }

        if (opcode == SCSI_CMD_INQUIRY &&
            srb_status == SRB_STATUS_SUCCESS) {
            uint8_t *resp_buf = (uint8_t *)hcb->data;
            struct scsi_res_inquiry *inq_data =
                (struct scsi_res_inquiry *)hcb->data;

            /* Get the buffer length reported by host */
            int resp_xfer_len = vm_srb->transfer_len;

            /* Get the available buffer length */
            int resp_buf_len = resp_xfer_len >= 5 ? resp_buf[4] + 5 : 0;
            int data_len = (resp_buf_len < resp_xfer_len) ?
                resp_buf_len : resp_xfer_len;
            if (data_len >= 5) {
                storvsc_debug("storvsc inquiry (%d) [%x %x %x %x %x ... ]", data_len,
                    resp_buf[0], resp_buf[1], resp_buf[2],
                    resp_buf[3], resp_buf[4]);
            }
            /*
             * XXX: Hyper-V (since win2012r2) responses inquiry with
             * unknown version (0) for GEN-2 DVD device.
             * Manually set the version number to SPC3 in order to
             * ask CAM to continue probing with "PROBE_REPORT_LUNS".
             * see probedone() in scsi_xpt.c
             */
            if (SID_TYPE(inq_data) == T_CDROM &&
                inq_data->version == 0 &&
                (vmstor_proto_version >= VMSTOR_PROTOCOL_VERSION_WIN8)) {
                inq_data->version = SCSI_REV_SPC3;
                storvsc_debug("set version from 0 to %d", inq_data->version);
            }
            /*
             * XXX: Manually fix the wrong response returned from WS2012
             */
            if (!is_scsi_valid(inq_data) &&
                (vmstor_proto_version == VMSTOR_PROTOCOL_VERSION_WIN8_1 ||
                vmstor_proto_version == VMSTOR_PROTOCOL_VERSION_WIN8 ||
                vmstor_proto_version == VMSTOR_PROTOCOL_VERSION_WIN7)) {
                if (data_len >= 4 &&
                    (resp_buf[2] == 0 || resp_buf[3] == 0)) {
                    resp_buf[2] = SCSI_REV_SPC3;
                    resp_buf[3] = 2; // resp fmt must be 2
                    storvsc_debug("fix version and resp fmt for 0x%x", vmstor_proto_version);
                }
            } else if (data_len >= SHORT_INQUIRY_LENGTH) {
                char vendor[16];

                storvsc_cam_strvis((u8*)vendor, (u8*)inq_data->vendor,
                    sizeof(inq_data->vendor), sizeof(vendor));
                /*
                 * XXX: Upgrade SPC2 to SPC3 if host is WIN8 or
                 * WIN2012 R2 in order to support UNMAP feature.
                 */
                if (!runtime_memcmp(vendor, "Msft", 4) &&
                    SID_ANSI_REV(inq_data) == SCSI_REV_SPC2 &&
                    (vmstor_proto_version ==
                     VMSTOR_PROTOCOL_VERSION_WIN8_1 ||
                     vmstor_proto_version ==
                     VMSTOR_PROTOCOL_VERSION_WIN8)) {
                    inq_data->version = SCSI_REV_SPC3;
                    storvsc_debug("storvsc upgrades SPC2 to SPC3");
                }
            }
        }
    } else {
        /**
         * On Some Windows hosts TEST_UNIT_READY command can return
         * SRB_STATUS_ERROR and sense data, for example, asc=0x3a,1
         * "(Medium not present - tray closed)". This error can be
         * ignored since it will be sent to host periodically.
         */
        boolean unit_not_ready = \
            vm_srb->scsi_status == SCSI_STATUS_CHECK_COND &&
            opcode == SCSI_CMD_TEST_UNIT_READY &&
            srb_status == SRB_STATUS_ERROR;
        if (!unit_not_ready) {
            storvsc_debug("storvsc scsi_status = %d, srb_status = %d", vm_srb->scsi_status, srb_status);
        }
    }

    hcb->scsi_status = (vm_srb->scsi_status & 0xFF);

    apply(hcb->completion);
    storvsc_free_request(sc, reqp);

    storvsc_hcb_dealloc(sc, hcb);
}

/**
 * @brief Free a request structure
 *
 * Free a request structure by returning it to the free list
 *
 * @param sc pointer to a softc
 * @param reqp pointer to a request structure
 */
static void storvsc_free_request(struct storvsc_softc *sc, struct hv_storvsc_request *reqp)
{
    u64 flags = spin_lock_irq(&sc->hs_lock);
    list_push_back(&sc->hs_free_list, &reqp->link);
    spin_unlock_irq(&sc->hs_lock, flags);
}

/**
 * @brief Determine type of storage device from GUID
 *
 * Using the type GUID, determine if this is a StorVSC (paravirtual
 * SCSI or BlkVSC (paravirtual IDE) device.
 *
 * @param dev a device
 * returns an enum
 */
static enum hv_storage_type storvsc_get_storage_type(hv_device* device)
{
    if (runtime_memcmp(&device->class_id, &gBlkVscDeviceType, sizeof(device->class_id)) == 0)
        return DRIVER_BLKVSC;
    if (runtime_memcmp(&device->class_id, &gStorVscDeviceType, sizeof(device->class_id)) == 0)
        return DRIVER_STORVSC;
    return DRIVER_UNKNOWN;
}

closure_function(1, 3, boolean, storvsc_probe,
                 kernel_heaps, kh,
                 struct hv_device*, device,
                 storage_attach, a,
                 boolean*, storvsc_attached)
{
    status s = storvsc_attach(bound(kh), device, a);
    if (!is_ok(s)) {
        msg_err("attach failed with status %v\n", s);
        return false;
    }
    *storvsc_attached = true;
    return true;
}

void init_storvsc(kernel_heaps kh)
{
    register_vmbus_driver(&gStorVscDeviceType, closure(heap_locked(kh), storvsc_probe, kh));
    register_vmbus_driver(&gBlkVscDeviceType, closure(heap_locked(kh), storvsc_probe, kh));
}
