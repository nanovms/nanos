/*-
 * Copyright (c) 2009-2012 Microsoft Corp.
 * Copyright (c) 2010-2012 Citrix Inc.
 * Copyright (c) 2012 NetApp Inc.
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

#define NULL 0

#include <kernel.h>
#include <page.h>
#include <hyperv_internal.h>
#include <hyperv.h>
#include <lwip/netif.h>
#include "hv_net_vsc.h"
#include "hv_rndis.h"
#include "hv_rndis_filter.h"

#ifdef HYPERV_RNDIS_DEBUG
#define hyperv_rndis_debug(x, ...) do {rprintf(" HYPERV RNDIS: " x "\n", ##__VA_ARGS__);} while(0)
#else
#define hyperv_rndis_debug(x, ...)
#endif


/*
 * Forward declarations
 */
static int  hv_rf_send_request(rndis_device *device, rndis_request *request,
                   uint32_t message_type);
static void hv_rf_receive_response(rndis_device *device, rndis_msg *response);
static void hv_rf_receive_indicate_status(rndis_device *device,
                      rndis_msg *response);
static void hv_rf_receive_data(rndis_device *device, rndis_msg *message,
                   netvsc_packet *pkt);
static int  hv_rf_query_device(rndis_device *device, uint32_t oid,
                   void *result, uint32_t *result_size);
static inline int hv_rf_query_device_mac(rndis_device *device);
static int  hv_rf_set_packet_filter(rndis_device *device, uint32_t new_filter);
static int  hv_rf_init_device(rndis_device *device);
static int  hv_rf_open_device(rndis_device *device);
static int  hv_rf_close_device(rndis_device *device);
static void hv_rf_on_send_completion(void *context);
static void hv_rf_on_send_request_completion(void *context);
static void hv_rf_on_send_request_halt_completion(void *context);

static inline void
hv_request_prepare_wait(rndis_request *request)
{
    request->wait_flag = true;
}

static inline void
hv_request_wait_for_reply(rndis_request *request, rndis_device *device)
{
    struct vmbus_channel *channel = device->net_dev->dev->channel;
    while (request->wait_flag) {
        vmbus_chan_poll_messages(channel);
        if (!request->wait_flag)
            break;
        kernel_delay(100);
    }
}

static inline u64
hv_get_phys_addr(void *virt)
{
    u64 ret = physical_from_virtual(virt);
    assert(ret != INVALID_PHYSICAL);
    return (ret);
}

/*
 * Allow module_param to work and override to switch to promiscuous mode.
 */
static inline rndis_device *
hv_get_rndis_device(struct hv_device *dev)
{
    rndis_device *device;

    device = allocate_zero(dev->device->general, sizeof(rndis_device));
    assert(device != INVALID_ADDRESS);

    spin_lock_init(&device->req_lock);

    list_init(&device->myrequest_list);

    device->state = RNDIS_DEV_UNINITIALIZED;

    return (device);
}

/*
 *
 */
static inline void
hv_put_rndis_device(rndis_device *device)
{
    hn_softc_t *dev = device->net_dev->dev->device;
    deallocate(dev->general, device, sizeof(*device));
}

/*
 *
 */
static inline rndis_request *
hv_rndis_request(rndis_device *device, uint32_t message_type,
         uint32_t message_length)
{
    rndis_request *request;
    rndis_msg *rndis_mesg;
    rndis_set_request *set;

    hn_softc_t *dev = device->net_dev->dev->device;

    request = allocate_zero(dev->general, sizeof(rndis_request));
    assert(request != INVALID_ADDRESS);

    rndis_mesg = &request->request_msg;
    rndis_mesg->ndis_msg_type = message_type;
    rndis_mesg->msg_len = message_length;

    /*
     * Set the request id. This field is always after the rndis header
     * for request/response packet types so we just use the set_request
     * as a template.
     */
    set = &rndis_mesg->msg.set_request;
    set->request_id = atomic_fetchadd32(&device->new_request_id, 1);
    /* Increment to get the new value (call above returns old value) */
    set->request_id += 1;

    /* Add to the request list */
    u64 flags = spin_lock_irq(&device->req_lock);
    list_push_back(&device->myrequest_list, &request->mylist_entry);
    spin_unlock_irq(&device->req_lock, flags);

    return (request);
}

/*
 *
 */
static inline void
hv_put_rndis_request(rndis_device *device, rndis_request *request)
{
    u64 flags = spin_lock_irq(&device->req_lock);
    list_delete(&request->mylist_entry);
    spin_unlock_irq(&device->req_lock, flags);

    hn_softc_t *dev = device->net_dev->dev->device;
    deallocate(dev->general, request, sizeof(rndis_request));
}

/*
 *
 */
static int
hv_rf_send_request(rndis_device *device, rndis_request *request,
           uint32_t message_type)
{
    int ret;
    netvsc_packet *packet;

    /* Set up the packet to send it */
    packet = &request->pkt;

    packet->is_data_pkt = false;
    packet->tot_data_buf_len = request->request_msg.msg_len;
    packet->page_buf_count = 1;

    packet->page_buffers[0].gpa_page =
        hv_get_phys_addr(&request->request_msg) >> PAGELOG;
    packet->page_buffers[0].gpa_len = request->request_msg.msg_len;
    packet->page_buffers[0].gpa_ofs =
        (unsigned long)&request->request_msg & (PAGESIZE - 1);

    packet->compl.send.send_completion_context = request; /* packet */
    if (message_type != REMOTE_NDIS_HALT_MSG) {
        packet->compl.send.on_send_completion =
            hv_rf_on_send_request_completion;
    } else {
        packet->compl.send.on_send_completion =
            hv_rf_on_send_request_halt_completion;
    }
    packet->compl.send.send_completion_tid = (unsigned long)device;

    ret = hv_nv_on_send(device->net_dev->dev, packet);

    return (ret);
}

/*
 * RNDIS filter receive response
 */
static void
hv_rf_receive_response(rndis_device *device, rndis_msg *response)
{
    rndis_request *request = NULL;
    boolean_t found = false;

    u64 flags = spin_lock_irq(&device->req_lock);
    list_foreach(&device->myrequest_list, i) {
        request = struct_from_list(i, rndis_request *, mylist_entry);
        if (request->request_msg.msg.init_request.request_id ==
                      response->msg.init_complete.request_id) {
            found = true;
            break;
        }
    }
    spin_unlock_irq(&device->req_lock, flags);

    if (found) {
        if (response->msg_len <= sizeof(rndis_msg)) {
            runtime_memcpy(&request->response_msg, response,
                response->msg_len);
        } else {
            if (response->ndis_msg_type == REMOTE_NDIS_RESET_CMPLT) {
                /* Does not have a request id field */
                request->response_msg.msg.reset_complete.status =
                    STATUS_BUFFER_OVERFLOW;
            } else {
                request->response_msg.msg.init_complete.status =
                    STATUS_BUFFER_OVERFLOW;
            }
        }

        request->wait_flag = false;
    }
}

/*
 * RNDIS filter receive indicate status
 */
static void
hv_rf_receive_indicate_status(rndis_device *device, rndis_msg *response)
{
    rndis_indicate_status *indicate = &response->msg.indicate_status;

    if (indicate->status == RNDIS_STATUS_MEDIA_CONNECT) {
        netvsc_linkstatus_callback(device->net_dev->dev, 1);
    } else if (indicate->status == RNDIS_STATUS_MEDIA_DISCONNECT) {
        netvsc_linkstatus_callback(device->net_dev->dev, 0);
    } else {
        /* TODO: */
    }
}

/*
 * RNDIS filter receive data
 */
static void
hv_rf_receive_data(rndis_device *device, rndis_msg *message, netvsc_packet *pkt)
{
    rndis_packet *rndis_pkt;
    rndis_per_packet_info *rppi;
    ndis_8021q_info       *rppi_vlan_info;
    uint32_t data_offset;

    rndis_pkt = &message->msg.packet;

    /*
     * Fixme:  Handle multiple rndis pkt msgs that may be enclosed in this
     * netvsc packet (ie tot_data_buf_len != message_length)
     */

    /* Remove rndis header, then pass data packet up the stack */
    data_offset = RNDIS_HEADER_SIZE + rndis_pkt->data_offset;

    /* L2 frame length, with L2 header, not including CRC */
    pkt->tot_data_buf_len        = rndis_pkt->data_length;
    pkt->page_buffers[0].gpa_ofs += data_offset;
    /* Buffer length now L2 frame length plus trailing junk */
    pkt->page_buffers[0].gpa_len -= data_offset;

    pkt->is_data_pkt = true;

    pkt->vlan_tci = 0;

    /*
     * Read the VLAN ID if supplied by the Hyper-V infrastructure.
     * Let higher-level driver code decide if it wants to use it.
     * Ignore CFI, priority for now as FreeBSD does not support these.
     */
    if (rndis_pkt->per_pkt_info_offset != 0) {
        /* rppi struct exists; compute its address */
        rppi = (rndis_per_packet_info *)((uint8_t *)rndis_pkt +
            rndis_pkt->per_pkt_info_offset);
        /* if VLAN ppi struct, get the VLAN ID */
        if (rppi->type == ieee_8021q_info) {
            rppi_vlan_info = (ndis_8021q_info *)((uint8_t *)rppi
                +  rppi->per_packet_info_offset);
            pkt->vlan_tci = rppi_vlan_info->u1.s1.vlan_id;
        }
    }

    netvsc_recv(device->net_dev->dev, pkt);
}

/*
 * RNDIS filter on receive
 */
int
hv_rf_on_receive(struct hv_device *device, netvsc_packet *pkt)
{
    hn_softc_t *sc = device->device;
    netvsc_dev *net_dev = sc->net_dev;
    rndis_device *rndis_dev;
    rndis_msg rndis_mesg;
    rndis_msg *rndis_hdr;

    /* Make sure the rndis device state is initialized */
    if (net_dev->extension == NULL)
        return (ENODEV);

    rndis_dev = (rndis_device *)net_dev->extension;
    if (rndis_dev->state == RNDIS_DEV_UNINITIALIZED)
        return (EINVAL);

    /* Shift virtual page number to form virtual page address */
    rndis_hdr = (rndis_msg *)(u64)(pkt->page_buffers[0].gpa_page << PAGELOG);

    rndis_hdr = (void *)((unsigned long)rndis_hdr
            + pkt->page_buffers[0].gpa_ofs);

    // TODO: FreeBSD commented out code!
    /*
     * Make sure we got a valid rndis message
     * Fixme:  There seems to be a bug in set completion msg where
     * its msg_len is 16 bytes but the byte_count field in the
     * xfer page range shows 52 bytes
     */
#if 0
    if (pkt->tot_data_buf_len != rndis_hdr->msg_len) {
        DPRINT_ERR(NETVSC, "invalid rndis message? (expected %u "
            "bytes got %u)... dropping this message!",
            rndis_hdr->msg_len, pkt->tot_data_buf_len);
        DPRINT_EXIT(NETVSC);

        return (-1);
    }
#endif

    runtime_memcpy(&rndis_mesg, rndis_hdr,
        (rndis_hdr->msg_len > sizeof(rndis_msg)) ?
        sizeof(rndis_msg) : rndis_hdr->msg_len);

    switch (rndis_mesg.ndis_msg_type) {

    /* data message */
    case REMOTE_NDIS_PACKET_MSG:
        hv_rf_receive_data(rndis_dev, &rndis_mesg, pkt);
        break;
    /* completion messages */
    case REMOTE_NDIS_INITIALIZE_CMPLT:
    case REMOTE_NDIS_QUERY_CMPLT:
    case REMOTE_NDIS_SET_CMPLT:
    case REMOTE_NDIS_RESET_CMPLT:
    case REMOTE_NDIS_KEEPALIVE_CMPLT:
        hv_rf_receive_response(rndis_dev, &rndis_mesg);
        break;
    /* notification message */
    case REMOTE_NDIS_INDICATE_STATUS_MSG:
        hv_rf_receive_indicate_status(rndis_dev, &rndis_mesg);
        break;
    default:
        hyperv_rndis_debug("hv_rf_on_receive():  Unknown msg_type 0x%x",
            rndis_mesg.ndis_msg_type);
        break;
    }

    return (0);
}

/*
 * RNDIS filter query device
 */
static int
hv_rf_query_device(rndis_device *device, uint32_t oid, void *result,
           uint32_t *result_size)
{
    rndis_request *request;
    uint32_t in_result_size = *result_size;
    rndis_query_request *query;
    rndis_query_complete *query_complete;
    int ret = 0;

    *result_size = 0;
    request = hv_rndis_request(device, REMOTE_NDIS_QUERY_MSG,
        RNDIS_MESSAGE_SIZE(rndis_query_request));
    if (request == NULL) {
        ret = -1;
        goto cleanup;
    }

    /* Set up the rndis query */
    query = &request->request_msg.msg.query_request;
    query->oid = oid;
    query->info_buffer_offset = sizeof(rndis_query_request); 
    query->info_buffer_length = 0;
    query->device_vc_handle = 0;

    hv_request_prepare_wait(request);
    ret = hv_rf_send_request(device, request, REMOTE_NDIS_QUERY_MSG);
    if (ret != 0) {
        /* Fixme:  printf added */
        hyperv_rndis_debug("RNDISFILTER request failed to Send!");
        goto cleanup;
    }

    hv_request_wait_for_reply(request, device);

    /* Copy the response back */
    query_complete = &request->response_msg.msg.query_complete;

    if (query_complete->info_buffer_length > in_result_size) {
        ret = EINVAL;
        goto cleanup;
    }

    runtime_memcpy(result, (void *)((unsigned long)query_complete +
        query_complete->info_buffer_offset),
        query_complete->info_buffer_length);

    *result_size = query_complete->info_buffer_length;

cleanup:
    if (request != NULL)
        hv_put_rndis_request(device, request);

    return (ret);
}

/*
 * RNDIS filter query device MAC address
 */
static inline int
hv_rf_query_device_mac(rndis_device *device)
{
    uint32_t size = HW_MACADDR_LEN;

    return (hv_rf_query_device(device,
        RNDIS_OID_802_3_PERMANENT_ADDRESS, device->hw_mac_addr, &size));
}

/*
 * RNDIS filter set packet filter
 * Sends an rndis request with the new filter, then waits for a response
 * from the host.
 * Returns zero on success, non-zero on failure.
 */
static int
hv_rf_set_packet_filter(rndis_device *device, uint32_t new_filter)
{

    rndis_request *request;
    rndis_set_request *set;
    rndis_set_complete *set_complete;
    uint32_t status;
    int ret;

    request = hv_rndis_request(device, REMOTE_NDIS_SET_MSG,
        RNDIS_MESSAGE_SIZE(rndis_set_request) + sizeof(uint32_t));
    if (request == NULL) {
        ret = -1;
        goto cleanup;
    }

    /* Set up the rndis set */
    set = &request->request_msg.msg.set_request;
    set->oid = RNDIS_OID_GEN_CURRENT_PACKET_FILTER;
    set->info_buffer_length = sizeof(uint32_t);
    set->info_buffer_offset = sizeof(rndis_set_request); 

    runtime_memcpy((void *)((unsigned long)set + sizeof(rndis_set_request)),
        &new_filter, sizeof(uint32_t));

    hv_request_prepare_wait(request);
    ret = hv_rf_send_request(device, request, REMOTE_NDIS_SET_MSG);
    if (ret != 0) {
        goto cleanup;
    }

    /*
     * Wait for the response from the host.  Another thread will signal
     * us when the response has arrived.
     */
    hv_request_wait_for_reply(request, device);

    /* Response received, check status */
    set_complete = &request->response_msg.msg.set_complete;
    status = set_complete->status;
    if (status != RNDIS_STATUS_SUCCESS) {
        /* Bad response status, return error */
        ret = -2;
    }

cleanup:
    if (request != NULL) {
        hv_put_rndis_request(device, request);
    }
    return (ret);
}

/*
 * RNDIS filter init device
 */
static int
hv_rf_init_device(rndis_device *device)
{
    rndis_request *request;
    rndis_initialize_request *init;
    rndis_initialize_complete *init_complete;
    uint32_t status;
    int ret;

    request = hv_rndis_request(device, REMOTE_NDIS_INITIALIZE_MSG,
        RNDIS_MESSAGE_SIZE(rndis_initialize_request));
    if (!request) {
        ret = -1;
        goto cleanup;
    }

    /* Set up the rndis set */
    init = &request->request_msg.msg.init_request;
    init->major_version = RNDIS_MAJOR_VERSION;
    init->minor_version = RNDIS_MINOR_VERSION;
    /*
     * Per the RNDIS document, this should be set to the max MTU
     * plus the header size.  However, 2048 works fine, so leaving
     * it as is.
     */
    init->max_xfer_size = 2048;

    device->state = RNDIS_DEV_INITIALIZING;

    hv_request_prepare_wait(request);
    ret = hv_rf_send_request(device, request, REMOTE_NDIS_INITIALIZE_MSG);
    if (ret != 0) {
        device->state = RNDIS_DEV_UNINITIALIZED;
        goto cleanup;
    }

    hv_request_wait_for_reply(request, device);

    init_complete = &request->response_msg.msg.init_complete;
    status = init_complete->status;
    if (status == RNDIS_STATUS_SUCCESS) {
        device->state = RNDIS_DEV_INITIALIZED;
        ret = 0;
    } else {
        device->state = RNDIS_DEV_UNINITIALIZED;
        ret = -1;
    }

cleanup:
    if (request) {
        hv_put_rndis_request(device, request);
    }

    return (ret);
}

#define HALT_COMPLETION_WAIT_COUNT      25

/*
 * RNDIS filter halt device
 */
static int
hv_rf_halt_device(rndis_device *device)
{
    rndis_request *request;
    rndis_halt_request *halt;
    int i, ret;

    /* Attempt to do a rndis device halt */
    request = hv_rndis_request(device, REMOTE_NDIS_HALT_MSG,
        RNDIS_MESSAGE_SIZE(rndis_halt_request));
    if (request == NULL) {
        return (-1);
    }

    /* initialize "poor man's semaphore" */
    request->halt_complete_flag = 0;

    /* Set up the rndis set */
    halt = &request->request_msg.msg.halt_request;
    halt->request_id = atomic_fetchadd32(&device->new_request_id, 1);
    /* Increment to get the new value (call above returns old value) */
    halt->request_id += 1;

    ret = hv_rf_send_request(device, request, REMOTE_NDIS_HALT_MSG);
    if (ret != 0) {
        return (-1);
    }

    /*
     * Wait for halt response from halt callback.  We must wait for
     * the transaction response before freeing the request and other
     * resources.
     */
    for (i=HALT_COMPLETION_WAIT_COUNT; i > 0; i--) {
        if (request->halt_complete_flag != 0) {
            break;
        }
        kernel_delay(400);
    }
    if (i == 0) {
        return (-1);
    }

    device->state = RNDIS_DEV_UNINITIALIZED;

    if (request != NULL) {
        hv_put_rndis_request(device, request);
    }

    return (0);
}

/*
 * RNDIS filter open device
 */
static int
hv_rf_open_device(rndis_device *device)
{
    int ret;

    if (device->state != RNDIS_DEV_INITIALIZED) {
        return (0);
    }

    if (hv_promisc_mode != 1) {
        ret = hv_rf_set_packet_filter(device,
            NDIS_PACKET_TYPE_BROADCAST     |
            NDIS_PACKET_TYPE_ALL_MULTICAST |
            NDIS_PACKET_TYPE_DIRECTED);
    } else {
        ret = hv_rf_set_packet_filter(device, 
            NDIS_PACKET_TYPE_PROMISCUOUS);
    }

    if (ret == 0) {
        device->state = RNDIS_DEV_DATAINITIALIZED;
    }

    return (ret);
}

/*
 * RNDIS filter close device
 */
static int
hv_rf_close_device(rndis_device *device)
{
    int ret;

    if (device->state != RNDIS_DEV_DATAINITIALIZED) {
        return (0);
    }

    ret = hv_rf_set_packet_filter(device, 0);
    if (ret == 0) {
        device->state = RNDIS_DEV_INITIALIZED;
    }

    return (ret);
}

/*
 * RNDIS filter on device add
 */
int
hv_rf_on_device_add(struct hv_device *dev, void *additl_info)
{
    int ret = 0;
    netvsc_dev *net_dev;
    rndis_device *rndis_dev;

    rndis_dev = hv_get_rndis_device(dev);
    assert(rndis_dev != INVALID_ADDRESS);

    /*
     * Let the inner driver handle this first to create the netvsc channel
     * NOTE! Once the channel is created, we may get a receive callback 
     * (hv_rf_on_receive()) before this call is completed.
     * Note:  Earlier code used a function pointer here.
     */
    net_dev = hv_nv_on_device_add(dev, additl_info);
    assert(net_dev != INVALID_ADDRESS);

    /*
     * Initialize the rndis device
     */

    net_dev->extension = rndis_dev;
    rndis_dev->net_dev = net_dev;


    /* Send the rndis initialization message */
    ret = hv_rf_init_device(rndis_dev);
    if (ret != 0) {
        /*
         * TODO: If rndis init failed, we will need to shut down
         * the channel
         */
    }

    /* Get the mac address */
    ret = hv_rf_query_device_mac(rndis_dev);
    if (ret != 0) {
        /* TODO: shut down rndis device and the channel */
    }

    struct netif *netif = (struct netif *)additl_info;

    runtime_memcpy(netif->hwaddr, rndis_dev->hw_mac_addr, sizeof(netif->hwaddr));

    return (ret);
}

/*
 * RNDIS filter on device remove
 */
int
hv_rf_on_device_remove(struct hv_device *device, boolean_t destroy_channel)
{
    hn_softc_t *sc = device->device;
    netvsc_dev *net_dev = sc->net_dev;
    rndis_device *rndis_dev = (rndis_device *)net_dev->extension;
    int ret;

    /* Halt and release the rndis device */
    ret = hv_rf_halt_device(rndis_dev);

    hv_put_rndis_device(rndis_dev);
    net_dev->extension = NULL;

    /* Pass control to inner driver to remove the device */
    ret |= hv_nv_on_device_remove(device, destroy_channel);

    return (ret);
}

/*
 * RNDIS filter on open
 */
int
hv_rf_on_open(struct hv_device *device)
{
    hn_softc_t *sc = device->device;
    netvsc_dev *net_dev = sc->net_dev;

    return (hv_rf_open_device((rndis_device *)net_dev->extension));
}

/*
 * RNDIS filter on close
 */
int
hv_rf_on_close(struct hv_device *device)
{
    hn_softc_t *sc = device->device;
    netvsc_dev *net_dev = sc->net_dev;

    return (hv_rf_close_device((rndis_device *)net_dev->extension));
}

/*
 * RNDIS filter on send
 */
int
hv_rf_on_send(struct hv_device *device, netvsc_packet *pkt)
{
    rndis_filter_packet *filter_pkt;
    rndis_msg *rndis_mesg;
    rndis_packet *rndis_pkt;
    rndis_per_packet_info *rppi;
    ndis_8021q_info       *rppi_vlan_info;
    uint32_t rndis_msg_size;
    int ret = 0;

    /* Add the rndis header */
    filter_pkt = (rndis_filter_packet *)pkt->extension;

    zero(filter_pkt, sizeof(rndis_filter_packet));

    rndis_mesg = &filter_pkt->message;
    rndis_msg_size = RNDIS_MESSAGE_SIZE(rndis_packet);

    if (pkt->vlan_tci != 0) {
        rndis_msg_size += sizeof(rndis_per_packet_info) +
            sizeof(ndis_8021q_info);
    }

    rndis_mesg->ndis_msg_type = REMOTE_NDIS_PACKET_MSG;
    rndis_mesg->msg_len = pkt->tot_data_buf_len + rndis_msg_size;

    rndis_pkt = &rndis_mesg->msg.packet;
    rndis_pkt->data_offset = sizeof(rndis_packet);
    rndis_pkt->data_length = pkt->tot_data_buf_len;

    pkt->is_data_pkt = true;
    pkt->page_buffers[0].gpa_page = hv_get_phys_addr(rndis_mesg) >> PAGELOG;
    pkt->page_buffers[0].gpa_ofs =
        (unsigned long)rndis_mesg & (PAGESIZE - 1);
    pkt->page_buffers[0].gpa_len = rndis_msg_size;

    /* Save the packet context */
    filter_pkt->completion_context =
        pkt->compl.send.send_completion_context;

    /* Use ours */
    pkt->compl.send.on_send_completion = hv_rf_on_send_completion;
    pkt->compl.send.send_completion_context = filter_pkt;

    /*
     * If there is a VLAN tag, we need to set up some additional
     * fields so the Hyper-V infrastructure will stuff the VLAN tag
     * into the frame.
     */
    if (pkt->vlan_tci != 0) {
        /* Move data offset past end of rppi + VLAN structs */
        rndis_pkt->data_offset += sizeof(rndis_per_packet_info) +
            sizeof(ndis_8021q_info);

        /* must be set when we have rppi, VLAN info */
        rndis_pkt->per_pkt_info_offset = sizeof(rndis_packet);
        rndis_pkt->per_pkt_info_length = sizeof(rndis_per_packet_info) +
            sizeof(ndis_8021q_info);

        /* rppi immediately follows rndis_pkt */
        rppi = (rndis_per_packet_info *)(rndis_pkt + 1);
        rppi->size = sizeof(rndis_per_packet_info) +
            sizeof(ndis_8021q_info);
        rppi->type = ieee_8021q_info;
        rppi->per_packet_info_offset = sizeof(rndis_per_packet_info);

        /* VLAN info immediately follows rppi struct */
        rppi_vlan_info = (ndis_8021q_info *)(rppi + 1);
        /* FreeBSD does not support CFI or priority */
        rppi_vlan_info->u1.s1.vlan_id = pkt->vlan_tci & 0xfff;
    }

    /*
     * Invoke netvsc send.  If return status is bad, the caller now
     * resets the context pointers before retrying.
     */
    ret = hv_nv_on_send(device, pkt);

    return (ret);
}

/*
 * RNDIS filter on send completion callback
 */
static void
hv_rf_on_send_completion(void *context)
{
    rndis_filter_packet *filter_pkt = (rndis_filter_packet *)context;

    /* Pass it back to the original handler */
    netvsc_xmit_completion(filter_pkt->completion_context);
}

/*
 * RNDIS filter on send request completion callback
 */
static void
hv_rf_on_send_request_completion(void *context)
{
}

/*
 * RNDIS filter on send request (halt only) completion callback
 */
static void
hv_rf_on_send_request_halt_completion(void *context)
{
    rndis_request *request = context;

    /*
     * Notify hv_rf_halt_device() about halt completion.
     * The halt code must wait for completion before freeing
     * the transaction resources.
     */
    request->halt_complete_flag = 1;
}
