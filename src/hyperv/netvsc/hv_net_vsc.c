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

/**
 * HyperV vmbus network VSC (virtual services client) module
 *
 */


#include <kernel.h>
#include <page.h>
#include <lwip/netif.h>
#include <hyperv_internal.h>
#include <hyperv.h>
#include <vmbus.h>
#include <net_system_structs.h>
#include "hv_net_vsc.h"
#include "hv_rndis.h"
#include "hv_rndis_filter.h"

#ifdef NETVSC_DEBUG
#define netvsc_debug(x, ...) do {rprintf(" NETVSC: " x "\n", ##__VA_ARGS__);} while(0)
#else
#define netvsc_debug(x, ...)
#endif

/*
 * Forward declarations
 */
static void hv_nv_on_channel_callback(struct vmbus_channel *, void *hv_device);
static int  hv_nv_init_send_buffer_with_net_vsp(struct hv_device *device);
static int  hv_nv_init_rx_buffer_with_net_vsp(struct hv_device *device);
static int  hv_nv_destroy_rx_buffer(netvsc_dev *net_dev);
static int  hv_nv_connect_to_vsp(struct hv_device *device);

static int  hv_nv_destroy_send_buffer(netvsc_dev *net_dev);
static void hv_nv_on_send_completion(struct hv_device *device,
                     struct vmbus_chanpkt_hdr *pkt);
static void hv_nv_on_receive(struct hv_device *device,
                 struct vmbus_chanpkt_hdr *pkt);
static void hv_nv_send_receive_completion(struct hv_device *device,
                      uint64_t tid);

/*
 *
 */
static inline netvsc_dev *
hv_nv_alloc_net_device(struct hv_device *dev)
{
    netvsc_dev *net_dev;

    net_dev = allocate_zero(dev->device->general, sizeof(netvsc_dev));
    assert(net_dev != INVALID_ADDRESS);

    net_dev->dev = dev;
    net_dev->destroy = false;
    dev->device->net_dev = net_dev;

    return (net_dev);
}


/*
 *
 */
static inline netvsc_dev *
hv_nv_get_outbound_net_device(struct hv_device *device)
{
    hn_softc_t *sc = device->device;
    netvsc_dev *net_dev = sc->net_dev;
    assert(net_dev != NULL);
    return (net_dev);
}

/*
 *
 */
static inline netvsc_dev *
hv_nv_get_inbound_net_device(struct hv_device *device)
{
    hn_softc_t *sc = device->device;
    netvsc_dev *net_dev = sc->net_dev;

    if (net_dev == NULL) {
        return (net_dev);
    }
    /*
     * When the device is being destroyed; we only
     * permit incoming packets if and only if there
     * are outstanding sends.
     */
    if (net_dev->destroy && net_dev->num_outstanding_sends == 0) {
        return (NULL);
    }

    return (net_dev);
}

static inline void
hv_nv_prepare_wait_for_channel_message(netvsc_dev *net_dev)
{
    net_dev->channel_init_wait_flag = true;
}

static inline void
hv_nv_wait_for_channel_message(netvsc_dev *net_dev)
{
    while (net_dev->channel_init_wait_flag) {
        vmbus_chan_poll_messages(net_dev->dev->channel);
        if (!net_dev->channel_init_wait_flag)
            break;
        kernel_delay(100);
    }
}

/*
 * Net VSC initialize receive buffer with net VSP
 * 
 * Net VSP:  Network virtual services client, also known as the
 *     Hyper-V extensible switch and the synthetic data path.
 */
static int
hv_nv_init_rx_buffer_with_net_vsp(struct hv_device *device)
{
    hn_softc_t *sc = device->device;
    netvsc_dev *net_dev;
    nvsp_msg *init_pkt;
    int ret = 0;

    net_dev = hv_nv_get_outbound_net_device(device);
    if (!net_dev) {
        return (ENODEV);
    }

    net_dev->rx_buf = allocate_zero(sc->contiguous, net_dev->rx_buf_size);
    assert(net_dev->rx_buf != INVALID_ADDRESS);
    assert((u64)net_dev->rx_buf == pad((u64)net_dev->rx_buf, PAGESIZE));

    bus_addr_t rx_buf_paddr = physical_from_virtual(net_dev->rx_buf);
    assert(rx_buf_paddr != INVALID_PHYSICAL);
    /*
     * Establish the GPADL handle for this buffer on this channel.
     * Note:  This call uses the vmbus connection rather than the
     * channel to establish the gpadl handle. 
     * GPADL:  Guest physical address descriptor list.
     */
    vmbus_chan_gpadl_connect(
        device->channel, rx_buf_paddr,
        net_dev->rx_buf_size, &net_dev->rx_buf_gpadl_handle);

    /* sema_wait(&ext->channel_init_sema); KYS CHECK */

    /* Notify the NetVsp of the gpadl handle */
    init_pkt = &net_dev->channel_init_packet;

    runtime_memset((u8 *)init_pkt, 0, sizeof(nvsp_msg));

    init_pkt->hdr.msg_type = nvsp_msg_1_type_send_rx_buf;
    init_pkt->msgs.vers_1_msgs.send_rx_buf.gpadl_handle =
        net_dev->rx_buf_gpadl_handle;
    init_pkt->msgs.vers_1_msgs.send_rx_buf.id =
        NETVSC_RECEIVE_BUFFER_ID;

    /* Send the gpadl notification request */

    hv_nv_prepare_wait_for_channel_message(net_dev);
    ret = vmbus_chan_send(device->channel,
        VMBUS_CHANPKT_TYPE_INBAND, VMBUS_CHANPKT_FLAG_RC,
        init_pkt, sizeof(nvsp_msg), (uint64_t)init_pkt);
    if (ret != 0) {
        goto cleanup;
    }

    hv_nv_wait_for_channel_message(net_dev);

    /* Check the response */
    if (init_pkt->msgs.vers_1_msgs.send_rx_buf_complete.status
        != nvsp_status_success) {
        ret = EINVAL;
        goto cleanup;
    }

    net_dev->rx_section_count =
        init_pkt->msgs.vers_1_msgs.send_rx_buf_complete.num_sections;

    net_dev->rx_sections = allocate(sc->general, (net_dev->rx_section_count *
        sizeof(nvsp_1_rx_buf_section)));
    assert(net_dev->rx_sections != INVALID_ADDRESS);

    runtime_memcpy(net_dev->rx_sections,
        init_pkt->msgs.vers_1_msgs.send_rx_buf_complete.sections,
        net_dev->rx_section_count * sizeof(nvsp_1_rx_buf_section));


    /*
     * For first release, there should only be 1 section that represents
     * the entire receive buffer
     */
    if (net_dev->rx_section_count != 1
        || net_dev->rx_sections->offset != 0) {
        ret = EINVAL;
        goto cleanup;
    }

    goto exit;

cleanup:
    hv_nv_destroy_rx_buffer(net_dev);

exit:
    return (ret);
}

/*
 * Net VSC initialize send buffer with net VSP
 */
static int
hv_nv_init_send_buffer_with_net_vsp(struct hv_device *device)
{
    hn_softc_t *sc = device->device;
    netvsc_dev *net_dev;
    nvsp_msg *init_pkt;
    int ret = 0;

    net_dev = hv_nv_get_outbound_net_device(device);
    if (!net_dev) {
        return (ENODEV);
    }

    net_dev->send_buf = allocate_zero(sc->contiguous, net_dev->send_buf_size);
    assert(net_dev->send_buf != INVALID_ADDRESS);
    assert((u64)net_dev->send_buf == pad((u64)net_dev->send_buf, PAGESIZE));

    bus_addr_t send_buf_paddr = physical_from_virtual(net_dev->send_buf);
    assert(send_buf_paddr != INVALID_PHYSICAL);
    /*
     * Establish the gpadl handle for this buffer on this channel.
     * Note:  This call uses the vmbus connection rather than the
     * channel to establish the gpadl handle. 
     */
    vmbus_chan_gpadl_connect(device->channel,
        send_buf_paddr, net_dev->send_buf_size,
        &net_dev->send_buf_gpadl_handle);

    /* Notify the NetVsp of the gpadl handle */

    init_pkt = &net_dev->channel_init_packet;

    zero(init_pkt, sizeof(nvsp_msg));

    init_pkt->hdr.msg_type = nvsp_msg_1_type_send_send_buf;
    init_pkt->msgs.vers_1_msgs.send_rx_buf.gpadl_handle =
        net_dev->send_buf_gpadl_handle;
    init_pkt->msgs.vers_1_msgs.send_rx_buf.id =
        NETVSC_SEND_BUFFER_ID;

    /* Send the gpadl notification request */

    hv_nv_prepare_wait_for_channel_message(net_dev);
    ret = vmbus_chan_send(device->channel,
        VMBUS_CHANPKT_TYPE_INBAND,
        VMBUS_CHANPKT_FLAG_RC,
        init_pkt, sizeof(nvsp_msg), (uint64_t)init_pkt);
    if (ret != 0) {
        goto cleanup;
    }

    hv_nv_wait_for_channel_message(net_dev);

    /* Check the response */
    if (init_pkt->msgs.vers_1_msgs.send_send_buf_complete.status
        != nvsp_status_success) {
        ret = EINVAL;
        goto cleanup;
    }

    net_dev->send_section_size =
        init_pkt->msgs.vers_1_msgs.send_send_buf_complete.section_size;

    goto exit;

cleanup:
    hv_nv_destroy_send_buffer(net_dev);

exit:
    return (ret);
}

/*
 * Net VSC destroy receive buffer
 */
static int
hv_nv_destroy_rx_buffer(netvsc_dev *net_dev)
{
    hn_softc_t *sc = net_dev->dev->device;
    nvsp_msg *revoke_pkt;
    int ret = 0;

    /*
     * If we got a section count, it means we received a
     * send_rx_buf_complete msg 
     * (ie sent nvsp_msg_1_type_send_rx_buf msg) therefore,
     * we need to send a revoke msg here
     */
    if (net_dev->rx_section_count) {
        /* Send the revoke receive buffer */
        revoke_pkt = &net_dev->revoke_packet;
        zero(revoke_pkt, sizeof(nvsp_msg));

        revoke_pkt->hdr.msg_type = nvsp_msg_1_type_revoke_rx_buf;
        revoke_pkt->msgs.vers_1_msgs.revoke_rx_buf.id =
            NETVSC_RECEIVE_BUFFER_ID;

        ret = vmbus_chan_send(net_dev->dev->channel,
            VMBUS_CHANPKT_TYPE_INBAND, 0,
            revoke_pkt, sizeof(nvsp_msg), (uint64_t)revoke_pkt);

        /*
         * If we failed here, we might as well return and have a leak 
         * rather than continue and a bugchk
         */
        if (ret != 0) {
            return (ret);
        }
    }

    /* Tear down the gpadl on the vsp end */
    if (net_dev->rx_buf_gpadl_handle) {
        vmbus_chan_gpadl_disconnect(net_dev->dev->channel,
            net_dev->rx_buf_gpadl_handle);
        /*
         * If we failed here, we might as well return and have a leak 
         * rather than continue and a bugchk
         */
        if (ret != 0) {
            return (ret);
        }
        net_dev->rx_buf_gpadl_handle = 0;
    }

    if (net_dev->rx_buf) {
        /* Free up the receive buffer */
        deallocate(sc->contiguous, net_dev->rx_buf, net_dev->rx_buf_size);
        net_dev->rx_buf = NULL;
    }

    if (net_dev->rx_sections) {
        deallocate(sc->general, net_dev->rx_sections, (net_dev->rx_section_count *
                                                       sizeof(nvsp_1_rx_buf_section)));
        net_dev->rx_sections = NULL;
        net_dev->rx_section_count = 0;
    }

    return (ret);
}

/*
 * Net VSC destroy send buffer
 */
static int
hv_nv_destroy_send_buffer(netvsc_dev *net_dev)
{
    hn_softc_t *sc = net_dev->dev->device;
    nvsp_msg *revoke_pkt;
    int ret = 0;

    /*
     * If we got a section count, it means we received a
     * send_rx_buf_complete msg 
     * (ie sent nvsp_msg_1_type_send_rx_buf msg) therefore,
     * we need to send a revoke msg here
     */
    if (net_dev->send_section_size) {
        /* Send the revoke send buffer */
        revoke_pkt = &net_dev->revoke_packet;
        runtime_memset((u8 *)revoke_pkt, 0, sizeof(nvsp_msg));

        revoke_pkt->hdr.msg_type =
            nvsp_msg_1_type_revoke_send_buf;
        revoke_pkt->msgs.vers_1_msgs.revoke_send_buf.id =
            NETVSC_SEND_BUFFER_ID;

        ret = vmbus_chan_send(net_dev->dev->channel,
            VMBUS_CHANPKT_TYPE_INBAND, 0,
            revoke_pkt, sizeof(nvsp_msg), (uint64_t)revoke_pkt);
        /*
         * If we failed here, we might as well return and have a leak 
         * rather than continue and a bugchk
         */
        if (ret != 0) {
            return (ret);
        }
    }

    /* Tear down the gpadl on the vsp end */
    if (net_dev->send_buf_gpadl_handle) {
        vmbus_chan_gpadl_disconnect(net_dev->dev->channel,
            net_dev->send_buf_gpadl_handle);

        net_dev->send_buf_gpadl_handle = 0;
    }

    if (net_dev->send_buf) {
        /* Free up the receive buffer */
        deallocate(sc->contiguous, net_dev->send_buf, net_dev->send_buf_size);
        net_dev->send_buf = NULL;
    }

    return (ret);
}


/*
 * Attempt to negotiate the caller-specified NVSP version
 *
 * For NVSP v2, Server 2008 R2 does not set
 * init_pkt->msgs.init_msgs.init_compl.negotiated_prot_vers
 * to the negotiated version, so we cannot rely on that.
 */
static int
hv_nv_negotiate_nvsp_protocol(struct hv_device *device, netvsc_dev *net_dev,
                  uint32_t nvsp_ver)
{
    nvsp_msg *init_pkt;
    int ret;

    init_pkt = &net_dev->channel_init_packet;
    zero(init_pkt, sizeof(nvsp_msg));
    init_pkt->hdr.msg_type = nvsp_msg_type_init;

    /*
     * Specify parameter as the only acceptable protocol version
     */
    init_pkt->msgs.init_msgs.init.p1.protocol_version = nvsp_ver;
    init_pkt->msgs.init_msgs.init.protocol_version_2 = nvsp_ver;

    hv_nv_prepare_wait_for_channel_message(net_dev);
    /* Send the init request */
    ret = vmbus_chan_send(device->channel,
        VMBUS_CHANPKT_TYPE_INBAND,
        VMBUS_CHANPKT_FLAG_RC,
        init_pkt, sizeof(nvsp_msg), (uint64_t)init_pkt);
    if (ret != 0)
        return (-1);

    hv_nv_wait_for_channel_message(net_dev);

    if (init_pkt->msgs.init_msgs.init_compl.status != nvsp_status_success)
        return (EINVAL);

    return (0);
}

/*
 * Send NDIS version 2 config packet containing MTU.
 *
 * Not valid for NDIS version 1.
 */
static int
hv_nv_send_ndis_config(struct hv_device *device, uint32_t mtu)
{
    netvsc_dev *net_dev;
    nvsp_msg *init_pkt;
    int ret;

    net_dev = hv_nv_get_outbound_net_device(device);
    if (!net_dev)
        return (-ENODEV);

    /*
     * Set up configuration packet, write MTU
     * Indicate we are capable of handling VLAN tags
     */
    init_pkt = &net_dev->channel_init_packet;
    zero(init_pkt, sizeof(nvsp_msg));
    init_pkt->hdr.msg_type = nvsp_msg_2_type_send_ndis_config;
    init_pkt->msgs.vers_2_msgs.send_ndis_config.mtu = mtu;
    init_pkt->
        msgs.vers_2_msgs.send_ndis_config.capabilities.u1.u2.ieee8021q
        = 1;

    /* Send the configuration packet */
    ret = vmbus_chan_send(device->channel,
        VMBUS_CHANPKT_TYPE_INBAND, 0,
        init_pkt, sizeof(nvsp_msg), (uint64_t)init_pkt);
    if (ret != 0)
        return (-EINVAL);

    return (0);
}

/*
 * Net VSC connect to VSP
 */
static int
hv_nv_connect_to_vsp(struct hv_device *device)
{
    netvsc_dev *net_dev;
    nvsp_msg *init_pkt;
    uint32_t nvsp_vers;
    uint32_t ndis_version;
    int ret = 0;
    hn_softc_t *sc = device->device;
    struct netif *ifp = sc->netif;

    net_dev = hv_nv_get_outbound_net_device(device);

    /*
     * Negotiate the NVSP version.  Try NVSP v2 first.
     */
    nvsp_vers = NVSP_PROTOCOL_VERSION_2;
    ret = hv_nv_negotiate_nvsp_protocol(device, net_dev, nvsp_vers);
    if (ret != 0) {
        /* NVSP v2 failed, try NVSP v1 */
        nvsp_vers = NVSP_PROTOCOL_VERSION_1;
        ret = hv_nv_negotiate_nvsp_protocol(device, net_dev, nvsp_vers);
        if (ret != 0) {
            /* NVSP v1 failed, return bad status */
            return (ret);
        }
    }
    net_dev->nvsp_version = nvsp_vers;

    netvsc_debug("NVSP protocol: %d", net_dev->nvsp_version);
    /*
     * Set the MTU if supported by this NVSP protocol version
     * This needs to be right after the NVSP init message per Haiyang
     */
    if (nvsp_vers >= NVSP_PROTOCOL_VERSION_2)
        ret = hv_nv_send_ndis_config(device, ifp->mtu);

    /*
     * Send the NDIS version
     */
    init_pkt = &net_dev->channel_init_packet;

    runtime_memset((u8 *)init_pkt, 0, sizeof(nvsp_msg));

    /*
     * Updated to version 5.1, minimum, for VLAN per Haiyang
     */
    ndis_version = NDIS_VERSION;

    init_pkt->hdr.msg_type = nvsp_msg_1_type_send_ndis_vers;
    init_pkt->msgs.vers_1_msgs.send_ndis_vers.ndis_major_vers =
        (ndis_version & 0xFFFF0000) >> 16;
    init_pkt->msgs.vers_1_msgs.send_ndis_vers.ndis_minor_vers =
        ndis_version & 0xFFFF;

    /* Send the init request */

    ret = vmbus_chan_send(device->channel,
        VMBUS_CHANPKT_TYPE_INBAND, 0,
        init_pkt, sizeof(nvsp_msg), (uint64_t)init_pkt);
    if (ret != 0) {
        goto cleanup;
    }
    /*
     * TODO:  BUGBUG - We have to wait for the above msg since the netvsp
     * uses KMCL which acknowledges packet (completion packet) 
     * since our Vmbus always set the
     * HV_VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED flag
     */
    /* sema_wait(&NetVscChannel->channel_init_sema); */

    /* Post the big receive buffer to NetVSP */
    ret = hv_nv_init_rx_buffer_with_net_vsp(device);
    if (ret == 0)
        ret = hv_nv_init_send_buffer_with_net_vsp(device);

cleanup:
    return (ret);
}

/*
 * Net VSC on device add
 * 
 * Callback when the device belonging to this driver is added
 */
netvsc_dev *
hv_nv_on_device_add(struct hv_device *device, void *additional_info)
{
    netvsc_dev *net_dev;
    netvsc_packet *packet;

    net_dev = hv_nv_alloc_net_device(device);
    assert(net_dev != INVALID_ADDRESS);

    /* Initialize the NetVSC channel extension */
    net_dev->rx_buf_size = NETVSC_RECEIVE_BUFFER_SIZE;
    spin_lock_init(&net_dev->rx_pkt_list_lock);

    net_dev->send_buf_size = NETVSC_SEND_BUFFER_SIZE;

    list_init(&net_dev->myrx_packet_list);

    /* 
     * malloc a sufficient number of netvsc_packet buffers to hold
     * a packet list.  Add them to the netvsc device packet queue.
     */
    for (int i=0; i < NETVSC_RECEIVE_PACKETLIST_COUNT; i++) {
        packet = allocate_zero(device->device->general,
            sizeof(netvsc_packet) + (NETVSC_RECEIVE_SG_COUNT * sizeof(struct vmbus_gpa_range)));
        assert(packet != INVALID_ADDRESS);
        list_push_back(&net_dev->myrx_packet_list, &packet->mylist_entry);
    }

    /*
     * Open the channel
     */
    vmbus_chan_open(device->channel,
        NETVSC_DEVICE_RING_BUFFER_SIZE, NETVSC_DEVICE_RING_BUFFER_SIZE,
        NULL, 0, hv_nv_on_channel_callback, device);
    /*
     * Connect with the NetVsp
     */
    int ret = hv_nv_connect_to_vsp(device);
    assert(ret == 0);

    netvsc_debug("CONNECTED TO VSP!");
    return (net_dev);
}

/*
 * Net VSC on send completion
 */
static void
hv_nv_on_send_completion(struct hv_device *device, struct vmbus_chanpkt_hdr *pkt)
{
    netvsc_dev *net_dev;
    nvsp_msg *nvsp_msg_pkt;
    netvsc_packet *net_vsc_pkt;

    net_dev = hv_nv_get_inbound_net_device(device);
    if (!net_dev) {
        return;
    }

    nvsp_msg_pkt =
        (nvsp_msg *)((unsigned long)pkt + (pkt->cph_hlen << 3));

    if (nvsp_msg_pkt->hdr.msg_type == nvsp_msg_type_init_complete
        || nvsp_msg_pkt->hdr.msg_type
            == nvsp_msg_1_type_send_rx_buf_complete
        || nvsp_msg_pkt->hdr.msg_type
            == nvsp_msg_1_type_send_send_buf_complete) {
        /* Copy the response back */
        runtime_memcpy(&net_dev->channel_init_packet, nvsp_msg_pkt,
            sizeof(nvsp_msg));
        net_dev->channel_init_wait_flag = false;
    } else if (nvsp_msg_pkt->hdr.msg_type ==
                   nvsp_msg_1_type_send_rndis_pkt_complete) {
        /* Get the send context */
        net_vsc_pkt =
            (netvsc_packet *)(unsigned long)pkt->cph_xactid;

        /* Notify the layer above us */
        net_vsc_pkt->compl.send.on_send_completion(
            net_vsc_pkt->compl.send.send_completion_context);

        atomic_subtract32(&net_dev->num_outstanding_sends, 1);
    }
}

/*
 * Net VSC on send
 * Sends a packet on the specified Hyper-V device.
 * Returns 0 on success, non-zero on failure.
 */
int
hv_nv_on_send(struct hv_device *device, netvsc_packet *pkt)
{
    netvsc_dev *net_dev;
    nvsp_msg send_msg;
    int ret;

    net_dev = hv_nv_get_outbound_net_device(device);
    if (!net_dev)
        return (ENODEV);

    send_msg.hdr.msg_type = nvsp_msg_1_type_send_rndis_pkt;
    if (pkt->is_data_pkt) {
        /* 0 is RMC_DATA */
        send_msg.msgs.vers_1_msgs.send_rndis_pkt.chan_type = 0;
    } else {
        /* 1 is RMC_CONTROL */
        send_msg.msgs.vers_1_msgs.send_rndis_pkt.chan_type = 1;
    }

    /* Not using send buffer section */
    send_msg.msgs.vers_1_msgs.send_rndis_pkt.send_buf_section_idx =
        0xFFFFFFFF;
    send_msg.msgs.vers_1_msgs.send_rndis_pkt.send_buf_section_size = 0;

    if (pkt->page_buf_count) {
        ret = vmbus_chan_send_sglist(device->channel,
            pkt->page_buffers, pkt->page_buf_count,
            &send_msg, sizeof(nvsp_msg), (uint64_t)pkt);
    } else {
        ret = vmbus_chan_send(device->channel,
            VMBUS_CHANPKT_TYPE_INBAND, VMBUS_CHANPKT_FLAG_RC,
            &send_msg, sizeof(nvsp_msg), (uint64_t)pkt);
    }

    /* Record outstanding send only if send_packet() succeeded */
    if (ret == 0)
        atomic_add32(&net_dev->num_outstanding_sends, 1);

    return (ret);
}

/*
 * Net VSC on receive
 *
 * In the FreeBSD Hyper-V virtual world, this function deals exclusively
 * with virtual addresses.
 */
static void 
hv_nv_on_receive(struct hv_device *device, struct vmbus_chanpkt_hdr *pkt)
{
    netvsc_dev *net_dev;
    struct vmbus_chanpkt_rxbuf *vm_xfer_page_pkt;
    nvsp_msg *nvsp_msg_pkt;
    unsigned long start;
    xfer_page_packet *xfer_page_pkt = NULL;
    int count = 0;
    int i = 0;

    net_dev = hv_nv_get_inbound_net_device(device);
    if (!net_dev)
        return;

    /*
     * All inbound packets other than send completion should be
     * xfer page packet.
     */
    if (pkt->cph_type != VMBUS_CHANPKT_TYPE_RXBUF)
        return;

    nvsp_msg_pkt = (nvsp_msg *)((unsigned long)pkt
        + (pkt->cph_hlen << 3));

    /* Make sure this is a valid nvsp packet */
    if (nvsp_msg_pkt->hdr.msg_type != nvsp_msg_1_type_send_rndis_pkt)
        return;

    vm_xfer_page_pkt = (struct vmbus_chanpkt_rxbuf *)pkt;

    if (vm_xfer_page_pkt->cp_rxbuf_id != NETVSC_RECEIVE_BUFFER_ID) {
        return;
    }

    struct list mylist_head;
    list_init(&mylist_head);

    /*
     * Grab free packets (range count + 1) to represent this xfer page
     * packet.  +1 to represent the xfer page packet itself.  We grab it
     * here so that we know exactly how many we can fulfill.
     */
    u64 flags = spin_lock_irq(&net_dev->rx_pkt_list_lock);
    while (!list_empty(&net_dev->myrx_packet_list)) {
        struct list *net_vsc_pkt = list_get_next(&net_dev->myrx_packet_list);
        list_delete(net_vsc_pkt);

        list_push_back(&mylist_head, net_vsc_pkt);

        if (++count == vm_xfer_page_pkt->cp_rxbuf_cnt + 1)
            break;
    }

    spin_unlock_irq(&net_dev->rx_pkt_list_lock, flags);

    /*
     * We need at least 2 netvsc pkts (1 to represent the xfer page
     * and at least 1 for the range) i.e. we can handle some of the
     * xfer page packet ranges...
     */
    if (count < 2) {
        /* Return netvsc packet to the freelist */
        flags = spin_lock_irq(&net_dev->rx_pkt_list_lock);
        for (i=count; i != 0; i--) {
            struct list *net_vsc_pkt = list_get_next(&mylist_head);
            list_delete(net_vsc_pkt);

            list_push_back(&net_dev->myrx_packet_list, net_vsc_pkt);
        }
        spin_unlock_irq(&net_dev->rx_pkt_list_lock, flags);

        hv_nv_send_receive_completion(device,
            vm_xfer_page_pkt->cp_hdr.cph_xactid);

        return;
    }

    /* Take the first packet in the list */
    struct list *l = list_get_next(&mylist_head);
    xfer_page_pkt = struct_from_list(l, xfer_page_packet *, mylist_entry);
    list_delete(l);

    /* This is how many data packets we can supply */
    xfer_page_pkt->count = count - 1;

    /* Each range represents 1 RNDIS pkt that contains 1 Ethernet frame */
    for (i=0; i < (count - 1); i++) {
        l = list_get_next(&mylist_head);
        netvsc_packet *net_vsc_pkt = struct_from_list(l, netvsc_packet *, mylist_entry);
        list_delete(l);

        /*
         * Initialize the netvsc packet
         */
        net_vsc_pkt->xfer_page_pkt = xfer_page_pkt;
        net_vsc_pkt->compl.rx.rx_completion_context = net_vsc_pkt;
        net_vsc_pkt->device = device;
        /* Save this so that we can send it back */
        net_vsc_pkt->compl.rx.rx_completion_tid =
            vm_xfer_page_pkt->cp_hdr.cph_xactid;

        net_vsc_pkt->tot_data_buf_len =
            vm_xfer_page_pkt->cp_rxbuf[i].rb_len;
        net_vsc_pkt->page_buf_count = 1;

        net_vsc_pkt->page_buffers[0].gpa_len =
            vm_xfer_page_pkt->cp_rxbuf[i].rb_len;

        /* The virtual address of the packet in the receive buffer */
        start = ((unsigned long)net_dev->rx_buf +
            vm_xfer_page_pkt->cp_rxbuf[i].rb_ofs);
        start = ((unsigned long)start) & ~(PAGESIZE - 1);

        /* Page number of the virtual page containing packet start */
        net_vsc_pkt->page_buffers[0].gpa_page = start >> PAGELOG;

        /* Calculate the page relative offset */
        net_vsc_pkt->page_buffers[0].gpa_ofs =
            vm_xfer_page_pkt->cp_rxbuf[i].rb_ofs & (PAGESIZE - 1);

        /*
         * In this implementation, we are dealing with virtual
         * addresses exclusively.  Since we aren't using physical
         * addresses at all, we don't care if a packet crosses a
         * page boundary.  For this reason, the original code to
         * check for and handle page crossings has been removed.
         */

        /*
         * Pass it to the upper layer.  The receive completion call
         * has been moved into this function.
         */
        hv_rf_on_receive(device, net_vsc_pkt);

        /*
         * Moved completion call back here so that all received 
         * messages (not just data messages) will trigger a response
         * message back to the host.
         */
        hv_nv_on_receive_completion(net_vsc_pkt);
    }
}

/*
 * Net VSC send receive completion
 */
static void
hv_nv_send_receive_completion(struct hv_device *device, uint64_t tid)
{
    nvsp_msg rx_comp_msg;
    int retries = 0;
    int ret = 0;

    rx_comp_msg.hdr.msg_type = nvsp_msg_1_type_send_rndis_pkt_complete;

    /* Pass in the status */
    rx_comp_msg.msgs.vers_1_msgs.send_rndis_pkt_complete.status =
        nvsp_status_success;

retry_send_cmplt:
    /* Send the completion */
    ret = vmbus_chan_send(device->channel,
        VMBUS_CHANPKT_TYPE_COMP, 0,
        &rx_comp_msg, sizeof(nvsp_msg), tid);
    if (ret == 0) {
        /* success */
        /* no-op */
    } else if (ret == EAGAIN) {
        /* no more room... wait a bit and attempt to retry 3 times */
        retries++;

        if (retries < 4) {
            kernel_delay(100);
            goto retry_send_cmplt;
        }
    }
}

/*
 * Net VSC on receive completion
 *
 * Send a receive completion packet to RNDIS device (ie NetVsp)
 */
void
hv_nv_on_receive_completion(void *context)
{
    netvsc_packet *packet = (netvsc_packet *)context;
    struct hv_device *device = (struct hv_device *)packet->device;
    netvsc_dev    *net_dev;
    uint64_t       tid = 0;
    boolean_t send_rx_completion = false;

    /*
     * Even though it seems logical to do a hv_nv_get_outbound_net_device()
     * here to send out receive completion, we are using
     * hv_nv_get_inbound_net_device() since we may have disabled
     * outbound traffic already.
     */
    net_dev = hv_nv_get_inbound_net_device(device);
    if (net_dev == NULL)
        return;

    /* Overloading use of the lock. */
    u64 flags = spin_lock_irq(&net_dev->rx_pkt_list_lock);

    packet->xfer_page_pkt->count--;

    /*
     * Last one in the line that represent 1 xfer page packet.
     * Return the xfer page packet itself to the free list.
     */
    if (packet->xfer_page_pkt->count == 0) {
        send_rx_completion = true;
        tid = packet->compl.rx.rx_completion_tid;
        list_push_back(&net_dev->myrx_packet_list,
                       &((netvsc_packet *)(packet->xfer_page_pkt))->mylist_entry);
    }

    /* Put the packet back on the free list */
    list_push_back(&net_dev->myrx_packet_list, &packet->mylist_entry);
    spin_unlock_irq(&net_dev->rx_pkt_list_lock, flags);

    /* Send a receive completion for the xfer page packet */
    if (send_rx_completion)
        hv_nv_send_receive_completion(device, tid);
}

/*
 * Net VSC on channel callback
 */
static void
hv_nv_on_channel_callback(struct vmbus_channel *context, void *hv_device)
{
    /* Fixme:  Magic number */
    const int net_pkt_size = 2048;
    struct hv_device *device = (struct hv_device *)hv_device;
    netvsc_dev *net_dev;
    int     bufferlen = net_pkt_size;
    int     ret = 0;

    uint8_t *buffer = allocate(device->device->general, net_pkt_size * sizeof(uint8_t));
    assert(buffer != INVALID_ADDRESS);

    net_dev = hv_nv_get_inbound_net_device(device);
    assert(net_dev != NULL);

    do {
        struct vmbus_chanpkt_hdr *desc = (struct vmbus_chanpkt_hdr *)buffer;
        int bytes_rxed = bufferlen;
        ret = vmbus_chan_recv_pkt(device->channel,
            desc, &bytes_rxed);
        if (ret == ENOBUFS) {
            /* Handle large packet */
            deallocate(device->device->general, buffer, bufferlen);
            buffer = allocate(device->device->general, bytes_rxed);
            if (buffer == INVALID_ADDRESS) {
                break;
            }
            bufferlen = bytes_rxed;
            continue;
        } else if (ret == EAGAIN) {
            /* No more channel packets; done! */
            break;
        }
        assert(ret == 0);
        switch (desc->cph_type) {
        case VMBUS_CHANPKT_TYPE_COMP:
            hv_nv_on_send_completion(device, desc);
            break;
        case VMBUS_CHANPKT_TYPE_RXBUF:
            hv_nv_on_receive(device, desc);
            break;
        default:
            break;
        }
    } while (1);
    deallocate(device->device->general, buffer, bufferlen);
}
