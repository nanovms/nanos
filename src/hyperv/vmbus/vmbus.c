#include <kernel.h>
#include <page.h>
#include <hyperv_internal.h>
#include <vmbus_xact.h>
#include "hyperv_var.h"
#include "vmbus.h"
#include "vmbus_chanvar.h"
#include "vmbus_var.h"
#include "vmbus_reg.h"

#define NULL 0

#ifdef VMBUS_DEBUG
#define vmbus_debug(x, ...) do { rprintf("VMBUS: " x "\n", ##__VA_ARGS__); } while(0)
#else
#define vmbus_debug(x, ...)
#endif

static void         vmbus_chanmsg_handle(vmbus_dev,
                    const struct vmbus_message *);

static const uint32_t       vmbus_version[] = {
    VMBUS_VERSION_WIN10,
    VMBUS_VERSION_WIN8_1,
    VMBUS_VERSION_WIN8,
    VMBUS_VERSION_WIN7,
    VMBUS_VERSION_WS2008
};

static const vmbus_chanmsg_proc_t
vmbus_chanmsg_handlers[VMBUS_CHANMSG_TYPE_MAX] = {
    VMBUS_CHANMSG_PROC_WAKEUP(CHOFFER),
    VMBUS_CHANMSG_PROC_WAKEUP(CHOFFER_DONE),
    VMBUS_CHANMSG_PROC_WAKEUP(CONNECT_RESP)
};

#define VMBUS_GPADL_START       0xe1e10

struct vmbus_msghc {
    struct vmbus_xact       *mh_xact;
    struct hypercall_postmsg_in mh_inprm_save;
};

uint32_t            vmbus_current_version;

static __inline void
vmbus_handle_intr1(vmbus_dev sc, int cpu)
{
    volatile struct vmbus_message *msg;
    struct vmbus_message *msg_base;

    msg_base = VMBUS_PCPU_GET(sc, message, cpu);

    /*
     * Check event timer.
     */
    msg = msg_base + VMBUS_SINT_TIMER;
    if (msg->msg_type == HYPERV_MSGTYPE_TIMER_EXPIRED) {
        msg->msg_type = HYPERV_MSGTYPE_NONE;

//        vmbus_et_intr(frame);

        /*
         * Make sure the write to msg_type (i.e. set to
         * HYPERV_MSGTYPE_NONE) happens before we read the
         * msg_flags and EOMing. Otherwise, the EOMing will
         * not deliver any more messages since there is no
         * empty slot
         *
         * NOTE:
         * mb() is used here, since atomic_thread_fence_seq_cst()
         * will become compiler fence on UP kernel.
         */
        memory_barrier();
        if (msg->msg_flags & VMBUS_MSGFLAG_PENDING) {
            /*
             * This will cause message queue rescan to possibly
             * deliver another msg from the hypervisor
             */
            write_msr(MSR_HV_EOM, 0);
        }
    }

    /*
     * Check events.  Hot path for network and storage I/O data; high rate.
     *
     * NOTE:
     * As recommended by the Windows guest fellows, we check events before
     * checking messages.
     */
    sc->vmbus_event_proc(sc, cpu);

    /*
     * Check messages.  Mainly management stuffs; ultra low rate.
     */
    msg = msg_base + VMBUS_SINT_MESSAGE;
    if (msg->msg_type != HYPERV_MSGTYPE_NONE) {
        vmbus_debug("SINT Message!");
        enqueue(bhqueue, VMBUS_PCPU_GET(sc, message_task, cpu));
    }
}

void
vmbus_handle_intr(vmbus_dev dev)
{
    int cpu = 0;

    /*
     * Disable preemption.
     */
    u64 flags = irq_disable_save();

    /*
     * Do a little interrupt counting.
     */
    (*VMBUS_PCPU_PTR(dev, intr_cnt, cpu))++;

    vmbus_handle_intr1(dev, cpu);

    /*
     * Enable preemption.
     */
    irq_restore(flags);
}

static void
vmbus_synic_setup(vmbus_dev dev)
{
    int cpu = 0;
    uint64_t val, orig, read_val;
    uint32_t sint;

    /*
     * Setup the SynIC message.
     */
    orig = read_msr(MSR_HV_SIMP);
    val = MSR_HV_SIMP_ENABLE | (orig & MSR_HV_SIMP_RSVD_MASK) |
        ((VMBUS_PCPU_GET(dev, message_dma.hv_paddr, cpu) >> PAGELOG) <<
         MSR_HV_SIMP_PGSHIFT);
    write_msr(MSR_HV_SIMP, val);

    read_val = read_msr(MSR_HV_SIMP);
    assert(val == read_val);
    /*
     * Setup the SynIC event flags.
     */
    orig = read_msr(MSR_HV_SIEFP);
    val = MSR_HV_SIEFP_ENABLE | (orig & MSR_HV_SIEFP_RSVD_MASK) |
        ((VMBUS_PCPU_GET(dev, event_flags_dma.hv_paddr, cpu)
          >> PAGELOG) << MSR_HV_SIEFP_PGSHIFT);
    write_msr(MSR_HV_SIEFP, val);

    read_val = read_msr(MSR_HV_SIEFP);
    assert(val == read_val);

    /*
     * Configure and unmask SINT for message and event flags.
     */
    sint = MSR_HV_SINT0 + VMBUS_SINT_MESSAGE;
    orig = read_msr(sint);
    val = dev->vmbus_idtvec | MSR_HV_SINT_AUTOEOI |
        (orig & MSR_HV_SINT_RSVD_MASK);
    write_msr(sint, val);

    read_val = read_msr(sint);
    assert(val == read_val);

    /*
     * Configure and unmask SINT for timer.
     */
    sint = MSR_HV_SINT0 + VMBUS_SINT_TIMER;
    orig = read_msr(sint);
    val = dev->vmbus_idtvec | MSR_HV_SINT_AUTOEOI |
        (orig & MSR_HV_SINT_RSVD_MASK);
    write_msr(sint, val);

    read_val = read_msr(sint);
    assert(val == read_val);
    /*
     * All done; enable SynIC.
     */
    orig = read_msr(MSR_HV_SCONTROL);
    val = MSR_HV_SCTRL_ENABLE | (orig & MSR_HV_SCTRL_RSVD_MASK);
    write_msr(MSR_HV_SCONTROL, val);

    read_val = read_msr(MSR_HV_SCONTROL);
    assert(val == read_val);
}

void
vmbus_msghc_reset(struct vmbus_msghc *mh, size_t dsize)
{
    struct hypercall_postmsg_in *inprm;

    if (dsize > HYPERCALL_POSTMSGIN_DSIZE_MAX)
        halt("invalid data size %zu", dsize);

    inprm = vmbus_xact_req_data(mh->mh_xact);
    runtime_memset((u8 *)inprm, 0, HYPERCALL_POSTMSGIN_SIZE);
    inprm->hc_connid = VMBUS_CONNID_MESSAGE;
    inprm->hc_msgtype = HYPERV_MSGTYPE_CHANNEL;
    inprm->hc_dsize = dsize;
}

void *
vmbus_msghc_dataptr(struct vmbus_msghc *mh)
{
    struct hypercall_postmsg_in *inprm;

    inprm = vmbus_xact_req_data(mh->mh_xact);
    return (inprm->hc_data);
}

struct vmbus_msghc *
vmbus_msghc_get(vmbus_dev dev, size_t dsize)
{
    struct vmbus_msghc *mh;
    struct vmbus_xact *xact;

    if (dsize > HYPERCALL_POSTMSGIN_DSIZE_MAX)
        halt("invalid data size %zu", dsize);

    xact = vmbus_xact_get(&dev->vmbus_xc,
        dsize + __offsetof(struct hypercall_postmsg_in, hc_data[0]));
    if (xact == NULL)
        return (NULL);

    mh = vmbus_xact_priv(xact, sizeof(*mh));
    mh->mh_xact = xact;

    vmbus_msghc_reset(mh, dsize);
    return (mh);
}

void
vmbus_msghc_put(vmbus_dev __unused, struct vmbus_msghc *mh)
{
    vmbus_xact_put(mh->mh_xact);
}

boolean
vmbus_msghc_exec_noresult(struct vmbus_msghc *mh)
{
    struct hypercall_postmsg_in *inprm = vmbus_xact_req_data(mh->mh_xact);
    bus_addr_t inprm_paddr = vmbus_xact_req_paddr(mh->mh_xact);
    assert(inprm_paddr != INVALID_PHYSICAL);

    /*
     * Save the input parameter so that we could restore the input
     * parameter if the Hypercall failed.
     *
     * XXX
     * Is this really necessary?!  i.e. Will the Hypercall ever
     * overwrite the input parameter?
     */
    runtime_memcpy(&mh->mh_inprm_save, inprm, HYPERCALL_POSTMSGIN_SIZE);
    /*
     * In order to cope with transient failures, e.g. insufficient
     * resources on host side, we retry the post message Hypercall
     * several times.  20 retries seem sufficient.
     */
#define HC_RETRY_MAX    20

    for (int i = 0; i < HC_RETRY_MAX; ++i) {
        uint64_t status;

        status = hypercall_post_message(inprm_paddr);
        if (status == HYPERCALL_STATUS_SUCCESS)
            return true;

        kern_pause();

        /* Restore input parameter and try again */
        runtime_memcpy(inprm, &mh->mh_inprm_save, HYPERCALL_POSTMSGIN_SIZE);
    }

    return false;
}

boolean
vmbus_msghc_exec(vmbus_dev __unused, struct vmbus_msghc *mh)
{
    vmbus_xact_activate(mh->mh_xact);
    if (!vmbus_msghc_exec_noresult(mh)) {
        vmbus_xact_deactivate(mh->mh_xact);
        return false;
    }
    return true;
}

void
vmbus_msghc_exec_cancel(vmbus_dev __unused, struct vmbus_msghc *mh)
{
    vmbus_xact_deactivate(mh->mh_xact);
}

const struct vmbus_message *
vmbus_msghc_wait_result(vmbus_dev dev, struct vmbus_msghc *mh)
{
    size_t resp_len;

    if (dev->poll_mode) {
        while (1) {
            vmbus_poll_messages(dev);
            const struct vmbus_message *ret = vmbus_xact_poll(mh->mh_xact, &resp_len);
            if (ret != NULL)
                return ret;
            kernel_delay(milliseconds(1));
        }
    } else {
        return (vmbus_xact_wait(mh->mh_xact, &resp_len));
    }
}

const struct vmbus_message *
vmbus_msghc_poll_result(vmbus_dev dev, struct vmbus_msghc *mh)
{
    size_t resp_len;

    if (dev->poll_mode) {
        while (1) {
            vmbus_poll_messages(dev);
            const struct vmbus_message *ret = vmbus_xact_poll(mh->mh_xact, &resp_len);
            if (ret != NULL)
                return ret;
            kernel_delay(milliseconds(1));
        }
    } else {
        return (vmbus_xact_poll(mh->mh_xact, &resp_len));
    }
}

const struct vmbus_message *
vmbus_msghc_poll_first(vmbus_dev __unused, struct vmbus_msghc *mh)
{
    size_t resp_len;

    return (vmbus_xact_poll_first(mh->mh_xact, &resp_len));
}

void
vmbus_msghc_wakeup(vmbus_dev dev, const struct vmbus_message *msg)
{
    vmbus_xact_ctx_wakeup(&dev->vmbus_xc, msg, sizeof(*msg));
}

uint32_t
vmbus_gpadl_alloc(vmbus_dev dev)
{
    uint32_t gpadl;

again:
    gpadl = atomic_fetchadd32(&dev->vmbus_gpadl, 1);
    if (gpadl == 0)
        goto again;
    return (gpadl);
}

static void
vmbus_msg_task(vmbus_dev sc, int num_messages)
{
    volatile struct vmbus_message *msg;

    msg = VMBUS_PCPU_GET(sc, message, 0) + VMBUS_SINT_MESSAGE;
    for (int i=0; !num_messages || i<num_messages; ++i) {
        if (msg->msg_type == HYPERV_MSGTYPE_NONE) {
            /* No message */
            break;
        } else if (msg->msg_type == HYPERV_MSGTYPE_CHANNEL) {
            /* Channel message */
            vmbus_chanmsg_handle(sc,
                (const struct vmbus_message *)msg);
        }

        msg->msg_type = HYPERV_MSGTYPE_NONE;
        /*
         * Make sure the write to msg_type (i.e. set to
         * HYPERV_MSGTYPE_NONE) happens before we read the
         * msg_flags and EOMing. Otherwise, the EOMing will
         * not deliver any more messages since there is no
         * empty slot
         *
         * NOTE:
         * mb() is used here, since atomic_thread_fence_seq_cst()
         * will become compiler fence on UP kernel.
         */
        memory_barrier();
        if (msg->msg_flags & VMBUS_MSGFLAG_PENDING) {
            /*
             * This will cause message queue rescan to possibly
             * deliver another msg from the hypervisor
             */
            write_msr(MSR_HV_EOM, 0);
        }
    }
}

static boolean vmbus_connect(vmbus_dev dev, uint32_t version)
{
    struct vmbus_chanmsg_connect *req;

    struct vmbus_msghc *mh = vmbus_msghc_get(dev, sizeof(*req));
    if (mh == NULL)
        return false;

    req = vmbus_msghc_dataptr(mh);
    assert(req != INVALID_ADDRESS);
    runtime_memset((u8 *)req, 0, sizeof(*req));
    req->chm_hdr.chm_type = VMBUS_CHANMSG_TYPE_CONNECT;
    req->chm_ver = version;
    req->chm_evtflags = dev->vmbus_evtflags_dma.hv_paddr;
    assert(req->chm_evtflags != INVALID_PHYSICAL);
    req->chm_mnf1 = dev->vmbus_mnf1_dma.hv_paddr;
    assert(req->chm_mnf1 != INVALID_PHYSICAL);
    req->chm_mnf2 = dev->vmbus_mnf2_dma.hv_paddr;
    assert(req->chm_mnf2 != INVALID_PHYSICAL);

    if (!vmbus_msghc_exec(dev, mh)) {
        vmbus_msghc_put(dev, mh);
        return false;
    }

    const struct vmbus_message *msg = NULL;
    while (1) {
        vmbus_poll_messages(dev);
        msg = vmbus_msghc_poll_result(dev, mh);
        if (msg != NULL)
            break;
        kernel_delay(milliseconds(1));
    }

    int done = ((const struct vmbus_chanmsg_connect_resp *)
        msg->msg_data)->chm_done;

    vmbus_msghc_put(dev, mh);

    return (done ? true : false);
}

static boolean
vmbus_init(vmbus_dev dev)
{
    for (int i = 0; i < _countof(vmbus_version); ++i) {

        boolean done = vmbus_connect(dev, vmbus_version[i]);
        if (done) {
            vmbus_current_version = vmbus_version[i];
            dev->vmbus_version = vmbus_version[i];
            vmbus_debug("version %d.%d",
                VMBUS_VERSION_MAJOR(dev->vmbus_version),
                VMBUS_VERSION_MINOR(dev->vmbus_version));
            return true;
        }
    }
    return false;
}

static void
vmbus_chanmsg_handle(vmbus_dev sc, const struct vmbus_message *msg)
{
    vmbus_chanmsg_proc_t msg_proc;
    uint32_t msg_type;

    msg_type = ((const struct vmbus_chanmsg_hdr *)msg->msg_data)->chm_type;
    if (msg_type >= VMBUS_CHANMSG_TYPE_MAX) {
        vmbus_debug("unknown message type 0x%x", msg_type);
        return;
    }

    msg_proc = vmbus_chanmsg_handlers[msg_type];
    if (msg_proc != NULL)
        msg_proc(sc, msg);

    /* Channel specific processing */
    vmbus_chan_msgproc(sc, msg);
}

closure_function(1, 0, void, vmbus_msg_task_closure,
                 vmbus_dev, sc)
{
    vmbus_dev sc = bound(sc);
    vmbus_msg_task(sc, 0);
}

static void
vmbus_dma_alloc(struct vmbus_dev *dev)
{
    dev->vmbus_pcpu[0].message = allocate_zero(dev->contiguous, PAGESIZE);
    assert(dev->vmbus_pcpu[0].message != INVALID_ADDRESS);
    dev->vmbus_pcpu[0].message_dma.hv_paddr = physical_from_virtual(dev->vmbus_pcpu[0].message);
    assert(dev->vmbus_pcpu[0].message_dma.hv_paddr != INVALID_PHYSICAL);

    dev->vmbus_pcpu[0].event_flags = allocate_zero(dev->contiguous, PAGESIZE);
    assert(dev->vmbus_pcpu[0].event_flags != INVALID_ADDRESS);
    dev->vmbus_pcpu[0].event_flags_dma.hv_paddr = physical_from_virtual(dev->vmbus_pcpu[0].event_flags);
    assert(dev->vmbus_pcpu[0].event_flags_dma.hv_paddr != INVALID_PHYSICAL);

    dev->vmbus_evtflags = allocate_zero(dev->contiguous, PAGESIZE);
    assert(dev->vmbus_evtflags != INVALID_ADDRESS);
    dev->vmbus_rx_evtflags = dev->vmbus_evtflags;
    dev->vmbus_tx_evtflags = dev->vmbus_evtflags + (PAGESIZE / 2);
    dev->vmbus_evtflags_dma.hv_paddr = physical_from_virtual(dev->vmbus_evtflags);
    assert(dev->vmbus_evtflags_dma.hv_paddr != INVALID_PHYSICAL);

    dev->vmbus_mnf1 = allocate_zero(dev->contiguous, PAGESIZE);
    assert(dev->vmbus_mnf1 != INVALID_ADDRESS);
    dev->vmbus_mnf1_dma.hv_paddr = physical_from_virtual(dev->vmbus_mnf1);
    assert(dev->vmbus_mnf1_dma.hv_paddr != INVALID_PHYSICAL);

    dev->vmbus_mnf2 = allocate_zero(dev->contiguous, PAGESIZE);
    assert(dev->vmbus_mnf2 != INVALID_ADDRESS);
    dev->vmbus_mnf2_dma.hv_paddr = physical_from_virtual(dev->vmbus_mnf2);
    assert(dev->vmbus_mnf2_dma.hv_paddr != INVALID_PHYSICAL);
}

closure_function(1, 0, void, vmbus_interrupt, vmbus_dev, dev)
{
    vmbus_dev dev = bound(dev);
    vmbus_handle_intr(dev);
}

void
vmbus_poll_messages(vmbus_dev dev)
{
    if (dev->poll_mode)
        vmbus_msg_task(dev, 0);
}

status
vmbus_attach(kernel_heaps kh, vmbus_dev *result)
{
    heap h = heap_general(kh);
    vmbus_dev dev = allocate_zero(h, sizeof(struct vmbus_dev));
    assert(dev != INVALID_ADDRESS);

    dev->general = h;
    dev->contiguous = heap_backed(kh);

    dev->vmbus_gpadl = VMBUS_GPADL_START;
    spin_lock_init(&dev->vmbus_prichan_lock); //"vmbus prichan"
    list_init(&dev->vmbus_prichans);
    spin_lock_init(&dev->vmbus_chan_lock); //"vmbus channel"
    list_init(&dev->vmbus_chans);

    vmbus_xact_ctx_create(dev, HYPERCALL_POSTMSGIN_SIZE, VMBUS_MSG_SIZE,
        sizeof(struct vmbus_msghc));

    dev->vmbus_pcpu[0].message_task = closure(dev->general, vmbus_msg_task_closure, dev);

    dev->vmbus_idtvec = allocate_interrupt();
    vmbus_debug("interrupt vector %d; registering", dev->vmbus_idtvec);
    dev->vmbus_intr_handler = closure(dev->general, vmbus_interrupt, dev);
    register_interrupt(dev->vmbus_idtvec, dev->vmbus_intr_handler, "vmbus");

    dev->poll_mode = true;

    vmbus_dma_alloc(dev);

    vmbus_synic_setup(dev);

    if (!vmbus_init(dev))
        return timm("result", "vmbus initialization failed");

    if (dev->vmbus_version == VMBUS_VERSION_WS2008 ||
        dev->vmbus_version == VMBUS_VERSION_WIN7)
        dev->vmbus_event_proc = vmbus_event_proc_compat;
    else
        dev->vmbus_event_proc = vmbus_event_proc;

    *result = dev;

    return STATUS_OK;
}

static bool
vmbus_driver_registered(const list driver_list, const struct hyperv_guid* chm_chtype)
{
    list_foreach(driver_list, l) {
        vmbus_driver xd = struct_from_list(l, vmbus_driver, l);
        if (!runtime_memcmp(chm_chtype, xd->type, sizeof(*xd->type)))
            return true;
    }
    return false;
}

status
vmbus_probe_channels(vmbus_dev dev, const list driver_list, list nodes)
{
    struct vmbus_chanmsg_chrequest *req;

    struct vmbus_msghc *mh = vmbus_msghc_get(dev, sizeof(*req));
    assert(mh != NULL);

    req = vmbus_msghc_dataptr(mh);
    req->chm_hdr.chm_type = VMBUS_CHANMSG_TYPE_CHREQUEST;

    if (!vmbus_msghc_exec(dev, mh)) {
        vmbus_msghc_put(dev, mh);
        return timm("result", "vmbus scan failed");
    }

    /* Collect responses */
    while ( 1 ) {
        // poll only one choffer message
        vmbus_msg_task(dev, 1);
        const struct vmbus_message *msg = vmbus_msghc_poll_first(dev, mh);
        if (msg == NULL) {
            kernel_delay(milliseconds(1));
            continue;
        }

        u32 msg_type = ((const struct vmbus_chanmsg_hdr *)msg->msg_data)->chm_type;
        /* Handle response */
        if (msg_type == VMBUS_CHANMSG_TYPE_CHOFFER) {

            const struct vmbus_chanmsg_choffer *offer = (const struct vmbus_chanmsg_choffer *)msg->msg_data;

            if (!vmbus_driver_registered(driver_list, &offer->chm_chtype)) {
                vmbus_debug("Ignored choffer for device "GUID_FMT"", GUID_ARG(offer->chm_chtype.hv_guid));
                continue;
            }

            struct vmbus_channel* new_channel = vmbus_chan_choffer_open_channel(dev, msg);
            if (!new_channel) {
                vmbus_debug("Failure opening channel for device "GUID_FMT"; ignoring choffer",
                            GUID_ARG(offer->chm_chtype.hv_guid));
                continue;
            }
            vmbus_debug("Opened channel for device "GUID_FMT"", GUID_ARG(offer->chm_chtype.hv_guid));
            buffer hv_dev = allocate_buffer(dev->general, sizeof(struct hv_device));
            struct hv_device *device = buffer_ref(hv_dev, 0);

            runtime_memcpy(&device->class_id, &offer->chm_chtype, sizeof(device->class_id));
            runtime_memcpy(&device->device_id, &offer->chm_chinst, sizeof(device->device_id));

            device->channel = new_channel;

            list_insert_before(nodes, &device->l);
        } else if (msg_type == VMBUS_CHANMSG_TYPE_CHOFFER_DONE) {
            /* End of offer list */
            vmbus_xact_deactivate(mh->mh_xact);
            break;
        } else {
            vmbus_debug("unexpected offer response type %d", msg_type );
            vmbus_xact_deactivate(mh->mh_xact);
            goto err_unexpected_offer;
        }
    }

    vmbus_msghc_put(dev, mh);
    return STATUS_OK;
err_unexpected_offer:
    vmbus_msghc_put(dev, mh);
    return timm("result", "unexpected channel offer");
}

void
vmbus_set_poll_mode(vmbus_dev dev, boolean poll_mode)
{
    dev->poll_mode = poll_mode;
}
