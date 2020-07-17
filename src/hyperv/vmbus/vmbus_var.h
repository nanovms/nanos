#ifndef _VMBUS_VAR_H_
#define _VMBUS_VAR_H_

#include <hyperv_busdma.h>
#include "vmbus_reg.h"

struct vmbus_xact {
	struct vmbus_xact_ctx		*x_ctx;
	void				*x_priv;

	void				*x_req;
	struct hyperv_dma		x_req_dma;

	const void			*x_resp;
	size_t				x_resp_len;
	void				*x_resp0;
};

struct vmbus_xact_ctx {
	size_t				xc_req_size;
	size_t				xc_resp_size;
	size_t				xc_priv_size;

	struct spinlock     xc_lock;
	/*
	 * Protected by xc_lock.
	 */
	uint32_t			xc_flags;	/* VMBUS_XACT_CTXF_ */
	struct vmbus_xact		*xc_free;
	struct vmbus_xact		*xc_active;
	struct vmbus_xact		*xc_orphan;
};

/*
 * NOTE: DO NOT CHANGE THIS.
 */
#define VMBUS_SINT_MESSAGE  2

/*
 * NOTE:
 * - DO NOT set it to the same value as VMBUS_SINT_MESSAGE.
 * - DO NOT set it to 0.
 */
#define VMBUS_SINT_TIMER    4

/*
 * NOTE: DO NOT CHANGE THESE
 */
#define VMBUS_CONNID_MESSAGE            1
#define VMBUS_CONNID_EVENT              2

struct vmbus_message;
typedef struct vmbus_dev *vmbus_dev;

typedef void            (*vmbus_chanmsg_proc_t)(vmbus_dev,
                            const struct vmbus_message *);

#define VMBUS_CHANMSG_PROC(name, func)  \
        [VMBUS_CHANMSG_TYPE_##name] = func
#define VMBUS_CHANMSG_PROC_WAKEUP(name) \
        VMBUS_CHANMSG_PROC(name, vmbus_msghc_wakeup)

/*
 * CACHE_LINE_SIZE is the compile-time maximum cache line size for an
 * architecture.  It should be used with appropriate caution.
 */
#define CACHE_LINE_SHIFT    6
#define CACHE_LINE_SIZE     (1 << CACHE_LINE_SHIFT)

struct vmbus_pcpu_data {
    u64          intr_cnt;  /* Hyper-V interrupt counter */
    struct vmbus_message    *message;   /* shared messages */
    uint32_t        vcpuid;     /* virtual cpuid */
    int         event_flags_cnt;/* # of event flags */
    struct vmbus_evtflags   *event_flags;   /* event flags from host */

    /* Rarely used fields */
    struct hyperv_dma   message_dma;    /* busdma glue */
    struct hyperv_dma   event_flags_dma;/* busdma glue */
    thunk message_task;
} __aligned(CACHE_LINE_SIZE);

typedef struct vmbus_dev {
    heap general;
    heap contiguous;                /* physically */

    void            (*vmbus_event_proc)(vmbus_dev, int);
    boolean poll_mode;

    u64          *vmbus_tx_evtflags;
                        /* event flags to host */
    struct vmbus_mnf    *vmbus_mnf2;    /* monitored by host */

    u64          *vmbus_rx_evtflags;

    struct vmbus_channel *volatile vmbus_chmap[VMBUS_CHAN_MAX];
    struct vmbus_xact_ctx vmbus_xc;
    struct vmbus_pcpu_data  vmbus_pcpu[MAXCPU];

    int         vmbus_idtvec;
    thunk       vmbus_intr_handler;

    uint32_t    vmbus_version;
    uint32_t        vmbus_gpadl;

    /* Shared memory for vmbus_{rx,tx}_evtflags */
    void            *vmbus_evtflags;
    struct hyperv_dma   vmbus_evtflags_dma;

    void            *vmbus_mnf1;    /* monitored by VM, unused */
    struct hyperv_dma   vmbus_mnf1_dma;
    struct hyperv_dma   vmbus_mnf2_dma;

    /* Primary channels */
    struct spinlock              vmbus_prichan_lock;
    struct list                  vmbus_prichans;

    /* Complete channel list */
    struct spinlock              vmbus_chan_lock;
    struct list                  vmbus_chans;
} *vmbus_dev;

#define VMBUS_PCPU_GET(sc, field, cpu)  (sc)->vmbus_pcpu[(cpu)].field
#define VMBUS_PCPU_PTR(sc, field, cpu)  &(sc)->vmbus_pcpu[(cpu)].field

uint32_t        vmbus_gpadl_alloc(vmbus_dev);
struct vmbus_msghc * vmbus_msghc_get(vmbus_dev, size_t);
void            vmbus_msghc_put(vmbus_dev, struct vmbus_msghc *);
void            *vmbus_msghc_dataptr(struct vmbus_msghc *);
boolean         vmbus_msghc_exec_noresult(struct vmbus_msghc *);
boolean         vmbus_msghc_exec(vmbus_dev, struct vmbus_msghc *);
void            vmbus_msghc_exec_cancel(vmbus_dev, struct vmbus_msghc *);
const struct vmbus_message *
                vmbus_msghc_wait_result(vmbus_dev, struct vmbus_msghc *);
const struct vmbus_message *
                vmbus_msghc_poll_result(vmbus_dev,
                    struct vmbus_msghc *);
void            vmbus_msghc_wakeup(vmbus_dev,
                    const struct vmbus_message *);
void            vmbus_msghc_reset(struct vmbus_msghc *, size_t);
void		vmbus_poll_messages(vmbus_dev);

status vmbus_attach(kernel_heaps kh, vmbus_dev *dev);
status vmbus_probe_channels(vmbus_dev dev, const list deriver_list, list nodes);
void vmbus_set_poll_mode(vmbus_dev dev, boolean);

#endif	/* !_VMBUS_VAR_H_ */
