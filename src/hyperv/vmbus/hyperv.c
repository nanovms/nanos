#include <kernel.h>
#include <hyperv_internal.h>
#include <hyperv.h>
#include "vmbus_reg.h"
#include "vmbus_var.h"
#include "hyperv_var.h"

//#define HYPERV_DEBUG
#ifdef HYPERV_DEBUG
#define hyperv_debug(x, ...) do { rprintf("HYPERV: " x "\n", ##__VA_ARGS__); } while(0)
#else
#define hyperv_debug(x, ...)
#endif

#define __FreeBSD_version 1100000

#define HYPERV_FREEBSD_BUILD        0ULL
#define HYPERV_FREEBSD_VERSION      ((uint64_t)__FreeBSD_version)
#define HYPERV_FREEBSD_OSID     0ULL

#define MSR_HV_GUESTID_BUILD_FREEBSD    \
    (HYPERV_FREEBSD_BUILD & MSR_HV_GUESTID_BUILD_MASK)
#define MSR_HV_GUESTID_VERSION_FREEBSD  \
    ((HYPERV_FREEBSD_VERSION << MSR_HV_GUESTID_VERSION_SHIFT) & \
     MSR_HV_GUESTID_VERSION_MASK)
#define MSR_HV_GUESTID_OSID_FREEBSD \
    ((HYPERV_FREEBSD_OSID << MSR_HV_GUESTID_OSID_SHIFT) & \
     MSR_HV_GUESTID_OSID_MASK)

#define MSR_HV_GUESTID_FREEBSD      \
    (MSR_HV_GUESTID_BUILD_FREEBSD | \
     MSR_HV_GUESTID_VERSION_FREEBSD | \
     MSR_HV_GUESTID_OSID_FREEBSD |  \
     MSR_HV_GUESTID_OSTYPE_FREEBSD)

typedef struct hyperv_platform_info {
    heap general;                  /* general heap for internal use */
    heap contiguous;               /* physically */

    /* probed devices and registered drivers */
    struct list vmbus_list;
    struct list driver_list;

    //hypercall
    struct hypercall_ctx hypercall_context;

    vmbus_dev vmbus;

    boolean initialized;
} *hyperv_platform_info;

BSS_RO_AFTER_INIT struct hyperv_platform_info hyperv_info;

u64
hypercall_post_message(bus_addr_t msg_paddr)
{
    return hypercall_md(hyperv_info.hypercall_context.hc_addr,
        HYPERCALL_POST_MESSAGE, msg_paddr, 0);
}

u64
hypercall_signal_event(bus_addr_t monprm_paddr)
{
    return hypercall_md(hyperv_info.hypercall_context.hc_addr,
        HYPERCALL_SIGNAL_EVENT, monprm_paddr, 0);
}

boolean
hyperv_detect(kernel_heaps kh) {
    hyperv_info.initialized = false;
    hyperv_info.general = heap_general(kh);
    hyperv_info.contiguous = (heap)heap_linear_backed(kh);

    if (!hyperv_arch_detect(kh))
        return false;

    /* Set guest id: othervise hypercall_create() fails */
    hyperv_write_msr(MSR_HV_GUEST_OS_ID, MSR_HV_GUESTID_FREEBSD);

    list_init(&hyperv_info.vmbus_list);
    list_init(&hyperv_info.driver_list);
    hyperv_info.initialized = true;
    return true;
}

boolean
hyperv_detected(void)
{
    return hyperv_info.initialized;
}

void
register_vmbus_driver(const struct hyperv_guid *type, vmbus_device_probe probe)
{
    vmbus_driver vd = allocate(hyperv_info.general, sizeof(struct vmbus_driver));
    assert(vd != INVALID_ADDRESS);
    vd->type = type;
    vd->probe = probe;
    list_insert_before(&hyperv_info.driver_list, &vd->l);
}

void
init_vmbus(kernel_heaps kh)
{
    hypercall_create(&hyperv_info.hypercall_context);

    status s = vmbus_attach(kh, &hyperv_info.vmbus);
    if (!is_ok(s)) {
        msg_err("attach failed with status %v\n", s);
        return;
    }

    init_netvsc(kh);
    init_storvsc(kh);
    init_vmbus_shutdown(kh);
}

status
hyperv_probe_devices(storage_attach a, boolean *storvsc_attached)
{
    status s = vmbus_probe_channels(hyperv_info.vmbus, &hyperv_info.driver_list, &hyperv_info.vmbus_list);
    if (!is_ok(s))
        return s;

    list_foreach(&hyperv_info.vmbus_list, nl) {
        list_foreach(&hyperv_info.driver_list, l) {
            vmbus_driver xd = struct_from_list(l, vmbus_driver, l);
            hv_device *device = struct_from_list(nl, hv_device*, l);
            if (runtime_memcmp(&device->class_id, xd->type, sizeof(*xd->type))) {
                continue;
            }
            apply(xd->probe, device, a, storvsc_attached);
        }
    }
    vmbus_set_poll_mode(hyperv_info.vmbus, false);
    return s;
}
